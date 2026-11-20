"""Brings the stack up as real OS processes, for the demonstrations.

This is process mode.  It gives genuine process and port separation and real
authentication boundaries, and it runs anywhere Python runs.  It does *not*
give network-namespace isolation -- in process mode a party that guesses the
model port can open a TCP connection to it, and is stopped by the model
refusing to authenticate it rather than by the network refusing to carry it.
Container mode (deploy/docker-compose.yml) adds that second layer.  Both
outcomes are reported distinctly by ``party.probe``.
"""

from __future__ import annotations

import atexit
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

#: Every stack that has been started and not yet stopped.  A caller that uses
#: ``with`` or ``try/finally`` never needs this; it exists for the paths that
#: do not run cleanup code, which is where orphans came from.
_LIVE: set["Stack"] = set()


def _stop_all() -> None:
    for stack in list(_LIVE):
        try:
            stack.stop()
        except OSError:
            pass


atexit.register(_stop_all)


# -- kill-on-parent-death --------------------------------------------------
#
# atexit covers a clean exit and the interpreter unwinding.  It does not cover
# the parent being killed outright -- taskkill /F, Stop-Process -Force, an
# editor tearing down the terminal that owns it -- because no Python code runs
# at all in that case.  The children then survive their parent, and a surviving
# gateway is worse than a surviving idle process: it still holds an AuditLog on
# artifacts/live-audit.log, so the next run appends a second, independent hash
# chain into the same file and the verifier reports a break that nobody caused.
#
# Windows has exactly one mechanism for this: a job object with
# KILL_ON_JOB_CLOSE.  The handle is held for the life of this process, and when
# the process dies for any reason the kernel closes it and terminates every
# process in the job.  There is no equivalent single call on POSIX, where the
# demonstrations run under a shell that signals the process group instead; this
# is therefore a no-op off Windows, and the atexit path above is what covers it.

_JOB: Any = None
_JOB_TRIED = False

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOBOBJECT_EXTENDED_LIMIT_INFORMATION = 9


def _job_handle() -> Any:
    """A process-wide job object, created once, or None if unavailable."""
    global _JOB, _JOB_TRIED
    if _JOB_TRIED:
        return _JOB
    _JOB_TRIED = True
    if sys.platform != "win32":
        return None

    import ctypes
    import ctypes.wintypes as wt

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BASIC_LIMIT(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wt.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wt.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wt.DWORD),
            ("SchedulingClass", wt.DWORD),
        ]

    class _EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BASIC_LIMIT),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wt.HANDLE
    k32.SetInformationJobObject.argtypes = [
        wt.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wt.DWORD,
    ]

    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = _EXTENDED_LIMIT()
    info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not k32.SetInformationJobObject(
        job,
        _JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        return None
    _JOB = job
    return _JOB


def _bind_to_parent(proc: subprocess.Popen) -> None:
    """Tie ``proc``'s lifetime to this process, where the OS supports it.

    Best effort by design: assignment can fail when this process already sits
    in a job that forbids nesting, and a demonstration that refuses to start
    because of a process-management detail would be worse than one that leaks a
    child on an abnormal kill.
    """
    job = _job_handle()
    if job is None:
        return
    import ctypes

    handle = getattr(proc, "_handle", None)
    if handle is None:
        return
    ctypes.WinDLL("kernel32", use_last_error=True).AssignProcessToJobObject(
        job, int(handle)
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise TimeoutError("%s:%d did not come up in %.1fs (%s)" % (host, port, timeout, last))


@dataclass(eq=False)
class Stack:
    """A running gateway, its model servers, and the audit log they share.

    ``eq=False`` so that identity is used for equality and hashing: two stacks
    are never interchangeable, and the registry in ``_LIVE`` needs to hold them
    by identity.
    """

    secret: str
    audit_path: str
    gateway_port: int
    red_model_port: int
    blue_model_port: int
    procs: list[subprocess.Popen] = field(default_factory=list)

    def stop(self) -> None:
        _LIVE.discard(self)
        for p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
        for p in reversed(self.procs):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        self.procs.clear()

    def __enter__(self) -> "Stack":
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


def start(
    *,
    secret: str = "demo-secret-not-for-production",
    tick_ms: float = 25.0,
    audit_path: str = "artifacts/audit.log",
    shared_model_endpoint: bool = False,
    shared_context: bool = False,
    unsafe_rate: float = 0.4,
    fresh_audit: bool = True,
    quiet: bool = True,
) -> Stack:
    """Start a stack.

    ``shared_model_endpoint`` points both parties at one model server and
    ``shared_context`` collapses that server's per-session contexts.  Together
    they reproduce failure mode #1 from the threat model: someone pointed two
    tenants at one model to save memory.
    """
    if fresh_audit and os.path.exists(audit_path):
        os.remove(audit_path)
    os.makedirs(os.path.dirname(os.path.abspath(audit_path)) or ".", exist_ok=True)

    env = dict(os.environ, DOUBLEBLIND_SECRET=secret, PYTHONUNBUFFERED="1")
    red_port = free_port()
    blue_port = red_port if shared_model_endpoint else free_port()
    gw_port = free_port()

    def spawn(args: list[str]) -> subprocess.Popen:
        proc = subprocess.Popen(
            [sys.executable, "-m", *args],
            env=env,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
        )
        _bind_to_parent(proc)
        return proc

    stack = Stack(
        secret=secret,
        audit_path=audit_path,
        gateway_port=gw_port,
        red_model_port=red_port,
        blue_model_port=blue_port,
    )
    # Registered before anything is spawned, so a failure part-way through
    # startup still leaves the processes that did start reachable by cleanup.
    _LIVE.add(stack)

    common = ["--unsafe-rate", str(unsafe_rate)]
    if shared_context:
        common.append("--shared-context")

    stack.procs.append(
        spawn(
            [
                "doubleblind.model_server",
                "--name",
                "red-model" if not shared_model_endpoint else "shared-model",
                "--port",
                str(red_port),
                *common,
            ]
        )
    )
    if not shared_model_endpoint:
        stack.procs.append(
            spawn(
                [
                    "doubleblind.model_server",
                    "--name",
                    "blue-model",
                    "--port",
                    str(blue_port),
                    *common,
                ]
            )
        )
    for port in {red_port, blue_port}:
        wait_for_port("127.0.0.1", port)

    stack.procs.append(
        spawn(
            [
                "doubleblind.gateway",
                "--port",
                str(gw_port),
                "--red-model",
                "127.0.0.1:%d" % red_port,
                "--blue-model",
                "127.0.0.1:%d" % blue_port,
                "--tick-ms",
                str(tick_ms),
                "--audit",
                audit_path,
            ]
        )
    )
    wait_for_port("127.0.0.1", gw_port)
    return stack
