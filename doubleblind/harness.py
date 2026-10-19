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

import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field


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


@dataclass
class Stack:
    """A running gateway, its model servers, and the audit log they share."""

    secret: str
    audit_path: str
    gateway_port: int
    red_model_port: int
    blue_model_port: int
    procs: list[subprocess.Popen] = field(default_factory=list)

    def stop(self) -> None:
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
        return subprocess.Popen(
            [sys.executable, "-m", *args],
            env=env,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
        )

    stack = Stack(
        secret=secret,
        audit_path=audit_path,
        gateway_port=gw_port,
        red_model_port=red_port,
        blue_model_port=blue_port,
    )

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
