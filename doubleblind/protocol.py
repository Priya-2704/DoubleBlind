"""Line-delimited JSON transport for DOUBLEBLIND.

Every message between a party and the gateway, and between the gateway and a
model server, is a single UTF-8 JSON object terminated by a newline.  Messages
carry an HMAC-SHA256 tag over a canonical encoding of the envelope, a per-sender
sequence number and a unique message id, so a recipient can reject
unauthenticated, reordered, duplicated or stale traffic.

Standard library only.
"""

from __future__ import annotations

import hmac
import json
import secrets
import socket
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

PROTOCOL_VERSION = 1

#: Longest line we will read before treating the peer as hostile.
MAX_LINE_BYTES = 1 << 20

#: How far a message timestamp may drift from local time before we reject it.
MAX_CLOCK_SKEW_S = 120.0

#: How many recently seen message ids each peer remembers, for replay rejection
#: of messages that arrive inside the skew window.
REPLAY_WINDOW = 4096

# Message types.
HELLO = "hello"
HELLO_OK = "hello_ok"
SUBMIT = "submit"
RESULT = "result"
ADVISORY = "advisory"
INFER = "infer"
INFER_OK = "infer_ok"
ERROR = "error"

MESSAGE_TYPES = frozenset(
    {HELLO, HELLO_OK, SUBMIT, RESULT, ADVISORY, INFER, INFER_OK, ERROR}
)

#: Envelope fields covered by the MAC, in the order they are serialised.
SIGNED_FIELDS = ("v", "msg_id", "session_id", "party", "seq", "ts", "type", "body")


class ProtocolError(Exception):
    """Raised when a peer sends something that does not satisfy the protocol."""

    def __init__(self, reason: str, code: str = "protocol_error") -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding, so two parties MAC identical bytes."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(obj: Any) -> str:
    """SHA-256 of the canonical encoding of ``obj``, as lowercase hex."""
    return sha256(canonical(obj)).hexdigest()


def new_id() -> str:
    return secrets.token_hex(16)


def derive_key(secret: str, purpose: str) -> bytes:
    """Split one shared secret into independent per-purpose keys.

    Reusing a single key for party authentication and for the audit chain would
    let a party that knows its own key forge log entries, so each purpose gets
    its own key.
    """
    return hmac.new(secret.encode("utf-8"), purpose.encode("utf-8"), sha256).digest()


def make_envelope(
    *,
    session_id: str,
    party: str,
    seq: int,
    msg_type: str,
    body: dict[str, Any],
    key: bytes,
    ts: float | None = None,
) -> dict[str, Any]:
    """Build a signed envelope ready to put on the wire."""
    if msg_type not in MESSAGE_TYPES:
        raise ProtocolError("unknown message type " + repr(msg_type))
    env = {
        "v": PROTOCOL_VERSION,
        "msg_id": new_id(),
        "session_id": session_id,
        "party": party,
        "seq": seq,
        "ts": time.time() if ts is None else ts,
        "type": msg_type,
        "body": body,
    }
    env["mac"] = compute_mac(env, key)
    return env


def compute_mac(env: dict[str, Any], key: bytes) -> str:
    payload = canonical([env[f] for f in SIGNED_FIELDS])
    return hmac.new(key, payload, sha256).hexdigest()


def check_schema(env: Any) -> None:
    """Structural validation, before any field is trusted or used."""
    if not isinstance(env, dict):
        raise ProtocolError("envelope is not an object", "bad_schema")
    required: dict[str, Any] = {
        "v": int,
        "msg_id": str,
        "session_id": str,
        "party": str,
        "seq": int,
        "ts": (int, float),
        "type": str,
        "body": dict,
        "mac": str,
    }
    for name, kind in required.items():
        if name not in env:
            raise ProtocolError("missing field " + repr(name), "bad_schema")
        if isinstance(env[name], bool) or not isinstance(env[name], kind):
            raise ProtocolError("field " + repr(name) + " has the wrong type", "bad_schema")
    extra = set(env) - set(required)
    if extra:
        raise ProtocolError("unexpected fields " + repr(sorted(extra)), "bad_schema")
    if env["v"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version", "bad_version")
    if env["type"] not in MESSAGE_TYPES:
        raise ProtocolError("unknown message type", "bad_schema")
    if env["seq"] < 0:
        raise ProtocolError("sequence number must not be negative", "bad_schema")
    if len(env["msg_id"]) != 32:
        raise ProtocolError("malformed message id", "bad_schema")


@dataclass
class PeerGuard:
    """Per-connection authentication, ordering and replay state for one peer.

    Sequence numbers must strictly increase, which rejects both replays and
    reordering.  The message-id set is a second line of defence that also covers
    a peer that resets its counter after a restart.
    """

    name: str
    key: bytes
    last_seq: int = -1
    seen: set[str] = field(default_factory=set)
    _order: list[str] = field(default_factory=list)

    def accept(self, env: dict[str, Any], *, now: float | None = None) -> None:
        """Authenticate and replay-check ``env``, or raise ``ProtocolError``."""
        check_schema(env)
        expected = compute_mac(env, self.key)
        if not hmac.compare_digest(expected, env["mac"]):
            raise ProtocolError("message authentication failed", "unauthenticated")

        now = time.time() if now is None else now
        if abs(now - float(env["ts"])) > MAX_CLOCK_SKEW_S:
            raise ProtocolError("timestamp outside the accepted window", "stale")

        if env["msg_id"] in self.seen:
            raise ProtocolError("message id already seen", "replay")
        if env["seq"] <= self.last_seq:
            raise ProtocolError("sequence number does not advance", "replay")

        self.last_seq = env["seq"]
        self.seen.add(env["msg_id"])
        self._order.append(env["msg_id"])
        if len(self._order) > REPLAY_WINDOW:
            self.seen.discard(self._order.pop(0))


class LineChannel:
    """A socket carrying newline-delimited JSON, with a bounded read buffer."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._buf = bytearray()
        self._closed = False

    @classmethod
    def connect(cls, host: str, port: int, timeout: float = 10.0) -> "LineChannel":
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return cls(sock)

    def send(self, env: dict[str, Any]) -> None:
        line = canonical(env) + b"\n"
        if len(line) > MAX_LINE_BYTES:
            raise ProtocolError("outgoing message exceeds the line limit", "too_large")
        self.sock.sendall(line)

    def recv(self) -> dict[str, Any] | None:
        """Read one message, or ``None`` once the peer has closed cleanly."""
        while True:
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line = bytes(self._buf[:nl])
                del self._buf[: nl + 1]
                try:
                    return json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ProtocolError("malformed JSON line: " + str(exc), "bad_schema")
            if len(self._buf) > MAX_LINE_BYTES:
                raise ProtocolError("line exceeds the read limit", "too_large")
            chunk = self.sock.recv(65536)
            if not chunk:
                if self._buf:
                    raise ProtocolError("connection closed mid-line", "truncated")
                return None
            self._buf.extend(chunk)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def __enter__(self) -> "LineChannel":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
