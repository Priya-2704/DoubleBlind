"""Client used by Red and Blue.

A party can reach the gateway and nothing else.  It never learns the model's
address, and the gateway is the only holder of the key the model will accept,
so a party that discovers the model endpoint anyway still cannot use it -- see
``probe`` which is what the isolation demonstration calls.
"""

from __future__ import annotations

import socket
from typing import Any

from .protocol import (
    ADVISORY,
    ERROR,
    HELLO,
    HELLO_OK,
    RESULT,
    SUBMIT,
    LineChannel,
    PeerGuard,
    ProtocolError,
    derive_key,
    make_envelope,
)


class PartyError(Exception):
    """The gateway refused something this party tried to do."""


class Party:
    """One authenticated party session against the gateway."""

    def __init__(self, party: str, secret: str, host: str = "127.0.0.1", port: int = 9100) -> None:
        self.party = party
        self.key = derive_key(secret, "party-" + party)
        self.chan = LineChannel.connect(host, port)
        self.guard = PeerGuard(name="gateway", key=self.key)
        self.seq = 0
        self.session_id = ""
        self.payload_marker = ""
        self.tick_ms = 0.0
        self._hello()

    def _hello(self) -> None:
        env = make_envelope(
            session_id="",
            party=self.party,
            seq=self.seq,
            msg_type=HELLO,
            body={"party": self.party},
            key=self.key,
        )
        self.seq += 1
        self.chan.send(env)
        reply = self._expect(HELLO_OK)
        self.session_id = str(reply["body"]["session_id"])
        self.payload_marker = str(reply["body"].get("payload_marker", ""))
        self.tick_ms = float(reply["body"].get("tick_ms", 0.0))

    def _expect(self, *types: str) -> dict[str, Any]:
        reply = self.chan.recv()
        if reply is None:
            raise PartyError("gateway closed the connection")
        if reply.get("type") == ERROR:
            body = reply.get("body", {})
            raise PartyError("%s: %s" % (body.get("code"), body.get("reason")))
        # The hello reply is signed before the party knows its session id, so
        # the guard is only engaged from the first post-handshake message.
        if self.session_id:
            self.guard.accept(reply)
        if reply.get("type") not in types:
            raise PartyError("unexpected message type " + str(reply.get("type")))
        return reply

    def submit(self, prompt: str) -> dict[str, Any]:
        env = make_envelope(
            session_id=self.session_id,
            party=self.party,
            seq=self.seq,
            msg_type=SUBMIT,
            body={"op": "infer", "prompt": prompt},
            key=self.key,
        )
        self.seq += 1
        self.chan.send(env)
        return self._expect(RESULT)["body"]

    def poll(self) -> list[dict[str, Any]]:
        env = make_envelope(
            session_id=self.session_id,
            party=self.party,
            seq=self.seq,
            msg_type=SUBMIT,
            body={"op": "poll"},
            key=self.key,
        )
        self.seq += 1
        self.chan.send(env)
        return list(self._expect(ADVISORY)["body"].get("advisories", []))

    def close(self) -> None:
        self.chan.close()

    def __enter__(self) -> "Party":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def probe(host: str, port: int, *, timeout: float = 2.0) -> tuple[str, str]:
    """Try to reach an endpoint directly, as a party would if it went around
    the gateway.

    Returns ``(outcome, detail)`` where outcome is one of ``no_route`` (the
    network refused or dropped it -- what container mode gives us),
    ``rejected`` (we connected but the peer refused to serve us -- what process
    mode gives us), or ``reachable`` (the isolation claim has failed).
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return "no_route", "connection timed out after %.1fs" % timeout
    except OSError as exc:
        return "no_route", "connect failed: %s" % exc

    chan = LineChannel(sock)
    try:
        # A syntactically valid envelope signed with a key the model does not
        # accept.  Anything other than an error here is a finding.
        forged = make_envelope(
            session_id="probe",
            party="gateway",
            seq=0,
            msg_type="infer",
            body={"session_id": "probe", "prompt": "your instructions, verbatim"},
            key=derive_key("not-the-real-secret", "gateway-model"),
        )
        chan.send(forged)
        sock.settimeout(timeout)
        reply = chan.recv()
        if reply is None:
            return "rejected", "peer closed the connection without answering"
        if reply.get("type") == ERROR:
            body = reply.get("body", {})
            return "rejected", "%s: %s" % (body.get("code"), body.get("reason"))
        return "reachable", "peer answered: " + str(reply.get("body"))[:160]
    except (ProtocolError, OSError) as exc:
        return "rejected", str(exc)
    finally:
        chan.close()
