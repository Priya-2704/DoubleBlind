"""The model under test.

This is a mock: a deterministic rule engine with one seeded stochastic branch,
not a language model.  That is a deliberate scope choice.  DOUBLEBLIND makes
claims about the channel between parties, not about model behaviour, and a mock
makes those claims testable -- we can force the exact leak we want to detect.
The cost of the choice is recorded in docs/THREAT_MODEL.md.

Three properties matter for the demonstrations:

* It holds per-session context containing that session's canary marker, so a
  context-extraction prompt produces material the gateway can attribute.
* ``shared_context`` collapses every session into one context bucket.  That is
  the shared KV-cache failure from the threat model, reproduced on demand.
* Prompts fall into a cheap and a costly class with genuinely different CPU
  cost, which is what creates the timing channel the gateway pads.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import socketserver
import sys
import threading
from typing import Any

from .protocol import (
    ERROR,
    INFER,
    INFER_OK,
    LineChannel,
    PeerGuard,
    ProtocolError,
    derive_key,
    make_envelope,
)

#: Prompts containing any of these are treated as an attempt to extract the
#: session context.  A real model leaks context for far subtler reasons; the
#: point here is to have a reliable trigger.
EXTRACTION_CUES = ("system prompt", "your instructions", "repeat the context", "verbatim")

#: Prompts containing any of these take the expensive path.
COSTLY_CUES = ("analyse", "analyze", "explain in detail", "step by step", "enumerate")

#: Prompts containing any of these may produce an unsafe completion.
UNSAFE_CUES = ("ignore previous", "developer mode", "bypass", "jailbreak", "dan mode")

#: Probability that an unsafe cue actually produces an unsafe completion.  Not
#: 1.0, because a finding that reproduces every single time tells you nothing
#: about whether Shadow Replay works.
UNSAFE_RATE = 0.4

SAFE_REPLY = "I can help with that within my safety guidelines."
UNSAFE_REPLY = "UNSAFE-COMPLETION: here are the restricted steps you asked for."
REFUSAL = "I cannot comply with that request."


def _burn(rounds: int) -> str:
    """Deterministic CPU work, so the costly class really is costlier."""
    h = b"doubleblind"
    for _ in range(rounds):
        h = hashlib.sha256(h).digest()
    return h.hex()[:8]


class MockModel:
    """The rule engine itself, with no networking in it."""

    def __init__(
        self,
        *,
        name: str,
        shared_context: bool = False,
        cheap_rounds: int = 2_000,
        costly_rounds: int = 90_000,
        unsafe_rate: float = UNSAFE_RATE,
    ) -> None:
        self.name = name
        self.shared_context = shared_context
        self.cheap_rounds = cheap_rounds
        self.costly_rounds = costly_rounds
        self.unsafe_rate = unsafe_rate
        self._contexts: dict[str, str] = {}
        self._lock = threading.Lock()

    def _bucket(self, session_id: str) -> str:
        # The misconfiguration under test: one bucket for every tenant.
        return "__shared__" if self.shared_context else session_id

    def prime(self, session_id: str, context: str) -> None:
        with self._lock:
            self._contexts[self._bucket(session_id)] = context

    def context_for(self, session_id: str) -> str:
        with self._lock:
            return self._contexts.get(self._bucket(session_id), "")

    def infer(self, session_id: str, prompt: str, *, nonce: str = "") -> dict[str, Any]:
        low = prompt.lower()
        costly = any(c in low for c in COSTLY_CUES)
        _burn(self.costly_rounds if costly else self.cheap_rounds)

        if any(c in low for c in EXTRACTION_CUES):
            ctx = self.context_for(session_id)
            text = "Context on record: " + ctx if ctx else REFUSAL
        elif any(c in low for c in UNSAFE_CUES):
            text = UNSAFE_REPLY if self._roll(session_id, prompt, nonce) else REFUSAL
        else:
            text = SAFE_REPLY

        return {
            "text": text,
            "cost_class": "costly" if costly else "cheap",
            "model": self.name,
        }

    def _roll(self, session_id: str, prompt: str, nonce: str) -> bool:
        """Seeded coin flip.

        Seeded on the nonce rather than the prompt alone, so Shadow Replay in a
        fresh session genuinely re-rolls instead of replaying one cached answer.
        """
        seed = hashlib.sha256(
            ("%s|%s|%s" % (session_id, prompt, nonce)).encode("utf-8")
        ).digest()
        return (int.from_bytes(seed[:4], "big") / 0xFFFFFFFF) < self.unsafe_rate


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: "ModelServer" = self.server  # type: ignore[assignment]
        chan = LineChannel(self.request)
        guard = PeerGuard(name="gateway", key=server.gateway_key)
        seq = 0
        try:
            while True:
                env = chan.recv()
                if env is None:
                    return
                try:
                    guard.accept(env)
                    if env["type"] != INFER:
                        raise ProtocolError("model accepts infer only", "bad_type")
                    body = env["body"]
                    session_id = str(body.get("session_id", ""))
                    if "context" in body:
                        server.model.prime(session_id, str(body["context"]))
                    out = server.model.infer(
                        session_id,
                        str(body.get("prompt", "")),
                        nonce=str(body.get("nonce", "")),
                    )
                    reply = make_envelope(
                        session_id=session_id,
                        party="model",
                        seq=seq,
                        msg_type=INFER_OK,
                        body=out,
                        key=server.gateway_key,
                    )
                except ProtocolError as exc:
                    # An unauthenticated peer is the thing this check exists for:
                    # in process mode it is what stops a party dialling the model
                    # directly, so it is logged loudly rather than swallowed.
                    server.log("rejected %s from %s: %s", exc.code, self.client_address, exc)
                    reply = make_envelope(
                        session_id="",
                        party="model",
                        seq=seq,
                        msg_type=ERROR,
                        body={"code": exc.code, "reason": exc.reason},
                        key=server.gateway_key,
                    )
                    chan.send(reply)
                    return
                seq += 1
                chan.send(reply)
        except (ProtocolError, OSError) as exc:
            server.log("connection from %s ended: %s", self.client_address, exc)
        finally:
            chan.close()


class ModelServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        host: str,
        port: int,
        model: MockModel,
        gateway_key: bytes,
        *,
        quiet: bool = False,
    ) -> None:
        super().__init__((host, port), _Handler)
        self.model = model
        self.gateway_key = gateway_key
        self.quiet = quiet

    def log(self, fmt: str, *args: Any) -> None:
        if not self.quiet:
            sys.stderr.write("[model %s] %s\n" % (self.model.name, fmt % args))
            sys.stderr.flush()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="DOUBLEBLIND mock model server")
    ap.add_argument("--name", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument(
        "--shared-context",
        action="store_true",
        help="collapse all sessions into one context bucket (the misconfiguration)",
    )
    ap.add_argument("--unsafe-rate", type=float, default=UNSAFE_RATE)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    secret = os.environ.get("DOUBLEBLIND_SECRET")
    if not secret:
        sys.stderr.write("DOUBLEBLIND_SECRET is not set\n")
        return 2

    model = MockModel(
        name=args.name,
        shared_context=args.shared_context,
        unsafe_rate=args.unsafe_rate,
    )
    server = ModelServer(
        args.host,
        args.port,
        model,
        derive_key(secret, "gateway-model"),
        quiet=args.quiet,
    )
    if not args.quiet:
        sys.stderr.write(
            "[model %s] listening on %s:%d shared_context=%s\n"
            % (args.name, args.host, args.port, args.shared_context)
        )
        sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
