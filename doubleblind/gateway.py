"""The gateway: the only permitted path between parties and the model.

Everything DOUBLEBLIND claims holds or fails here.  The gateway:

* authenticates each party and gives it its own session and model connection;
* issues that session its DNA markers and primes the model context with them;
* scans every message it is about to release for markers owned by another
  session, and quarantines rather than releases when it finds one;
* reduces the material Blue receives to four advisory fields, and asserts that
  reduction instead of trusting it;
* holds responses to a fixed tick before release;
* records every decision in a hash-chained log.

Concentrating all of this in one component is the design's main weakness, and
it is stated as such in docs/THREAT_MODEL.md: compromise the gateway and every
property falls together.
"""

from __future__ import annotations

import argparse
import os
import socketserver
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from . import dna as dna_mod
from .audit import AuditLog
from .dna import DnaRegistry, SessionDna
from .protocol import (
    ADVISORY,
    ERROR,
    HELLO,
    HELLO_OK,
    INFER,
    RESULT,
    SUBMIT,
    LineChannel,
    PeerGuard,
    ProtocolError,
    derive_key,
    digest,
    make_envelope,
    new_id,
)
from .timing import NullGate, TickGate

PARTIES = ("red", "blue")

#: The complete set of fields Blue may ever receive about a finding.  Anything
#: else -- the payload, the raw completion, session history, marker values --
#: stays on the Red side of the gateway.
ADVISORY_FIELDS = ("advisory_id", "category", "severity", "mitigation_hint")

#: Blue's advisory is built from a closed vocabulary rather than from text
#: derived at runtime.  This is the primary control: if every value an advisory
#: can carry is drawn from a fixed set written at build time, no amount of Red
#: payload can reach Blue through it, whatever the classifier does.  Scanning
#: free text for leaked payload is the weaker design -- we tried it first and
#: it false-positived on the shared English substring " instruction".
CATEGORIES = frozenset({"no_finding", "policy_bypass", "context_disclosure"})
SEVERITIES = frozenset({"none", "low", "medium", "high"})
MITIGATIONS = frozenset(
    {
        "no action required",
        "tighten refusal policy for instruction-override phrasing",
        "review context-handling policy for disclosure prompts",
    }
)

#: Shortest run of payload characters treated as a leak, for any field that is
#: somehow not drawn from the vocabulary above.  A backstop, not the control.
SHINGLE = 12


class AdvisoryLeak(Exception):
    """Raised when an advisory would carry material Blue must not see."""


@dataclass
class Session:
    session_id: str
    party: str
    dna: SessionDna
    model_addr: tuple[str, int]
    model_seq: int = 0
    out_seq: int = 0
    submissions: int = 0
    payloads: list[str] = field(default_factory=list)


@dataclass
class GatewayConfig:
    host: str = "127.0.0.1"
    port: int = 9100
    red_model: tuple[str, int] = ("127.0.0.1", 9201)
    blue_model: tuple[str, int] = ("127.0.0.1", 9202)
    tick_ms: float = 25.0
    audit_path: str = "artifacts/audit.log"
    quiet: bool = False


def build_advisory(text: str, *, severity: str = "medium") -> dict[str, str]:
    """Derive Blue's four fields from a Red-side result.

    Nothing here is copied from the payload or the completion; the advisory is
    constructed from a classification, which is the whole point.
    """
    unsafe = "UNSAFE-COMPLETION" in text
    return {
        "advisory_id": new_id()[:12],
        "category": "policy_bypass" if unsafe else "no_finding",
        "severity": severity if unsafe else "none",
        "mitigation_hint": (
            "tighten refusal policy for instruction-override phrasing"
            if unsafe
            else "no action required"
        ),
    }


def assert_advisory_clean(advisory: dict[str, Any], payloads: list[str]) -> None:
    """Enforce the Blue-side reduction rather than assuming it.

    Checked in order of strength: the field set is exactly the permitted one,
    every value is drawn from the closed vocabulary, no DNA marker appears, and
    -- for any value that somehow escaped the vocabulary -- no run of Red
    payload text survives inside it.
    """
    if set(advisory) != set(ADVISORY_FIELDS):
        raise AdvisoryLeak(
            "advisory fields %s do not match the permitted set %s"
            % (sorted(advisory), sorted(ADVISORY_FIELDS))
        )

    free_text: list[str] = []
    for field_name, allowed in (
        ("category", CATEGORIES),
        ("severity", SEVERITIES),
        ("mitigation_hint", MITIGATIONS),
    ):
        value = str(advisory[field_name])
        if value not in allowed:
            raise AdvisoryLeak(
                "advisory field %r carries %r, which is not in the permitted "
                "vocabulary" % (field_name, value[:60])
            )

    adv_id = str(advisory["advisory_id"])
    if len(adv_id) != 12 or any(c not in "0123456789abcdef" for c in adv_id):
        free_text.append(adv_id)

    # Markers are case-sensitive, so this scan runs on the original text.
    # Folding case first silently defeats it -- a unit test caught exactly that.
    raw_blob = " ".join(str(v) for v in advisory.values())
    if dna_mod.MARKER_RE.search(raw_blob):
        raise AdvisoryLeak("advisory carries a DNA marker")

    for value in free_text:
        low_value = value.lower()
        for payload in payloads:
            low = payload.lower()
            for i in range(0, max(0, len(low) - SHINGLE) + 1):
                if low[i : i + SHINGLE] in low_value:
                    raise AdvisoryLeak(
                        "advisory reproduces payload text: "
                        + repr(low[i : i + SHINGLE])
                    )


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        gw: "Gateway" = self.server  # type: ignore[assignment]
        chan = LineChannel(self.request)
        session: Session | None = None
        model: LineChannel | None = None
        guard: PeerGuard | None = None
        try:
            while True:
                env = chan.recv()
                if env is None:
                    return
                try:
                    if session is None:
                        session, guard, model = gw.open_session(env)
                        chan.send(
                            gw.sign(
                                session,
                                HELLO_OK,
                                {
                                    "session_id": session.session_id,
                                    "tick_ms": gw.cfg.tick_ms,
                                    "payload_marker": session.dna.payload.value,
                                },
                            )
                        )
                        continue

                    assert guard is not None and model is not None
                    guard.accept(env)
                    if env["type"] != SUBMIT:
                        raise ProtocolError("expected a submit", "bad_type")
                    reply = gw.handle_submit(session, env, model)
                    chan.send(reply)
                except (ProtocolError, AdvisoryLeak) as exc:
                    code = getattr(exc, "code", "advisory_leak")
                    gw.audit.append(
                        "rejected",
                        {
                            "peer": "%s:%s" % self.client_address[:2],
                            "code": code,
                            "reason": str(exc),
                        },
                    )
                    gw.log("rejected %s from %s: %s", code, self.client_address, exc)
                    chan.send(
                        make_envelope(
                            session_id=session.session_id if session else "",
                            party="gateway",
                            seq=session.out_seq if session else 0,
                            msg_type=ERROR,
                            body={"code": code, "reason": str(exc)},
                            key=gw.party_keys.get(
                                session.party if session else "red", b""
                            ),
                        )
                    )
                    return
        except (ProtocolError, OSError) as exc:
            gw.log("connection from %s ended: %s", self.client_address, exc)
        finally:
            if model is not None:
                model.close()
            chan.close()


class Gateway(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, cfg: GatewayConfig, secret: str) -> None:
        super().__init__((cfg.host, cfg.port), _Handler)
        self.cfg = cfg
        self.party_keys = {p: derive_key(secret, "party-" + p) for p in PARTIES}
        self.model_key = derive_key(secret, "gateway-model")
        self.audit = AuditLog(cfg.audit_path, derive_key(secret, "audit-checkpoint"))
        self.registry = DnaRegistry()
        self.gate = TickGate(cfg.tick_ms / 1000.0) if cfg.tick_ms > 0 else NullGate()
        self.advisories: list[dict[str, Any]] = []
        self._adv_lock = threading.Lock()
        self.audit.append(
            "gateway_start",
            {
                "listen": "%s:%d" % (cfg.host, cfg.port),
                "red_model": "%s:%d" % cfg.red_model,
                "blue_model": "%s:%d" % cfg.blue_model,
                "tick_ms": cfg.tick_ms,
                "shared_model_endpoint": cfg.red_model == cfg.blue_model,
            },
        )

    # -- session setup ---------------------------------------------------

    def open_session(
        self, env: dict[str, Any]
    ) -> tuple[Session, PeerGuard, LineChannel]:
        from .protocol import check_schema

        check_schema(env)
        if env["type"] != HELLO:
            raise ProtocolError("first message must be hello", "bad_type")
        party = str(env["body"].get("party", ""))
        if party not in PARTIES:
            raise ProtocolError("unknown party", "unknown_party")

        guard = PeerGuard(name=party, key=self.party_keys[party])
        guard.accept(env)

        session_id = new_id()
        session = Session(
            session_id=session_id,
            party=party,
            dna=dna_mod.provision(self.registry, session_id, party),
            model_addr=self.cfg.red_model if party == "red" else self.cfg.blue_model,
        )

        model = LineChannel.connect(*session.model_addr)
        # Prime the model with a context that carries this session's marker, so
        # any context that escapes into another session can be attributed.
        self._model_call(
            session,
            model,
            {
                "session_id": session_id,
                "context": "session=%s party=%s canary=%s"
                % (session_id, party, session.dna.context.value),
                "prompt": "",
                "nonce": new_id(),
            },
        )
        self.audit.append(
            "session_open",
            {
                "session_id": session_id,
                "party": party,
                "model_addr": "%s:%d" % session.model_addr,
                "context_marker": session.dna.context.value,
                "payload_marker": session.dna.payload.value,
            },
        )
        self.log("session %s opened for %s on %s:%d", session_id[:8], party, *session.model_addr)
        return session, guard, model

    # -- request path ----------------------------------------------------

    def handle_submit(
        self, session: Session, env: dict[str, Any], model: LineChannel
    ) -> dict[str, Any]:
        body = env["body"]
        op = str(body.get("op", "infer"))
        if op == "poll":
            return self._handle_poll(session)
        if op != "infer":
            raise ProtocolError("unknown op", "bad_op")

        prompt = str(body.get("prompt", ""))
        session.submissions += 1
        session.payloads.append(prompt)
        self.audit.append(
            "submit",
            {
                "session_id": session.session_id,
                "party": session.party,
                "payload_digest": digest(prompt),
                "payload_len": len(prompt),
            },
        )

        # Red's payload is tagged before it reaches the model, so the marker
        # travels with any copy of it the model later emits anywhere.
        tagged = "%s %s" % (prompt, session.dna.payload.value)
        out = self._model_call(
            session,
            model,
            {
                "session_id": session.session_id,
                "prompt": tagged,
                "nonce": new_id(),
            },
        )
        text = str(out.get("text", ""))

        hits = self.registry.scan(
            text, session_id=session.session_id, party=session.party
        )
        if hits:
            return self._quarantine(session, hits, out)

        released = dna_mod.DnaRegistry.strip(text).strip()
        advisory = build_advisory(released)
        assert_advisory_clean(advisory, session.payloads)

        if advisory["category"] != "no_finding":
            with self._adv_lock:
                self.advisories.append(advisory)
            self.audit.append(
                "advisory_published",
                {"session_id": session.session_id, **advisory},
            )

        waited = self.gate.wait()
        self.audit.append(
            "release",
            {
                "session_id": session.session_id,
                "party": session.party,
                "result_digest": digest(released),
                "cost_class": out.get("cost_class"),
                "tick_wait_ms": round(waited * 1000.0, 3),
            },
        )
        return self.sign(
            session,
            RESULT,
            {
                "text": released,
                "cost_class": out.get("cost_class"),
                "quarantined": False,
                "advisory_id": advisory["advisory_id"],
            },
        )

    def _quarantine(
        self, session: Session, hits: list[dna_mod.LeakHit], out: dict[str, Any]
    ) -> dict[str, Any]:
        """Withhold a contaminated response and record who it came from."""
        record = [
            {
                "marker": h.marker,
                "source_session": h.source_session,
                "source_party": h.source_party,
                "kind": h.kind,
            }
            for h in hits
        ]
        self.audit.append(
            "leak_detected",
            {
                "session_id": session.session_id,
                "party": session.party,
                "hits": record,
                "withheld_digest": digest(out.get("text", "")),
            },
        )
        for h in hits:
            self.log("LEAK %s", h.describe())
        self.gate.wait()
        return self.sign(
            session,
            RESULT,
            {
                "text": "",
                "quarantined": True,
                "reason": "cross-session marker detected",
                "hits": record,
            },
        )

    def _handle_poll(self, session: Session) -> dict[str, Any]:
        if session.party != "blue":
            raise ProtocolError("only blue polls advisories", "forbidden")
        with self._adv_lock:
            items = list(self.advisories)
        for adv in items:
            assert_advisory_clean(adv, [])
        self.audit.append(
            "advisory_delivered",
            {"session_id": session.session_id, "count": len(items)},
        )
        self.gate.wait()
        return self.sign(session, ADVISORY, {"advisories": items})

    # -- helpers ---------------------------------------------------------

    def _model_call(
        self, session: Session, model: LineChannel, body: dict[str, Any]
    ) -> dict[str, Any]:
        env = make_envelope(
            session_id=session.session_id,
            party="gateway",
            seq=session.model_seq,
            msg_type=INFER,
            body=body,
            key=self.model_key,
        )
        session.model_seq += 1
        model.send(env)
        reply = model.recv()
        if reply is None:
            raise ProtocolError("model closed the connection", "model_down")
        if reply.get("type") == ERROR:
            raise ProtocolError(
                "model rejected the call: " + str(reply.get("body")), "model_error"
            )
        return dict(reply.get("body", {}))

    def sign(
        self, session: Session, msg_type: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        env = make_envelope(
            session_id=session.session_id,
            party="gateway",
            seq=session.out_seq,
            msg_type=msg_type,
            body=body,
            key=self.party_keys[session.party],
        )
        session.out_seq += 1
        return env

    def log(self, fmt: str, *args: Any) -> None:
        if not self.cfg.quiet:
            sys.stderr.write("[gateway] " + (fmt % args) + "\n")
            sys.stderr.flush()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="DOUBLEBLIND gateway")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--red-model", default="127.0.0.1:9201")
    ap.add_argument("--blue-model", default="127.0.0.1:9202")
    ap.add_argument(
        "--tick-ms",
        type=float,
        default=25.0,
        help="fixed release tick; 0 disables padding (the unpadded arm)",
    )
    ap.add_argument("--audit", default="artifacts/audit.log")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    secret = os.environ.get("DOUBLEBLIND_SECRET")
    if not secret:
        sys.stderr.write("DOUBLEBLIND_SECRET is not set\n")
        return 2

    def addr(s: str) -> tuple[str, int]:
        host, _, port = s.rpartition(":")
        return host, int(port)

    cfg = GatewayConfig(
        host=args.host,
        port=args.port,
        red_model=addr(args.red_model),
        blue_model=addr(args.blue_model),
        tick_ms=args.tick_ms,
        audit_path=args.audit,
        quiet=args.quiet,
    )
    gw = Gateway(cfg, secret)
    if not args.quiet:
        sys.stderr.write(
            "[gateway] listening on %s:%d tick=%.1fms audit=%s\n"
            % (cfg.host, cfg.port, cfg.tick_ms, cfg.audit_path)
        )
        sys.stderr.flush()
    try:
        gw.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        gw.audit.close()
        gw.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
