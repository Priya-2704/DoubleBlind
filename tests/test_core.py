"""Unit tests for the parts whose failure would be silent.

Run with:  py -3.12 -m unittest discover -s tests -v

These cover the controls, not the happy path -- the happy path is what
scripts/demo.py exercises end to end.  What is tested here is the behaviour on
bad input, because a check that passes everything also passes the demo.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from doubleblind import audit, dna, timing  # noqa: E402
from doubleblind.gateway import (  # noqa: E402
    AdvisoryLeak,
    assert_advisory_clean,
    build_advisory,
)
from doubleblind.protocol import (  # noqa: E402
    HELLO,
    PeerGuard,
    ProtocolError,
    derive_key,
    make_envelope,
)

SECRET = "test-secret"


class TestProtocol(unittest.TestCase):
    def setUp(self) -> None:
        self.key = derive_key(SECRET, "party-red")
        self.guard = PeerGuard(name="red", key=self.key)

    def env(self, seq: int, **over: object) -> dict:
        e = make_envelope(
            session_id="s",
            party="red",
            seq=seq,
            msg_type=HELLO,
            body={"party": "red"},
            key=self.key,
        )
        e.update(over)
        return e

    def test_accepts_a_well_formed_message(self) -> None:
        self.guard.accept(self.env(0))

    def test_rejects_a_wrong_key(self) -> None:
        other = make_envelope(
            session_id="s",
            party="red",
            seq=0,
            msg_type=HELLO,
            body={"party": "red"},
            key=derive_key("wrong", "party-red"),
        )
        with self.assertRaises(ProtocolError) as ctx:
            self.guard.accept(other)
        self.assertEqual(ctx.exception.code, "unauthenticated")

    def test_rejects_a_tampered_body(self) -> None:
        e = self.env(0)
        e["body"] = {"party": "blue"}
        with self.assertRaises(ProtocolError) as ctx:
            self.guard.accept(e)
        self.assertEqual(ctx.exception.code, "unauthenticated")

    def test_rejects_a_replayed_message(self) -> None:
        e = self.env(0)
        self.guard.accept(e)
        with self.assertRaises(ProtocolError) as ctx:
            self.guard.accept(e)
        self.assertIn(ctx.exception.code, {"replay"})

    def test_rejects_a_non_advancing_sequence(self) -> None:
        self.guard.accept(self.env(5))
        with self.assertRaises(ProtocolError) as ctx:
            self.guard.accept(self.env(5))
        self.assertEqual(ctx.exception.code, "replay")

    def test_rejects_a_stale_timestamp(self) -> None:
        e = make_envelope(
            session_id="s",
            party="red",
            seq=0,
            msg_type=HELLO,
            body={"party": "red"},
            key=self.key,
            ts=time.time() - 9999,
        )
        with self.assertRaises(ProtocolError) as ctx:
            self.guard.accept(e)
        self.assertEqual(ctx.exception.code, "stale")

    def test_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            self.guard.accept(self.env(0, surprise=1))
        self.assertEqual(ctx.exception.code, "bad_schema")


class TestAudit(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "a.log")
        self.key = derive_key(SECRET, "audit-checkpoint")

    def write_entries(self, n: int = 6) -> audit.AuditLog:
        log = audit.AuditLog(self.path, self.key, checkpoint_every=4)
        for i in range(n):
            log.append("event", {"i": i})
        return log

    def test_intact_log_verifies(self) -> None:
        self.write_entries()
        self.assertTrue(audit.verify(self.path, self.key).ok)

    def test_edit_is_detected_and_localised(self) -> None:
        self.write_entries()
        lines = open(self.path, encoding="utf-8").read().splitlines()
        rec = json.loads(lines[2])
        rec["data"]["i"] = 999
        lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        open(self.path, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")

        v = audit.verify(self.path, self.key)
        self.assertFalse(v.ok)
        self.assertEqual(v.failures[0]["idx"], 2)
        self.assertEqual(v.failures[0]["kind"], "content-edited")

    def test_deletion_is_detected(self) -> None:
        self.write_entries()
        lines = open(self.path, encoding="utf-8").read().splitlines()
        del lines[3]
        open(self.path, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
        self.assertFalse(audit.verify(self.path, self.key).ok)

    def test_truncation_is_not_detected_without_a_checkpoint(self) -> None:
        """A documented limit, asserted so it cannot regress unnoticed.

        Dropping entries from the end leaves a shorter but internally valid
        chain.  Only a checkpoint covering a later index exposes it, which is
        why checkpoints exist and why a verifier must compare the head against
        an externally held value.
        """
        self.write_entries(3)  # fewer than checkpoint_every
        lines = open(self.path, encoding="utf-8").read().splitlines()
        open(self.path, "w", encoding="utf-8", newline="\n").write(
            "\n".join(lines[:2]) + "\n"
        )
        self.assertTrue(audit.verify(self.path, self.key).ok)

    def test_forged_checkpoint_is_detected(self) -> None:
        self.write_entries(8)
        lines = open(self.path, encoding="utf-8").read().splitlines()
        for i, line in enumerate(lines):
            rec = json.loads(line)
            if rec["event"] == "checkpoint":
                rec["data"]["hmac"] = "0" * 64
                rec["content_digest"] = audit.sha256(
                    audit.canonical(rec["data"])
                ).hexdigest()
                rec["entry_hash"] = audit.entry_hash(
                    rec["idx"], rec["ts"], rec["event"], rec["content_digest"], rec["prev"]
                )
                lines[i] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
                break
        open(self.path, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")

        v = audit.verify(self.path, self.key)
        self.assertFalse(v.ok)
        self.assertTrue(any(f["kind"] == "checkpoint-forged" for f in v.failures))


class TestDna(unittest.TestCase):
    def setUp(self) -> None:
        self.reg = dna.DnaRegistry()
        self.a = dna.provision(self.reg, "a" * 32, "red")
        self.b = dna.provision(self.reg, "b" * 32, "blue")

    def test_own_marker_is_not_a_leak(self) -> None:
        text = "context " + self.a.context.value
        self.assertEqual(self.reg.scan(text, session_id="a" * 32, party="red"), [])

    def test_foreign_marker_is_attributed(self) -> None:
        text = "context " + self.b.context.value
        hits = self.reg.scan(text, session_id="a" * 32, party="red")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].source_session, "b" * 32)
        self.assertEqual(hits[0].source_party, "blue")

    def test_unissued_marker_is_flagged(self) -> None:
        text = "DBX-CTX-deadbeef-0123456789abcdef"
        hits = self.reg.scan(text, session_id="a" * 32, party="red")
        self.assertEqual(hits[0].kind, "unattributed")

    def test_strip_removes_markers(self) -> None:
        text = "hello " + self.a.payload.value + " world"
        self.assertNotIn("DBX-", dna.DnaRegistry.strip(text))

    def test_paraphrase_is_not_detected(self) -> None:
        """The stated blind spot, asserted so the README stays true."""
        leaked_meaning = "the other session was told to refuse policy overrides"
        self.assertEqual(
            self.reg.scan(leaked_meaning, session_id="a" * 32, party="red"), []
        )


class TestAdvisory(unittest.TestCase):
    def test_finding_advisory_is_clean(self) -> None:
        adv = build_advisory("UNSAFE-COMPLETION: something")
        assert_advisory_clean(adv, ["ignore previous instructions"])

    def test_extra_field_is_refused(self) -> None:
        adv = build_advisory("UNSAFE-COMPLETION: x")
        adv["raw_payload"] = "ignore previous instructions"
        with self.assertRaises(AdvisoryLeak):
            assert_advisory_clean(adv, [])

    def test_off_vocabulary_value_is_refused(self) -> None:
        adv = build_advisory("UNSAFE-COMPLETION: x")
        adv["mitigation_hint"] = "block the phrase: ignore previous instructions"
        with self.assertRaises(AdvisoryLeak):
            assert_advisory_clean(adv, [])

    def test_marker_in_advisory_is_refused(self) -> None:
        adv = build_advisory("UNSAFE-COMPLETION: x")
        adv["advisory_id"] = "DBX-CTX-deadbeef-0123456789abcdef"
        with self.assertRaises(AdvisoryLeak):
            assert_advisory_clean(adv, [])


class TestTiming(unittest.TestCase):
    def test_identical_distributions_give_no_advantage(self) -> None:
        xs = [1.0, 2.0, 3.0, 4.0]
        self.assertAlmostEqual(timing.auc(xs, list(xs)), 0.5, places=6)

    def test_disjoint_distributions_give_full_advantage(self) -> None:
        self.assertAlmostEqual(timing.auc([1.0, 2.0], [9.0, 10.0]), 1.0, places=6)

    def test_advantage_is_folded_and_symmetric(self) -> None:
        a, b = [1.0, 2.0], [9.0, 10.0]
        self.assertAlmostEqual(timing.auc(a, b), timing.auc(b, a), places=6)

    def test_advantage_never_below_half(self) -> None:
        self.assertGreaterEqual(timing.auc([5.0, 6.0], [1.0, 2.0]), 0.5)

    def test_tick_gate_quantises(self) -> None:
        gate = timing.TickGate(0.05, epoch=0.0)
        self.assertAlmostEqual(gate.next_boundary(0.0), 0.05, places=9)
        self.assertAlmostEqual(gate.next_boundary(0.06), 0.10, places=9)


class TestReplayStats(unittest.TestCase):
    def test_wilson_brackets_the_point_estimate(self) -> None:
        from doubleblind.replay import wilson

        low, high = wilson(5, 20)
        self.assertLess(low, 0.25)
        self.assertGreater(high, 0.25)

    def test_wilson_stays_inside_the_unit_interval(self) -> None:
        from doubleblind.replay import wilson

        for s, n in ((0, 10), (10, 10), (1, 3)):
            low, high = wilson(s, n)
            self.assertGreaterEqual(low, 0.0)
            self.assertLessEqual(high, 1.0)


if __name__ == "__main__":
    unittest.main()
