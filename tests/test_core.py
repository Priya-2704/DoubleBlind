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


class TestDelta(unittest.TestCase):
    """The contamination delta's reporting logic.

    The experiment itself needs two live stacks and is exercised by
    scripts/measure_delta.py and act 7.  What is tested here is the part that
    would fail silently: a wrong reading of the two arms, or a clean-arm false
    positive that does not reach the report.
    """

    @staticmethod
    def _arm(name: str, contaminated: int, trials: int = 20, turns: int = 4):
        from doubleblind.delta import ArmResult
        from doubleblind.replay import wilson

        low, high = wilson(contaminated, trials)
        return ArmResult(
            arm=name,
            turns=turns,
            trials=trials,
            contaminated=contaminated,
            blue_sessions=100,
            ci_low=low,
            ci_high=high,
        )

    def _point(self, clean: int, shared: int, turns: int = 4):
        from doubleblind.delta import DeltaPoint

        return DeltaPoint(
            turns=turns,
            clean=self._arm("clean", clean, turns=turns),
            shared=self._arm("shared", shared, turns=turns),
        )

    def test_delta_is_the_difference_between_the_arms(self) -> None:
        point = self._point(clean=0, shared=20)
        self.assertAlmostEqual(point.delta, 1.0)

    def test_separated_arms_are_reported_disjoint(self) -> None:
        self.assertTrue(self._point(clean=0, shared=20).disjoint)

    def test_overlapping_arms_are_not_reported_disjoint(self) -> None:
        # 0/20 and 3/20 have overlapping Wilson intervals at n=20.  The weaker
        # reading is the correct one: a visible gap in the point estimates is
        # not a separation.
        self.assertFalse(self._point(clean=0, shared=3).disjoint)

    def test_equal_arms_are_not_reported_disjoint(self) -> None:
        self.assertFalse(self._point(clean=4, shared=4).disjoint)

    def test_clean_arm_detections_are_counted_as_false_positives(self) -> None:
        from doubleblind.delta import DeltaResult

        # Contamination cannot occur in the clean arm, so anything it reports
        # is the detector over-reporting and must surface rather than be
        # averaged away.
        result = DeltaResult(
            points=[self._point(clean=0, shared=20, turns=1),
                    self._point(clean=2, shared=20, turns=4)]
        )
        self.assertEqual(result.false_positives, 2)

    def test_a_clean_control_reports_no_false_positives(self) -> None:
        from doubleblind.delta import DeltaResult

        result = DeltaResult(points=[self._point(clean=0, shared=17)])
        self.assertEqual(result.false_positives, 0)

    def test_lookup_of_an_unmeasured_session_length_is_none(self) -> None:
        from doubleblind.delta import DeltaResult

        result = DeltaResult(points=[self._point(clean=0, shared=5, turns=4)])
        self.assertIsNotNone(result.at(4))
        self.assertIsNone(result.at(9))

    def test_json_carries_both_arms_and_the_lower_bound_caveat(self) -> None:
        from doubleblind.delta import DeltaResult

        payload = DeltaResult(points=[self._point(clean=0, shared=20)]).to_json()
        arms = payload["points"][0]["arms"]
        self.assertEqual(set(arms), {"clean", "shared"})
        self.assertEqual(arms["shared"]["contaminated"], 20)
        self.assertEqual(payload["false_positives_in_clean_arm"], 0)
        self.assertTrue(
            any("lower bound" in lim for lim in payload["limitations"]),
            "the pack must not quote the rate without its direction of error",
        )

    def test_unknown_arm_is_refused(self) -> None:
        from doubleblind.delta import run_arm

        # Guards against a typo silently measuring the clean topology twice and
        # reporting a delta of zero as a result.
        with self.assertRaises(ValueError):
            run_arm(arm="contaminated", turns=1, trials=1)


class TestHarnessCleanup(unittest.TestCase):
    """The registry that stops stacks nobody stopped explicitly.

    A leaked gateway is worse than a leaked idle process: it keeps an AuditLog
    open on the same file the next run will use, so two independent hash chains
    end up interleaved and the verifier reports a break nobody caused.
    """

    @staticmethod
    def _stack():
        from doubleblind import harness

        # No procs, so nothing is spawned and stop() is a no-op over an empty
        # list -- this exercises the registry, not the process handling.
        return harness.Stack(
            secret="x",
            audit_path="unused.log",
            gateway_port=1,
            red_model_port=2,
            blue_model_port=3,
        )

    def test_stack_is_hashable(self) -> None:
        # The registry is a set. A dataclass left at the default eq=True has
        # __hash__ set to None, which would break every start() call.
        s = self._stack()
        self.assertEqual(len({s, s}), 1)

    def test_two_stacks_are_distinct_registry_entries(self) -> None:
        # Identity, not field equality: two stacks with identical ports are
        # still two stacks, and collapsing them would drop one from cleanup.
        a, b = self._stack(), self._stack()
        self.assertEqual(len({a, b}), 2)

    def test_stop_deregisters(self) -> None:
        from doubleblind import harness

        s = self._stack()
        harness._LIVE.add(s)
        s.stop()
        self.assertNotIn(s, harness._LIVE)

    def test_stopping_twice_does_not_raise(self) -> None:
        # atexit runs after an explicit stop in the normal case, so the second
        # stop must be harmless rather than an error on the way out.
        s = self._stack()
        s.stop()
        s.stop()

    def test_stop_all_clears_the_registry(self) -> None:
        from doubleblind import harness

        s = self._stack()
        harness._LIVE.add(s)
        harness._stop_all()
        self.assertNotIn(s, harness._LIVE)


class TestAgentReplay(unittest.TestCase):
    """Shadow Replay against the real agent API, exercised offline.

    The transport is replaced with recorded responses. An integration whose
    statistics can only be checked by spending money on a live service does not
    get checked, so the scoring and the denominator are tested here and only
    the HTTP call itself is left to the live run.
    """

    MARKER = "DBX-PLD-f1c70721-9c4e2a7b61d05f38"

    def _client(self, runs):
        """A client whose batch returns len(runs) ids and replays `runs`."""
        from doubleblind.agent_replay import TinyAgentClient

        ids = ["run-%d" % i for i in range(len(runs))]
        by_id = dict(zip(ids, runs))

        def transport(method, path, body):
            if method == "POST":
                return {"run_ids": ids, "error": None}
            return by_id[path.rsplit("/", 1)[-1]]

        return TinyAgentClient(transport=transport)

    @staticmethod
    def _run(status="COMPLETED", result=None, steps=4):
        return {"status": status, "result": result, "num_of_steps": steps}

    def _replay(self, runs, marker=None, timeout_s=1.0):
        from doubleblind.agent_replay import agent_replay

        # A short timeout, because a status outside the terminal set is a thing
        # these tests deliberately produce and the poll loop would otherwise sit
        # on it for the full production window.
        return agent_replay(
            fixture_url="https://example.test/f.html",
            goal="summarise this page",
            marker=marker or self.MARKER,
            trials=len(runs),
            client=self._client(runs),
            poll_s=0.05,
            timeout_s=timeout_s,
        )

    def test_marker_in_the_result_counts_as_a_reproduction(self) -> None:
        res = self._replay([self._run(result="summary. " + self.MARKER)] * 4)
        self.assertEqual(res.reproductions, 4)
        self.assertEqual(res.rate, 1.0)

    def test_clean_result_is_not_a_reproduction(self) -> None:
        res = self._replay([self._run(result="an ordinary summary")] * 4)
        self.assertEqual(res.reproductions, 0)

    def test_four_clean_runs_do_not_license_not_reproduced(self) -> None:
        # 0/4 has a Wilson interval of about [0, 0.49]. Four trials cannot
        # support "this does not reproduce", and the verdict must not pretend
        # otherwise just because the point estimate is zero.
        res = self._replay([self._run(result="clean")] * 4)
        self.assertEqual(res.rate, 0.0)
        self.assertEqual(res.verdict, "INTERMITTENT")

    def test_enough_clean_runs_do_license_not_reproduced(self) -> None:
        res = self._replay([self._run(result="clean")] * 40)
        self.assertEqual(res.verdict, "NOT REPRODUCED")
        self.assertLess(res.ci_high, 0.1)

    def test_marker_is_found_inside_structured_output(self) -> None:
        # output_schema makes result an object, not a string. Scoring must look
        # through it rather than silently never matching.
        res = self._replay([self._run(result={"summary": "x " + self.MARKER})])
        self.assertEqual(res.reproductions, 1)

    def test_failed_runs_leave_the_denominator(self) -> None:
        # Counting a crashed run as a non-reproduction would understate the
        # rate; dropping it silently would hide that the experiment was short.
        runs = [self._run(result=self.MARKER)] * 5 + [
            self._run(status="FAILED"),
            self._run(status="CANCELLED"),
        ]
        res = self._replay(runs)
        self.assertEqual(res.failed_runs, 2)
        self.assertEqual(res.scored, 5)
        self.assertEqual(res.rate, 1.0)
        self.assertEqual(res.statuses["FAILED"], 1)

    def test_a_run_that_never_finishes_is_not_counted_as_a_result(self) -> None:
        # RUNNING is not terminal. The poll window closes, and the run must be
        # reported as unfinished rather than scored as a non-reproduction.
        runs = [self._run(result=self.MARKER), self._run(status="RUNNING")]
        res = self._replay(runs, timeout_s=0.3)
        self.assertEqual(res.scored, 1)
        self.assertEqual(res.reproductions, 1)
        self.assertEqual(res.failed_runs, 1)

    def test_every_run_failing_is_no_data_not_zero_percent(self) -> None:
        res = self._replay([self._run(status="FAILED")] * 3)
        self.assertEqual(res.scored, 0)
        self.assertIn("NO DATA", res.verdict)

    def test_intermittent_is_reported_with_its_interval(self) -> None:
        runs = [self._run(result=self.MARKER)] * 5 + [self._run(result="clean")] * 15
        res = self._replay(runs)
        self.assertEqual(res.verdict, "INTERMITTENT")
        self.assertLess(res.ci_low, res.rate)
        self.assertGreater(res.ci_high, res.rate)

    def test_a_non_marker_string_is_refused(self) -> None:
        # A typo'd marker would scan for something that cannot appear and
        # report 0.00 as though the injection had failed.
        with self.assertRaises(ValueError):
            self._replay([self._run()], marker="not-a-marker")

    def test_json_states_that_the_rate_is_a_lower_bound(self) -> None:
        payload = self._replay([self._run(result="clean")]).to_json()
        self.assertTrue(
            any("lower bound" in lim for lim in payload["limitations"]),
            "the scoring blind spot must travel with the number",
        )

    def test_missing_key_is_a_clear_error(self) -> None:
        from doubleblind.agent_replay import TinyAgentClient, TinyAgentError

        saved = os.environ.pop("TINYFISH_API_KEY", None)
        try:
            with self.assertRaises(TinyAgentError):
                TinyAgentClient()
        finally:
            if saved is not None:
                os.environ["TINYFISH_API_KEY"] = saved


class TestProofPackDelta(unittest.TestCase):
    def test_pack_without_a_delta_says_so(self) -> None:
        from doubleblind import proofpack

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.log")
            key = derive_key(SECRET, "audit-checkpoint")
            log = audit.AuditLog(path, key)
            log.append("session_open", {"session_id": "s1"})
            pack = proofpack.build(audit_path=path, audit_key=key)

        self.assertIsNone(pack["contamination_delta"])
        self.assertTrue(
            any("no contamination delta" in lim.lower() for lim in pack["limitations"]),
            "a pack with no delta must say what it therefore cannot assert",
        )


if __name__ == "__main__":
    unittest.main()
