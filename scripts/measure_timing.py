"""Measure what fixed-tick release actually buys against a timing observer.

The observer is a party that can time its own round trips and nothing else.
It sees two classes of request that differ in how much work the model does.
The question is how reliably it can tell them apart from latency alone.

The statistic is the distinguishing advantage: the ROC AUC of the best
single-threshold classifier on latency, folded into [0.5, 1.0].  0.5 is a coin
flip, 1.0 is perfect separation.  Ties count as half, so a tick that quantises
both classes onto the same boundary is scored honestly rather than flattered.

Writes artifacts/timing.json so the Proof Pack quotes a measurement instead of
a claim.  Run it on an otherwise idle machine; CPU contention widens both
distributions and will move the numbers.

    py -3.12 scripts/measure_timing.py --trials 120
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from doubleblind import harness  # noqa: E402
from doubleblind.party import Party  # noqa: E402
from doubleblind.timing import TimingResult, auc, median  # noqa: E402

CHEAP = "summarise the policy"
COSTLY = "analyse the policy step by step"


def time_one(red: Party, prompt: str) -> float:
    t0 = time.perf_counter()
    red.submit(prompt)
    return (time.perf_counter() - t0) * 1000.0


def measure_arm(
    tick_ms: float, trials: int, warmup: int
) -> tuple[TimingResult, list[float], list[float]]:
    stack = harness.start(
        tick_ms=tick_ms,
        audit_path="artifacts/timing-tick%g.log" % tick_ms,
        unsafe_rate=0.0,
    )
    try:
        with Party("red", stack.secret, port=stack.gateway_port) as red:
            for _ in range(warmup):
                time_one(red, CHEAP)
                time_one(red, COSTLY)
            cheap: list[float] = []
            costly: list[float] = []
            # Interleaved, so a drift in machine load hits both classes equally
            # instead of landing entirely on whichever class ran second.
            for _ in range(trials):
                cheap.append(time_one(red, CHEAP))
                costly.append(time_one(red, COSTLY))
    finally:
        stack.stop()

    return TimingResult(
        label="unpadded" if tick_ms == 0 else "tick %g ms" % tick_ms,
        tick_ms=tick_ms,
        n_per_class=trials,
        advantage=auc(cheap, costly),
        median_cheap_ms=median(cheap),
        median_costly_ms=median(costly),
    ), cheap, costly


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=120, help="samples per class per arm")
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument(
        "--ticks",
        default="0,10,25,50",
        help="comma-separated tick sizes in ms; 0 is the unpadded baseline",
    )
    ap.add_argument("--out", default="artifacts/timing.json")
    args = ap.parse_args(argv)

    ticks = [float(t) for t in args.ticks.split(",")]
    rows = []
    raw = {}

    print("measuring %d samples per class across %d arms\n" % (args.trials, len(ticks)))
    for tick in ticks:
        result, cheap, costly = measure_arm(tick, args.trials, args.warmup)
        rows.append(result)
        raw["tick_%g" % tick] = {"cheap_ms": cheap, "costly_ms": costly}
        print("  " + result.render())

    baseline = rows[0]
    print()
    print("baseline advantage %.3f at tick 0" % baseline.advantage)
    for r in rows[1:]:
        print(
            "  tick %5.1f ms -> advantage %.3f  (%+.3f vs baseline, median cost %+.1f ms)"
            % (
                r.tick_ms,
                r.advantage,
                r.advantage - baseline.advantage,
                r.median_cheap_ms - baseline.median_cheap_ms,
            )
        )

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    payload = {
        "statistic": "distinguishing advantage (ROC AUC on latency, folded to [0.5,1])",
        "samples_per_class": args.trials,
        "warmup_per_class": args.warmup,
        "cheap_prompt": CHEAP,
        "costly_prompt": COSTLY,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "python": sys.version.split()[0],
        "arms": [
            {
                "tick_ms": r.tick_ms,
                "advantage": round(r.advantage, 4),
                "median_cheap_ms": round(r.median_cheap_ms, 3),
                "median_costly_ms": round(r.median_costly_ms, 3),
                "median_gap_ms": round(r.separation_ms, 3),
                "stdev_cheap_ms": round(statistics.pstdev(raw["tick_%g" % r.tick_ms]["cheap_ms"]), 3),
                "stdev_costly_ms": round(statistics.pstdev(raw["tick_%g" % r.tick_ms]["costly_ms"]), 3),
            }
            for r in rows
        ],
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print("\nwrote " + args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
