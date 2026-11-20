"""Measure how much of a run's result comes from the environment rather than
the model.

Shadow Replay tells you whether a finding reproduces.  It cannot tell you
whether the stack that produced it was clean, and a finding that only
reproduces in a contaminated stack is an observation about the deployment, not
about the model.  This script measures that difference directly: the same Red
workload, under the same concurrent Blue load, against two deployments that
differ in exactly one thing -- whether the parties share a model server and a
context bucket.

The clean arm is a negative control.  Contamination is impossible there by
construction, so every detection it reports is a false positive and the arm's
job is to show there are none.

The sweep is over session length because that is the mechanism: the window in
which another tenant can overwrite the shared context bucket opens when a
session is primed and closes when that session next reads it.  A one-turn probe
of a contaminated stack mostly comes back clean.  The same stack, probed for
four turns, does not.

Writes artifacts/delta.json so the Proof Pack quotes a measurement instead of a
claim.  Run it on an otherwise idle machine; the rate depends on host
scheduling and on the concurrent load, both of which are recorded in the
output.

    py -3.12 scripts/measure_delta.py --trials 30
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from doubleblind import delta  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="DOUBLEBLIND contamination delta")
    ap.add_argument("--trials", type=int, default=30, help="Red sessions per cell")
    ap.add_argument(
        "--turns",
        default=",".join(str(t) for t in delta.DEFAULT_TURNS),
        help="comma-separated session lengths to sweep",
    )
    ap.add_argument("--tick-ms", type=float, default=25.0)
    ap.add_argument(
        "--blue-pause",
        type=float,
        default=0.0,
        help="seconds Blue waits between sessions; 0 is continuous load",
    )
    ap.add_argument("--out", default="artifacts/delta.json")
    args = ap.parse_args(argv)

    turns_grid = tuple(int(t) for t in args.turns.split(","))
    cells = len(turns_grid) * 2
    print(
        "two arms x %d session lengths = %d cells, %d Red sessions each\n"
        % (len(turns_grid), cells, args.trials)
    )

    started = time.time()
    result = delta.measure(
        turns_grid=turns_grid,
        trials=args.trials,
        tick_ms=args.tick_ms,
        blue_pause=args.blue_pause,
        progress=lambda s: print("  running %s" % s),
    )

    print("\n" + result.render())
    print()

    fp = result.false_positives
    if fp:
        print(
            "  WARNING  %d false positive(s) in the clean arm -- contamination is"
            % fp
        )
        print("           impossible there, so the detector is over-reporting.")
    else:
        print("  clean arm reported no contamination at any session length")

    single = result.at(min(turns_grid))
    longest = result.at(max(turns_grid))
    if single and longest and single.shared.rate < longest.shared.rate:
        print()
        print(
            "  A %d-turn probe of the contaminated stack came back clean %.0f%% of"
            % (single.turns, (1.0 - single.shared.rate) * 100.0)
        )
        print(
            "  the time. At %d turns it came back clean %.0f%% of the time. A"
            % (longest.turns, (1.0 - longest.shared.rate) * 100.0)
        )
        print("  single-turn harness samples the condition that hides this.")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    payload = result.to_json()
    payload["measured_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    payload["python"] = sys.version.split()[0]
    payload["elapsed_s"] = round(time.time() - started, 1)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print("\nwrote %s in %.0fs" % (args.out, time.time() - started))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
