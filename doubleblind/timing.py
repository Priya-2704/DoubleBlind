"""Fixed-tick release, and the statistic used to measure what it buys.

A response is not forwarded when it is ready.  It is held until the next tick
boundary on a session-independent grid, so the latency an observer measures is
quantised to the tick and carries correspondingly less information about how
much work the model actually did.

This reduces an observable timing channel.  It does not close it: a difference
larger than one tick still separates the classes, and the scheduler itself has
jitter.  The honest way to report this is an effect size, which is what
``auc`` computes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Sequence


class TickGate:
    """Releases at multiples of ``tick_s`` measured from a fixed epoch."""

    def __init__(self, tick_s: float, *, epoch: float | None = None) -> None:
        if tick_s <= 0:
            raise ValueError("tick must be positive")
        self.tick_s = tick_s
        self.epoch = time.perf_counter() if epoch is None else epoch

    def next_boundary(self, now: float | None = None) -> float:
        now = time.perf_counter() if now is None else now
        elapsed = now - self.epoch
        ticks = int(elapsed // self.tick_s) + 1
        return self.epoch + ticks * self.tick_s

    def wait(self, now: float | None = None) -> float:
        """Block until the next boundary; return the seconds spent waiting."""
        now = time.perf_counter() if now is None else now
        target = self.next_boundary(now)
        delay = target - now
        if delay > 0:
            time.sleep(delay)
        return max(0.0, delay)


class NullGate:
    """No padding at all, for the unpadded arm of a measurement."""

    tick_s = 0.0

    def wait(self, now: float | None = None) -> float:
        return 0.0


def auc(class_a: Sequence[float], class_b: Sequence[float]) -> float:
    """Probability that a sample from ``class_b`` exceeds one from ``class_a``.

    This is the Mann-Whitney U statistic normalised to [0, 1], which equals the
    ROC AUC of the best single-threshold classifier on this one feature.  It is
    folded to [0.5, 1.0] and reported as a *distinguishing advantage*: 0.5 means
    an observer watching latency alone does no better than a coin flip, 1.0
    means the two classes never overlap.

    Ties count as half, so identical quantised latencies drive the value toward
    0.5 rather than flattering the result.
    """
    if not class_a or not class_b:
        raise ValueError("both classes need at least one sample")

    wins = 0.0
    for a in class_a:
        for b in class_b:
            if b > a:
                wins += 1.0
            elif b == a:
                wins += 0.5
    raw = wins / (len(class_a) * len(class_b))
    return max(raw, 1.0 - raw)


@dataclass
class TimingResult:
    """One measured arm of the timing experiment."""

    label: str
    tick_ms: float
    n_per_class: int
    advantage: float
    median_cheap_ms: float
    median_costly_ms: float

    @property
    def separation_ms(self) -> float:
        return self.median_costly_ms - self.median_cheap_ms

    def render(self) -> str:
        return (
            "%-18s tick=%6.1f ms  n=%d/class  advantage=%.3f  "
            "median gap=%+.2f ms"
            % (
                self.label,
                self.tick_ms,
                self.n_per_class,
                self.advantage,
                self.separation_ms,
            )
        )


def median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return float("nan")
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0
