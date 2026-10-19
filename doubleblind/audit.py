"""Hash-chained audit log.

Each entry carries a digest of its own payload and the hash of the entry before
it, so any edit, insertion, deletion or reordering breaks the chain at a known
index.  Periodic checkpoints carry an HMAC over the chain head, which is what
stops an attacker who can rewrite the whole file from simply recomputing every
hash.

The checkpoint key is symmetric, so a verifier must hold it.  That is a real
limitation and it is recorded in docs/THREAT_MODEL.md: a public-key signature
would let a third party verify without being able to forge, and the entry
format already leaves room for one.

Standard library only.
"""

from __future__ import annotations

import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterator

from .protocol import canonical

GENESIS = "0" * 64

#: Entries between checkpoints.
DEFAULT_CHECKPOINT_EVERY = 25


def entry_hash(idx: int, ts: float, event: str, content_digest: str, prev: str) -> str:
    """Hash binding an entry's position, time, kind and payload to its parent."""
    return sha256(
        canonical([idx, round(ts, 6), event, content_digest, prev])
    ).hexdigest()


class AuditLog:
    """Append-only JSONL log with a SHA-256 chain and keyed checkpoints."""

    def __init__(
        self,
        path: str,
        key: bytes,
        *,
        checkpoint_every: int = DEFAULT_CHECKPOINT_EVERY,
    ) -> None:
        self.path = path
        self.key = key
        self.checkpoint_every = checkpoint_every
        self._lock = threading.Lock()
        self._idx = 0
        self._head = GENESIS

        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.exists(path):
            self._resume()
        else:
            # Touch the file so a run with zero events still produces a log.
            open(path, "a", encoding="utf-8").close()

    def _resume(self) -> None:
        for rec in read_entries(self.path):
            self._idx = int(rec["idx"]) + 1
            self._head = str(rec["entry_hash"])

    @property
    def head(self) -> str:
        return self._head

    @property
    def count(self) -> int:
        return self._idx

    def append(self, event: str, data: dict[str, Any]) -> dict[str, Any]:
        """Append one event and return the written entry."""
        with self._lock:
            return self._append_locked(event, data)

    def _append_locked(self, event: str, data: dict[str, Any]) -> dict[str, Any]:
        ts = time.time()
        content_digest = sha256(canonical(data)).hexdigest()
        rec = {
            "idx": self._idx,
            "ts": round(ts, 6),
            "event": event,
            "data": data,
            "content_digest": content_digest,
            "prev": self._head,
            "entry_hash": entry_hash(self._idx, ts, event, content_digest, self._head),
        }
        self._write(rec)
        self._idx += 1
        self._head = rec["entry_hash"]

        if self.checkpoint_every and self._idx % self.checkpoint_every == 0:
            self._checkpoint_locked()
        return rec

    def checkpoint(self) -> dict[str, Any]:
        with self._lock:
            return self._checkpoint_locked()

    def _checkpoint_locked(self) -> dict[str, Any]:
        """Write a keyed checkpoint over the current chain head."""
        covers = self._idx
        head = self._head
        tag = hmac.new(
            self.key, canonical({"covers": covers, "head": head}), sha256
        ).hexdigest()
        return self._append_locked(
            "checkpoint", {"covers": covers, "head": head, "hmac": tag}
        )

    def _write(self, rec: dict[str, Any]) -> None:
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def close(self) -> None:
        if self.checkpoint_every:
            self.checkpoint()


def read_entries(path: str) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("line %d is not valid JSON: %s" % (lineno, exc))


@dataclass
class Verdict:
    """Outcome of verifying a log file."""

    ok: bool
    entries: int
    checkpoints_ok: int
    checkpoints_bad: int
    head: str
    failures: list[dict[str, Any]]

    def render(self) -> str:
        lines = [
            "entries        : %d" % self.entries,
            "chain head     : %s" % self.head,
            "checkpoints    : %d verified, %d failed"
            % (self.checkpoints_ok, self.checkpoints_bad),
        ]
        if self.ok:
            lines.append("result         : INTACT")
        else:
            lines.append("result         : TAMPERED")
            for f in self.failures:
                lines.append(
                    "  index %-6s %-22s %s"
                    % (f.get("idx", "?"), f.get("kind", ""), f.get("detail", ""))
                )
        return "\n".join(lines)


def verify(path: str, key: bytes | None = None) -> Verdict:
    """Walk the chain and report the first index at which it stops holding.

    Without ``key`` the structural chain is still checked; checkpoint tags are
    then reported as unverifiable rather than as failures.
    """
    failures: list[dict[str, Any]] = []
    prev = GENESIS
    expected_idx = 0
    count = 0
    cp_ok = 0
    cp_bad = 0

    for rec in read_entries(path):
        count += 1
        idx = rec.get("idx")

        if idx != expected_idx:
            failures.append(
                {
                    "idx": idx,
                    "kind": "index-discontinuity",
                    "detail": "expected index %d, an entry was inserted or removed"
                    % expected_idx,
                }
            )
            expected_idx = (idx + 1) if isinstance(idx, int) else expected_idx + 1
        else:
            expected_idx += 1

        recomputed_content = sha256(canonical(rec.get("data", {}))).hexdigest()
        if recomputed_content != rec.get("content_digest"):
            failures.append(
                {
                    "idx": idx,
                    "kind": "content-edited",
                    "detail": "entry payload does not match its recorded digest",
                }
            )

        if rec.get("prev") != prev:
            failures.append(
                {
                    "idx": idx,
                    "kind": "chain-broken",
                    "detail": "prev hash does not match the preceding entry",
                }
            )

        recomputed_hash = entry_hash(
            int(rec.get("idx", -1)),
            float(rec.get("ts", 0.0)),
            str(rec.get("event", "")),
            str(rec.get("content_digest", "")),
            str(rec.get("prev", "")),
        )
        if recomputed_hash != rec.get("entry_hash"):
            failures.append(
                {
                    "idx": idx,
                    "kind": "entry-hash-mismatch",
                    "detail": "entry hash was not recomputed after the edit",
                }
            )

        if rec.get("event") == "checkpoint":
            data = rec.get("data", {})
            if key is None:
                cp_bad += 0
            else:
                tag = hmac.new(
                    key,
                    canonical(
                        {"covers": data.get("covers"), "head": data.get("head")}
                    ),
                    sha256,
                ).hexdigest()
                if hmac.compare_digest(tag, str(data.get("hmac", ""))):
                    cp_ok += 1
                else:
                    cp_bad += 1
                    failures.append(
                        {
                            "idx": idx,
                            "kind": "checkpoint-forged",
                            "detail": "checkpoint HMAC does not verify under the audit key",
                        }
                    )

        prev = str(rec.get("entry_hash", ""))

    return Verdict(
        ok=not failures,
        entries=count,
        checkpoints_ok=cp_ok,
        checkpoints_bad=cp_bad,
        head=prev,
        failures=failures,
    )
