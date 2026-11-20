"""Proof Pack: the evidence bundle that accompanies a run's findings.

The pack is assembled only from material that was recorded while the run
happened -- the audit chain, the verifier's verdict on it, the replay counts
and the timing measurement.  Nothing in it is re-derived from the findings
themselves, which is what makes it possible for a reader to disagree with our
conclusions while still checking our record.

A pack that fails its own verification is still emitted, marked failed.  A
bundle that can only be produced when the news is good is not evidence.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from hashlib import sha256
from typing import Any

from .audit import verify
from .protocol import canonical


def _file_digest(path: str) -> str:
    h = sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build(
    *,
    audit_path: str,
    audit_key: bytes,
    findings: list[dict[str, Any]] | None = None,
    timing_path: str | None = None,
    delta_path: str | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a pack from the recorded artefacts of one run."""
    verdict = verify(audit_path, audit_key)

    timing: dict[str, Any] | None = None
    if timing_path and os.path.exists(timing_path):
        with open(timing_path, encoding="utf-8") as fh:
            timing = json.load(fh)

    # The contamination delta is what lets a reader tell a claim about the
    # model from a claim about the deployment it was measured in.  A pack
    # without it still verifies; it just asserts less.
    contamination: dict[str, Any] | None = None
    if delta_path and os.path.exists(delta_path):
        with open(delta_path, encoding="utf-8") as fh:
            contamination = json.load(fh)

    pack: dict[str, Any] = {
        "schema": "doubleblind/proofpack/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "isolation_mode": (config or {}).get("isolation_mode", "process"),
        },
        "config": config or {},
        "audit": {
            "path": os.path.basename(audit_path),
            "file_sha256": _file_digest(audit_path),
            "entries": verdict.entries,
            "chain_head": verdict.head,
            "checkpoints_verified": verdict.checkpoints_ok,
            "checkpoints_failed": verdict.checkpoints_bad,
            "intact": verdict.ok,
            "failures": verdict.failures,
        },
        "findings": findings or [],
        "timing": timing,
        "contamination_delta": contamination,
        "limitations": [
            "The model under test is a deterministic mock with one seeded "
            "stochastic branch, not a language model.",
            "Container isolation shares a host kernel; a container escape "
            "defeats every property in this pack at once.",
            "DNA detects verbatim marker propagation only. Paraphrase and "
            "semantic influence carry no marker and will not be flagged.",
            "Checkpoints are HMAC-keyed, so verification requires the audit "
            "key. A third party cannot verify without also being able to forge.",
            "Resource and availability channels between parties are not "
            "measured.",
        ],
    }
    if contamination is None:
        pack["limitations"].append(
            "No contamination delta accompanies this pack, so it carries no "
            "evidence distinguishing a property of the model from a property "
            "of the deployment it was measured in. Run "
            "scripts/measure_delta.py."
        )
    else:
        pack["limitations"].append(
            "The contamination delta counts contamination the release scan "
            "detected. DNA sees verbatim marker propagation only, so the "
            "shared-arm rate is a lower bound and the clean arm evidences the "
            "absence of detected contamination, not of contamination."
        )
    # The pack commits to itself last, so the digest covers everything above.
    pack["pack_sha256"] = sha256(canonical(pack)).hexdigest()
    return pack


def write(pack: dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(pack, fh, indent=2, sort_keys=True)
    return path


def check(path: str) -> tuple[bool, str]:
    """Re-verify a pack's self-digest."""
    with open(path, encoding="utf-8") as fh:
        pack = json.load(fh)
    claimed = pack.pop("pack_sha256", "")
    actual = sha256(canonical(pack)).hexdigest()
    if claimed == actual:
        return True, "pack digest matches"
    return False, "pack digest mismatch: claimed %s, recomputed %s" % (
        claimed[:16],
        actual[:16],
    )
