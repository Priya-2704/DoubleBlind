"""Independently verify an audit log, or a Proof Pack, from the command line.

    py -3.12 scripts/verify_log.py artifacts/audit.log
    py -3.12 scripts/verify_log.py artifacts/proofpack.json --pack

Exit status is 0 when intact and 1 when not, so this can gate a pipeline.

Without --key (or DOUBLEBLIND_SECRET) the hash chain is still checked in full;
only the checkpoint HMACs are skipped, and the output says so.  That is the
useful property for a reviewer who has the log but not the key: they can detect
any edit that did not also rewrite every following entry.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from doubleblind.audit import verify  # noqa: E402
from doubleblind.proofpack import check  # noqa: E402
from doubleblind.protocol import derive_key  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path")
    ap.add_argument("--key", help="shared secret; defaults to DOUBLEBLIND_SECRET")
    ap.add_argument("--pack", action="store_true", help="verify a Proof Pack instead")
    args = ap.parse_args(argv)

    if args.pack:
        good, detail = check(args.path)
        print(detail)
        return 0 if good else 1

    secret = args.key or os.environ.get("DOUBLEBLIND_SECRET")
    key = derive_key(secret, "audit-checkpoint") if secret else None
    if key is None:
        print("no key supplied: chain verified, checkpoint HMACs skipped\n")

    verdict = verify(args.path, key)
    print(verdict.render())
    return 0 if verdict.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
