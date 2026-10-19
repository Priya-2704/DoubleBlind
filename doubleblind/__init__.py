"""DOUBLEBLIND -- isolation and evidence for adversarial model evaluation.

Red, Blue and the model under test run in separate trust domains.  All
permitted traffic goes through one mediating gateway that tags, scans, reduces,
pads and logs it.  The deliverable of a run is not a finding; it is a finding
plus machine-checkable evidence about the conditions it was produced under.

Standard library only, Python 3.12.
"""

__version__ = "0.1.0"

__all__ = [
    "audit",
    "dna",
    "gateway",
    "harness",
    "model_server",
    "party",
    "protocol",
    "replay",
    "timing",
]
