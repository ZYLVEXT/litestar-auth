"""Verify language-neutral SPIFFE ID vectors against authweave-workload[spiffe]."""

from __future__ import annotations

import json
from pathlib import Path

from authweave_workload.spiffe import SpiffeValidationError, parse_spiffe_id

MANIFEST = Path(__file__).resolve().parent / "manifest.json"


def main() -> int:
    """Verify every manifest case.

    Returns:
        A shell status.
    """
    data = json.loads(MANIFEST.read_text())
    failures = 0
    for case in data["cases"]:
        try:
            parse_spiffe_id(case["spiffe_id"])
            passed = True
        except SpiffeValidationError:
            passed = False
        ok = passed if case["expect"] == "pass" else not passed
        if ok:
            pass
        else:
            failures += 1
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
