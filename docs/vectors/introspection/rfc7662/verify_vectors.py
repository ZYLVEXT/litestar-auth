"""Verify language-neutral RFC 7662 plain introspection vectors."""

from __future__ import annotations

import json
from pathlib import Path

from authweave_workload.introspection import IntrospectionValidationError, parse_plain_introspection

MANIFEST = Path(__file__).resolve().parent / "manifest.json"


def main() -> int:
    """Verify every manifest case.

    Returns:
        A shell status.
    """
    data = json.loads(MANIFEST.read_text())
    failures = 0
    for case in data["cases"]:
        raw = json.dumps(case["body"]).encode()
        try:
            parse_plain_introspection(raw)
            passed = True
        except IntrospectionValidationError:
            passed = False
        ok = passed if case["expect"] == "pass" else not passed
        if ok:
            pass
        else:
            failures += 1
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
