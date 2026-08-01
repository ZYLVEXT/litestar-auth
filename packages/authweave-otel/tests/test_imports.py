"""Import-isolation tests for authweave-otel."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.imports


def test_import_does_not_load_opentelemetry_sdk_or_exporters() -> None:
    script = """
import json
import sys
import authweave_otel

blocked = ("opentelemetry.sdk", "opentelemetry.exporter")
loaded = sorted(name for name in sys.modules if name.startswith(blocked))
print(json.dumps(loaded))
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == []
