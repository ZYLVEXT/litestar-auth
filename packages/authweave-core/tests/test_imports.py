"""Import-isolation tests for authweave-core."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.imports


def test_base_import_does_not_load_framework_storage_or_crypto_packages() -> None:
    script = """
import json
import sys
import authweave_core

blocked = ("litestar", "sqlalchemy", "redis", "jwt", "cryptography")
print(json.dumps(sorted(name for name in sys.modules if name.split(".", 1)[0] in blocked)))
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == []
