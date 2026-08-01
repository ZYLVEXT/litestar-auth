"""Optional dependency isolation tests."""

from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = pytest.mark.imports


def test_base_import_does_not_load_litestar_or_redis() -> None:
    code = (
        "import sys, authweave_http_signatures; assert 'litestar' not in sys.modules; assert 'redis' not in sys.modules"
    )
    subprocess.run([sys.executable, "-I", "-c", code], check=True)
