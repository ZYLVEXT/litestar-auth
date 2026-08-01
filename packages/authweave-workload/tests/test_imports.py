"""Optional dependency isolation tests."""

from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = pytest.mark.imports


def test_base_import_does_not_load_optional_implementations() -> None:
    code = (
        "import sys, authweave_workload; "
        "assert 'litestar' not in sys.modules; "
        "assert 'sqlalchemy' not in sys.modules; "
        "assert 'cryptography' not in sys.modules; "
        "assert 'jwt' not in sys.modules; "
        "assert 'authweave_workload.dpop' not in sys.modules; "
        "assert 'authweave_workload.spiffe' not in sys.modules; "
        "assert 'authweave_workload.introspection' not in sys.modules; "
        "assert 'authweave_workload.redis_store' not in sys.modules"
    )
    subprocess.run([sys.executable, "-I", "-c", code], check=True)
