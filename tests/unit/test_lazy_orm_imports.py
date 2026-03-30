"""Verify default ORM modules are not loaded until explicitly needed."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.imports]

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )


def test_import_root_package_does_not_load_default_models() -> None:
    """Importing the root package wires plugin/config without loading ``litestar_auth.models``."""
    proc = _run_isolated(
        "import sys\nimport litestar_auth\nassert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_db_package_does_not_load_sqlalchemy_adapter() -> None:
    """``import litestar_auth.db`` exposes base types only."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.db\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n"
        "assert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_db_sqlalchemy_module_does_not_load_models() -> None:
    """Loading the adapter module does not import default ORM classes."""
    proc = _run_isolated(
        "import sys\nimport litestar_auth.db.sqlalchemy\nassert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_plugin_config_does_not_load_sqlalchemy_adapter() -> None:
    """Plugin config must not pull ``db.sqlalchemy`` until the default DB factory runs."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth._plugin.config\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n"
        "assert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_plugin_public_module_does_not_load_models() -> None:
    """``litestar_auth.plugin`` stays free of ``litestar_auth.models`` on import."""
    proc = _run_isolated(
        "import sys\nimport litestar_auth.plugin\nassert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
