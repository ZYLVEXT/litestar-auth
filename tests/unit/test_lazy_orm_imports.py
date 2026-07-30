"""Modern-only import boundaries for the v7 package."""

from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = pytest.mark.unit


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    """Run an import assertion in a fresh interpreter.

    Returns:
        Completed child-process result.
    """
    return subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_isolated(code: str) -> None:
    result = _run_isolated(code)
    assert result.returncode == 0, result.stdout + result.stderr


def test_root_import_keeps_reference_orm_and_adapter_lazy() -> None:
    """The public package import does not load optional reference persistence."""
    _assert_isolated(
        "import sys\n"
        "import litestar_auth\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n",
    )


def test_database_adapter_import_keeps_reference_models_lazy() -> None:
    """The generic SQLAlchemy adapter does not import bundled models."""
    _assert_isolated(
        "import sys\nimport litestar_auth.db.sqlalchemy\nassert 'litestar_auth.models' not in sys.modules\n",
    )


def test_plugin_config_loads_token_models_but_not_reference_user_models() -> None:
    """The typed DB preset owns token models without loading reference user/OAuth mappers."""
    _assert_isolated(
        "import sys\n"
        "import litestar_auth._plugin.config\n"
        "assert 'litestar_auth._plugin.database_token' in sys.modules\n"
        "assert 'litestar_auth.authentication.strategy.db_models' in sys.modules\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n",
    )


def test_models_package_keeps_reference_mappers_lazy() -> None:
    """Importing the model facade does not eagerly map optional model families."""
    _assert_isolated(
        "import sys\n"
        "import litestar_auth.models\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n",
    )


def test_default_user_db_factory_imports_adapter_only_when_called() -> None:
    """The default user-store adapter remains deferred until factory invocation."""
    _assert_isolated(
        "import sys\n"
        "from litestar_auth.plugin import LitestarAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "config = LitestarAuthConfig(user_model=UserModel)\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n"
        "database = config.resolve_user_db_factory()(object())\n"
        "assert database.user_model is UserModel\n"
        "assert 'litestar_auth.db.sqlalchemy' in sys.modules\n",
    )


def test_database_preset_construction_keeps_reference_mappers_lazy() -> None:
    """Constructing the supported DB profile does not import reference user/OAuth models."""
    _assert_isolated(
        "import sys\n"
        "from litestar_auth._plugin.config import DatabaseTokenAuthConfig\n"
        "from litestar_auth.authentication.transport.cookie import CookieTransportConfig\n"
        "from litestar_auth.plugin import LitestarAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "config = LitestarAuthConfig(\n"
        "    database_token_auth=DatabaseTokenAuthConfig(\n"
        "        token_hash_secret='modern-db-session-secret-7fA9!qR4#kM2',\n"
        "        cookie=CookieTransportConfig(allow_insecure_cookie_auth=True),\n"
        "    ),\n"
        "    user_model=UserModel,\n"
        ")\n"
        "assert config.database_token_auth is not None\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n",
    )
