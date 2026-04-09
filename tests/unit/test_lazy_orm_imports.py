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


def test_import_db_package_exposes_only_base_store_types() -> None:
    """The public ``litestar_auth.db`` package stops short of the SQLAlchemy adapter."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.db as auth_db\n"
        "assert auth_db.__all__ == ('BaseOAuthAccountStore', 'BaseUserStore')\n"
        "assert not hasattr(auth_db, 'SQLAlchemyUserDatabase')\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n",
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


def test_import_models_package_keeps_user_and_oauth_submodules_lazy() -> None:
    """Importing ``litestar_auth.models`` keeps both concrete ORM submodules deferred."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.models as models\n"
        "assert models.__dir__() == [\n"
        "    'AccessTokenMixin',\n"
        "    'OAuthAccount',\n"
        "    'OAuthAccountMixin',\n"
        "    'RefreshTokenMixin',\n"
        "    'User',\n"
        "    'UserAuthRelationshipMixin',\n"
        "    'UserModelMixin',\n"
        "    'import_token_orm_models',\n"
        "]\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_models_mixins_module_does_not_register_oauth_encryption_events() -> None:
    """Importing ``litestar_auth.models.mixins`` keeps OAuth mapper hooks deferred."""
    proc = _run_isolated(
        "from sqlalchemy import event\n"
        "from litestar_auth.models.mixins import OAuthAccountMixin\n"
        "from litestar_auth.oauth_encryption import _decrypt_loaded_oauth_tokens\n"
        "assert not event.contains(OAuthAccountMixin, 'load', _decrypt_loaded_oauth_tokens)\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_accessing_oauth_account_from_models_package_only_loads_oauth_submodule() -> None:
    """Lazy ``OAuthAccount`` access loads ``models.oauth`` without importing the reference ``User`` model."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.models as models\n"
        "oauth_model = models.OAuthAccount\n"
        "assert oauth_model.__module__ == 'litestar_auth.models.oauth'\n"
        "assert 'litestar_auth.models.oauth' in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_importing_oauth_model_registers_oauth_encryption_events() -> None:
    """Loading the bundled OAuth model registers its encryption hooks without importing ``models.user``."""
    proc = _run_isolated(
        "import sys\n"
        "from sqlalchemy import event\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "from litestar_auth.oauth_encryption import _decrypt_loaded_oauth_tokens\n"
        "assert event.contains(OAuthAccount, 'load', _decrypt_loaded_oauth_tokens)\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_models_package_token_registration_helper_keeps_user_and_oauth_submodules_lazy() -> None:
    """The canonical models-layer token helper does not import ``models.user`` or ``models.oauth``."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.authentication.strategy as strategy\n"
        "import litestar_auth.models as models\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "canonical_models = models.import_token_orm_models()\n"
        "compatibility_models = strategy.import_token_orm_models()\n"
        "assert canonical_models == compatibility_models\n"
        "assert [model.__name__ for model in canonical_models] == ['AccessToken', 'RefreshToken']\n"
        "assert [model.__module__ for model in canonical_models] == [\n"
        "    'litestar_auth.authentication.strategy.db_models',\n"
        "    'litestar_auth.authentication.strategy.db_models',\n"
        "]\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_models_package_token_registration_helper_stays_lazy_until_reference_mappers_are_loaded() -> None:
    """The canonical token helper stays lazy until the reference ORM submodules are imported explicitly."""
    proc = _run_isolated(
        "import sys\n"
        "from sqlalchemy import inspect\n"
        "import litestar_auth.authentication.strategy as strategy\n"
        "import litestar_auth.models as models\n"
        "access_token_model, refresh_token_model = models.import_token_orm_models()\n"
        "assert strategy.import_token_orm_models() == (access_token_model, refresh_token_model)\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "assert OAuthAccount.__module__ == 'litestar_auth.models.oauth'\n"
        "assert 'litestar_auth.models.oauth' in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "from litestar_auth.models import User\n"
        "relationships = inspect(User).relationships\n"
        "assert 'litestar_auth.models.user' in sys.modules\n"
        "assert relationships['access_tokens'].mapper.class_ is access_token_model\n"
        "assert relationships['refresh_tokens'].mapper.class_ is refresh_token_model\n"
        "assert relationships['oauth_accounts'].mapper.class_ is OAuthAccount\n"
        "assert strategy.import_token_orm_models() == (access_token_model, refresh_token_model)\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_strategy_package_keeps_models_namespace_unloaded() -> None:
    """Importing ``litestar_auth.authentication.strategy`` keeps the compatibility path model-lazy."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.authentication.strategy as strategy\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "token_models = strategy.import_token_orm_models()\n"
        "assert [model.__name__ for model in token_models] == ['AccessToken', 'RefreshToken']\n"
        "assert [model.__module__ for model in token_models] == [\n"
        "    'litestar_auth.authentication.strategy.db_models',\n"
        "    'litestar_auth.authentication.strategy.db_models',\n"
        "]\n"
        "assert 'litestar_auth.authentication.strategy.db_models' in sys.modules\n"
        "assert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_canonical_db_bearer_plugin_setup_keeps_models_and_adapter_lazy() -> None:
    """The common DB bearer stack stays import-lazy until the default DB factory is actually used."""
    proc = _run_isolated(
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar_auth import (\n"
        "    AuthenticationBackend,\n"
        "    BearerTransport,\n"
        "    DatabaseTokenStrategy,\n"
        "    LitestarAuth,\n"
        "    LitestarAuthConfig,\n"
        ")\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "backend = AuthenticationBackend(\n"
        "    name='database',\n"
        "    transport=BearerTransport(),\n"
        "    strategy=cast(Any, DatabaseTokenStrategy(session=object(), token_hash_secret='x' * 40)),\n"
        ")\n"
        "config = LitestarAuthConfig(\n"
        "    backends=[backend],\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    user_manager_kwargs={},\n"
        ")\n"
        "LitestarAuth(config)\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_default_user_db_factory_imports_adapter_only_when_called() -> None:
    """The plugin's default ``user_db_factory`` keeps the adapter deferred until first use."""
    proc = _run_isolated(
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar_auth import AuthenticationBackend, BearerTransport, DatabaseTokenStrategy, LitestarAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "backend = AuthenticationBackend(\n"
        "    name='database',\n"
        "    transport=BearerTransport(),\n"
        "    strategy=cast(Any, DatabaseTokenStrategy(session=object(), token_hash_secret='x' * 40)),\n"
        ")\n"
        "config = LitestarAuthConfig(\n"
        "    backends=[backend],\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        ")\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "database = config.resolve_user_db_factory()(object())\n"
        "assert database.__class__.__name__ == 'SQLAlchemyUserDatabase'\n"
        "assert database.user_model is UserModel\n"
        "assert 'litestar_auth.db.sqlalchemy' in sys.modules\n"
        "assert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_db_bearer_preset_config_keeps_models_and_adapter_lazy() -> None:
    """The DB-token config field does not eagerly import ORM models or the SQLAlchemy adapter."""
    proc = _run_isolated(
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar_auth import LitestarAuth, LitestarAuthConfig\n"
        "from litestar_auth._plugin.config import DatabaseTokenAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "config = LitestarAuthConfig(\n"
        "    database_token_auth=DatabaseTokenAuthConfig(\n"
        "        token_hash_secret='x' * 40,\n"
        "    ),\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    user_manager_kwargs={},\n"
        ")\n"
        "LitestarAuth(config)\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "assert 'litestar_auth.db.sqlalchemy' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_db_bearer_plugin_runtime_bootstrap_loads_models_package_without_reference_mappers() -> None:
    """DB-token plugin startup loads the canonical models helper without importing reference ORM modules."""
    proc = _run_isolated(
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar.config.app import AppConfig\n"
        "from litestar_auth.manager import UserManagerSecurity\n"
        "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig\n"
        "from litestar_auth._plugin.config import DatabaseTokenAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "config = LitestarAuthConfig(\n"
        "    database_token_auth=DatabaseTokenAuthConfig(token_hash_secret='x' * 40),\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    user_manager_security=UserManagerSecurity(\n"
        "        verification_token_secret='y' * 32,\n"
        "        reset_password_token_secret='z' * 32,\n"
        "    ),\n"
        ")\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "plugin = LitestarAuth(config)\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "plugin.on_app_init(AppConfig())\n"
        "assert 'litestar_auth.models' in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
