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
    """``import litestar_auth.db`` exposes base contracts only."""
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
        "assert auth_db.__all__ == ('ApiKeyData', 'BaseApiKeyStore', 'BaseOAuthAccountStore', "
        "'BaseOrganizationStore', 'BaseUserStore', 'MembershipData', 'OAuthAccountData', "
        "'OrganizationData', 'OrganizationInvitationData')\n"
        "assert not hasattr(auth_db, 'SQLAlchemyApiKeyStore')\n"
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
        "assert 'litestar_auth._plugin.database_token' not in sys.modules\n"
        "assert 'litestar_auth._plugin.user_manager_builder' not in sys.modules\n"
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


def test_import_contrib_package_does_not_load_role_admin_surface() -> None:
    """Importing ``litestar_auth.contrib`` keeps the new role-admin package opt-in."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.contrib\n"
        "assert 'litestar_auth.contrib.role_admin' not in sys.modules\n"
        "assert 'litestar_auth.contrib.role_admin._controller' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_models_package_keeps_concrete_orm_submodules_lazy() -> None:
    """Importing ``litestar_auth.models`` keeps concrete ORM submodules deferred."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.models as models\n"
        "assert models.__dir__() == [\n"
        "    'AccessTokenMixin',\n"
        "    'ApiKey',\n"
        "    'ApiKeyMixin',\n"
        "    'OAuthAccount',\n"
        "    'OAuthAccountMixin',\n"
        "    'Organization',\n"
        "    'OrganizationInvitation',\n"
        "    'OrganizationInvitationMixin',\n"
        "    'OrganizationMembership',\n"
        "    'OrganizationMembershipMixin',\n"
        "    'OrganizationMixin',\n"
        "    'RefreshTokenMixin',\n"
        "    'Role',\n"
        "    'RoleMixin',\n"
        "    'User',\n"
        "    'UserAuthRelationshipMixin',\n"
        "    'UserModelMixin',\n"
        "    'UserRole',\n"
        "    'UserRoleAssociationMixin',\n"
        "    'UserRoleRelationshipMixin',\n"
        "    'import_token_orm_models',\n"
        "]\n"
        "assert 'litestar_auth.models.api_key' not in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "assert 'litestar_auth.models.organization' not in sys.modules\n"
        "assert 'litestar_auth.models.role' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_models_mixins_module_does_not_register_oauth_encryption_events() -> None:
    """Importing ``litestar_auth.models.mixins`` keeps OAuth mapper hooks deferred."""
    proc = _run_isolated(
        "from sqlalchemy import event\n"
        "from litestar_auth.models.mixins import OAuthAccountMixin\n"
        "from litestar_auth._oauth_mapper_events import _decrypt_loaded_oauth_tokens\n"
        "assert not event.contains(OAuthAccountMixin, 'load', _decrypt_loaded_oauth_tokens)\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_accessing_api_key_from_models_package_only_loads_api_key_submodule() -> None:
    """Lazy ``ApiKey`` access loads ``models.api_key`` without importing the reference ``User`` model."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.models as models\n"
        "api_key_model = models.ApiKey\n"
        "assert api_key_model.__module__ == 'litestar_auth.models.api_key'\n"
        "assert 'litestar_auth.models.api_key' in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n",
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


def test_accessing_role_models_from_models_package_only_loads_role_submodule() -> None:
    """Lazy role-model access loads ``models.role`` without importing the reference ``User`` model."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.models as models\n"
        "role_model = models.Role\n"
        "user_role_model = models.UserRole\n"
        "assert role_model.__module__ == 'litestar_auth.models.role'\n"
        "assert user_role_model.__module__ == 'litestar_auth.models.role'\n"
        "assert 'litestar_auth.models.role' in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_accessing_organization_models_from_models_package_only_loads_organization_submodule() -> None:
    """Lazy organization-model access loads ``models.organization`` without importing the reference ``User`` model."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.models as models\n"
        "organization_model = models.Organization\n"
        "invitation_model = models.OrganizationInvitation\n"
        "membership_model = models.OrganizationMembership\n"
        "assert organization_model.__module__ == 'litestar_auth.models.organization'\n"
        "assert invitation_model.__module__ == 'litestar_auth.models.organization'\n"
        "assert membership_model.__module__ == 'litestar_auth.models.organization'\n"
        "assert organization_model.__table__.c.slug.unique is True\n"
        "assert organization_model.__table__.c.slug.index is True\n"
        "assert set(invitation_model.__table__.c.keys()) == {\n"
        "    'created_at', 'expires_at', 'id', 'invited_email', 'organization_id', 'roles', 'status', 'token_hash'\n"
        "}\n"
        "assert set(membership_model.__table__.c.keys()) == {'organization_id', 'roles', 'user_id'}\n"
        "assert 'litestar_auth.models.organization' in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_importing_oauth_model_registers_oauth_encryption_events() -> None:
    """Loading the bundled OAuth model registers its encryption hooks without importing ``models.user``."""
    proc = _run_isolated(
        "import sys\n"
        "from sqlalchemy import event\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "from litestar_auth._oauth_mapper_events import _decrypt_loaded_oauth_tokens\n"
        "assert event.contains(OAuthAccount, 'load', _decrypt_loaded_oauth_tokens)\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_models_package_token_registration_helper_keeps_user_and_oauth_submodules_lazy() -> None:
    """The canonical models-layer token helper does not import ``models.user`` or ``models.oauth``."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.models as models\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "token_models = models.import_token_orm_models()\n"
        "assert [model.__name__ for model in token_models] == ['AccessToken', 'RefreshToken']\n"
        "assert [model.__module__ for model in token_models] == [\n"
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
        "import litestar_auth.models as models\n"
        "access_token_model, refresh_token_model = models.import_token_orm_models()\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "assert 'litestar_auth.models.api_key' not in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "assert OAuthAccount.__module__ == 'litestar_auth.models.oauth'\n"
        "assert 'litestar_auth.models.oauth' in sys.modules\n"
        "assert 'litestar_auth.models.api_key' not in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "from litestar_auth.models import User\n"
        "relationships = inspect(User).relationships\n"
        "assert 'litestar_auth.models.user' in sys.modules\n"
        "assert relationships['api_keys'].mapper.class_.__module__ == 'litestar_auth.models.api_key'\n"
        "assert relationships['access_tokens'].mapper.class_ is access_token_model\n"
        "assert relationships['refresh_tokens'].mapper.class_ is refresh_token_model\n"
        "assert relationships['oauth_accounts'].mapper.class_ is OAuthAccount\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_accessing_user_model_maps_slim_auth_column_inventory() -> None:
    """The reference ``User`` mapper exposes the expected slim auth column inventory."""
    proc = _run_isolated(
        "from sqlalchemy import inspect\n"
        "import litestar_auth.models as models\n"
        "User = models.User\n"
        "assert set(User.__table__.c.keys()) <= {'email', 'hashed_password', 'id', 'is_active', 'is_verified', 'recovery_codes', 'sa_orm_sentinel', 'totp_secret'}\n"
        "user = User(email='user@example.com', hashed_password='hashed-password')\n"
        "assert user.roles == []\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_strategy_package_keeps_models_namespace_unloaded() -> None:
    """Importing ``litestar_auth.authentication.strategy`` does not expose the removed token helper."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth.authentication.strategy as strategy\n"
        "assert 'litestar_auth.models' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert strategy.__all__ == (\n"
        "    'ApiKeyContext',\n"
        "    'ApiKeyNonceStore',\n"
        "    'ApiKeyNonceStoreResult',\n"
        "    'ApiKeyStrategy',\n"
        "    'ApiKeyStrategyConfig',\n"
        "    'ContextualStrategy',\n"
        "    'DatabaseTokenModels',\n"
        "    'DatabaseTokenStrategy',\n"
        "    'DatabaseTokenStrategyConfig',\n"
        "    'InMemoryApiKeyNonceStore',\n"
        "    'JWTContext',\n"
        "    'JWTStrategy',\n"
        "    'JWTStrategyConfig',\n"
        "    'RedisApiKeyNonceStore',\n"
        "    'RedisApiKeyNonceStoreClient',\n"
        "    'RedisTokenStrategy',\n"
        "    'RedisTokenStrategyConfig',\n"
        "    'RefreshableStrategy',\n"
        "    'Strategy',\n"
        "    'UserManagerProtocol',\n"
        ")\n"
        "assert not hasattr(strategy, 'import_token_orm_models')\n"
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
        "    LitestarAuth,\n"
        "    LitestarAuthConfig,\n"
        ")\n"
        "from litestar_auth.authentication.strategy import DatabaseTokenStrategy\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "    roles = []\n"
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
        "    strategy=cast(Any, DatabaseTokenStrategy(session=object(), token_hash_secret='0123456789abcdef' * 4)),\n"
        ")\n"
        "config = LitestarAuthConfig(\n"
        "    backends=[backend],\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
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
        "from litestar_auth import AuthenticationBackend, BearerTransport, LitestarAuthConfig\n"
        "from litestar_auth.authentication.strategy import DatabaseTokenStrategy\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "backend = AuthenticationBackend(\n"
        "    name='database',\n"
        "    transport=BearerTransport(),\n"
        "    strategy=cast(Any, DatabaseTokenStrategy(session=object(), token_hash_secret='0123456789abcdef' * 4)),\n"
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
        "    roles = []\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "config = LitestarAuthConfig(\n"
        "    database_token_auth=DatabaseTokenAuthConfig(\n"
        "        token_hash_secret='0123456789abcdef' * 4,\n"
        "    ),\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
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
        "    roles = []\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "config = LitestarAuthConfig(\n"
        "    database_token_auth=DatabaseTokenAuthConfig(token_hash_secret='0123456789abcdef' * 4),\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    user_manager_security=UserManagerSecurity(\n"
        "        verification_token_secret='89abcdef01234567' * 4,\n"
        "        reset_password_token_secret='fedcba9876543210' * 4,\n"
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
