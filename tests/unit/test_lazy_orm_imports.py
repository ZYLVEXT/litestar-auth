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


def _no_concrete_extension_or_orm_imports_code(action: str) -> str:
    return (
        "import sys\n"
        f"{action}\n"
        "allowed_extension_kernel_modules = {\n"
        "    'litestar_auth.extensions',\n"
        "    'litestar_auth._plugin.extensions',\n"
        "    'litestar_auth._plugin.extensions._context',\n"
        "    'litestar_auth._plugin.extensions._contracts',\n"
        "    'litestar_auth._plugin.extensions._registry',\n"
        "}\n"
        "loaded_extension_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'tests.support.extensions'\n"
        "    or name == 'litestar_auth.extensions'\n"
        "    or name.startswith('litestar_auth.extensions.')\n"
        "    or name == 'litestar_auth._plugin.extensions'\n"
        "    or name.startswith('litestar_auth._plugin.extensions.')\n"
        "}\n"
        "loaded_orm_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'litestar_auth.models'\n"
        "    or name.startswith('litestar_auth.models.')\n"
        "    or name == 'litestar_auth.db.sqlalchemy'\n"
        "    or name.startswith('litestar_auth.db.sqlalchemy.')\n"
        "}\n"
        "unexpected_extension_modules = loaded_extension_modules - allowed_extension_kernel_modules\n"
        "assert not unexpected_extension_modules, sorted(unexpected_extension_modules)\n"
        "assert not loaded_orm_modules, sorted(loaded_orm_modules)\n"
    )


def _no_entry_point_discovery_code(action: str) -> str:
    return (
        "import importlib.abc\n"
        "import importlib.metadata\n"
        "import sys\n"
        "auth_extension_group = 'litestar_auth.extensions'\n"
        "original_entry_points = importlib.metadata.entry_points\n"
        "class BlockDiscoveredExtensionImport(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, fullname, path, target=None):\n"
        "        if fullname == 'litestar_auth_ext_probe' or fullname.startswith('litestar_auth_ext_probe.'):\n"
        "            raise AssertionError(f'discovered extension module imported: {fullname}')\n"
        "        return None\n"
        "class BlockAuthExtensionEntryPoints:\n"
        "    def __init__(self, entry_points):\n"
        "        self._entry_points = entry_points\n"
        "    def select(self, *args, **kwargs):\n"
        "        if kwargs.get('group') == auth_extension_group:\n"
        "            raise AssertionError('auth extension entry-point loading should be opt-in')\n"
        "        return self._entry_points.select(*args, **kwargs)\n"
        "    def get(self, group, default=None):\n"
        "        if group == auth_extension_group:\n"
        "            raise AssertionError('auth extension entry-point loading should be opt-in')\n"
        "        return self._entry_points.get(group, default)\n"
        "    def __iter__(self):\n"
        "        return iter(self._entry_points)\n"
        "    def __getattr__(self, name):\n"
        "        return getattr(self._entry_points, name)\n"
        "def blocked_entry_points(*args, **kwargs):\n"
        "    if kwargs.get('group') == auth_extension_group:\n"
        "        raise AssertionError('auth extension entry-point loading should be opt-in')\n"
        "    entry_points = original_entry_points(*args, **kwargs)\n"
        "    if args or kwargs:\n"
        "        return entry_points\n"
        "    return BlockAuthExtensionEntryPoints(entry_points)\n"
        "sys.meta_path.insert(0, BlockDiscoveredExtensionImport())\n"
        "importlib.metadata.entry_points = blocked_entry_points\n"
        f"{action}\n"
        "assert 'litestar_auth._plugin.extensions._discovery' not in sys.modules\n"
        "assert not {\n"
        "    name for name in sys.modules if name == 'litestar_auth_ext_probe' or name.startswith('litestar_auth_ext_probe.')\n"
        "}\n"
    )


def _no_bundled_extension_or_optional_feature_imports_code(action: str) -> str:
    return (
        "import sys\n"
        f"{action}\n"
        "blocked_exact_modules = {\n"
        "    'cryptography.fernet',\n"
        "    'cryptography.hazmat.primitives.kdf.hkdf',\n"
        "    'litestar_auth._plugin.role_model_family',\n"
        "    'litestar_auth._totp_stores',\n"
        "    'litestar_auth.controllers._api_key_admin',\n"
        "    'litestar_auth.controllers._api_key_common',\n"
        "    'litestar_auth.controllers._api_key_self',\n"
        "    'litestar_auth.controllers.api_keys',\n"
        "    'litestar_auth.controllers.totp',\n"
        "    'litestar_auth.db.sqlalchemy',\n"
        "    'litestar_auth.models',\n"
        "    'redis.asyncio',\n"
        "}\n"
        "blocked_prefixes = (\n"
        "    'httpx_oauth.',\n"
        "    'litestar_auth._plugin.api_key_controller.',\n"
        "    'litestar_auth._plugin.organization_admin.',\n"
        "    'litestar_auth._plugin.role_admin.',\n"
        "    'litestar_auth._plugin.totp_controller.',\n"
        "    'litestar_auth.contrib.organization_admin.',\n"
        "    'litestar_auth.contrib.redis.',\n"
        "    'litestar_auth.contrib.role_admin.',\n"
        "    'litestar_auth.controllers.totp_',\n"
        "    'litestar_auth.db.sqlalchemy.',\n"
        "    'litestar_auth.models.',\n"
        "    'litestar_auth.oauth.',\n"
        "    'redis.asyncio.',\n"
        ")\n"
        "blocked_prefix_roots = {\n"
        "    'httpx_oauth',\n"
        "    'litestar_auth._plugin.api_key_controller',\n"
        "    'litestar_auth._plugin.organization_admin',\n"
        "    'litestar_auth._plugin.role_admin',\n"
        "    'litestar_auth._plugin.totp_controller',\n"
        "    'litestar_auth.contrib.organization_admin',\n"
        "    'litestar_auth.contrib.redis',\n"
        "    'litestar_auth.contrib.role_admin',\n"
        "    'litestar_auth.oauth',\n"
        "}\n"
        "loaded = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name in blocked_exact_modules\n"
        "    or name in blocked_prefix_roots\n"
        "    or name.startswith(blocked_prefixes)\n"
        "}\n"
        "assert not loaded, sorted(loaded)\n"
    )


def _no_role_admin_controller_or_orm_imports_code(action: str) -> str:
    return (
        "import sys\n"
        f"{action}\n"
        "role_admin_controller_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name in {\n"
        "        'litestar_auth.contrib.role_admin._controller',\n"
        "        'litestar_auth.contrib.role_admin._controller_handler_utils',\n"
        "        'litestar_auth.contrib.role_admin._controller_handlers',\n"
        "        'litestar_auth.contrib.role_admin._error_responses',\n"
        "        'litestar_auth.contrib.role_admin._schemas',\n"
        "        'litestar_auth.contrib.role_admin._session_wiring',\n"
        "    }\n"
        "}\n"
        "role_admin_orm_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'litestar_auth._plugin.role_admin'\n"
        "    or name.startswith('litestar_auth._plugin.role_admin.')\n"
        "    or name == 'litestar_auth._plugin.role_model_family'\n"
        "    or name == 'litestar_auth.models'\n"
        "    or name.startswith('litestar_auth.models.')\n"
        "    or name == 'litestar_auth.db.sqlalchemy'\n"
        "    or name.startswith('litestar_auth.db.sqlalchemy.')\n"
        "}\n"
        "assert not role_admin_controller_modules, sorted(role_admin_controller_modules)\n"
        "assert not role_admin_orm_modules, sorted(role_admin_orm_modules)\n"
    )


def _no_organization_admin_controller_or_orm_imports_code(action: str) -> str:
    return (
        "import sys\n"
        f"{action}\n"
        "organization_admin_controller_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name in {\n"
        "        'litestar_auth.contrib.organization_admin._controller',\n"
        "        'litestar_auth.contrib.organization_admin._error_responses',\n"
        "        'litestar_auth.contrib.organization_admin._schemas',\n"
        "    }\n"
        "}\n"
        "organization_admin_orm_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'litestar_auth._plugin.organization_admin'\n"
        "    or name.startswith('litestar_auth._plugin.organization_admin.')\n"
        "    or name == 'litestar_auth.models'\n"
        "    or name.startswith('litestar_auth.models.')\n"
        "    or name == 'litestar_auth.db.sqlalchemy'\n"
        "    or name.startswith('litestar_auth.db.sqlalchemy.')\n"
        "}\n"
        "assert not organization_admin_controller_modules, sorted(organization_admin_controller_modules)\n"
        "assert not organization_admin_orm_modules, sorted(organization_admin_orm_modules)\n"
    )


def _no_oauth_extension_or_optional_dependency_imports_code(action: str) -> str:
    return (
        "import sys\n"
        f"{action}\n"
        "oauth_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'litestar_auth.oauth'\n"
        "    or name.startswith('litestar_auth.oauth.')\n"
        "}\n"
        "httpx_oauth_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'httpx_oauth'\n"
        "    or name.startswith('httpx_oauth.')\n"
        "}\n"
        "oauth_crypto_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name in {\n"
        "        'cryptography.fernet',\n"
        "        'cryptography.hazmat.primitives.kdf.hkdf',\n"
        "    }\n"
        "}\n"
        "assert not oauth_modules, sorted(oauth_modules)\n"
        "assert not httpx_oauth_modules, sorted(httpx_oauth_modules)\n"
        "assert not oauth_crypto_modules, sorted(oauth_crypto_modules)\n"
    )


def _no_totp_controller_or_optional_dependency_imports_code(action: str) -> str:
    return (
        "import sys\n"
        f"{action}\n"
        "totp_controller_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'litestar_auth._plugin.totp_controller'\n"
        "    or name.startswith('litestar_auth._plugin.totp_controller.')\n"
        "    or name == 'litestar_auth.controllers.totp'\n"
        "    or name.startswith('litestar_auth.controllers.totp_')\n"
        "    or name == 'litestar_auth._totp_stores'\n"
        "}\n"
        "totp_cryptography_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name in {\n"
        "        'cryptography.fernet',\n"
        "        'cryptography.hazmat.primitives.kdf.hkdf',\n"
        "    }\n"
        "}\n"
        "assert not totp_controller_modules, sorted(totp_controller_modules)\n"
        "assert not totp_cryptography_modules, sorted(totp_cryptography_modules)\n"
    )


def _no_api_key_controller_or_optional_dependency_imports_code(action: str) -> str:
    return (
        "import sys\n"
        f"{action}\n"
        "api_key_controller_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name in {\n"
        "        'litestar_auth.controllers.api_keys',\n"
        "        'litestar_auth.controllers._api_key_admin',\n"
        "        'litestar_auth.controllers._api_key_common',\n"
        "        'litestar_auth.controllers._api_key_self',\n"
        "    }\n"
        "}\n"
        "api_key_cryptography_modules = {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'cryptography.fernet'\n"
        "}\n"
        "assert not api_key_controller_modules, sorted(api_key_controller_modules)\n"
        "assert not api_key_cryptography_modules, sorted(api_key_cryptography_modules)\n"
    )


def test_import_root_package_does_not_load_default_models() -> None:
    """Importing the root package wires plugin/config without loading ``litestar_auth.models``."""
    proc = _run_isolated(
        "import sys\nimport litestar_auth\nassert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_root_package_does_not_load_concrete_extensions_or_orm_modules() -> None:
    """The public root import exposes extension contracts without concrete extension or ORM modules."""
    proc = _run_isolated(_no_concrete_extension_or_orm_imports_code("import litestar_auth"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.parametrize(
    ("action", "import_path"),
    [
        pytest.param("import litestar_auth", "litestar_auth", id="root"),
        pytest.param("import litestar_auth.config", "litestar_auth.config", id="config"),
        pytest.param("import litestar_auth.extensions", "litestar_auth.extensions", id="extensions"),
    ],
)
def test_default_import_paths_do_not_load_extension_entry_points(action: str, import_path: str) -> None:
    """Importing public auth modules does not inspect external extension entry points by default."""
    proc = _run_isolated(
        _no_entry_point_discovery_code(
            f"{action}\nassert 'litestar_auth_ext_probe' not in sys.modules\nassert {import_path!r} in sys.modules",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_default_extension_resolution_does_not_load_extension_entry_points() -> None:
    """Resolving extensions with default discovery disabled does not inspect package entry points."""
    proc = _run_isolated(
        _no_entry_point_discovery_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "config = LitestarAuthConfig(user_model=UserModel)\n"
            "assert config.auto_discover_extensions is False\n"
            "assert config.resolve_extensions() == ()\n",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_root_package_does_not_load_bundled_extensions_or_optional_features() -> None:
    """The public root import keeps bundled extensions and optional dependency modules lazy."""
    proc = _run_isolated(_no_bundled_extension_or_optional_feature_imports_code("import litestar_auth"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_public_config_does_not_load_bundled_extensions_or_optional_features() -> None:
    """Public config helpers stay free of ORM, SQLAlchemy, bundled extensions, and optional deps."""
    proc = _run_isolated(_no_bundled_extension_or_optional_feature_imports_code("import litestar_auth.config"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_public_extensions_does_not_load_bundled_extensions_or_optional_features() -> None:
    """The extension-author facade is import-light until a lazy helper is resolved."""
    proc = _run_isolated(_no_bundled_extension_or_optional_feature_imports_code("import litestar_auth.extensions"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_root_package_does_not_load_role_admin_controller_or_orm_modules() -> None:
    """The public root import keeps the opt-in role-admin controller and ORM helpers lazy."""
    proc = _run_isolated(_no_role_admin_controller_or_orm_imports_code("import litestar_auth"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_root_package_does_not_load_organization_admin_controller_or_orm_modules() -> None:
    """The public root import keeps the opt-in organization-admin controller and ORM helpers lazy."""
    proc = _run_isolated(_no_organization_admin_controller_or_orm_imports_code("import litestar_auth"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_root_package_does_not_load_oauth_extension_or_optional_dependencies() -> None:
    """The public root import keeps OAuth internals and optional dependencies lazy."""
    proc = _run_isolated(_no_oauth_extension_or_optional_dependency_imports_code("import litestar_auth"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_root_package_does_not_load_totp_controller_or_optional_dependencies() -> None:
    """The public root import keeps TOTP controller internals and cryptography lazy."""
    proc = _run_isolated(_no_totp_controller_or_optional_dependency_imports_code("import litestar_auth"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_root_package_does_not_load_api_key_controller_or_optional_dependencies() -> None:
    """The public root import keeps API-key controller internals and cryptography lazy."""
    proc = _run_isolated(_no_api_key_controller_or_optional_dependency_imports_code("import litestar_auth"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_totp_controller_package_reports_lazy_exports_without_loading_controller() -> None:
    """The private TOTP controller package exposes helper names without resolving them."""
    proc = _run_isolated(
        "import sys\n"
        "import litestar_auth._plugin.totp_controller as totp_controller\n"
        "assert dir(totp_controller) == sorted(totp_controller.__all__)\n"
        "assert 'litestar_auth._plugin.totp_controller._core' not in sys.modules\n"
        "assert 'litestar_auth.controllers.totp' not in sys.modules\n"
        "assert 'litestar_auth._totp_stores' not in sys.modules\n"
        "assert 'cryptography.fernet' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_controllers_package_dir_reports_lazy_public_exports_without_loading_oauth() -> None:
    """The public controllers package exposes lazy export names without resolving OAuth."""
    proc = _run_isolated(
        _no_oauth_extension_or_optional_dependency_imports_code(
            "import litestar_auth.controllers as controllers\nassert dir(controllers) == sorted(controllers.__all__)",
        ),
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


def test_import_plugin_config_does_not_load_concrete_extensions_or_orm_modules() -> None:
    """The config import path keeps concrete extension and ORM modules behind explicit opt-ins."""
    proc = _run_isolated(_no_concrete_extension_or_orm_imports_code("import litestar_auth._plugin.config"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_import_plugin_public_module_does_not_load_models() -> None:
    """``litestar_auth.plugin`` stays free of ``litestar_auth.models`` on import."""
    proc = _run_isolated(
        "import sys\nimport litestar_auth.plugin\nassert 'litestar_auth.models' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_plugin_startup_does_not_load_concrete_extensions_or_orm_modules() -> None:
    """Constructing and initializing the plugin with ``extensions=()`` keeps extension opt-ins lazy."""
    proc = _run_isolated(
        _no_concrete_extension_or_orm_imports_code(
            "from typing import Any, cast\n"
            "from litestar.config.app import AppConfig\n"
            "from litestar_auth.authentication.backend import AuthenticationBackend\n"
            "from litestar_auth.authentication.strategy.base import Strategy\n"
            "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
            "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class DummySessionMaker:\n"
            "    def __call__(self) -> object:\n"
            "        return object()\n"
            "class StaticStrategy(Strategy[UserModel, int]):\n"
            "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
            "        return None\n"
            "    async def write_token(self, user: UserModel) -> str:\n"
            "        return 'token'\n"
            "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
            "        return None\n"
            "def user_manager_factory(**kwargs: object) -> object:\n"
            "    return object()\n"
            "backend = AuthenticationBackend(\n"
            "    name='bearer',\n"
            "    transport=BearerTransport(),\n"
            "    strategy=StaticStrategy(),\n"
            ")\n"
            "config = LitestarAuthConfig(\n"
            "    backends=[backend],\n"
            "    user_model=UserModel,\n"
            "    user_manager_factory=cast(Any, user_manager_factory),\n"
            "    session_maker=cast(Any, DummySessionMaker()),\n"
            "    extensions=(),\n"
            "    include_register=False,\n"
            "    include_verify=False,\n"
            "    include_reset_password=False,\n"
            "    include_openapi_security=False,\n"
            ")\n"
            "plugin = LitestarAuth(config)\n"
            "plugin.on_app_init(AppConfig())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_plugin_startup_does_not_load_bundled_extensions_or_optional_features() -> None:
    """Startup with ``extensions=()`` does not import disabled bundled extension implementations."""
    proc = _run_isolated(
        _no_bundled_extension_or_optional_feature_imports_code(
            "from typing import Any, cast\n"
            "from litestar.config.app import AppConfig\n"
            "from litestar_auth.authentication.backend import AuthenticationBackend\n"
            "from litestar_auth.authentication.strategy.base import Strategy\n"
            "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
            "from litestar_auth.plugin import ApiKeyConfig, LitestarAuth, LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class DummySessionMaker:\n"
            "    def __call__(self) -> object:\n"
            "        return object()\n"
            "class StaticStrategy(Strategy[UserModel, int]):\n"
            "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
            "        return None\n"
            "    async def write_token(self, user: UserModel) -> str:\n"
            "        return 'token'\n"
            "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
            "        return None\n"
            "def user_manager_factory(**kwargs: object) -> object:\n"
            "    return object()\n"
            "backend = AuthenticationBackend(\n"
            "    name='bearer',\n"
            "    transport=BearerTransport(),\n"
            "    strategy=StaticStrategy(),\n"
            ")\n"
            "config = LitestarAuthConfig(\n"
            "    backends=[backend],\n"
            "    user_model=UserModel,\n"
            "    user_manager_factory=cast(Any, user_manager_factory),\n"
            "    session_maker=cast(Any, DummySessionMaker()),\n"
            "    api_keys=ApiKeyConfig(enabled=False),\n"
            "    extensions=(),\n"
            "    include_register=False,\n"
            "    include_verify=False,\n"
            "    include_reset_password=False,\n"
            "    include_openapi_security=False,\n"
            ")\n"
            "plugin = LitestarAuth(config)\n"
            "plugin.on_app_init(AppConfig())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_config_does_not_load_role_admin_controller_or_orm_modules() -> None:
    """Constructing config with ``extensions=()`` does not load the role-admin opt-in."""
    proc = _run_isolated(
        _no_role_admin_controller_or_orm_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_other_extension_config_does_not_load_role_admin_controller_or_orm_modules() -> None:
    """Constructing config with unrelated extensions does not load the role-admin opt-in."""
    proc = _run_isolated(
        _no_role_admin_controller_or_orm_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class NoopExtension:\n"
            "    name = 'noop'\n"
            "    @staticmethod\n"
            "    def validate(context: object) -> None:\n"
            "        return None\n"
            "    @staticmethod\n"
            "    def register(context: object) -> None:\n"
            "        return None\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=(NoopExtension(),))",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_config_does_not_load_organization_admin_controller_or_orm_modules() -> None:
    """Constructing config with ``extensions=()`` does not load the organization-admin opt-in."""
    proc = _run_isolated(
        _no_organization_admin_controller_or_orm_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_other_extension_config_does_not_load_organization_admin_controller_or_orm_modules() -> None:
    """Constructing config with unrelated extensions does not load the organization-admin opt-in."""
    proc = _run_isolated(
        _no_organization_admin_controller_or_orm_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class NoopExtension:\n"
            "    name = 'noop'\n"
            "    @staticmethod\n"
            "    def validate(context: object) -> None:\n"
            "        return None\n"
            "    @staticmethod\n"
            "    def register(context: object) -> None:\n"
            "        return None\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=(NoopExtension(),))",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_config_does_not_load_oauth_extension_or_optional_dependencies() -> None:
    """Constructing config with ``extensions=()`` and no OAuth inventory keeps OAuth lazy."""
    proc = _run_isolated(
        _no_oauth_extension_or_optional_dependency_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_other_extension_config_does_not_load_oauth_extension_or_optional_dependencies() -> None:
    """Constructing config with unrelated extensions and no OAuth inventory keeps OAuth lazy."""
    proc = _run_isolated(
        _no_oauth_extension_or_optional_dependency_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class NoopExtension:\n"
            "    name = 'noop'\n"
            "    @staticmethod\n"
            "    def validate(context: object) -> None:\n"
            "        return None\n"
            "    @staticmethod\n"
            "    def register(context: object) -> None:\n"
            "        return None\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=(NoopExtension(),))",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_config_does_not_load_totp_controller_or_optional_dependencies() -> None:
    """Constructing config with ``extensions=()`` and no TOTP config keeps TOTP lazy."""
    proc = _run_isolated(
        _no_totp_controller_or_optional_dependency_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_config_does_not_load_api_key_controller_or_optional_dependencies() -> None:
    """Constructing config with ``extensions=()`` and disabled API keys keeps API-key controllers lazy."""
    proc = _run_isolated(
        _no_api_key_controller_or_optional_dependency_imports_code(
            "from litestar_auth.plugin import ApiKeyConfig, LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "LitestarAuthConfig(user_model=UserModel, api_keys=ApiKeyConfig(enabled=False), extensions=())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_default_api_key_config_does_not_load_api_key_controller_or_optional_dependencies() -> None:
    """Constructing config without API-key options keeps API-key controllers lazy."""
    proc = _run_isolated(
        _no_api_key_controller_or_optional_dependency_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "LitestarAuthConfig(user_model=UserModel)",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_other_extension_config_does_not_load_totp_controller_or_optional_dependencies() -> None:
    """Constructing config with unrelated extensions and no TOTP config keeps TOTP lazy."""
    proc = _run_isolated(
        _no_totp_controller_or_optional_dependency_imports_code(
            "from litestar_auth.plugin import LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class NoopExtension:\n"
            "    name = 'noop'\n"
            "    @staticmethod\n"
            "    def validate(context: object) -> None:\n"
            "        return None\n"
            "    @staticmethod\n"
            "    def register(context: object) -> None:\n"
            "        return None\n"
            "LitestarAuthConfig(user_model=UserModel, extensions=(NoopExtension(),))",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_plugin_startup_does_not_load_totp_controller_or_optional_dependencies() -> None:
    """Initializing the plugin with ``extensions=()`` and no TOTP config keeps TOTP lazy."""
    proc = _run_isolated(
        _no_totp_controller_or_optional_dependency_imports_code(
            "from typing import Any, cast\n"
            "from litestar.config.app import AppConfig\n"
            "from litestar_auth.authentication.backend import AuthenticationBackend\n"
            "from litestar_auth.authentication.strategy.base import Strategy\n"
            "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
            "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class DummySessionMaker:\n"
            "    def __call__(self) -> object:\n"
            "        return object()\n"
            "class StaticStrategy(Strategy[UserModel, int]):\n"
            "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
            "        return None\n"
            "    async def write_token(self, user: UserModel) -> str:\n"
            "        return 'token'\n"
            "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
            "        return None\n"
            "def user_manager_factory(**kwargs: object) -> object:\n"
            "    return object()\n"
            "backend = AuthenticationBackend(\n"
            "    name='bearer',\n"
            "    transport=BearerTransport(),\n"
            "    strategy=StaticStrategy(),\n"
            ")\n"
            "config = LitestarAuthConfig(\n"
            "    backends=[backend],\n"
            "    user_model=UserModel,\n"
            "    user_manager_factory=cast(Any, user_manager_factory),\n"
            "    session_maker=cast(Any, DummySessionMaker()),\n"
            "    extensions=(),\n"
            "    include_register=False,\n"
            "    include_verify=False,\n"
            "    include_reset_password=False,\n"
            "    include_openapi_security=False,\n"
            ")\n"
            "plugin = LitestarAuth(config)\n"
            "plugin.on_app_init(AppConfig())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_empty_extension_plugin_startup_does_not_load_api_key_controller_or_optional_dependencies() -> None:
    """Initializing the plugin with ``extensions=()`` and disabled API keys keeps API-key controllers lazy."""
    proc = _run_isolated(
        _no_api_key_controller_or_optional_dependency_imports_code(
            "from typing import Any, cast\n"
            "from litestar.config.app import AppConfig\n"
            "from litestar_auth.authentication.backend import AuthenticationBackend\n"
            "from litestar_auth.authentication.strategy.base import Strategy\n"
            "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
            "from litestar_auth.plugin import ApiKeyConfig, LitestarAuth, LitestarAuthConfig\n"
            "class UserModel:\n"
            "    email = 'user@example.com'\n"
            "    roles = []\n"
            "class DummySessionMaker:\n"
            "    def __call__(self) -> object:\n"
            "        return object()\n"
            "class StaticStrategy(Strategy[UserModel, int]):\n"
            "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
            "        return None\n"
            "    async def write_token(self, user: UserModel) -> str:\n"
            "        return 'token'\n"
            "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
            "        return None\n"
            "def user_manager_factory(**kwargs: object) -> object:\n"
            "    return object()\n"
            "backend = AuthenticationBackend(\n"
            "    name='bearer',\n"
            "    transport=BearerTransport(),\n"
            "    strategy=StaticStrategy(),\n"
            ")\n"
            "config = LitestarAuthConfig(\n"
            "    backends=[backend],\n"
            "    user_model=UserModel,\n"
            "    user_manager_factory=cast(Any, user_manager_factory),\n"
            "    session_maker=cast(Any, DummySessionMaker()),\n"
            "    api_keys=ApiKeyConfig(enabled=False),\n"
            "    extensions=(),\n"
            "    include_register=False,\n"
            "    include_verify=False,\n"
            "    include_reset_password=False,\n"
            "    include_openapi_security=False,\n"
            ")\n"
            "plugin = LitestarAuth(config)\n"
            "plugin.on_app_init(AppConfig())",
        ),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_role_admin_extension_registration_loads_controller_modules_only_at_registration() -> None:
    """The extension symbol and instance stay lazy until registration asks for the controller."""
    proc = _run_isolated(
        "import sys\n"
        "from litestar_auth.contrib.role_admin import RoleAdminExtension\n"
        "extension = RoleAdminExtension()\n"
        "blocked_before_register = {\n"
        "    'litestar_auth.contrib.role_admin._controller',\n"
        "    'litestar_auth.contrib.role_admin._controller_handler_utils',\n"
        "    'litestar_auth.contrib.role_admin._controller_handlers',\n"
        "    'litestar_auth.contrib.role_admin._error_responses',\n"
        "    'litestar_auth.contrib.role_admin._schemas',\n"
        "    'litestar_auth.contrib.role_admin._session_wiring',\n"
        "    'litestar_auth._plugin.role_admin',\n"
        "    'litestar_auth._plugin.role_model_family',\n"
        "    'litestar_auth.models',\n"
        "    'litestar_auth.db.sqlalchemy',\n"
        "}.intersection(sys.modules)\n"
        "assert not blocked_before_register, sorted(blocked_before_register)\n"
        "from litestar_auth.models import User\n"
        "from litestar_auth.plugin import LitestarAuthConfig\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "config = LitestarAuthConfig(user_model=User, session_maker=DummySessionMaker())\n"
        "class RegistrationContext:\n"
        "    def __init__(self) -> None:\n"
        "        self.config = config\n"
        "        self.controllers = []\n"
        "    def mark_auth_route_handler(self, controller: object) -> object:\n"
        "        return controller\n"
        "    def add_controller(self, controller: object) -> None:\n"
        "        self.controllers.append(controller)\n"
        "context = RegistrationContext()\n"
        "extension.register(context)\n"
        "assert context.controllers\n"
        "assert 'litestar_auth.contrib.role_admin._controller' in sys.modules\n"
        "assert 'litestar_auth.contrib.role_admin._controller_handlers' in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_organization_admin_extension_registration_loads_controller_modules_only_at_registration() -> None:
    """The extension symbol and instance stay lazy until registration asks for the controller."""
    proc = _run_isolated(
        "import sys\n"
        "from uuid import UUID\n"
        "from litestar_auth.contrib.organization_admin import OrganizationAdminExtension\n"
        "extension = OrganizationAdminExtension()\n"
        "blocked_before_register = {\n"
        "    'litestar_auth.contrib.organization_admin._controller',\n"
        "    'litestar_auth.contrib.organization_admin._error_responses',\n"
        "    'litestar_auth.contrib.organization_admin._schemas',\n"
        "    'litestar_auth._plugin.organization_admin',\n"
        "    'litestar_auth.models',\n"
        "    'litestar_auth.db.sqlalchemy',\n"
        "}.intersection(sys.modules)\n"
        "assert not blocked_before_register, sorted(blocked_before_register)\n"
        "from litestar_auth.models import User\n"
        "from litestar_auth.plugin import LitestarAuthConfig, OrganizationConfig\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "config = LitestarAuthConfig(\n"
        "    user_model=User,\n"
        "    session_maker=DummySessionMaker(),\n"
        "    id_parser=UUID,\n"
        "    organization_config=OrganizationConfig(enabled=True, store_factory=lambda _session: object()),\n"
        ")\n"
        "class RegistrationContext:\n"
        "    def __init__(self) -> None:\n"
        "        self.config = config\n"
        "        self.security_requirements = []\n"
        "        self.controllers = []\n"
        "    def mark_auth_route_handler(self, controller: object) -> object:\n"
        "        return controller\n"
        "    def add_controller(self, controller: object) -> None:\n"
        "        self.controllers.append(controller)\n"
        "context = RegistrationContext()\n"
        "extension.register(context)\n"
        "assert context.controllers\n"
        "assert 'litestar_auth.contrib.organization_admin._controller' in sys.modules\n"
        "assert 'litestar_auth.contrib.organization_admin._error_responses' in sys.modules\n"
        "assert 'litestar_auth.contrib.organization_admin._schemas' in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_api_key_extension_registration_loads_controller_modules_only_when_enabled() -> None:
    """Enabled API-key management loads controller internals only when its extension registers."""
    proc = _run_isolated(
        "import sys\n"
        "from litestar_auth.plugin import ApiKeyConfig, LitestarAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "    roles = []\n"
        "config = LitestarAuthConfig(\n"
        "    user_model=UserModel,\n"
        "    api_keys=ApiKeyConfig(enabled=True, allowed_scopes=('read',), signing_enabled=True),\n"
        ")\n"
        "api_key_controller_modules = {\n"
        "    'litestar_auth.controllers.api_keys',\n"
        "    'litestar_auth.controllers._api_key_admin',\n"
        "    'litestar_auth.controllers._api_key_common',\n"
        "    'litestar_auth.controllers._api_key_self',\n"
        "}\n"
        "assert not api_key_controller_modules.intersection(sys.modules)\n"
        "assert 'cryptography.fernet' not in sys.modules\n"
        "extensions = config.resolve_extensions()\n"
        "assert [extension.name for extension in extensions] == ['api_keys']\n"
        "assert 'litestar_auth._plugin.api_key_controller._extension' in sys.modules\n"
        "assert not api_key_controller_modules.intersection(sys.modules)\n"
        "assert 'cryptography.fernet' not in sys.modules\n"
        "class RegistrationContext:\n"
        "    def __init__(self) -> None:\n"
        "        self.config = config\n"
        "        self.security_requirements = []\n"
        "        self.controllers = []\n"
        "    def add_controller(self, controller: object) -> None:\n"
        "        self.controllers.append(controller)\n"
        "context = RegistrationContext()\n"
        "extensions[0].register(context)\n"
        "assert context.controllers\n"
        "assert 'litestar_auth.controllers.api_keys' in sys.modules\n"
        "assert 'litestar_auth.controllers._api_key_admin' in sys.modules\n"
        "assert 'litestar_auth.controllers._api_key_common' in sys.modules\n"
        "assert 'litestar_auth.controllers._api_key_self' in sys.modules\n"
        "assert 'cryptography.fernet' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_totp_extension_registration_loads_controller_modules_only_when_configured() -> None:
    """Configured TOTP routes load controller internals during extension registration."""
    proc = _run_isolated(
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar.config.app import AppConfig\n"
        "from litestar_auth.authentication.backend import AuthenticationBackend\n"
        "from litestar_auth.authentication.strategy.base import Strategy\n"
        "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
        "from litestar_auth.manager import UserManagerSecurity\n"
        "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig, TotpConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "    roles = []\n"
        "    totp_secret = None\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "class StaticStrategy(Strategy[UserModel, int]):\n"
        "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
        "        return None\n"
        "    async def write_token(self, user: UserModel) -> str:\n"
        "        return 'token'\n"
        "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
        "        return None\n"
        "def user_manager_factory(**kwargs: object) -> object:\n"
        "    return object()\n"
        "backend = AuthenticationBackend(\n"
        "    name='bearer',\n"
        "    transport=BearerTransport(),\n"
        "    strategy=StaticStrategy(),\n"
        ")\n"
        "config = LitestarAuthConfig(\n"
        "    backends=[backend],\n"
        "    user_model=UserModel,\n"
        "    user_manager_factory=cast(Any, user_manager_factory),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    user_manager_security=UserManagerSecurity(\n"
        "        totp_recovery_code_lookup_secret='recovery-code-secret-0123456789abcdef',\n"
        "    ),\n"
        "    include_register=False,\n"
        "    include_verify=False,\n"
        "    include_reset_password=False,\n"
        "    include_openapi_security=False,\n"
        "    unsafe_testing=True,\n"
        "    totp_config=TotpConfig(\n"
        "        totp_pending_secret='0123456789abcdef' * 4,\n"
        "        totp_enable_requires_password=False,\n"
        "    ),\n"
        ")\n"
        "assert not {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'litestar_auth._plugin.totp_controller'\n"
        "    or name.startswith('litestar_auth._plugin.totp_controller.')\n"
        "    or name == 'litestar_auth.controllers.totp'\n"
        "    or name.startswith('litestar_auth.controllers.totp_')\n"
        "    or name == 'litestar_auth._totp_stores'\n"
        "}\n"
        "extensions = config.resolve_extensions()\n"
        "assert [extension.name for extension in extensions] == ['totp']\n"
        "assert 'litestar_auth._plugin.totp_controller._extension' in sys.modules\n"
        "assert 'litestar_auth._plugin.totp_controller._core' not in sys.modules\n"
        "assert 'litestar_auth.controllers.totp' not in sys.modules\n"
        "plugin = LitestarAuth(config)\n"
        "plugin.on_app_init(AppConfig())\n"
        "assert 'litestar_auth._plugin.totp_controller._core' in sys.modules\n"
        "assert 'litestar_auth._plugin.totp_controller._settings' in sys.modules\n"
        "assert 'litestar_auth._plugin.totp_controller._factory' in sys.modules\n"
        "assert 'litestar_auth.controllers.totp' in sys.modules\n"
        "assert 'litestar_auth._totp_stores' in sys.modules\n"
        "assert 'cryptography.fernet' not in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_totp_extension_registration_loads_cryptography_only_for_encrypted_enrollment() -> None:
    """TOTP controller registration imports cryptography when enrollment encryption is configured."""
    proc = _run_isolated(
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar.config.app import AppConfig\n"
        "from litestar_auth.authentication.backend import AuthenticationBackend\n"
        "from litestar_auth.authentication.strategy.base import Strategy\n"
        "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
        "from litestar_auth.manager import UserManagerSecurity\n"
        "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig, TotpConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "    roles = []\n"
        "    totp_secret = None\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "class StaticStrategy(Strategy[UserModel, int]):\n"
        "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
        "        return None\n"
        "    async def write_token(self, user: UserModel) -> str:\n"
        "        return 'token'\n"
        "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
        "        return None\n"
        "def user_manager_factory(**kwargs: object) -> object:\n"
        "    return object()\n"
        "backend = AuthenticationBackend(\n"
        "    name='bearer',\n"
        "    transport=BearerTransport(),\n"
        "    strategy=StaticStrategy(),\n"
        ")\n"
        "config = LitestarAuthConfig(\n"
        "    backends=[backend],\n"
        "    user_model=UserModel,\n"
        "    user_manager_factory=cast(Any, user_manager_factory),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    user_manager_security=UserManagerSecurity(\n"
        "        totp_secret_key='MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=',\n"
        "        totp_recovery_code_lookup_secret='recovery-code-secret-0123456789abcdef',\n"
        "    ),\n"
        "    include_register=False,\n"
        "    include_verify=False,\n"
        "    include_reset_password=False,\n"
        "    include_openapi_security=False,\n"
        "    unsafe_testing=True,\n"
        "    totp_config=TotpConfig(\n"
        "        totp_pending_secret='0123456789abcdef' * 4,\n"
        "        totp_enable_requires_password=False,\n"
        "    ),\n"
        ")\n"
        "assert 'cryptography.fernet' not in sys.modules\n"
        "plugin = LitestarAuth(config)\n"
        "plugin.on_app_init(AppConfig())\n"
        "assert 'litestar_auth.controllers.totp' in sys.modules\n"
        "assert 'cryptography.fernet' in sys.modules\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_oauth_extension_registration_loads_oauth_modules_only_when_configured() -> None:
    """Configured plugin-owned OAuth routes load OAuth internals during extension startup."""
    proc = _run_isolated(
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar.config.app import AppConfig\n"
        "from litestar_auth.authentication.backend import AuthenticationBackend\n"
        "from litestar_auth.authentication.strategy.base import Strategy\n"
        "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
        "from litestar_auth.config import OAuthProviderConfig\n"
        "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig, OAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "    roles = []\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "class StaticStrategy(Strategy[UserModel, int]):\n"
        "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
        "        return None\n"
        "    async def write_token(self, user: UserModel) -> str:\n"
        "        return 'token'\n"
        "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
        "        return None\n"
        "class FakeOAuthClient:\n"
        "    async def get_authorization_url(\n"
        "        self,\n"
        "        redirect_uri: str,\n"
        "        state: str,\n"
        "        *,\n"
        "        scope: str | list[str] | None = None,\n"
        "        code_challenge: str | None = None,\n"
        "        code_challenge_method: str | None = None,\n"
        "    ) -> str:\n"
        "        return 'https://provider.example/authorize'\n"
        "    async def get_access_token(\n"
        "        self,\n"
        "        code: str,\n"
        "        redirect_uri: str,\n"
        "        *,\n"
        "        code_verifier: str | None = None,\n"
        "    ) -> dict[str, object]:\n"
        "        return {'access_token': 'access-token'}\n"
        "    async def get_id_email(self, access_token: str) -> tuple[str, str]:\n"
        "        return 'provider-user', 'user@example.com'\n"
        "def user_manager_factory(**kwargs: object) -> object:\n"
        "    return object()\n"
        "backend = AuthenticationBackend(\n"
        "    name='bearer',\n"
        "    transport=BearerTransport(),\n"
        "    strategy=StaticStrategy(),\n"
        ")\n"
        "config = LitestarAuthConfig(\n"
        "    backends=[backend],\n"
        "    user_model=UserModel,\n"
        "    user_manager_factory=cast(Any, user_manager_factory),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    include_register=False,\n"
        "    include_verify=False,\n"
        "    include_reset_password=False,\n"
        "    include_openapi_security=False,\n"
        "    unsafe_testing=True,\n"
        "    oauth_config=OAuthConfig(\n"
        "        oauth_providers=(OAuthProviderConfig(name='github', client=FakeOAuthClient()),),\n"
        "        oauth_redirect_base_url='https://app.example/auth',\n"
        "        oauth_flow_cookie_secret='oauth-flow-cookie-secret-1234567890',\n"
        "    ),\n"
        ")\n"
        "assert not {\n"
        "    name for name in sys.modules if name == 'litestar_auth.oauth' or name.startswith('litestar_auth.oauth.')\n"
        "}\n"
        "plugin = LitestarAuth(config)\n"
        "plugin.on_app_init(AppConfig())\n"
        "assert 'litestar_auth.oauth._extension' in sys.modules\n"
        "assert 'litestar_auth.oauth._client.adapter' in sys.modules\n"
        "assert 'litestar_auth.oauth._flow_cookie' in sys.modules\n"
        "assert 'cryptography.fernet' in sys.modules\n"
        "assert not {name for name in sys.modules if name == 'httpx_oauth' or name.startswith('httpx_oauth.')}\n",
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
