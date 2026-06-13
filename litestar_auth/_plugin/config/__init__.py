"""Configuration contracts for the plugin facade."""

# ruff: noqa: RUF067

from __future__ import annotations

import sys

from litestar_auth._plugin.config import _core as _core
from litestar_auth._plugin.config._core import (
    _VALID_LOGIN_IDENTIFIERS as _VALID_LOGIN_IDENTIFIERS,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_API_KEY_BACKEND_NAME as DEFAULT_API_KEY_BACKEND_NAME,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS as DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_API_KEY_MAX_KEYS_PER_USER as DEFAULT_API_KEY_MAX_KEYS_PER_USER,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES as DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_API_KEY_TTL as DEFAULT_API_KEY_TTL,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY as DEFAULT_BACKENDS_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_CONFIG_DEPENDENCY_KEY as DEFAULT_CONFIG_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_CSRF_COOKIE_NAME as DEFAULT_CSRF_COOKIE_NAME,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY as DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_DATABASE_TOKEN_BACKEND_NAME as DEFAULT_DATABASE_TOKEN_BACKEND_NAME,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_DATABASE_TOKEN_BYTES as DEFAULT_DATABASE_TOKEN_BYTES,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_DATABASE_TOKEN_MAX_AGE as DEFAULT_DATABASE_TOKEN_MAX_AGE,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE as DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_DB_SESSION_DEPENDENCY_KEY as DEFAULT_DB_SESSION_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_LOGIN_MINIMUM_RESPONSE_SECONDS as DEFAULT_LOGIN_MINIMUM_RESPONSE_SECONDS,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY as DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS as DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_REQUEST_VERIFY_MINIMUM_RESPONSE_SECONDS as DEFAULT_REQUEST_VERIFY_MINIMUM_RESPONSE_SECONDS,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY as DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_TOTP_STEPUP_TTL_SECONDS as DEFAULT_TOTP_STEPUP_TTL_SECONDS,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY as DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_USER_MODEL_DEPENDENCY_KEY as DEFAULT_USER_MODEL_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    DEFAULT_VERIFY_MINIMUM_RESPONSE_SECONDS as DEFAULT_VERIFY_MINIMUM_RESPONSE_SECONDS,
)
from litestar_auth._plugin.config._core import (
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY as OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config._core import (
    AccountLockoutConfig as AccountLockoutConfig,
)
from litestar_auth._plugin.config._core import (
    ApiKeyConfig as ApiKeyConfig,
)
from litestar_auth._plugin.config._core import (
    ConfigurationError as ConfigurationError,
)
from litestar_auth._plugin.config._core import (
    ControllerHook as ControllerHook,
)
from litestar_auth._plugin.config._core import (
    DatabaseTokenAuthConfig as DatabaseTokenAuthConfig,
)
from litestar_auth._plugin.config._core import (
    DbSessionDependencyKey as DbSessionDependencyKey,
)
from litestar_auth._plugin.config._core import (
    ExceptionResponseHook as ExceptionResponseHook,
)
from litestar_auth._plugin.config._core import (
    FeatureRegistry as FeatureRegistry,
)
from litestar_auth._plugin.config._core import (
    LitestarAuthConfig as LitestarAuthConfig,
)
from litestar_auth._plugin.config._core import (
    MiddlewareHook as MiddlewareHook,
)
from litestar_auth._plugin.config._core import (
    OAuthConfig as OAuthConfig,
)
from litestar_auth._plugin.config._core import (
    OrganizationConfig as OrganizationConfig,
)
from litestar_auth._plugin.config._core import (
    PasswordValidatorFactory as PasswordValidatorFactory,
)
from litestar_auth._plugin.config._core import (
    ResolvedAuthConfigDefaults as ResolvedAuthConfigDefaults,
)
from litestar_auth._plugin.config._core import (
    ResolvedFeatureDefaults as ResolvedFeatureDefaults,
)
from litestar_auth._plugin.config._core import (
    StartupBackendInventory as StartupBackendInventory,
)
from litestar_auth._plugin.config._core import (
    StartupBackendTemplate as StartupBackendTemplate,
)
from litestar_auth._plugin.config._core import (
    TotpConfig as TotpConfig,
)
from litestar_auth._plugin.config._core import (
    TotpStepUpPolicyMode as TotpStepUpPolicyMode,
)
from litestar_auth._plugin.config._core import (
    UserDatabaseFactory as UserDatabaseFactory,
)
from litestar_auth._plugin.config._core import (
    UserManagerFactory as UserManagerFactory,
)
from litestar_auth._plugin.config._core import (
    _build_default_user_db as _build_default_user_db,
)
from litestar_auth._plugin.config._core import (
    _normalize_config_superuser_role_name as _normalize_config_superuser_role_name,
)
from litestar_auth._plugin.config._core import (
    _resolve_plugin_managed_totp_secret_storage_policy as _resolve_plugin_managed_totp_secret_storage_policy,
)
from litestar_auth._plugin.config._core import (
    require_session_maker as require_session_maker,
)
from litestar_auth._plugin.config._core import (
    resolve_backend_inventory as resolve_backend_inventory,
)

globals().update(
    {name: value for name, value in vars(_core).items() if not (name.startswith("__") and name.endswith("__"))},
)
sys.modules[__name__] = _core
