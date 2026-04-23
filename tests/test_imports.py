"""Integration coverage for the root package public API."""

from __future__ import annotations

import importlib
import inspect
import logging
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)
from uuid import UUID

import pytest

import litestar_auth
import litestar_auth._plugin as plugin_internals
import litestar_auth.authentication.strategy as strategy_module
import litestar_auth.config as config_module
import litestar_auth.contrib.redis as redis_contrib_module
import litestar_auth.controllers as controllers_package
import litestar_auth.controllers.auth as auth_controller_module
import litestar_auth.controllers.reset as reset_controller_module
import litestar_auth.controllers.totp as totp_controller_module
import litestar_auth.controllers.verify as verify_controller_module
import litestar_auth.db as db_module
import litestar_auth.models as models_module
import litestar_auth.oauth as oauth_package_module
import litestar_auth.payloads as payloads_module
import litestar_auth.plugin as plugin_module
import litestar_auth.ratelimit as ratelimit_module
import litestar_auth.schemas as schemas_module
import litestar_auth.totp as totp_module
from litestar_auth import (
    AuthenticationBackend,
    Authenticator,
    BaseUserManager,
    BearerTransport,
    CookieTransport,
    DatabaseTokenAuthConfig,
    ErrorCode,
    GuardedUserProtocol,
    LitestarAuth,
    LitestarAuthConfig,
    LitestarAuthError,
    OAuthConfig,
    OAuthProviderConfig,
    RoleCapableUserProtocol,
    TotpConfig,
    TotpUserProtocol,
    UserManagerSecurity,
    UserProtocol,
    UserProtocolStrict,
    __all__,
    __version__,
    has_all_roles,
    has_any_role,
    is_active,
    is_authenticated,
    is_superuser,
    is_verified,
)
from litestar_auth.authentication.strategy import DatabaseTokenStrategy, JWTStrategy, RedisTokenStrategy, Strategy
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore, JWTDenylistStore, RedisJWTDenylistStore
from litestar_auth.authentication.transport import Transport
from litestar_auth.config import require_password_length
from litestar_auth.contrib.redis import (
    RedisAuthClientProtocol,
    RedisAuthPreset,
    RedisAuthRateLimitTier,
)
from litestar_auth.contrib.redis import (
    RedisTotpEnrollmentStore as ContribRedisTotpEnrollmentStore,
)
from litestar_auth.controllers import (
    TotpUserManagerProtocol,
    create_auth_controller,
    create_oauth_associate_controller,
    create_oauth_controller,
    create_register_controller,
    create_reset_password_controller,
    create_totp_controller,
    create_users_controller,
    create_verify_controller,
)
from litestar_auth.db import BaseOAuthAccountStore, BaseUserStore
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    OAuthAccountAlreadyLinkedError,
    TokenError,
    UserAlreadyExistsError,
    UserNotExistsError,
)
from litestar_auth.oauth import create_provider_oauth_controller, load_httpx_oauth_client
from litestar_auth.oauth.client_adapter import (
    OAuthEmailVerificationAsyncClientProtocol,
    OAuthEmailVerificationSyncClientProtocol,
    make_async_email_verification_client,
)
from litestar_auth.password import PasswordHelper
from litestar_auth.payloads import (
    ForgotPassword,
    LoginCredentials,
    RefreshTokenRequest,
    RequestVerifyToken,
    ResetPassword,
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableResponse,
    TotpVerifyRequest,
    VerifyToken,
)
from litestar_auth.ratelimit import (
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS,
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP,
    AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    AuthRateLimitConfig,
    AuthRateLimitEndpointGroup,
    AuthRateLimitEndpointSlot,
    AuthRateLimitSlot,
    EndpointRateLimit,
    InMemoryRateLimiter,
    RedisRateLimiter,
)
from litestar_auth.schemas import UserCreate, UserRead, UserUpdate
from litestar_auth.totp import (
    InMemoryTotpEnrollmentStore,
    InMemoryUsedTotpCodeStore,
    RedisTotpEnrollmentStore,
    RedisUsedTotpCodeStore,
    generate_totp_secret,
    generate_totp_uri,
    verify_totp,
    verify_totp_with_store,
)
from litestar_auth.types import DbSessionDependencyKey
from tests._helpers import ExampleUser, cast_fakeredis
from tests.conftest import project_version_from_pyproject

if TYPE_CHECKING:
    import msgspec
    from sqlalchemy.ext.asyncio import AsyncSession

    from tests._helpers import AsyncFakeRedis, AsyncFakeRedisFactory

SHARED_MAX_ATTEMPTS = 5
SHARED_WINDOW_SECONDS = 60
REFRESH_MAX_ATTEMPTS = 10
REFRESH_WINDOW_SECONDS = 300
TOTP_MAX_ATTEMPTS = 5
TOTP_WINDOW_SECONDS = 300
ONE_MINUTE_TTL_SECONDS = 60
ONE_MINUTE_TTL_FLOOR = ONE_MINUTE_TTL_SECONDS - 1
ONE_MINUTE_TTL_MS = ONE_MINUTE_TTL_SECONDS * 1000
REMOVED_ROOT_PAYLOAD_EXPORTS = (
    "ForgotPassword",
    "LoginCredentials",
    "RefreshTokenRequest",
    "RequestVerifyToken",
    "ResetPassword",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableResponse",
    "TotpVerifyRequest",
    "UserCreate",
    "UserRead",
    "UserUpdate",
    "VerifyToken",
)
REMOVED_CONTROLLERS_PAYLOAD_EXPORTS = (
    "ForgotPassword",
    "LoginCredentials",
    "RefreshTokenRequest",
    "RequestVerifyToken",
    "ResetPassword",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableResponse",
    "TotpVerifyRequest",
    "VerifyToken",
)
REMOVED_PAYLOAD_SCHEMA_EXPORTS = ("UserCreate", "UserRead", "UserUpdate")
REMOVED_ROOT_SECONDARY_EXPORTS = (
    "AccessToken",
    "AuthRateLimitConfig",
    "AuthenticationError",
    "AuthorizationError",
    "ConfigurationError",
    "DatabaseTokenStrategy",
    "DbSessionDependencyKey",
    "EndpointRateLimit",
    "InMemoryJWTDenylistStore",
    "InMemoryRateLimiter",
    "InMemoryTotpEnrollmentStore",
    "InMemoryUsedTotpCodeStore",
    "InvalidPasswordError",
    "InvalidResetPasswordTokenError",
    "InvalidVerifyTokenError",
    "JWTDenylistStore",
    "JWTStrategy",
    "OAuthAccountAlreadyLinkedError",
    "PasswordHelper",
    "RedisJWTDenylistStore",
    "RedisRateLimiter",
    "RedisTokenStrategy",
    "RedisTotpEnrollmentStore",
    "RedisUsedTotpCodeStore",
    "RefreshToken",
    "Strategy",
    "TokenError",
    "TotpEnrollmentStore",
    "TotpUserManagerProtocol",
    "Transport",
    "UsedTotpCodeStore",
    "UserAlreadyExistsError",
    "UserNotExistsError",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_provider_oauth_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
    "generate_totp_secret",
    "generate_totp_uri",
    "load_httpx_oauth_client",
    "require_password_length",
    "verify_totp",
    "verify_totp_with_store",
)

pytestmark = [pytest.mark.unit, pytest.mark.imports]
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
EMAIL_MAX_LENGTH = 320


def _field_meta(schema_type: type[msgspec.Struct], field_name: str) -> msgspec.Meta:
    """Return the ``msgspec.Meta`` attached to a struct field annotation.

    Raises:
        AssertionError: If the field annotation does not expose ``msgspec.Meta``.
    """
    annotation = get_type_hints(schema_type, include_extras=True)[field_name]

    for candidate in (annotation, *get_args(annotation)):
        value = getattr(candidate, "__value__", candidate)
        if get_origin(value) is not Annotated:
            continue

        _, meta = get_args(value)
        return meta

    msg = f"{schema_type.__name__}.{field_name} is missing msgspec metadata."
    raise AssertionError(msg)


class _RootImportCoverageUserManager(BaseUserManager[ExampleUser, UUID]):
    """Minimal manager type for public import coverage."""


class _RootImportCoverageSession:
    """Minimal request-scoped session stub for preset import coverage."""

    async def commit(self) -> None:
        """No-op commit for request lifecycle parity."""

    async def rollback(self) -> None:
        """No-op rollback for request lifecycle parity."""

    async def close(self) -> None:
        """No-op close for request lifecycle parity."""


class _RootImportCoverageSessionFactory:
    """Callable session factory matching the documented plugin contract."""

    def __call__(self) -> AsyncSession:
        """Return a request-scoped session stub."""
        return cast("AsyncSession", _RootImportCoverageSession())


def _current_database_token_strategy_type() -> type[Any]:
    """Return the current DB-token strategy class after cross-test module reloads."""
    db_strategy_module = importlib.import_module("litestar_auth.authentication.strategy.db")
    return cast("type[Any]", db_strategy_module.DatabaseTokenStrategy)


def test_root_package_reexports_public_api() -> None:
    """The package root exposes the documented public auth API."""
    assert __version__ == project_version_from_pyproject()
    assert LitestarAuth is not None
    assert LitestarAuthConfig is not None
    assert AuthenticationBackend is not None
    assert Authenticator is not None
    assert UserProtocol is not None
    assert UserProtocolStrict is not None
    assert GuardedUserProtocol is not None
    assert RoleCapableUserProtocol is not None
    assert TotpUserProtocol is not None
    assert BearerTransport is not None
    assert CookieTransport is not None
    assert DatabaseTokenAuthConfig is not None
    assert OAuthConfig is not None
    assert OAuthProviderConfig is not None
    assert TotpConfig is not None
    assert BaseUserManager is not None
    assert UserManagerSecurity is not None
    assert callable(is_authenticated)
    assert callable(is_active)
    assert callable(is_verified)
    assert callable(is_superuser)
    assert callable(has_any_role)
    assert callable(has_all_roles)
    assert ErrorCode is not None
    assert LitestarAuthError is not None


def test_root_package_reexports_role_guard_factories() -> None:
    """The package root exposes the documented role guard factories."""
    assert callable(has_any_role)
    assert callable(has_all_roles)


def test_root_package_exports_canonical_database_token_preset_entrypoint() -> None:
    """The root package exposes the documented DB bearer preset entrypoint."""
    session_maker = _RootImportCoverageSessionFactory()
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(token_hash_secret="x" * 40),
        user_model=ExampleUser,
        user_manager_class=_RootImportCoverageUserManager,
        session_maker=session_maker,
        user_db_factory=lambda _session: cast("Any", object()),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )

    preset = config.database_token_auth
    assert preset is not None
    assert preset.token_hash_secret == "x" * 40
    assert config.session_maker is session_maker

    backend = config.resolve_startup_backends()[0]
    current_plugin_module = importlib.import_module("litestar_auth.plugin")
    database_token_strategy_type = _current_database_token_strategy_type()
    assert isinstance(backend, current_plugin_module.StartupBackendTemplate)
    assert backend.name == "database"
    assert isinstance(backend.transport, BearerTransport)
    assert isinstance(backend.strategy, database_token_strategy_type)


def test_public_user_schema_reuse_surface_stays_importable() -> None:
    """Custom-schema email/password helpers stay on the dedicated public schemas module."""
    user_create_email_meta = _field_meta(UserCreate, "email")
    user_update_email_meta = _field_meta(UserUpdate, "email")
    user_create_meta = _field_meta(UserCreate, "password")
    user_update_meta = _field_meta(UserUpdate, "password")
    user_read_roles_annotation = get_type_hints(UserRead, include_extras=True)["roles"]
    user_update_roles_annotation = get_type_hints(UserUpdate, include_extras=True)["roles"]
    user_create_email_annotation = get_type_hints(UserCreate, include_extras=True)["email"]
    user_update_email_annotation = get_type_hints(UserUpdate, include_extras=True)["email"]
    user_create_annotation = get_type_hints(UserCreate, include_extras=True)["password"]
    user_update_annotation = get_type_hints(UserUpdate, include_extras=True)["password"]
    email_field_value = getattr(schemas_module.UserEmailField, "__value__", schemas_module.UserEmailField)
    password_field_value = getattr(schemas_module.UserPasswordField, "__value__", schemas_module.UserPasswordField)

    assert schemas_module.__all__ == ("UserCreate", "UserEmailField", "UserPasswordField", "UserRead", "UserUpdate")
    assert schemas_module.UserEmailField is not None
    assert schemas_module.UserEmailField.__module__ == "litestar_auth.schemas"
    assert schemas_module.UserPasswordField is not None
    assert schemas_module.UserPasswordField.__module__ == "litestar_auth.schemas"
    assert not hasattr(litestar_auth, "UserEmailField")
    assert not hasattr(litestar_auth, "UserPasswordField")
    assert getattr(user_create_email_annotation, "__value__", user_create_email_annotation) == email_field_value
    assert (
        getattr(get_args(user_update_email_annotation)[0], "__value__", get_args(user_update_email_annotation)[0])
        == email_field_value
    )
    assert get_args(user_update_email_annotation)[1] is type(None)
    assert getattr(user_create_annotation, "__value__", user_create_annotation) == password_field_value
    assert (
        getattr(get_args(user_update_annotation)[0], "__value__", get_args(user_update_annotation)[0])
        == password_field_value
    )
    assert get_args(user_update_annotation)[1] is type(None)
    assert user_read_roles_annotation == list[str]
    assert get_args(user_update_roles_annotation)[0] == list[str]
    assert get_args(user_update_roles_annotation)[1] is type(None)
    assert user_create_email_meta.max_length == EMAIL_MAX_LENGTH
    assert user_update_email_meta.max_length == EMAIL_MAX_LENGTH
    assert user_create_email_meta.pattern == EMAIL_PATTERN
    assert user_update_email_meta.pattern == EMAIL_PATTERN
    assert user_create_meta.min_length == config_module.DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert user_update_meta.min_length == config_module.DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert user_create_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert user_update_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert require_password_length is config_module.require_password_length


def test_models_and_strategy_modules_expose_documented_orm_setup_surface() -> None:
    """The ORM docs point to a models-owned setup flow plus explicit strategy compatibility APIs."""
    access_token_model, refresh_token_model = models_module.import_token_orm_models()
    token_models = strategy_module.DatabaseTokenModels(
        access_token_model=access_token_model,
        refresh_token_model=refresh_token_model,
    )

    assert models_module.__all__ == (
        "AccessTokenMixin",
        "OAuthAccount",
        "OAuthAccountMixin",
        "RefreshTokenMixin",
        "Role",
        "RoleMixin",
        "User",
        "UserAuthRelationshipMixin",
        "UserModelMixin",
        "UserRole",
        "UserRoleAssociationMixin",
        "UserRoleRelationshipMixin",
        "import_token_orm_models",
    )
    assert strategy_module.__all__ == (
        "DatabaseTokenModels",
        "DatabaseTokenStrategy",
        "JWTStrategy",
        "RedisTokenStrategy",
        "RefreshableStrategy",
        "Strategy",
        "UserManagerProtocol",
        "import_token_orm_models",
    )
    assert models_module.AccessTokenMixin.__name__ == "AccessTokenMixin"
    assert models_module.OAuthAccountMixin.__name__ == "OAuthAccountMixin"
    assert models_module.RefreshTokenMixin.__name__ == "RefreshTokenMixin"
    assert models_module.Role.__name__ == "Role"
    assert models_module.RoleMixin.__name__ == "RoleMixin"
    assert models_module.UserAuthRelationshipMixin.__name__ == "UserAuthRelationshipMixin"
    assert models_module.UserModelMixin.__name__ == "UserModelMixin"
    assert models_module.UserRole.__name__ == "UserRole"
    assert models_module.UserRoleAssociationMixin.__name__ == "UserRoleAssociationMixin"
    assert models_module.UserRoleRelationshipMixin.__name__ == "UserRoleRelationshipMixin"
    assert models_module.import_token_orm_models.__module__ == "litestar_auth.models.tokens"
    assert strategy_module.import_token_orm_models.__module__ == "litestar_auth.authentication.strategy.db_models"
    assert strategy_module.import_token_orm_models() == (access_token_model, refresh_token_model)
    assert token_models == strategy_module.DatabaseTokenModels()


def test_root_package_does_not_promote_token_orm_bootstrap_helper() -> None:
    """The canonical token bootstrap helper stays on ``litestar_auth.models`` rather than the root package."""
    assert "import_token_orm_models" not in __all__
    assert not hasattr(litestar_auth, "import_token_orm_models")
    assert "import_token_orm_models" in models_module.__all__
    assert "import_token_orm_models" in strategy_module.__all__


def test_root_and_db_packages_keep_orm_symbols_on_documented_modules() -> None:
    """The package root and ``litestar_auth.db`` keep ORM wiring on the documented modules."""
    assert "Role" not in __all__
    assert "User" not in __all__
    assert "OAuthAccount" not in __all__
    assert "SQLAlchemyUserDatabase" not in __all__
    assert not hasattr(litestar_auth, "Role")
    assert not hasattr(litestar_auth, "User")
    assert not hasattr(litestar_auth, "OAuthAccount")
    assert not hasattr(litestar_auth, "SQLAlchemyUserDatabase")
    assert db_module.__all__ == ("BaseOAuthAccountStore", "BaseUserStore")
    assert db_module.BaseOAuthAccountStore is BaseOAuthAccountStore
    assert db_module.BaseUserStore is BaseUserStore
    assert not hasattr(db_module, "SQLAlchemyUserDatabase")


def test_sqlalchemy_user_database_keeps_documented_keyword_contract() -> None:
    """The SQLAlchemy adapter keeps ``user_model`` and ``oauth_account_model`` as keyword-only inputs."""
    init_signature = inspect.signature(SQLAlchemyUserDatabase.__init__)

    assert init_signature.parameters["session"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert init_signature.parameters["user_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert init_signature.parameters["oauth_account_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert init_signature.parameters["oauth_account_model"].default is None


def test_controller_factories_and_payloads_stay_canonical() -> None:
    """Controller factories and payload structs resolve from their canonical modules."""
    assert LoginCredentials.__struct_fields__ == ("identifier", "password")
    assert RefreshTokenRequest.__struct_fields__ == ("refresh_token",)
    assert ForgotPassword.__struct_fields__ == ("email",)
    assert ResetPassword.__struct_fields__ == ("token", "password")
    assert VerifyToken.__struct_fields__ == ("token",)
    assert RequestVerifyToken.__struct_fields__ == ("email",)
    assert TotpConfirmEnableRequest.__struct_fields__ == ("enrollment_token", "code")
    assert TotpConfirmEnableResponse.__struct_fields__ == ("enabled",)
    assert TotpEnableResponse.__struct_fields__ == ("secret", "uri", "enrollment_token")
    assert TotpVerifyRequest.__struct_fields__ == ("pending_token", "code")
    assert TotpDisableRequest.__struct_fields__ == ("code",)
    assert TotpUserManagerProtocol is not None
    assert callable(create_auth_controller)
    assert callable(create_register_controller)
    assert callable(create_verify_controller)
    assert callable(create_reset_password_controller)
    assert callable(create_users_controller)
    assert callable(create_totp_controller)
    assert callable(create_oauth_controller)


def test_root_package_does_not_reexport_payload_or_schema_structs() -> None:
    """Payload and schema structs must be imported from ``payloads`` or ``schemas``."""
    for symbol in REMOVED_ROOT_PAYLOAD_EXPORTS:
        assert symbol not in __all__
        assert not hasattr(litestar_auth, symbol)

    assert payloads_module.LoginCredentials is LoginCredentials
    assert payloads_module.RefreshTokenRequest is RefreshTokenRequest
    assert payloads_module.ForgotPassword is ForgotPassword
    assert payloads_module.ResetPassword is ResetPassword
    assert payloads_module.VerifyToken is VerifyToken
    assert payloads_module.RequestVerifyToken is RequestVerifyToken
    assert payloads_module.TotpConfirmEnableRequest is TotpConfirmEnableRequest
    assert payloads_module.TotpConfirmEnableResponse is TotpConfirmEnableResponse
    assert payloads_module.TotpEnableResponse is TotpEnableResponse
    assert payloads_module.TotpVerifyRequest is TotpVerifyRequest
    assert payloads_module.TotpDisableRequest is TotpDisableRequest
    assert schemas_module.UserCreate is UserCreate
    assert schemas_module.UserRead is UserRead
    assert schemas_module.UserUpdate is UserUpdate


def test_oauth_package_exposes_canonical_login_helper_and_not_advanced_controller_factory() -> None:
    """The OAuth package keeps the login helper canonical and custom controller factories elsewhere."""
    assert oauth_package_module.__all__ == (
        "OAuthEmailVerificationAsyncClientProtocol",
        "OAuthEmailVerificationSyncClientProtocol",
        "create_provider_oauth_controller",
        "load_httpx_oauth_client",
        "make_async_email_verification_client",
    )
    assert oauth_package_module.OAuthEmailVerificationAsyncClientProtocol is OAuthEmailVerificationAsyncClientProtocol
    assert oauth_package_module.OAuthEmailVerificationSyncClientProtocol is OAuthEmailVerificationSyncClientProtocol
    assert oauth_package_module.create_provider_oauth_controller is create_provider_oauth_controller
    assert oauth_package_module.load_httpx_oauth_client is load_httpx_oauth_client
    assert oauth_package_module.make_async_email_verification_client is make_async_email_verification_client
    assert not hasattr(litestar_auth, "create_provider_oauth_controller")
    assert not hasattr(litestar_auth, "load_httpx_oauth_client")
    assert not hasattr(oauth_package_module, "create_oauth_controller")
    assert controllers_package.create_oauth_controller is create_oauth_controller
    assert controllers_package.create_oauth_associate_controller is create_oauth_associate_controller


def test_ratelimit_module_exposes_canonical_shared_backend_builder() -> None:
    """The public ratelimit module exposes the shared-backend builder entrypoint."""
    current_config_class = ratelimit_module.AuthRateLimitConfig
    current_endpoint_class = ratelimit_module.EndpointRateLimit
    current_memory_limiter_class = ratelimit_module.InMemoryRateLimiter
    current_redis_limiter_class = ratelimit_module.RedisRateLimiter
    credential_backend = current_memory_limiter_class(max_attempts=3, window_seconds=60)
    refresh_backend = current_memory_limiter_class(max_attempts=4, window_seconds=90)
    totp_backend = current_memory_limiter_class(max_attempts=5, window_seconds=120)
    group_backends: dict[AuthRateLimitEndpointGroup, InMemoryRateLimiter] = {
        "totp": totp_backend,
        "refresh": refresh_backend,
    }
    disabled_slots = AUTH_RATE_LIMIT_VERIFICATION_SLOTS

    config = current_config_class.from_shared_backend(
        credential_backend,
        group_backends=group_backends,
        disabled=disabled_slots,
    )

    assert current_config_class.__name__ == AuthRateLimitConfig.__name__
    assert current_endpoint_class.__name__ == EndpointRateLimit.__name__
    assert current_memory_limiter_class.__name__ == InMemoryRateLimiter.__name__
    assert current_redis_limiter_class.__name__ == RedisRateLimiter.__name__
    assert "AuthRateLimitConfig" in ratelimit_module.__all__
    assert "EndpointRateLimit" in ratelimit_module.__all__
    assert "InMemoryRateLimiter" in ratelimit_module.__all__
    assert "RedisRateLimiter" in ratelimit_module.__all__
    assert config.login == current_endpoint_class(backend=credential_backend, scope="ip_email", namespace="login")
    assert config.refresh == current_endpoint_class(backend=refresh_backend, scope="ip", namespace="refresh")
    assert config.forgot_password == current_endpoint_class(
        backend=credential_backend,
        scope="ip_email",
        namespace="forgot-password",
    )
    assert config.totp_verify == current_endpoint_class(backend=totp_backend, scope="ip", namespace="totp-verify")
    assert config.verify_token is None
    assert config.request_verify_token is None
    assert config.totp_disable == current_endpoint_class(
        backend=totp_backend,
        scope="ip",
        namespace="totp-disable",
    )


async def test_root_package_supports_documented_redis_migration_recipe_and_totp_replay_store(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """Public imports remain sufficient for the documented Redis migration recipe."""
    current_plugin_module = importlib.reload(plugin_module)
    current_root_module = importlib.reload(litestar_auth)

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module, "_load_used_totp_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module, "_load_enrollment_redis_asyncio", load_optional_redis)

    current_endpoint_class = ratelimit_module.EndpointRateLimit
    rate_limit_redis_client = async_fakeredis_factory()
    rate_limit_redis = cast_fakeredis(rate_limit_redis_client, RedisAuthClientProtocol)
    totp_redis_client = async_fakeredis_factory()
    totp_redis = cast_fakeredis(totp_redis_client, RedisAuthClientProtocol)
    credential_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=5, window_seconds=60)
    refresh_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=10, window_seconds=300)
    totp_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=5, window_seconds=300)
    forgot_password_override = EndpointRateLimit(
        backend=credential_backend,
        scope="ip_email",
        namespace="forgot_password",
    )
    reset_password_override = EndpointRateLimit(
        backend=credential_backend,
        scope="ip",
        namespace="reset_password",
    )
    totp_enable_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_enable",
    )
    totp_confirm_enable_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_confirm_enable",
    )
    totp_verify_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_verify",
    )
    totp_disable_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_disable",
    )
    rate_limit_config = AuthRateLimitConfig.from_shared_backend(
        credential_backend,
        group_backends={"refresh": refresh_backend, "totp": totp_backend},
        disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
        endpoint_overrides={
            AuthRateLimitSlot.FORGOT_PASSWORD: forgot_password_override,
            AuthRateLimitSlot.RESET_PASSWORD: reset_password_override,
            AuthRateLimitSlot.TOTP_ENABLE: totp_enable_override,
            AuthRateLimitSlot.TOTP_CONFIRM_ENABLE: totp_confirm_enable_override,
            AuthRateLimitSlot.TOTP_VERIFY: totp_verify_override,
            AuthRateLimitSlot.TOTP_DISABLE: totp_disable_override,
        },
    )
    used_tokens_store = RedisUsedTotpCodeStore(redis=totp_redis)
    enrollment_store = RedisTotpEnrollmentStore(redis=totp_redis)
    pending_jti_store = RedisJWTDenylistStore(redis=totp_redis)
    totp_config = TotpConfig(
        totp_pending_secret="p" * 32,
        totp_pending_jti_store=pending_jti_store,
        totp_used_tokens_store=used_tokens_store,
        totp_enrollment_store=enrollment_store,
    )

    assert current_root_module.TotpConfig is current_plugin_module.TotpConfig
    assert AuthRateLimitConfig.__name__ == ratelimit_module.AuthRateLimitConfig.__name__
    assert RedisTotpEnrollmentStore.__name__ == totp_module.RedisTotpEnrollmentStore.__name__
    assert RedisUsedTotpCodeStore.__name__ == totp_module.RedisUsedTotpCodeStore.__name__
    assert rate_limit_config.login == current_endpoint_class(
        backend=credential_backend,
        scope="ip_email",
        namespace="login",
    )
    assert rate_limit_config.refresh == current_endpoint_class(backend=refresh_backend, scope="ip", namespace="refresh")
    assert rate_limit_config.forgot_password is forgot_password_override
    assert rate_limit_config.totp_verify is totp_verify_override
    assert rate_limit_config.totp_disable is totp_disable_override
    assert rate_limit_config.verify_token is None
    assert rate_limit_config.request_verify_token is None
    assert totp_config.totp_pending_jti_store is pending_jti_store
    assert totp_config.totp_used_tokens_store is used_tokens_store
    assert totp_config.totp_enrollment_store is enrollment_store
    assert (await used_tokens_store.mark_used("user-1", 7, 60.0)).stored is True
    await pending_jti_store.deny("pending-jti", ttl_seconds=ONE_MINUTE_TTL_SECONDS)
    assert await pending_jti_store.is_denied("pending-jti") is True
    assert await totp_redis_client.get("litestar_auth:totp:used:user-1:7") == b"1"
    assert await totp_redis_client.get("litestar_auth:jwt:denylist:pending-jti") == b"1"
    assert 0 < await totp_redis_client.pttl("litestar_auth:totp:used:user-1:7") <= ONE_MINUTE_TTL_MS
    assert (
        ONE_MINUTE_TTL_FLOOR
        <= await totp_redis_client.ttl("litestar_auth:jwt:denylist:pending-jti")
        <= ONE_MINUTE_TTL_SECONDS
    )


def test_contrib_redis_module_exposes_high_level_preset_without_root_reexport() -> None:
    """The Redis contrib preset stays on the contrib module instead of the package root."""
    preset_hints = get_type_hints(RedisAuthPreset, include_extras=True)

    assert redis_contrib_module.RedisAuthPreset is RedisAuthPreset
    assert redis_contrib_module.RedisAuthRateLimitTier is RedisAuthRateLimitTier
    assert redis_contrib_module.__all__ == (
        "RedisAuthClientProtocol",
        "RedisAuthPreset",
        "RedisAuthRateLimitTier",
        "RedisTokenStrategy",
        "RedisTotpEnrollmentStore",
        "RedisUsedTotpCodeStore",
    )
    assert redis_contrib_module.RedisAuthClientProtocol is RedisAuthClientProtocol
    assert redis_contrib_module.RedisTotpEnrollmentStore is ContribRedisTotpEnrollmentStore
    assert preset_hints["redis"] is RedisAuthClientProtocol
    assert hasattr(RedisAuthPreset, "build_totp_enrollment_store")
    assert hasattr(RedisAuthPreset, "build_totp_pending_jti_store")
    assert "RedisAuthClientProtocol" not in __all__
    assert "RedisAuthPreset" not in __all__
    assert "RedisAuthRateLimitTier" not in __all__
    assert not hasattr(litestar_auth, "RedisAuthClientProtocol")
    assert not hasattr(litestar_auth, "RedisAuthPreset")
    assert not hasattr(litestar_auth, "RedisAuthRateLimitTier")


async def test_contrib_redis_preset_supports_documented_shared_client_recipe(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The canonical contrib preset recipe derives rate limiting plus the TOTP Redis stores."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module, "_load_used_totp_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module, "_load_enrollment_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth.authentication.strategy.jwt._load_redis_asyncio", load_optional_redis)
    redis_client = cast_fakeredis(async_fakeredis, RedisAuthClientProtocol)
    assert isinstance(redis_client, RedisAuthClientProtocol)
    preset = RedisAuthPreset(
        redis=redis_client,
        rate_limit_tier=RedisAuthRateLimitTier(
            max_attempts=SHARED_MAX_ATTEMPTS,
            window_seconds=SHARED_WINDOW_SECONDS,
        ),
        group_rate_limit_tiers={
            "refresh": RedisAuthRateLimitTier(
                max_attempts=REFRESH_MAX_ATTEMPTS,
                window_seconds=REFRESH_WINDOW_SECONDS,
            ),
            "totp": RedisAuthRateLimitTier(
                max_attempts=TOTP_MAX_ATTEMPTS,
                window_seconds=TOTP_WINDOW_SECONDS,
                key_prefix="totp:",
            ),
        },
        totp_used_tokens_key_prefix="used:",
        totp_pending_jti_key_prefix="pending:",
    )

    rate_limit_config = preset.build_rate_limit_config(
        disabled=AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"],
    )
    used_tokens_store = preset.build_totp_used_tokens_store()
    pending_jti_store = preset.build_totp_pending_jti_store()
    enrollment_store = preset.build_totp_enrollment_store()
    totp_config = TotpConfig(
        totp_pending_secret="p" * 32,
        totp_pending_jti_store=pending_jti_store,
        totp_used_tokens_store=used_tokens_store,
        totp_enrollment_store=enrollment_store,
    )

    assert rate_limit_config.login is not None
    assert rate_limit_config.login.backend.__class__ is ratelimit_module.RedisRateLimiter
    assert rate_limit_config.login.backend.redis is redis_client
    assert rate_limit_config.login.backend.max_attempts == SHARED_MAX_ATTEMPTS
    assert rate_limit_config.login.backend.window_seconds == SHARED_WINDOW_SECONDS
    assert rate_limit_config.refresh is not None
    assert rate_limit_config.refresh.backend.__class__ is ratelimit_module.RedisRateLimiter
    assert rate_limit_config.refresh.backend.redis is redis_client
    assert rate_limit_config.refresh.backend.max_attempts == REFRESH_MAX_ATTEMPTS
    assert rate_limit_config.refresh.backend.window_seconds == REFRESH_WINDOW_SECONDS
    assert rate_limit_config.totp_verify is not None
    assert rate_limit_config.totp_verify.backend.__class__ is ratelimit_module.RedisRateLimiter
    assert rate_limit_config.totp_verify.backend.key_prefix == "totp:"
    assert AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"] == AUTH_RATE_LIMIT_VERIFICATION_SLOTS
    assert rate_limit_config.verify_token is None
    assert rate_limit_config.request_verify_token is None
    assert totp_config.totp_pending_jti_store is pending_jti_store
    assert totp_config.totp_used_tokens_store is used_tokens_store
    assert totp_config.totp_enrollment_store is enrollment_store
    assert used_tokens_store._redis is redis_client
    assert pending_jti_store.redis is redis_client
    assert enrollment_store._redis is redis_client
    assert (await used_tokens_store.mark_used("user-1", 7, 60.0)).stored is True
    await pending_jti_store.deny("pending-jti", ttl_seconds=ONE_MINUTE_TTL_SECONDS)
    assert await pending_jti_store.is_denied("pending-jti") is True
    assert await async_fakeredis.get("used:user-1:7") == b"1"
    assert await async_fakeredis.get("pending:pending-jti") == b"1"
    assert 0 < await async_fakeredis.pttl("used:user-1:7") <= ONE_MINUTE_TTL_MS
    assert ONE_MINUTE_TTL_FLOOR <= await async_fakeredis.ttl("pending:pending-jti") <= ONE_MINUTE_TTL_SECONDS


def test_ratelimit_identifier_contract_stays_on_the_public_ratelimit_module() -> None:
    """Rate-limit typing stays on the ratelimit module without leaking onto the package root."""
    current_slot_alias = ratelimit_module.AuthRateLimitEndpointSlot
    current_group_alias = ratelimit_module.AuthRateLimitEndpointGroup

    assert current_slot_alias.__name__ == AuthRateLimitEndpointSlot.__name__
    assert current_group_alias.__name__ == AuthRateLimitEndpointGroup.__name__
    assert get_args(ratelimit_module.RateLimitScope.__value__) == ("ip", "ip_email")
    assert get_args(current_slot_alias.__value__) == (
        "login",
        "refresh",
        "register",
        "forgot_password",
        "reset_password",
        "totp_enable",
        "totp_confirm_enable",
        "totp_verify",
        "totp_disable",
        "verify_token",
        "request_verify_token",
    )
    assert get_args(current_group_alias.__value__) == (
        "login",
        "password_reset",
        "refresh",
        "register",
        "totp",
        "verification",
    )
    assert ratelimit_module.AUTH_RATE_LIMIT_ENDPOINT_SLOTS == AUTH_RATE_LIMIT_ENDPOINT_SLOTS
    assert ratelimit_module.AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP == AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP
    assert ratelimit_module.AUTH_RATE_LIMIT_VERIFICATION_SLOTS == AUTH_RATE_LIMIT_VERIFICATION_SLOTS
    assert AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"] == AUTH_RATE_LIMIT_VERIFICATION_SLOTS
    assert "AuthRateLimitEndpointSlot" in ratelimit_module.__all__
    assert "AuthRateLimitEndpointGroup" in ratelimit_module.__all__
    assert "AUTH_RATE_LIMIT_ENDPOINT_SLOTS" in ratelimit_module.__all__
    assert "AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP" in ratelimit_module.__all__
    assert "AUTH_RATE_LIMIT_VERIFICATION_SLOTS" in ratelimit_module.__all__
    assert "RateLimitScope" in ratelimit_module.__all__
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_CATALOG")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT")
    assert not hasattr(litestar_auth, "_AUTH_RATE_LIMIT_ENDPOINT_CATALOG")
    assert not hasattr(litestar_auth, "RateLimitScope")
    assert not hasattr(litestar_auth, "AUTH_RATE_LIMIT_ENDPOINT_SLOTS")
    assert not hasattr(litestar_auth, "AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP")
    assert not hasattr(litestar_auth, "AUTH_RATE_LIMIT_VERIFICATION_SLOTS")
    assert not hasattr(litestar_auth, "AuthRateLimitEndpointSlot")
    assert not hasattr(litestar_auth, "AuthRateLimitEndpointGroup")
    assert "AUTH_RATE_LIMIT_ENDPOINT_SLOTS" not in __all__
    assert "AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP" not in __all__
    assert "AUTH_RATE_LIMIT_VERIFICATION_SLOTS" not in __all__
    assert "AuthRateLimitEndpointSlot" not in __all__
    assert "AuthRateLimitEndpointGroup" not in __all__


def test_payload_module_is_authoritative_boundary_without_controllers_package_reexports() -> None:
    """Payloads resolve from the dedicated module without controllers-package aliases."""
    assert controllers_package.__all__ == (
        "TotpUserManagerProtocol",
        "create_auth_controller",
        "create_oauth_associate_controller",
        "create_oauth_controller",
        "create_register_controller",
        "create_reset_password_controller",
        "create_totp_controller",
        "create_users_controller",
        "create_verify_controller",
    )
    assert payloads_module.__all__ == (
        "ForgotPassword",
        "LoginCredentials",
        "RefreshTokenRequest",
        "RequestVerifyToken",
        "ResetPassword",
        "TotpConfirmEnableRequest",
        "TotpConfirmEnableResponse",
        "TotpDisableRequest",
        "TotpEnableRequest",
        "TotpEnableResponse",
        "TotpVerifyRequest",
        "VerifyToken",
    )
    assert payloads_module.LoginCredentials is LoginCredentials
    assert payloads_module.LoginCredentials is auth_controller_module.LoginCredentials
    assert payloads_module.RefreshTokenRequest is auth_controller_module.RefreshTokenRequest
    assert payloads_module.ForgotPassword is reset_controller_module.ForgotPassword
    assert payloads_module.ResetPassword is reset_controller_module.ResetPassword
    assert payloads_module.VerifyToken is verify_controller_module.VerifyToken
    assert payloads_module.RequestVerifyToken is verify_controller_module.RequestVerifyToken
    assert payloads_module.TotpEnableRequest is totp_controller_module.TotpEnableRequest
    assert payloads_module.TotpConfirmEnableRequest is TotpConfirmEnableRequest
    assert payloads_module.TotpConfirmEnableResponse is TotpConfirmEnableResponse
    assert payloads_module.TotpEnableResponse is TotpEnableResponse
    assert payloads_module.TotpVerifyRequest is TotpVerifyRequest
    assert payloads_module.TotpDisableRequest is TotpDisableRequest
    for symbol in REMOVED_CONTROLLERS_PAYLOAD_EXPORTS:
        assert symbol not in controllers_package.__all__
        assert not hasattr(controllers_package, symbol)
    for symbol in REMOVED_PAYLOAD_SCHEMA_EXPORTS:
        assert symbol not in payloads_module.__all__
        assert not hasattr(payloads_module, symbol)
    assert schemas_module.UserCreate is UserCreate
    assert schemas_module.UserRead is UserRead
    assert schemas_module.UserUpdate is UserUpdate


def test_exception_hierarchy_stays_on_canonical_module() -> None:
    """Exception subclasses stay on ``litestar_auth.exceptions`` while the root exports the base type."""
    assert issubclass(AuthenticationError, LitestarAuthError)
    assert issubclass(AuthorizationError, LitestarAuthError)
    assert issubclass(ConfigurationError, LitestarAuthError)
    assert issubclass(OAuthAccountAlreadyLinkedError, AuthenticationError)
    assert issubclass(OAuthAccountAlreadyLinkedError, LitestarAuthError)
    assert issubclass(TokenError, LitestarAuthError)
    assert issubclass(UserAlreadyExistsError, AuthenticationError)
    assert issubclass(UserNotExistsError, AuthenticationError)
    assert issubclass(InvalidPasswordError, AuthenticationError)
    assert issubclass(InvalidVerifyTokenError, TokenError)
    assert issubclass(InvalidResetPasswordTokenError, TokenError)
    assert not hasattr(litestar_auth, "AuthenticationError")
    assert not hasattr(litestar_auth, "TokenError")


def test_root_package_all_excludes_private_symbols() -> None:
    """`__all__` lists only public names."""
    assert tuple(__all__) == (
        "DEFAULT_SUPERUSER_ROLE_NAME",
        "AuthenticationBackend",
        "Authenticator",
        "BaseUserManager",
        "BearerTransport",
        "CookieTransport",
        "DatabaseTokenAuthConfig",
        "ErrorCode",
        "GuardedUserProtocol",
        "LitestarAuth",
        "LitestarAuthConfig",
        "LitestarAuthError",
        "OAuthConfig",
        "OAuthProviderConfig",
        "RoleCapableUserProtocol",
        "TotpConfig",
        "TotpUserProtocol",
        "UserManagerSecurity",
        "UserProtocol",
        "UserProtocolStrict",
        "__version__",
        "has_all_roles",
        "has_any_role",
        "is_active",
        "is_authenticated",
        "is_superuser",
        "is_verified",
    )
    assert all(not symbol.startswith("_") or symbol == "__version__" for symbol in __all__)
    assert len(__all__) == len(set(__all__))
    assert "_UserManagerProxy" not in __all__
    assert "ErrorCode" in __all__
    assert "has_any_role" in __all__
    assert "has_all_roles" in __all__
    assert {
        "GuardedUserProtocol",
        "RoleCapableUserProtocol",
        "TotpUserProtocol",
        "UserProtocol",
        "UserProtocolStrict",
    } <= set(__all__)
    assert "Authenticator" in __all__
    for symbol in REMOVED_ROOT_PAYLOAD_EXPORTS:
        assert symbol not in __all__
    for symbol in REMOVED_ROOT_SECONDARY_EXPORTS:
        assert symbol not in __all__
    assert "LitestarAuth" in __all__
    assert "DatabaseTokenAuthConfig" in __all__


def test_root_package_does_not_reexport_secondary_surfaces() -> None:
    """Secondary APIs stay on canonical submodules instead of the package root."""
    for symbol in REMOVED_ROOT_SECONDARY_EXPORTS:
        assert not hasattr(litestar_auth, symbol)

    assert AccessToken is not None
    assert RefreshToken is not None
    assert PasswordHelper is not None
    assert Transport is not None
    assert Strategy is not None
    assert DbSessionDependencyKey is not None
    assert JWTStrategy is not None
    assert DatabaseTokenStrategy is not None
    assert RedisTokenStrategy is not None
    assert InMemoryRateLimiter is not None
    assert RedisRateLimiter is not None
    assert EndpointRateLimit is not None
    assert AuthRateLimitConfig is not None
    assert InMemoryJWTDenylistStore is not None
    assert InMemoryTotpEnrollmentStore is not None
    assert InMemoryUsedTotpCodeStore is not None
    assert JWTDenylistStore is not None
    assert RedisJWTDenylistStore is not None
    assert RedisTotpEnrollmentStore is not None
    assert RedisUsedTotpCodeStore is not None
    assert BaseUserStore is not None
    assert SQLAlchemyUserDatabase is not None
    assert UserRead.__struct_fields__ == ("id", "email", "is_active", "is_verified", "roles")
    assert UserCreate.__struct_fields__ == ("email", "password")
    assert UserUpdate.__struct_fields__ == ("password", "email", "is_active", "is_verified", "roles")
    assert callable(create_provider_oauth_controller)
    assert callable(create_oauth_associate_controller)
    assert callable(load_httpx_oauth_client)
    assert callable(require_password_length)
    assert callable(generate_totp_secret)
    assert callable(generate_totp_uri)
    assert callable(verify_totp)
    assert callable(verify_totp_with_store)


def test_root_package_all_entries_resolve_to_attributes() -> None:
    """Each declared public export resolves from the package root."""
    for symbol in __all__:
        assert hasattr(litestar_auth, symbol)
        assert getattr(litestar_auth, symbol) is not None


def test_root_package_does_not_export_compat_aliases() -> None:
    """Backward-compat root aliases were removed; import from ``litestar_auth.plugin`` or ``litestar_auth.db``."""
    assert "AuthPlugin" not in __all__
    assert "BaseUserDatabase" not in __all__
    assert not hasattr(litestar_auth, "AuthPlugin")
    assert not hasattr(litestar_auth, "BaseUserDatabase")


def test_plugin_module_public_exports_no_compat_shims() -> None:
    """Plugin module exposes ``LitestarAuth``, ``LitestarAuthConfig``, config dataclasses; legacy shims removed."""
    current_plugin_internals = importlib.reload(plugin_internals)
    current_plugin_module = importlib.reload(plugin_module)
    current_root_module = importlib.reload(litestar_auth)

    assert plugin_module.__all__ == (
        "DatabaseTokenAuthConfig",
        "LitestarAuth",
        "LitestarAuthConfig",
        "OAuthConfig",
        "OAuthProviderConfig",
        "StartupBackendTemplate",
        "TotpConfig",
    )
    assert current_plugin_module.DatabaseTokenAuthConfig is current_root_module.DatabaseTokenAuthConfig
    assert current_plugin_module.LitestarAuthConfig is current_plugin_internals.LitestarAuthConfig
    assert current_plugin_module.StartupBackendTemplate.__module__ == "litestar_auth._plugin.config"
    assert not hasattr(current_root_module, "StartupBackendTemplate")
    assert "AuthPlugin" not in plugin_module.__all__
    assert not hasattr(plugin_module, "AuthPlugin")
    for name in (
        "DEFAULT_CONFIG_DEPENDENCY_KEY",
        "DEFAULT_USER_MANAGER_DEPENDENCY_KEY",
        "DEFAULT_BACKENDS_DEPENDENCY_KEY",
        "DEFAULT_USER_MODEL_DEPENDENCY_KEY",
        "DEFAULT_CSRF_COOKIE_NAME",
        "OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY",
        "_ScopedUserDatabaseProxy",
    ):
        assert not hasattr(plugin_module, name)


def test_root_package_installs_null_handler() -> None:
    """The package root configures a NullHandler for library-safe logging."""
    assert any(
        isinstance(handler, logging.NullHandler) for handler in logging.getLogger(litestar_auth.__name__).handlers
    )
