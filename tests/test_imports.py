"""Integration coverage for the root package public API."""

from __future__ import annotations

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
import litestar_auth._redis_protocols as redis_protocols_module
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
    AccessToken,
    AuthenticationBackend,
    AuthenticationError,
    Authenticator,
    AuthorizationError,
    AuthRateLimitConfig,
    BaseUserManager,
    BearerTransport,
    ConfigurationError,
    CookieTransport,
    DatabaseTokenAuthConfig,
    DatabaseTokenStrategy,
    EndpointRateLimit,
    ErrorCode,
    ForgotPassword,
    GuardedUserProtocol,
    InMemoryJWTDenylistStore,
    InMemoryRateLimiter,
    InMemoryUsedTotpCodeStore,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    JWTDenylistStore,
    JWTStrategy,
    LitestarAuth,
    LitestarAuthConfig,
    LitestarAuthError,
    LoginCredentials,
    OAuthAccountAlreadyLinkedError,
    PasswordHelper,
    RedisJWTDenylistStore,
    RedisRateLimiter,
    RedisTokenStrategy,
    RedisUsedTotpCodeStore,
    RefreshToken,
    RefreshTokenRequest,
    RequestVerifyToken,
    ResetPassword,
    Strategy,
    TokenError,
    TotpConfig,
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableResponse,
    TotpUserManagerProtocol,
    TotpUserProtocol,
    TotpVerifyRequest,
    Transport,
    UserAlreadyExistsError,
    UserCreate,
    UserNotExistsError,
    UserProtocol,
    UserRead,
    UserUpdate,
    VerifyToken,
    __all__,
    __version__,
    create_auth_controller,
    create_oauth_associate_controller,
    create_oauth_controller,
    create_provider_oauth_controller,
    create_register_controller,
    create_reset_password_controller,
    create_totp_controller,
    create_users_controller,
    create_verify_controller,
    generate_totp_secret,
    generate_totp_uri,
    is_active,
    is_authenticated,
    is_superuser,
    is_verified,
    load_httpx_oauth_client,
    require_password_length,
    verify_totp,
    verify_totp_with_store,
)
from litestar_auth._redis_protocols import RedisSharedAuthClient
from litestar_auth.contrib.redis import RedisAuthPreset, RedisAuthRateLimitTier
from litestar_auth.db import BaseOAuthAccountStore, BaseUserStore
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.ratelimit import (
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS,
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP,
    AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    AuthRateLimitEndpointGroup,
    AuthRateLimitEndpointSlot,
    AuthRateLimitNamespaceStyle,
)
from tests._helpers import ExampleUser
from tests.conftest import project_version_from_pyproject

if TYPE_CHECKING:
    import msgspec
    from sqlalchemy.ext.asyncio import AsyncSession

SHARED_MAX_ATTEMPTS = 5
SHARED_WINDOW_SECONDS = 60
REFRESH_MAX_ATTEMPTS = 10
REFRESH_WINDOW_SECONDS = 300
TOTP_MAX_ATTEMPTS = 5
TOTP_WINDOW_SECONDS = 300

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


class _PublicImportRedisClient:
    """Minimal async Redis double for public import coverage."""

    def __init__(self) -> None:
        """Initialize recorded store calls."""
        self.set_calls: list[tuple[str, str, bool, int | None]] = []

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> int:
        """Return a neutral Lua result for constructor-only rate-limit coverage."""
        del script, numkeys, keys_and_args
        return 0

    async def delete(self, *names: str) -> int:
        """Return a successful delete count for protocol conformance."""
        del names
        return 1

    async def set(
        self,
        name: str,
        value: str,
        *,
        nx: bool = False,
        px: int | None = None,
    ) -> bool | None:
        """Record a TOTP replay-store write.

        Returns:
            ``True`` to simulate a successful first-write reservation.
        """
        self.set_calls.append((name, value, nx, px))
        return True


def test_root_package_reexports_public_api() -> None:
    """The package root exposes the documented public auth API."""
    assert __version__ == project_version_from_pyproject()
    assert LitestarAuth is not None
    assert LitestarAuthConfig is not None
    assert AccessToken is not None
    assert RefreshToken is not None
    assert PasswordHelper is not None
    assert AuthenticationBackend is not None
    assert Authenticator is not None
    assert Transport is not None
    assert Strategy is not None
    assert UserProtocol is not None
    assert GuardedUserProtocol is not None
    assert TotpUserProtocol is not None
    assert BearerTransport is not None
    assert CookieTransport is not None
    assert JWTStrategy is not None
    assert DatabaseTokenAuthConfig is not None
    assert DatabaseTokenStrategy is not None
    assert RedisTokenStrategy is not None
    assert InMemoryRateLimiter is not None
    assert RedisRateLimiter is not None
    assert EndpointRateLimit is not None
    assert AuthRateLimitConfig is not None
    assert InMemoryJWTDenylistStore is not None
    assert InMemoryUsedTotpCodeStore is not None
    assert JWTDenylistStore is not None
    assert RedisJWTDenylistStore is not None
    assert RedisUsedTotpCodeStore is not None
    assert callable(generate_totp_secret)
    assert callable(generate_totp_uri)
    assert callable(verify_totp)
    assert callable(verify_totp_with_store)
    assert BaseUserStore is not None
    assert SQLAlchemyUserDatabase is not None
    assert BaseUserManager is not None
    assert UserRead.__struct_fields__ == ("id", "email", "is_active", "is_verified", "is_superuser")
    assert UserCreate.__struct_fields__ == ("email", "password")
    assert UserUpdate.__struct_fields__ == ("password", "email", "is_active", "is_verified", "is_superuser")
    assert callable(is_authenticated)
    assert callable(is_active)
    assert callable(is_verified)
    assert callable(is_superuser)
    assert callable(create_provider_oauth_controller)
    assert callable(create_oauth_associate_controller)
    assert callable(load_httpx_oauth_client)
    assert callable(require_password_length)
    assert ErrorCode is not None


def test_root_package_exports_canonical_database_token_preset_entrypoint() -> None:
    """The root package exposes the documented DB bearer preset entrypoint."""
    session_maker = _RootImportCoverageSessionFactory()
    config = LitestarAuthConfig[ExampleUser, UUID].with_database_token_auth(
        database_token_auth=DatabaseTokenAuthConfig(token_hash_secret="x" * 40),
        user_model=ExampleUser,
        user_manager_class=_RootImportCoverageUserManager,
        session_maker=session_maker,
        user_db_factory=lambda _session: cast("Any", object()),
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
    )

    preset = config.database_token_auth
    assert preset is not None
    assert preset.token_hash_secret == "x" * 40
    assert config.session_maker is session_maker

    backend = config.backends[0]
    assert backend.name == "database"
    assert isinstance(backend.transport, BearerTransport)
    assert isinstance(backend.strategy, litestar_auth.DatabaseTokenStrategy)


def test_public_user_schema_reuse_surface_stays_importable() -> None:
    """Custom-schema email/password helpers stay on the dedicated public schemas module."""
    user_create_email_meta = _field_meta(UserCreate, "email")
    user_update_email_meta = _field_meta(UserUpdate, "email")
    user_create_meta = _field_meta(UserCreate, "password")
    user_update_meta = _field_meta(UserUpdate, "password")
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
    assert user_create_email_meta.max_length == EMAIL_MAX_LENGTH
    assert user_update_email_meta.max_length == EMAIL_MAX_LENGTH
    assert user_create_email_meta.pattern == EMAIL_PATTERN
    assert user_update_email_meta.pattern == EMAIL_PATTERN
    assert user_create_meta.min_length == config_module.DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert user_update_meta.min_length == config_module.DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert user_create_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert user_update_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert litestar_auth.require_password_length is config_module.require_password_length


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
        "User",
        "UserAuthRelationshipMixin",
        "UserModelMixin",
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
    assert models_module.UserAuthRelationshipMixin.__name__ == "UserAuthRelationshipMixin"
    assert models_module.UserModelMixin.__name__ == "UserModelMixin"
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
    assert "User" not in __all__
    assert "OAuthAccount" not in __all__
    assert "SQLAlchemyUserDatabase" not in __all__
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


def test_root_package_reexports_controller_factories_and_payloads() -> None:
    """The package root exposes controller factories and their public payload structs."""
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


def test_oauth_package_exposes_canonical_login_helper_and_not_advanced_controller_factory() -> None:
    """The OAuth package keeps the login helper canonical and custom controller factories elsewhere."""
    assert oauth_package_module.__all__ == ("create_provider_oauth_controller", "load_httpx_oauth_client")
    assert oauth_package_module.create_provider_oauth_controller is create_provider_oauth_controller
    assert oauth_package_module.load_httpx_oauth_client is load_httpx_oauth_client
    assert litestar_auth.create_provider_oauth_controller is oauth_package_module.create_provider_oauth_controller
    assert litestar_auth.load_httpx_oauth_client is oauth_package_module.load_httpx_oauth_client
    assert not hasattr(oauth_package_module, "create_oauth_controller")
    assert controllers_package.create_oauth_controller is create_oauth_controller
    assert controllers_package.create_oauth_associate_controller is create_oauth_associate_controller


def test_ratelimit_module_exposes_canonical_shared_backend_builder() -> None:
    """The public ratelimit module exposes the shared-backend builder entrypoint."""
    current_config_class = ratelimit_module.AuthRateLimitConfig
    current_endpoint_class = ratelimit_module.EndpointRateLimit
    current_memory_limiter_class = ratelimit_module.InMemoryRateLimiter
    current_redis_limiter_class = ratelimit_module.RedisRateLimiter
    current_namespace_style_alias = ratelimit_module.AuthRateLimitNamespaceStyle
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
        namespace_style="snake_case",
    )

    assert current_config_class.__name__ == AuthRateLimitConfig.__name__
    assert current_endpoint_class.__name__ == EndpointRateLimit.__name__
    assert current_memory_limiter_class.__name__ == InMemoryRateLimiter.__name__
    assert current_redis_limiter_class.__name__ == RedisRateLimiter.__name__
    assert current_namespace_style_alias.__name__ == AuthRateLimitNamespaceStyle.__name__
    assert "AuthRateLimitConfig" in ratelimit_module.__all__
    assert "EndpointRateLimit" in ratelimit_module.__all__
    assert "AuthRateLimitNamespaceStyle" in ratelimit_module.__all__
    assert "InMemoryRateLimiter" in ratelimit_module.__all__
    assert "RedisRateLimiter" in ratelimit_module.__all__
    assert config.login == current_endpoint_class(backend=credential_backend, scope="ip_email", namespace="login")
    assert config.refresh == current_endpoint_class(backend=refresh_backend, scope="ip", namespace="refresh")
    assert config.forgot_password == current_endpoint_class(
        backend=credential_backend,
        scope="ip_email",
        namespace="forgot_password",
    )
    assert config.totp_verify == current_endpoint_class(backend=totp_backend, scope="ip", namespace="totp_verify")
    assert config.verify_token is None
    assert config.request_verify_token is None
    assert config.totp_disable == current_endpoint_class(
        backend=totp_backend,
        scope="ip",
        namespace="totp_disable",
    )


async def test_root_package_supports_documented_redis_migration_recipe_and_totp_replay_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public imports remain sufficient for the documented Redis migration recipe."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module, "_load_redis_asyncio", load_optional_redis)

    current_endpoint_class = ratelimit_module.EndpointRateLimit
    rate_limit_redis = _PublicImportRedisClient()
    totp_redis = _PublicImportRedisClient()
    credential_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=5, window_seconds=60)
    refresh_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=10, window_seconds=300)
    totp_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=5, window_seconds=300)
    rate_limit_config = AuthRateLimitConfig.from_shared_backend(
        credential_backend,
        group_backends={"refresh": refresh_backend, "totp": totp_backend},
        disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
        namespace_style="snake_case",
    )
    used_tokens_store = RedisUsedTotpCodeStore(redis=totp_redis)
    totp_config = TotpConfig(
        totp_pending_secret="p" * 32,
        totp_used_tokens_store=used_tokens_store,
    )

    assert TotpConfig is plugin_module.TotpConfig
    assert AuthRateLimitConfig.__name__ == ratelimit_module.AuthRateLimitConfig.__name__
    assert RedisUsedTotpCodeStore.__name__ == totp_module.RedisUsedTotpCodeStore.__name__
    assert rate_limit_config.login == current_endpoint_class(
        backend=credential_backend,
        scope="ip_email",
        namespace="login",
    )
    assert rate_limit_config.refresh == current_endpoint_class(backend=refresh_backend, scope="ip", namespace="refresh")
    assert rate_limit_config.forgot_password == current_endpoint_class(
        backend=credential_backend,
        scope="ip_email",
        namespace="forgot_password",
    )
    assert rate_limit_config.totp_verify == current_endpoint_class(
        backend=totp_backend,
        scope="ip",
        namespace="totp_verify",
    )
    assert rate_limit_config.totp_disable == current_endpoint_class(
        backend=totp_backend,
        scope="ip",
        namespace="totp_disable",
    )
    assert rate_limit_config.verify_token is None
    assert rate_limit_config.request_verify_token is None
    assert totp_config.totp_used_tokens_store is used_tokens_store
    assert await used_tokens_store.mark_used("user-1", 7, 60.0) is True
    assert totp_redis.set_calls == [("litestar_auth:totp:used:user-1:7", "1", True, 60_000)]


def test_contrib_redis_module_exposes_high_level_preset_without_root_reexport() -> None:
    """The Redis contrib preset stays on the contrib module instead of the package root."""
    preset_hints = get_type_hints(RedisAuthPreset, include_extras=True)

    assert redis_contrib_module.RedisAuthPreset is RedisAuthPreset
    assert redis_contrib_module.RedisAuthRateLimitTier is RedisAuthRateLimitTier
    assert redis_contrib_module.__all__ == (
        "RedisAuthPreset",
        "RedisAuthRateLimitTier",
        "RedisTokenStrategy",
        "RedisUsedTotpCodeStore",
    )
    assert preset_hints["redis"] is RedisSharedAuthClient
    assert RedisSharedAuthClient.__module__ == redis_protocols_module.__name__
    assert "RedisAuthPreset" not in __all__
    assert "RedisAuthRateLimitTier" not in __all__
    assert not hasattr(litestar_auth, "RedisAuthPreset")
    assert not hasattr(litestar_auth, "RedisAuthRateLimitTier")


async def test_contrib_redis_preset_supports_documented_shared_client_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The contrib preset derives both Redis auth helpers from one shared client."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module, "_load_redis_asyncio", load_optional_redis)
    redis_client: RedisSharedAuthClient = _PublicImportRedisClient()
    assert isinstance(redis_client, RedisSharedAuthClient)
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
    )

    rate_limit_config = preset.build_rate_limit_config(
        disabled=AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"],
        namespace_style="snake_case",
    )
    used_tokens_store = preset.build_totp_used_tokens_store()

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
    assert used_tokens_store._redis is redis_client
    assert await used_tokens_store.mark_used("user-1", 7, 60.0) is True
    assert redis_client.set_calls == [("used:user-1:7", "1", True, 60_000)]


def test_ratelimit_identifier_contract_stays_on_the_public_ratelimit_module() -> None:
    """Rate-limit typing stays on the ratelimit module without leaking onto the package root."""
    current_slot_alias = ratelimit_module.AuthRateLimitEndpointSlot
    current_group_alias = ratelimit_module.AuthRateLimitEndpointGroup
    current_namespace_style_alias = ratelimit_module.AuthRateLimitNamespaceStyle

    assert current_slot_alias.__name__ == AuthRateLimitEndpointSlot.__name__
    assert current_group_alias.__name__ == AuthRateLimitEndpointGroup.__name__
    assert current_namespace_style_alias.__name__ == AuthRateLimitNamespaceStyle.__name__
    assert get_args(ratelimit_module.RateLimitScope.__value__) == ("ip", "ip_email")
    assert get_args(current_namespace_style_alias.__value__) == ("route", "snake_case")
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
    assert "AuthRateLimitNamespaceStyle" in ratelimit_module.__all__
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
    assert not hasattr(litestar_auth, "AuthRateLimitNamespaceStyle")
    assert not hasattr(litestar_auth, "AuthRateLimitEndpointSlot")
    assert not hasattr(litestar_auth, "AuthRateLimitEndpointGroup")
    assert "AUTH_RATE_LIMIT_ENDPOINT_SLOTS" not in __all__
    assert "AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP" not in __all__
    assert "AUTH_RATE_LIMIT_VERIFICATION_SLOTS" not in __all__
    assert "AuthRateLimitNamespaceStyle" not in __all__
    assert "AuthRateLimitEndpointSlot" not in __all__
    assert "AuthRateLimitEndpointGroup" not in __all__


def test_payload_module_is_authoritative_boundary_with_compat_reexports() -> None:
    """Payloads resolve from the dedicated module and stay aliased from compatibility paths."""
    assert controllers_package.__all__ == (
        "ForgotPassword",
        "LoginCredentials",
        "RefreshTokenRequest",
        "RequestVerifyToken",
        "ResetPassword",
        "TotpConfirmEnableRequest",
        "TotpConfirmEnableResponse",
        "TotpDisableRequest",
        "TotpEnableResponse",
        "TotpUserManagerProtocol",
        "TotpVerifyRequest",
        "VerifyToken",
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
        "UserCreate",
        "UserRead",
        "UserUpdate",
        "VerifyToken",
    )
    assert payloads_module.UserCreate is UserCreate
    assert payloads_module.UserRead is UserRead
    assert payloads_module.UserUpdate is UserUpdate
    assert payloads_module.LoginCredentials is LoginCredentials
    assert payloads_module.LoginCredentials is controllers_package.LoginCredentials
    assert payloads_module.LoginCredentials is auth_controller_module.LoginCredentials
    assert payloads_module.RefreshTokenRequest is controllers_package.RefreshTokenRequest
    assert payloads_module.RefreshTokenRequest is auth_controller_module.RefreshTokenRequest
    assert payloads_module.ForgotPassword is controllers_package.ForgotPassword
    assert payloads_module.ForgotPassword is reset_controller_module.ForgotPassword
    assert payloads_module.ResetPassword is controllers_package.ResetPassword
    assert payloads_module.ResetPassword is reset_controller_module.ResetPassword
    assert payloads_module.VerifyToken is controllers_package.VerifyToken
    assert payloads_module.VerifyToken is verify_controller_module.VerifyToken
    assert payloads_module.RequestVerifyToken is controllers_package.RequestVerifyToken
    assert payloads_module.RequestVerifyToken is verify_controller_module.RequestVerifyToken
    assert payloads_module.TotpConfirmEnableRequest is controllers_package.TotpConfirmEnableRequest
    assert payloads_module.TotpEnableRequest is totp_controller_module.TotpEnableRequest
    assert payloads_module.TotpConfirmEnableRequest is TotpConfirmEnableRequest
    assert payloads_module.TotpConfirmEnableResponse is controllers_package.TotpConfirmEnableResponse
    assert payloads_module.TotpConfirmEnableResponse is TotpConfirmEnableResponse
    assert payloads_module.TotpEnableResponse is controllers_package.TotpEnableResponse
    assert payloads_module.TotpEnableResponse is TotpEnableResponse
    assert payloads_module.TotpVerifyRequest is controllers_package.TotpVerifyRequest
    assert payloads_module.TotpVerifyRequest is TotpVerifyRequest
    assert payloads_module.TotpDisableRequest is controllers_package.TotpDisableRequest
    assert payloads_module.TotpDisableRequest is TotpDisableRequest


def test_root_package_reexports_exception_hierarchy() -> None:
    """The package root exposes all public exception types."""
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


def test_root_package_all_excludes_private_symbols() -> None:
    """`__all__` lists only public names."""
    assert all(not symbol.startswith("_") for symbol in __all__)
    assert len(__all__) == len(set(__all__))
    assert "_UserManagerProxy" not in __all__
    assert "AuthRateLimitConfig" in __all__
    assert "EndpointRateLimit" in __all__
    assert "ErrorCode" in __all__
    assert "InMemoryRateLimiter" in __all__
    assert "RedisRateLimiter" in __all__
    assert "generate_totp_secret" in __all__
    assert "generate_totp_uri" in __all__
    assert "verify_totp" in __all__
    assert "verify_totp_with_store" in __all__
    assert "InMemoryJWTDenylistStore" in __all__
    assert "InMemoryUsedTotpCodeStore" in __all__
    assert "JWTDenylistStore" in __all__
    assert "RedisJWTDenylistStore" in __all__
    assert "RedisUsedTotpCodeStore" in __all__
    assert "UserProtocol" in __all__
    assert "GuardedUserProtocol" in __all__
    assert "TotpUserProtocol" in __all__
    assert "TotpUserManagerProtocol" in __all__
    assert "Authenticator" in __all__
    assert "RefreshToken" in __all__
    assert "LoginCredentials" in __all__
    assert "RefreshTokenRequest" in __all__
    assert "ForgotPassword" in __all__
    assert "ResetPassword" in __all__
    assert "VerifyToken" in __all__
    assert "RequestVerifyToken" in __all__
    assert "TotpConfirmEnableRequest" in __all__
    assert "TotpConfirmEnableResponse" in __all__
    assert "TotpEnableResponse" in __all__
    assert "TotpVerifyRequest" in __all__
    assert "TotpDisableRequest" in __all__
    assert "create_auth_controller" in __all__
    assert "create_oauth_associate_controller" in __all__
    assert "create_register_controller" in __all__
    assert "create_verify_controller" in __all__
    assert "create_reset_password_controller" in __all__
    assert "create_users_controller" in __all__
    assert "create_totp_controller" in __all__
    assert "create_oauth_controller" in __all__
    assert "OAuthAccountAlreadyLinkedError" in __all__
    assert "require_password_length" in __all__
    assert "LitestarAuth" in __all__
    assert "DatabaseTokenAuthConfig" in __all__


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
    assert plugin_module.__all__ == ("LitestarAuth", "LitestarAuthConfig", "OAuthConfig", "TotpConfig")
    assert plugin_module.LitestarAuthConfig is plugin_internals.LitestarAuthConfig
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
