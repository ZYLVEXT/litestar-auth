"""Unit tests for the Litestar auth plugin orchestrator helpers."""

from __future__ import annotations

import asyncio
import importlib
import warnings
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from litestar.config.app import AppConfig
from litestar.config.csrf import CSRFConfig
from litestar.exceptions import ClientException
from litestar.middleware import DefineMiddleware

import litestar_auth._plugin.startup as startup_module
import litestar_auth.plugin as plugin_module
from litestar_auth import DEFAULT_SUPERUSER_ROLE_NAME
from litestar_auth._plugin import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
)
from litestar_auth._plugin.dependencies import (
    DependencyProviders,
    client_exception_handler,
    register_dependencies,
)
from litestar_auth.authentication import Authenticator, LitestarAuthMiddleware
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.db_models import DatabaseTokenModels
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore, JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.config import require_password_length
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import (
    DatabaseTokenAuthConfig,
    LitestarAuth,
    LitestarAuthConfig,
    OAuthConfig,
    TotpConfig,
)
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    EndpointRateLimit,
    InMemoryRateLimiter,
    RedisClientProtocol,
    RedisRateLimiter,
)
from litestar_auth.totp import InMemoryTotpEnrollmentStore, InMemoryUsedTotpCodeStore, SecurityWarning
from tests._helpers import cast_fakeredis
from tests.integration.test_orchestrator import (
    DummySession,
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.config import OAuthProviderConfig
    from tests._helpers import AsyncFakeRedis

pytestmark = pytest.mark.unit


def _current_startup_backend_template_type() -> type[Any]:
    """Return the current startup-backend template class after reload-oriented tests."""
    plugin_config_module = importlib.import_module("litestar_auth._plugin.config")
    return cast("type[Any]", plugin_config_module.StartupBackendTemplate)


def _current_database_token_strategy_type() -> type[Any]:
    """Return the current DB-token strategy class after reload-oriented tests."""
    db_strategy_module = importlib.import_module("litestar_auth.authentication.strategy.db")
    return cast("type[Any]", db_strategy_module.DatabaseTokenStrategy)


def _oauth_provider(*, name: str, client: object) -> OAuthProviderConfig:
    """Build an OAuthProviderConfig using the current runtime class.

    Returns:
        The current-runtime OAuthProviderConfig instance.
    """
    config_module = importlib.import_module("litestar_auth.config")
    oauth_provider_config_type = cast("type[Any]", config_module.OAuthProviderConfig)
    return oauth_provider_config_type(name=name, client=client)


def _current_authentication_backend_type() -> type[Any]:
    """Return the current backend class after reload-oriented tests."""
    backend_module = importlib.import_module("litestar_auth.authentication.backend")
    return cast("type[Any]", backend_module.AuthenticationBackend)


def test_plugin_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records the module body."""
    reloaded_module = importlib.reload(plugin_module)

    assert reloaded_module.DatabaseTokenAuthConfig.__name__ == DatabaseTokenAuthConfig.__name__
    assert reloaded_module.LitestarAuth.__name__ == LitestarAuth.__name__
    assert reloaded_module.LitestarAuthConfig.__name__ == LitestarAuthConfig.__name__
    assert reloaded_module.__all__ == (
        "DatabaseTokenAuthConfig",
        "LitestarAuth",
        "LitestarAuthConfig",
        "OAuthConfig",
        "OAuthProviderConfig",
        "StartupBackendTemplate",
        "TotpConfig",
    )


def _minimal_config(
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    include_users: bool = False,
    user_manager_class: type[Any] | None = None,
    login_identifier: Literal["email", "username"] = "email",
    superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for orchestrator-focused tests.

    Returns:
        Configured plugin settings suitable for isolated orchestrator tests.
    """
    user_db = InMemoryUserDatabase([])
    configured_backends = backends or [
        AuthenticationBackend[ExampleUser, UUID](
            name="primary",
            transport=BearerTransport(),
            strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-orchestrator")),
        ),
    ]
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=configured_backends,
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=user_manager_class or PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
        ),
        include_users=include_users,
        login_identifier=login_identifier,
        superuser_role_name=superuser_role_name,
    )


def test_litestar_auth_init_delegates_to_validate_config() -> None:
    """Plugin construction keeps validation ownership inside the facade."""
    config = _minimal_config()

    with patch("litestar_auth.plugin.validate_config") as validate_config_mock:
        LitestarAuth(config)

    validate_config_mock.assert_called_once_with(config)


def test_on_app_init_runs_lifecycle_steps_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """App init runs startup warnings, key validation, and registration steps in order."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig()
    calls: list[str] = []

    monkeypatch.setattr(
        "litestar_auth.plugin.warn_insecure_plugin_startup_defaults",
        lambda _config: calls.append("warn"),
    )
    monkeypatch.setattr(
        "litestar_auth.plugin.require_oauth_token_encryption_for_configured_providers",
        lambda **_kwargs: calls.append("require-oauth-key"),
    )
    monkeypatch.setattr(
        "litestar_auth.plugin.require_secure_oauth_redirect_in_production",
        lambda **_kwargs: calls.append("require-oauth-redirect"),
    )
    monkeypatch.setattr(
        "litestar_auth.plugin.bootstrap_bundled_token_orm_models",
        lambda _config: calls.append("bootstrap-token-models"),
    )
    monkeypatch.setattr(plugin, "_register_dependencies", lambda _app_config: calls.append("dependencies"))
    monkeypatch.setattr(plugin, "_register_middleware", lambda _app_config: calls.append("middleware"))
    monkeypatch.setattr(
        plugin,
        "_register_openapi_security",
        lambda _app_config: (calls.append("openapi-security"), None)[1],
    )
    monkeypatch.setattr(
        plugin,
        "_register_controllers",
        lambda _app_config, *, security=None: calls.append("controllers") or [],  # noqa: ARG005
    )
    monkeypatch.setattr(plugin, "_register_exception_handlers", lambda _route_handlers: calls.append("exceptions"))

    result = plugin.on_app_init(app_config)

    assert result is app_config
    assert calls == [
        "warn",
        "require-oauth-key",
        "require-oauth-redirect",
        "bootstrap-token-models",
        "dependencies",
        "middleware",
        "openapi-security",
        "controllers",
        "exceptions",
    ]


def test_register_openapi_security_disabled_returns_none() -> None:
    """When include_openapi_security is False, _register_openapi_security returns None."""
    config = _minimal_config()
    config.include_openapi_security = False
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    result = plugin._register_openapi_security(app_config)

    assert result is None


def test_on_app_init_registers_middleware_controllers_dependencies_and_exceptions() -> None:
    """App init mutates AppConfig with the orchestrator's core wiring."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie",
        transport=CookieTransport(cookie_name="authcookie", path="/auth", secure=False, samesite="strict"),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie-plugin")),
    )
    config = _minimal_config(backends=[backend], include_users=True)
    config.csrf_secret = "c" * 32
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    result = plugin.on_app_init(app_config)

    assert result is app_config
    assert DEFAULT_CONFIG_DEPENDENCY_KEY in result.dependencies
    assert DEFAULT_USER_MANAGER_DEPENDENCY_KEY in result.dependencies
    assert DEFAULT_BACKENDS_DEPENDENCY_KEY in result.dependencies
    assert DEFAULT_USER_MODEL_DEPENDENCY_KEY in result.dependencies
    assert "db_session" in result.dependencies
    assert result.route_handlers
    auth_controller = next(handler for handler in result.route_handlers if getattr(handler, "path", None) == "/auth")
    assert not result.exception_handlers or ClientException not in result.exception_handlers
    auth_handler = cast("Any", auth_controller).exception_handlers[ClientException]
    assert auth_handler.__name__ == client_exception_handler.__name__
    assert auth_handler.__module__ == client_exception_handler.__module__
    assert isinstance(result.csrf_config, CSRFConfig)
    assert result.csrf_config.cookie_name == DEFAULT_CSRF_COOKIE_NAME
    assert result.csrf_config.cookie_path == "/auth"
    assert result.csrf_config.cookie_secure is False
    assert result.csrf_config.cookie_samesite == "strict"

    middleware = result.middleware[0]
    assert isinstance(middleware, DefineMiddleware)
    assert getattr(middleware.middleware, "__name__", "") == LitestarAuthMiddleware.__name__
    assert middleware.kwargs["authenticator_factory"] == plugin._build_authenticator
    assert middleware.kwargs["auth_cookie_names"] == frozenset({b"authcookie", b"authcookie_refresh"})
    assert middleware.kwargs["superuser_role_name"] == "superuser"

    session_getter = middleware.kwargs["get_request_session"]
    assert isinstance(session_getter, partial)
    assert session_getter.func.__name__ == "get_or_create_scoped_session"


def test_on_app_init_bootstraps_bundled_token_models_for_db_token_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """App init uses the models-layer token bootstrap hook for the canonical DB-token preset."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=plugin_module._plugin_config.DatabaseTokenAuthConfig(
            token_hash_secret="a" * 40,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )
    plugin = LitestarAuth(config)
    bootstrap_calls: list[object] = []

    def _record_bootstrap(configured_config: object) -> None:
        bootstrap_calls.append(configured_config)

    monkeypatch.setattr("litestar_auth.plugin.bootstrap_bundled_token_orm_models", _record_bootstrap)

    plugin.on_app_init(AppConfig())

    assert bootstrap_calls == [config]


def test_bundled_token_bootstrap_loader_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """The startup loader only resolves the models-layer bootstrap helper once per process."""

    class _ModelsModule:
        def __init__(self) -> None:
            self.calls = 0

        def import_token_orm_models(self) -> tuple[type[object], type[object]]:
            self.calls += 1
            return object, object

    models_module = _ModelsModule()
    startup_module._load_bundled_token_orm_models.cache_clear()
    monkeypatch.setattr(startup_module.importlib, "import_module", lambda _name: models_module)

    first_result = startup_module._load_bundled_token_orm_models()
    second_result = startup_module._load_bundled_token_orm_models()

    assert first_result == (object, object)
    assert second_result == first_result
    assert models_module.calls == 1
    startup_module._load_bundled_token_orm_models.cache_clear()


def test_bundled_token_bootstrap_detection_skips_custom_token_models() -> None:
    """Startup bootstrap detection skips app-owned token model contracts.

    Uses two backends so that after the first DB-token backend's bundled-model
    check returns False, the for-loop continues to the next iteration. This
    exercises the "custom-models -> next backend" branch in
    ``_uses_bundled_database_token_models``.
    """

    class AppAccessToken:
        token = None
        created_at = None
        user_id = None
        user = None

    class AppRefreshToken:
        token = None
        created_at = None
        user_id = None
        user = None

    custom_strategy = DatabaseTokenStrategy(
        session=cast("Any", object()),
        token_hash_secret="x" * 40,
        token_models=DatabaseTokenModels(
            access_token_model=AppAccessToken,
            refresh_token_model=AppRefreshToken,
        ),
    )
    custom_backend = AuthenticationBackend[ExampleUser, UUID](
        name="database",
        transport=BearerTransport(),
        strategy=cast("Any", custom_strategy),
    )
    other_backend = AuthenticationBackend[ExampleUser, UUID](
        name="other",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="other")),
    )
    config = _minimal_config(backends=[custom_backend, other_backend])

    assert plugin_module._plugin_config._uses_bundled_database_token_models(config) is False


def test_on_app_init_warns_for_nondurable_jwt_strategy_when_acknowledged() -> None:
    """Lifecycle startup still surfaces the JWT durability warning after explicit opt-in."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="jwt-backend",
        transport=CookieTransport(),
        strategy=cast("Any", JWTStrategy(secret="a" * 32, algorithm="HS256")),
    )
    config = _minimal_config(backends=[backend])
    config.allow_nondurable_jwt_revocation = True
    config.csrf_secret = "c" * 32
    plugin = LitestarAuth(config)

    with pytest.warns(SecurityWarning, match="process-local in-memory denylist"):
        plugin.on_app_init(AppConfig())


def test_on_app_init_warns_security_warning_for_inmemory_rate_limiter_in_production() -> None:
    """Production app init emits SecurityWarning when rate-limit state is process-local."""
    config = _minimal_config()
    config.rate_limit_config = AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
            scope="ip",
            namespace="login",
        ),
    )
    plugin = LitestarAuth(config)

    with pytest.warns(SecurityWarning, match="process-local in-memory backend"):
        plugin.on_app_init(AppConfig())


def test_on_app_init_does_not_warn_for_redis_rate_limiter(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Shared Redis-backed rate limiting stays silent during app init."""

    def load_redis_asyncio() -> object:
        return object()

    monkeypatch.setattr("litestar_auth.ratelimit._load_redis_asyncio", load_redis_asyncio)

    config = _minimal_config()
    config.rate_limit_config = AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=RedisRateLimiter(
                redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
                max_attempts=3,
                window_seconds=60,
            ),
            scope="ip",
            namespace="login",
        ),
    )
    plugin = LitestarAuth(config)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        plugin.on_app_init(AppConfig())

    assert not any(issubclass(record.category, SecurityWarning) for record in records)


def test_on_app_init_does_not_warn_for_inmemory_rate_limiter_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing-mode lifecycle suppresses the in-memory rate-limit startup warning."""
    config = _minimal_config()
    config.unsafe_testing = True
    config.rate_limit_config = AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
            scope="ip",
            namespace="login",
        ),
    )
    plugin = LitestarAuth(config)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        plugin.on_app_init(AppConfig())

    assert not any(issubclass(record.category, SecurityWarning) for record in records)


def test_on_app_init_rejects_mismatched_cookie_transport_settings() -> None:
    """Lifecycle middleware registration still rejects incompatible cookie transport shapes."""
    first_backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-primary",
        transport=CookieTransport(path="/auth"),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie-primary")),
    )
    second_backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-secondary",
        transport=CookieTransport(path="/other-auth"),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie-secondary")),
    )
    config = _minimal_config(backends=[first_backend, second_backend])
    config.csrf_secret = "c" * 32
    plugin = LitestarAuth(config)

    with pytest.raises(ValueError, match="must share path, domain, secure, and samesite"):
        plugin.on_app_init(AppConfig())


def test_on_app_init_accepts_multiple_matching_cookie_transports() -> None:
    """Matching cookie transports share one orchestrator-managed CSRF config."""
    backends = [
        AuthenticationBackend[ExampleUser, UUID](
            name=f"cookie-{index}",
            transport=CookieTransport(path="/auth", secure=False, samesite="strict"),
            strategy=cast("Any", InMemoryTokenStrategy(token_prefix=f"cookie-{index}")),
        )
        for index in range(3)
    ]
    config = _minimal_config(backends=backends)
    config.csrf_secret = "c" * 32
    plugin = LitestarAuth(config)

    result = plugin.on_app_init(AppConfig())

    assert result.csrf_config is not None
    assert result.csrf_config.cookie_path == "/auth"
    assert result.csrf_config.cookie_samesite == "strict"


def test_on_app_init_requires_oauth_token_encryption_key_for_oauth_providers() -> None:
    """OAuth-enabled startup fails closed without an encryption key in non-test runtime."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
    )
    plugin = LitestarAuth(config)

    with (
        pytest.warns(SecurityWarning, match="oauth_token_encryption_key is not set"),
        pytest.raises(Exception, match=r"Fernet\.generate_key\(\)") as exc_info,
    ):
        plugin.on_app_init(AppConfig())

    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_on_app_init_allows_oauth_providers_when_encryption_key_is_configured() -> None:
    """Configured OAuth encryption keys keep app-init startup guard silent."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        result = plugin.on_app_init(AppConfig())

    assert result is not None
    assert not any(issubclass(record.category, SecurityWarning) for record in records)


@pytest.mark.parametrize(
    ("redirect_base_url", "message"),
    [
        pytest.param(
            "http://app.example.com/auth",
            "public HTTPS origin",
            id="public-http-origin",
        ),
        pytest.param(
            "https://localhost/auth",
            "non-loopback public HTTPS origin",
            id="loopback-https-origin",
        ),
        pytest.param(
            "https://user@app.example.com/auth",
            "without userinfo, query, or fragment",
            id="userinfo-origin",
        ),
        pytest.param(
            "https://app.example.com/auth?next=/dashboard",
            "without userinfo, query, or fragment",
            id="query-origin",
        ),
        pytest.param(
            "https://app.example.com/auth#callback",
            "without userinfo, query, or fragment",
            id="fragment-origin",
        ),
    ],
)
def test_on_app_init_rejects_insecure_oauth_redirect_origins_in_production(
    redirect_base_url: str,
    message: str,
) -> None:
    """Production app init fails closed for insecure plugin-owned OAuth redirect bases."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_redirect_base_url=redirect_base_url,
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match=message):
        plugin.on_app_init(AppConfig(debug=False))


def test_on_app_init_allows_loopback_oauth_redirect_origin_in_debug_mode() -> None:
    """Debug mode preserves explicit localhost OAuth plugin recipes."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_redirect_base_url="http://localhost/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)

    result = plugin.on_app_init(AppConfig(debug=True))

    assert result is not None


def test_on_app_init_warns_security_warning_for_inmemory_totp_used_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production startup warns when the TOTP replay store is process-local."""
    config = _minimal_config()
    config.totp_config = TotpConfig(
        totp_pending_secret="x" * 32,
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
        totp_enrollment_store=InMemoryTotpEnrollmentStore(),
    )
    config.user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="verify-secret-12345678901234567890",
        reset_password_token_secret="reset-secret-123456789012345678901",
        totp_secret_key=Fernet.generate_key().decode(),
        id_parser=UUID,
    )
    plugin = LitestarAuth(config)

    with pytest.warns(SecurityWarning, match="InMemoryUsedTotpCodeStore"):
        plugin.on_app_init(AppConfig())


def test_on_app_init_allows_missing_oauth_token_encryption_key_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode bypasses the OAuth token-encryption startup guard."""
    config = _minimal_config()
    config.unsafe_testing = True
    config.oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
    )
    plugin = LitestarAuth(config)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        result = plugin.on_app_init(AppConfig())

    assert result is not None
    assert not any(issubclass(record.category, SecurityWarning) for record in records)


def test_on_app_init_testing_recipe_suppresses_single_process_security_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit unsafe testing keeps the documented single-process recipe warning-free."""
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="cookie",
                transport=CookieTransport(secure=False),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie-testing")),
            ),
            AuthenticationBackend[ExampleUser, UUID](
                name="jwt",
                transport=BearerTransport(),
                strategy=cast("Any", JWTStrategy(secret="a" * 32, algorithm="HS256")),
            ),
        ],
    )
    config.unsafe_testing = True
    config.csrf_secret = "c" * 32
    config.oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
    )
    config.rate_limit_config = AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
            scope="ip",
            namespace="login",
        ),
    )
    config.totp_config = TotpConfig(
        totp_pending_secret="x" * 32,
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
        totp_enrollment_store=InMemoryTotpEnrollmentStore(),
    )
    config.user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="verify-secret-12345678901234567890",
        reset_password_token_secret="reset-secret-123456789012345678901",
        totp_secret_key=Fernet.generate_key().decode(),
        id_parser=UUID,
    )
    plugin = LitestarAuth(config)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        result = plugin.on_app_init(AppConfig())

    assert result is not None
    assert not any(issubclass(record.category, SecurityWarning) for record in records)


def test_register_dependencies_delegates_with_bound_provider_methods() -> None:
    """Dependency registration passes the plugin's bound provider methods through unchanged."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig()

    with patch("litestar_auth.plugin.register_dependencies") as register_dependencies_mock:
        plugin._register_dependencies(app_config)

    register_dependencies_mock.assert_called_once()
    _, config_arg = register_dependencies_mock.call_args.args
    providers = cast("DependencyProviders", register_dependencies_mock.call_args.kwargs["providers"])

    assert config_arg is plugin.config
    assert cast("Any", providers.config)() is plugin.config
    assert providers.user_manager is plugin._provide_user_manager
    assert providers.backends is plugin._provide_request_backends
    assert cast("Any", providers.user_model)() is plugin.config.user_model
    assert providers.oauth_associate_user_manager is plugin._provide_oauth_associate_user_manager
    assert providers.oauth_associate_user_manager is not providers.user_manager


def test_register_dependencies_registers_db_session_when_using_builtin_session_maker() -> None:
    """Dependency helpers publish the plugin-owned DB session provider when needed."""
    app_config = AppConfig()
    app_config.dependencies = {}
    config = _minimal_config()
    config.db_session_dependency_key = "my_db_session"

    async def _provide_config() -> object:
        await asyncio.sleep(0)
        return config

    async def _provide_user_manager() -> object:
        await asyncio.sleep(0)
        yield object()

    async def _provide_backends() -> object:
        await asyncio.sleep(0)
        return ()

    async def _provide_user_model() -> object:
        await asyncio.sleep(0)
        return ExampleUser

    async def _provide_oauth_associate() -> object:
        await asyncio.sleep(0)
        yield object()

    register_dependencies(
        app_config,
        config,
        providers=DependencyProviders(
            config=_provide_config,
            user_manager=_provide_user_manager,
            backends=_provide_backends,
            user_model=_provide_user_model,
            oauth_associate_user_manager=_provide_oauth_associate,
        ),
    )

    assert "my_db_session" in app_config.dependencies


def test_register_dependencies_skips_builtin_db_session_when_external_declared() -> None:
    """Dependency helpers avoid registering a conflicting DB-session provider."""
    app_config = AppConfig()
    app_config.dependencies = {}
    config = _minimal_config()
    config.db_session_dependency_provided_externally = True

    async def _provide_config() -> object:
        await asyncio.sleep(0)
        return config

    async def _provide_user_manager() -> object:
        await asyncio.sleep(0)
        yield object()

    async def _provide_backends() -> object:
        await asyncio.sleep(0)
        return ()

    async def _provide_user_model() -> object:
        await asyncio.sleep(0)
        return ExampleUser

    async def _provide_oauth_associate() -> object:
        await asyncio.sleep(0)
        yield object()

    register_dependencies(
        app_config,
        config,
        providers=DependencyProviders(
            config=_provide_config,
            user_manager=_provide_user_manager,
            backends=_provide_backends,
            user_model=_provide_user_model,
            oauth_associate_user_manager=_provide_oauth_associate,
        ),
    )

    assert config.db_session_dependency_key not in app_config.dependencies


def test_register_exception_handlers_delegates_to_shared_registration_function() -> None:
    """Exception-handler registration goes through the shared dependency helper."""
    plugin = LitestarAuth(_minimal_config())
    route_handlers = [cast("Any", object())]

    with patch("litestar_auth.plugin.register_exception_handlers") as register_handlers_mock:
        plugin._register_exception_handlers(route_handlers)

    register_handlers_mock.assert_called_once_with(route_handlers, exception_response_hook=None)


def test_register_controllers_extends_route_handlers() -> None:
    """Controller registration appends the shared controller set onto AppConfig."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig()
    app_config.route_handlers.append(cast("Any", "existing"))

    with patch("litestar_auth.plugin.build_controllers", return_value=["new-controller"]) as build_controllers_mock:
        controllers = plugin._register_controllers(app_config)

    assert controllers == ["new-controller"]
    assert app_config.route_handlers == ["existing", "new-controller"]
    build_controllers_mock.assert_called_once_with(plugin.config, security=None)


def test_on_app_init_registers_exception_handlers_for_all_app_route_handlers() -> None:
    """App init lets the shared helper filter the full route handler inventory."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig(route_handlers=[cast("Any", "existing-route")])
    new_controllers = [cast("Any", "plugin-controller")]

    with (
        patch("litestar_auth.plugin.warn_insecure_plugin_startup_defaults"),
        patch("litestar_auth.plugin.require_oauth_token_encryption_for_configured_providers"),
        patch("litestar_auth.plugin.require_secure_oauth_redirect_in_production"),
        patch("litestar_auth.plugin.bootstrap_bundled_token_orm_models"),
        patch.object(plugin, "_register_dependencies"),
        patch.object(plugin, "_register_middleware"),
        patch("litestar_auth.plugin.build_controllers", return_value=new_controllers),
        patch("litestar_auth.plugin.register_exception_handlers") as register_handlers_mock,
    ):
        plugin.on_app_init(app_config)

    assert app_config.route_handlers == ["existing-route", "plugin-controller"]
    register_handlers_mock.assert_called_once_with(app_config.route_handlers, exception_response_hook=None)


@dataclass(slots=True)
class _ScopedProxyRecorder:
    user_db: object
    oauth_token_encryption: object | None


@dataclass(slots=True)
class _FakeSessionBoundBackend:
    strategy: object
    name: str = "fake"
    transport: object | None = None
    bound_session: object | None = None

    def with_session(self, session: object) -> _FakeSessionBoundBackend:
        self.bound_session = session
        return self


@dataclass(slots=True)
class _InvalidationStrategy:
    invalidate_all_tokens: AsyncMock

    def with_session(self, _session: object) -> _InvalidationStrategy:
        return self


EXPECTED_BOUND_BACKEND_COUNT = 2


def test_build_user_manager_wraps_user_db_and_passes_bound_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    """Custom factories receive the bounded build contract and own extra manager wiring."""
    plugin = LitestarAuth(_minimal_config())
    session = object()
    raw_user_db = object()
    captured: dict[str, object] = {}
    plugin.config.password_validator_factory = lambda _config: lambda _password: None

    plugin.config.user_db_factory = lambda configured_session: raw_user_db if configured_session is session else None  # ty:ignore[invalid-assignment]
    monkeypatch.setattr("litestar_auth.plugin.ScopedUserDatabaseProxyImpl", _ScopedProxyRecorder)
    monkeypatch.setattr(
        plugin,
        "_session_bound_backends",
        lambda configured_session: [f"backend-for-{id(configured_session)}"],
    )

    def _factory(**kwargs: object) -> object:
        captured.update(kwargs)
        return "manager"

    plugin._user_manager_factory = _factory

    manager = plugin._build_user_manager(cast("Any", session))

    assert manager == "manager"
    assert set(captured) == {"session", "user_db", "config", "backends", "skip_reuse_warning"}
    assert captured["session"] is session
    assert captured["config"] is plugin.config
    assert captured["user_db"] == _ScopedProxyRecorder(
        user_db=raw_user_db,
        oauth_token_encryption=plugin._oauth_token_encryption,
    )
    assert captured["backends"] == (f"backend-for-{id(session)}",)


def test_build_user_manager_attaches_session_bound_backends() -> None:
    """Built managers receive request-local backends bound to the active session."""
    config = _minimal_config(
        backends=[
            cast("AuthenticationBackend[ExampleUser, UUID]", _FakeSessionBoundBackend(strategy=object())),
            cast("AuthenticationBackend[ExampleUser, UUID]", _FakeSessionBoundBackend(strategy=object())),
        ],
    )
    plugin = LitestarAuth(config)

    session = object()
    manager = plugin._build_user_manager(cast("Any", session))

    assert len(manager.backends) == EXPECTED_BOUND_BACKEND_COUNT
    assert all(getattr(backend, "bound_session", None) is session for backend in manager.backends)


def test_build_user_manager_passes_login_identifier_from_config() -> None:
    """Session-bound manager construction forwards login_identifier from plugin config."""
    plugin = LitestarAuth(_minimal_config(login_identifier="username"))

    manager = plugin._build_user_manager(cast("Any", object()))

    assert manager.login_identifier == "username"


def test_build_user_manager_passes_superuser_role_name_from_config() -> None:
    """Session-bound manager construction forwards the normalized superuser role name."""
    plugin = LitestarAuth(_minimal_config(superuser_role_name=" Admin "))

    manager = plugin._build_user_manager(cast("Any", object()))

    assert manager.superuser_role_name == "admin"


def test_build_user_manager_uses_plugin_warning_owner_for_default_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bundled manager builder passes the explicit reused-secret skip flag."""
    plugin = LitestarAuth(_minimal_config())
    captured: list[bool] = []

    def _record_factory(**kwargs: object) -> object:
        captured.append(cast("bool", kwargs["skip_reuse_warning"]))
        return plugin_module._plugin_config.build_user_manager(**kwargs)

    monkeypatch.setattr(plugin, "_user_manager_factory", _record_factory)

    plugin._build_user_manager(cast("Any", DummySession()))

    assert captured == [True]


def test_build_user_manager_uses_plugin_warning_owner_baseline_for_custom_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Custom factories receive the explicit reused-secret skip flag from the plugin."""
    plugin = LitestarAuth(_minimal_config())
    captured: list[bool] = []

    def _record_factory(**kwargs: object) -> object:
        captured.append(cast("bool", kwargs["skip_reuse_warning"]))
        return "manager"

    monkeypatch.setattr(plugin, "_user_manager_factory", _record_factory)

    manager = plugin._build_user_manager(cast("Any", DummySession()))

    assert manager == "manager"
    assert captured == [True]


def test_build_user_manager_passes_typed_security_to_security_only_manager() -> None:
    """Plugin-owned construction forwards the typed security bundle end-to-end when supported."""

    class _SecurityOnlyManager(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            security: UserManagerSecurity[UUID],
            password_validator: object | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME,
            skip_reuse_warning: bool = False,
            unsafe_testing: bool = False,
        ) -> None:
            self.received_security = security
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=cast("Any", password_validator),
                backends=backends,
                login_identifier=login_identifier,
                superuser_role_name=superuser_role_name,
                skip_reuse_warning=skip_reuse_warning,
                unsafe_testing=unsafe_testing,
            )

    backend = _FakeSessionBoundBackend(strategy=object())
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[cast("AuthenticationBackend[ExampleUser, UUID]", backend)],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=_SecurityOnlyManager,
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            password_helper=PasswordHelper(),
        ),
        id_parser=UUID,
        login_identifier="username",
    )
    plugin = LitestarAuth(config)
    session = object()

    manager = plugin._build_user_manager(cast("Any", session))
    typed_manager = cast("Any", manager)

    assert typed_manager.received_security.verification_token_secret == "verify-secret-12345678901234567890"
    assert typed_manager.received_security.reset_password_token_secret == "reset-secret-123456789012345678901"
    assert typed_manager.received_security.id_parser is UUID
    assert manager.id_parser is UUID
    assert manager.login_identifier == "username"
    assert len(manager.backends) == 1
    assert manager.backends[0] is cast("Any", backend)
    assert backend.bound_session is session


def test_build_user_manager_uses_explicit_password_validator_factory() -> None:
    """Session-bound manager construction respects explicit password-validator factories."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: lambda password: require_password_length(password, 10)
    plugin = LitestarAuth(config)

    manager = plugin._build_user_manager(cast("Any", object()))

    assert manager.password_validator is not None
    with pytest.raises(ValueError, match="at least 10"):
        manager.password_validator("short")


def test_build_user_manager_allows_nonstandard_manager_contract_through_factory() -> None:
    """`user_manager_factory` remains the escape hatch for non-canonical constructors."""

    class LegacyManagerWithoutSecurity(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            password_validator: object | None = None,
            verification_token_secret: str,
            reset_password_token_secret: str,
            id_parser: Callable[[str], UUID] | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                password_validator=cast("Any", password_validator),
                security=UserManagerSecurity[UUID](
                    verification_token_secret=verification_token_secret,
                    reset_password_token_secret=reset_password_token_secret,
                    id_parser=id_parser,
                ),
                backends=backends,
                login_identifier=login_identifier,
            )

    config = _minimal_config(user_manager_class=LegacyManagerWithoutSecurity, login_identifier="username")
    config.password_validator_factory = lambda _config: lambda password: require_password_length(password, 10)

    def _factory(**kwargs: object) -> LegacyManagerWithoutSecurity:
        session_config = cast("LitestarAuthConfig[ExampleUser, UUID]", kwargs["config"])
        security = session_config.user_manager_security
        assert security is not None
        return LegacyManagerWithoutSecurity(
            cast("Any", kwargs["user_db"]),
            password_helper=session_config.resolve_password_helper(),
            password_validator=plugin_module._plugin_config.resolve_password_validator(session_config),
            verification_token_secret=cast("str", security.verification_token_secret),
            reset_password_token_secret=cast("str", security.reset_password_token_secret),
            id_parser=session_config.id_parser,
            backends=cast("tuple[object, ...]", kwargs["backends"]),
            login_identifier=session_config.login_identifier,
        )

    config.user_manager_factory = _factory
    plugin = LitestarAuth(config)

    manager = plugin._build_user_manager(cast("Any", object()))

    assert isinstance(manager, LegacyManagerWithoutSecurity)
    assert manager.id_parser is UUID
    assert manager.login_identifier == "username"
    assert manager.password_validator is not None
    with pytest.raises(ValueError, match="at least 10"):
        manager.password_validator("short")


@pytest.mark.asyncio
async def test_session_bound_user_manager_update_triggers_strategy_invalidation_on_email_change() -> None:
    """Session-bound managers revoke backend sessions after sensitive updates."""
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=PasswordHelper().hash("correct-password"),
    )
    user_db = InMemoryUserDatabase([user])
    invalidate_mock = AsyncMock()
    backend = _FakeSessionBoundBackend(strategy=_InvalidationStrategy(invalidate_all_tokens=invalidate_mock))
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[cast("AuthenticationBackend[ExampleUser, UUID]", backend)],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )
    plugin = LitestarAuth(config)

    manager = plugin._build_user_manager(cast("Any", DummySession()))
    await manager.update({"email": "updated@example.com"}, user)

    invalidate_mock.assert_awaited_once()


def test_session_bound_user_manager_uses_explicit_account_state_validator_contract() -> None:
    """Session-bound managers preserve the configured account-state validator contract."""
    calls: list[tuple[ExampleUser, bool]] = []

    class _TrackingManager(PluginUserManager):
        def require_account_state(self, user: ExampleUser, *, require_verified: bool = False) -> None:
            del self
            calls.append((user, require_verified))

    plugin = LitestarAuth(_minimal_config(user_manager_class=_TrackingManager))
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=PasswordHelper().hash("correct-password"),
    )

    manager = plugin._build_user_manager(cast("Any", DummySession()))
    manager.require_account_state(user, require_verified=True)

    assert calls == [(user, True)]


def test_session_bound_backends_rebinds_each_backend_to_current_session() -> None:
    """Configured backends are rebound against the request-local session."""

    @dataclass(slots=True)
    class _BackendRecorder:
        name: str
        seen_sessions: list[object]
        transport: object | None = None
        strategy: object | None = None

        def with_session(self, session: object) -> str:
            self.seen_sessions.append(session)
            return f"{self.name}-{id(session)}"

    first_backend = _BackendRecorder(name="first", seen_sessions=[])
    second_backend = _BackendRecorder(name="second", seen_sessions=[])
    plugin = LitestarAuth(_minimal_config(backends=cast("Any", [first_backend, second_backend])))
    session = object()

    rebound_backends = plugin._session_bound_backends(cast("Any", session))

    assert rebound_backends == [f"first-{id(session)}", f"second-{id(session)}"]
    assert first_backend.seen_sessions == [session]
    assert second_backend.seen_sessions == [session]


def test_session_bound_backends_rebinds_database_token_backends_in_order_and_preserves_names() -> None:
    """Canonical DB bearer backends keep public names/order while rebinding strategies per request."""
    database_token_strategy_type = _current_database_token_strategy_type()
    authentication_backend_type = _current_authentication_backend_type()
    first_backend = authentication_backend_type(
        name="primary",
        transport=BearerTransport(),
        strategy=database_token_strategy_type(
            session=cast("Any", object()),
            token_hash_secret="a" * 40,
            max_age=timedelta(minutes=10),
        ),
    )
    second_strategy = database_token_strategy_type(
        session=cast("Any", object()),
        token_hash_secret="b" * 40,
        refresh_max_age=timedelta(days=14),
        accept_legacy_plaintext_tokens=True,
    )
    second_backend = authentication_backend_type(
        name="secondary",
        transport=BearerTransport(),
        strategy=second_strategy,
    )
    config = _minimal_config(backends=[first_backend, second_backend])
    config.allow_legacy_plaintext_tokens = True
    plugin = LitestarAuth(config)
    active_session = object()

    rebound_backends = plugin._session_bound_backends(cast("Any", active_session))

    assert [backend.name for backend in rebound_backends] == ["primary", "secondary"]
    assert isinstance(rebound_backends[0], authentication_backend_type)
    assert isinstance(rebound_backends[1], authentication_backend_type)
    assert rebound_backends[0] is not first_backend
    assert rebound_backends[1] is not second_backend
    assert rebound_backends[0].transport is first_backend.transport
    assert rebound_backends[1].transport is second_backend.transport
    assert isinstance(rebound_backends[0].strategy, database_token_strategy_type)
    assert isinstance(rebound_backends[1].strategy, database_token_strategy_type)
    assert rebound_backends[0].strategy.session is active_session
    assert rebound_backends[1].strategy.session is active_session
    assert rebound_backends[1].strategy.refresh_max_age == second_strategy.refresh_max_age
    assert rebound_backends[1].strategy.accept_legacy_plaintext_tokens is True


def test_session_bound_backends_realizes_database_token_preset_from_request_session() -> None:
    """The DB bearer preset resolves request-scoped backends without a startup session template."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=plugin_module._plugin_config.DatabaseTokenAuthConfig(
            token_hash_secret="a" * 40,
            max_age=timedelta(minutes=10),
            refresh_max_age=timedelta(days=14),
            accept_legacy_plaintext_tokens=True,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
        enable_refresh=True,
    )
    config.allow_legacy_plaintext_tokens = True
    plugin = LitestarAuth(config)
    active_session = type("_ActiveSession", (), {"marker": "request-session"})()
    startup_backend_template_type = _current_startup_backend_template_type()
    database_token_strategy_type = _current_database_token_strategy_type()
    authentication_backend_type = _current_authentication_backend_type()

    rebound_backends = plugin._session_bound_backends(cast("Any", active_session))
    template_backend = config.resolve_startup_backends()[0]
    template_strategy = cast("Any", template_backend.strategy)
    rebound_strategy = cast("Any", rebound_backends[0].strategy)

    assert [backend.name for backend in rebound_backends] == ["database"]
    assert isinstance(template_backend, startup_backend_template_type)
    assert isinstance(rebound_backends[0], authentication_backend_type)
    assert rebound_backends[0] is not template_backend
    assert isinstance(template_strategy, database_token_strategy_type)
    assert isinstance(rebound_strategy, database_token_strategy_type)
    assert rebound_strategy.session is active_session
    assert rebound_strategy.refresh_max_age == timedelta(days=14)
    assert rebound_strategy.accept_legacy_plaintext_tokens is True


def test_build_authenticator_uses_session_bound_backends_and_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """Authenticator construction reuses the session-bound backends and manager instance."""
    plugin = LitestarAuth(_minimal_config())
    session = object()
    expected_backends = ["backend"]
    manager = object()

    monkeypatch.setattr(
        plugin,
        "_session_bound_backends",
        lambda configured_session: expected_backends if configured_session is session else [],
    )
    monkeypatch.setattr(
        plugin,
        "_build_user_manager",
        lambda configured_session, *, backends=None: (
            manager if configured_session is session and backends == expected_backends else None
        ),
    )

    authenticator = plugin._build_authenticator(cast("Any", session))

    assert isinstance(authenticator, Authenticator)
    assert authenticator.backends is expected_backends
    assert authenticator.user_manager is manager


def test_register_middleware_without_cookie_transports_skips_csrf_registration() -> None:
    """Bearer-only setups still register middleware without creating CSRF config."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig()

    plugin._register_middleware(app_config)

    assert app_config.csrf_config is None
    middleware = app_config.middleware[0]
    assert isinstance(middleware, DefineMiddleware)
    assert middleware.kwargs["auth_cookie_names"] == frozenset()
    assert middleware.kwargs["superuser_role_name"] == "superuser"


def test_resolve_account_state_validator_delegates_to_shared_validation_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The orchestrator resolves manager-class account-state checks through the shared helper."""
    plugin = LitestarAuth(_minimal_config())

    def _sentinel_validator(_user: ExampleUser, *, require_verified: bool = False) -> None:
        del _user, require_verified

    seen_manager_classes: list[type[object]] = []

    def _resolve(manager_class: type[object]) -> object:
        seen_manager_classes.append(manager_class)
        return _sentinel_validator

    monkeypatch.setattr(plugin_module, "resolve_user_manager_account_state_validator", _resolve)

    validator = plugin._resolve_account_state_validator()

    assert validator is _sentinel_validator
    assert seen_manager_classes == [plugin.config.user_manager_class]


def test_resolve_account_state_validator_returns_callable_account_state_contract() -> None:
    """The plugin resolves the supported `require_account_state(user, *, require_verified=...)` callable."""
    calls: list[tuple[ExampleUser, bool]] = []
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=PasswordHelper().hash("correct-password"),
    )

    class _CallableValidatorManager:
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            security: UserManagerSecurity[UUID] | None = None,
            password_validator: object | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME,
            unsafe_testing: bool = False,
        ) -> None:
            del (
                user_db,
                password_helper,
                security,
                password_validator,
                backends,
                login_identifier,
                superuser_role_name,
                unsafe_testing,
            )

        @staticmethod
        async def authenticate(identifier: str, password: str) -> None:
            del identifier, password

        @staticmethod
        def require_account_state(user: ExampleUser, *, require_verified: bool = False) -> None:
            calls.append((user, require_verified))

    plugin = LitestarAuth(_minimal_config(user_manager_class=_CallableValidatorManager))

    validator = plugin._resolve_account_state_validator()

    validator(user, require_verified=True)

    assert calls == [(user, True)]


def test_resolve_account_state_validator_raises_for_missing_callable() -> None:
    """Manager classes without a callable validator fail with a contract error."""

    class _MissingValidatorManager(PluginUserManager):
        require_account_state = None

    plugin = LitestarAuth(_minimal_config())
    plugin.config.user_manager_class = _MissingValidatorManager

    with pytest.raises(TypeError, match="require_account_state"):
        plugin._resolve_account_state_validator()


def test_provider_helpers_return_configured_objects() -> None:
    """Provider helpers expose the config values used by dependency registration."""
    plugin = LitestarAuth(_minimal_config())
    provided_backends = plugin._provide_backends()
    startup_backend_template_type = _current_startup_backend_template_type()

    assert all(isinstance(backend, startup_backend_template_type) for backend in provided_backends)
    assert [backend.name for backend in provided_backends] == [backend.name for backend in plugin.config.backends]
    assert plugin._provide_config() is plugin.config
    assert plugin._provide_user_model() is plugin.config.user_model


def test_provider_helpers_return_startup_templates_for_database_token_preset() -> None:
    """Provider helpers expose startup-only templates for the canonical DB-token preset."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=plugin_module._plugin_config.DatabaseTokenAuthConfig(
            token_hash_secret="a" * 40,
            backend_name="opaque-db",
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )
    plugin = LitestarAuth(config)
    startup_backend_template_type = _current_startup_backend_template_type()

    provided_backends = plugin._provide_backends()

    assert len(provided_backends) == 1
    assert isinstance(provided_backends[0], startup_backend_template_type)
    assert provided_backends[0].name == "opaque-db"


@pytest.mark.asyncio
async def test_provide_user_manager_respects_custom_db_session_key() -> None:
    """Provider wrapper parameter names follow db_session_dependency_key."""
    config = _minimal_config()
    config.db_session_dependency_key = "custom_db"
    plugin = LitestarAuth(config)
    session = DummySession()

    gen = cast("Any", plugin._provide_user_manager(custom_db=session))
    try:
        manager = await anext(gen)
        assert manager is not None
    finally:
        await gen.aclose()


def test_provide_request_backends_respects_custom_db_session_key() -> None:
    """Backends DI resolves request-scoped backends through the configured session key."""

    @dataclass(slots=True)
    class _BackendRecorder:
        seen_sessions: list[object]
        name: str = "recorder"
        transport: object | None = None
        strategy: object | None = None

        def with_session(self, session: object) -> str:
            self.seen_sessions.append(session)
            return f"bound-{id(session)}"

    recorder = _BackendRecorder(seen_sessions=[])
    config = _minimal_config(backends=cast("Any", [recorder]))
    config.db_session_dependency_key = "custom_db"
    plugin = LitestarAuth(config)
    session = object()

    rebound_backends = cast("Any", plugin._provide_request_backends)(custom_db=session)

    assert rebound_backends == [f"bound-{id(session)}"]
    assert recorder.seen_sessions == [session]


def test_provide_request_backends_accepts_positional_session_argument() -> None:
    """Backends DI also supports the direct positional session-provider path."""

    @dataclass(slots=True)
    class _BackendRecorder:
        seen_sessions: list[object]
        name: str = "recorder"
        transport: object | None = None
        strategy: object | None = None

        def with_session(self, session: object) -> str:
            self.seen_sessions.append(session)
            return f"bound-{id(session)}"

    recorder = _BackendRecorder(seen_sessions=[])
    plugin = LitestarAuth(_minimal_config(backends=cast("Any", [recorder])))
    session = object()

    rebound_backends = cast("Any", plugin._provide_request_backends)(session)

    assert rebound_backends == [f"bound-{id(session)}"]
    assert recorder.seen_sessions == [session]


def test_provide_request_backends_rejects_positional_and_keyword_session() -> None:
    """Backends DI fails closed when both positional and keyword session inputs are provided."""
    plugin = LitestarAuth(_minimal_config())
    session = object()

    with pytest.raises(TypeError, match="got multiple values for argument 'db_session'"):
        cast("Any", plugin._provide_request_backends)(session, db_session=session)


def test_provide_request_backends_validates_dependency_inputs() -> None:
    """Backends DI rejects missing or unexpected dependency arguments before building backends."""
    plugin = LitestarAuth(_minimal_config())

    with pytest.raises(TypeError, match="missing 1 required positional argument: 'db_session'"):
        cast("Any", plugin._provide_request_backends)()

    with pytest.raises(TypeError, match="got an unexpected keyword argument 'other'"):
        cast("Any", plugin._provide_request_backends)(other=object())


def test_provide_request_backends_realizes_database_token_preset_from_request_session() -> None:
    """Preset backends DI returns a backend bound to the active request-local session."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=plugin_module._plugin_config.DatabaseTokenAuthConfig(
            token_hash_secret="a" * 40,
            max_age=timedelta(minutes=10),
            refresh_max_age=timedelta(days=14),
            accept_legacy_plaintext_tokens=True,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
        enable_refresh=True,
    )
    config.allow_legacy_plaintext_tokens = True
    plugin = LitestarAuth(config)
    active_session = type("_ActiveSession", (), {"marker": "request-session"})()
    startup_backend_template_type = _current_startup_backend_template_type()
    database_token_strategy_type = _current_database_token_strategy_type()
    authentication_backend_type = _current_authentication_backend_type()
    template_backend = config.resolve_startup_backends()[0]

    rebound_backends = cast("Any", plugin._provide_request_backends)(db_session=active_session)

    assert isinstance(template_backend, startup_backend_template_type)
    assert [backend.name for backend in rebound_backends] == ["database"]
    assert isinstance(rebound_backends[0], authentication_backend_type)
    assert isinstance(template_backend.strategy, database_token_strategy_type)
    assert isinstance(rebound_backends[0].strategy, database_token_strategy_type)
    assert rebound_backends[0].strategy.session is active_session


@pytest.mark.asyncio
async def test_provide_user_manager_yields_request_scoped_manager() -> None:
    """Provider wrappers yield one session-bound manager for each injected session."""
    plugin = LitestarAuth(_minimal_config())
    session = DummySession()

    gen = cast("Any", plugin._provide_user_manager(session))
    try:
        manager = await anext(gen)
        assert manager is not None
        assert isinstance(manager, PluginUserManager)
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_provide_oauth_associate_user_manager_yields_manager() -> None:
    """OAuth associate provider wrappers share the same request-scoped manager behavior."""
    plugin = LitestarAuth(_minimal_config())
    session = DummySession()

    gen = cast("Any", plugin._provide_oauth_associate_user_manager(session))
    try:
        manager = await anext(gen)
        assert manager is not None
    finally:
        await gen.aclose()


def test_totp_backend_returns_configured_named_backend() -> None:
    """The plugin exposes the same TOTP backend selected by the configured helper rules."""
    primary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="primary")),
    )
    secondary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="secondary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="secondary")),
    )
    plugin = LitestarAuth(
        _minimal_config(
            backends=[primary_backend, secondary_backend],
        ),
    )
    plugin.config.totp_config = TotpConfig(
        totp_pending_secret="p" * 32,
        totp_backend_name="secondary",
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_enrollment_store=InMemoryTotpEnrollmentStore(),
    )

    startup_backend = plugin._totp_backend()
    startup_backend_template_type = _current_startup_backend_template_type()

    assert isinstance(startup_backend, startup_backend_template_type)
    assert startup_backend.name == secondary_backend.name
    assert startup_backend.transport is secondary_backend.transport
    assert startup_backend.strategy is secondary_backend.strategy


def test_public_aliases_reexport_nested_config_types() -> None:
    """Plugin module re-exports nested config dataclasses for public callers."""
    assert OAuthConfig.__name__ == "OAuthConfig"
    assert TotpConfig.__name__ == "TotpConfig"


def test_plugins_hold_distinct_explicit_oauth_token_policies() -> None:
    """Separate plugin instances keep independent explicit OAuth token policies."""
    first_config = _minimal_config()
    second_config = _minimal_config()
    first_config.oauth_config = OAuthConfig(oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
    second_config.oauth_config = OAuthConfig(oauth_token_encryption_key="YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=")

    first_plugin = LitestarAuth(first_config)
    second_plugin = LitestarAuth(second_config)

    assert first_plugin._oauth_token_encryption is not None
    assert first_plugin._oauth_token_encryption.key == "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
    assert first_plugin._oauth_token_encryption.unsafe_testing is False
    assert second_plugin._oauth_token_encryption is not None
    assert second_plugin._oauth_token_encryption.key == "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
    assert second_plugin._oauth_token_encryption.unsafe_testing is False
    assert first_plugin._oauth_token_encryption is not second_plugin._oauth_token_encryption
