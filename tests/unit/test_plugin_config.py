"""Unit tests for plugin configuration validation and provider methods."""

from __future__ import annotations

import asyncio
import importlib
import logging
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator
from litestar.config.app import AppConfig

import litestar_auth._plugin.config as plugin_config_module
from litestar_auth._plugin.config import (
    OAuthConfig,
    TotpConfig,
    build_user_manager,
    default_password_validator_factory,
    require_session_maker,
    resolve_password_validator,
    resolve_user_manager_factory,
    user_manager_accepts_login_identifier,
    user_manager_accepts_password_validator,
)
from litestar_auth._plugin.dependencies import DependencyProviders, register_dependencies
from litestar_auth._plugin.validation import validate_config, warn_insecure_plugin_startup_defaults
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH
from litestar_auth.manager import require_password_length
from litestar_auth.models import User as OrmUser
from litestar_auth.oauth_encryption import get_oauth_encryption_key_callable, oauth_token_encryption_scope
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter, RedisRateLimiter
from litestar_auth.totp import InMemoryUsedTotpCodeStore, SecurityWarning
from tests.integration.test_orchestrator import (
    DummySession,
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit

EXPECTED_BACKEND_COUNT = 2


@contextmanager
def _raises_configuration_error(*, match: str) -> Generator[pytest.ExceptionInfo[Exception], None, None]:
    """Assert a ConfigurationError without depending on reloaded class identity.

    Yields:
        Pytest exception info for the captured error.
    """
    with pytest.raises(Exception, match=match) as exc_info:
        yield exc_info

    assert exc_info.type.__name__ == "ConfigurationError"
    assert exc_info.type.__module__ == "litestar_auth.exceptions"


def test_plugin_config_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and dataclass execution."""
    reloaded_module = importlib.reload(plugin_config_module)

    assert reloaded_module.LitestarAuthConfig.__name__ == LitestarAuthConfig.__name__
    assert reloaded_module.OAuthConfig.__name__ == OAuthConfig.__name__


def _minimal_config(
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    include_users: bool = False,
    totp_config: TotpConfig | None = None,
    user_manager_class: type[Any] | None = None,
    login_identifier: Literal["email", "username"] = "email",
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal config for plugin tests.

    Returns:
        LitestarAuthConfig instance for the given options.
    """
    user_db = InMemoryUserDatabase([])
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )
    strategies = backends if backends is not None else [default_backend]
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=strategies,
        user_model=ExampleUser,
        user_manager_class=user_manager_class or PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
        include_users=include_users,
        totp_config=totp_config,
        login_identifier=login_identifier,
    )


def test_litestar_auth_init_invokes_validate_testing_mode_for_startup() -> None:
    """LitestarAuth construction runs validate_testing_mode_for_startup via validate_config."""
    config = _minimal_config()
    with patch("litestar_auth._plugin.validation.validate_testing_mode_for_startup") as mock_vtm:
        LitestarAuth(config)
    mock_vtm.assert_called_once()


def test_validate_config_raises_when_no_backends() -> None:
    """_validate_config raises ValueError when backends list is empty."""
    config = _minimal_config(backends=[])

    with pytest.raises(ValueError, match="at least one authentication backend"):
        LitestarAuth(config)


def test_validate_config_raises_when_include_users_without_list_users() -> None:
    """_validate_config raises when include_users=True and user_manager_class has no list_users."""

    # Class that exposes list_users as non-callable so validation fails.
    class ManagerWithoutListUsers(PluginUserManager):
        list_users = None

    config = _minimal_config(include_users=True, user_manager_class=ManagerWithoutListUsers)

    with pytest.raises(ValueError, match="list_users"):
        LitestarAuth(config)


def test_validate_config_raises_when_include_totp_without_secret() -> None:
    """_validate_config raises when include_totp=True and totp_pending_secret is missing."""
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret=""))

    with pytest.raises(ValueError, match="totp_pending_secret"):
        LitestarAuth(config)


def test_validate_config_raises_when_totp_secret_too_short() -> None:
    """_validate_config raises ConfigurationError when totp_pending_secret is too short."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret="short", totp_used_tokens_store=cast("Any", object())),
    )

    with _raises_configuration_error(match="at least 32"):
        LitestarAuth(config)


def test_validate_config_rejects_testing_mode_in_non_test_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Startup fails fast when testing mode is enabled outside pytest runtime."""
    config = _minimal_config()
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    with _raises_configuration_error(match=r"LITESTAR_AUTH_TESTING=1"):
        LitestarAuth(config)


def test_validate_config_allows_testing_mode_under_pytest_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Testing-mode startup remains allowed during pytest execution."""
    config = _minimal_config()
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/unit/test_plugin_config.py::test_example")

    LitestarAuth(config)


def test_plugins_hold_distinct_oauth_encryption_keys() -> None:
    """Separate plugin instances can register different OAuth encryption keys."""
    key_provider = get_oauth_encryption_key_callable()
    first_config = _minimal_config()
    second_config = _minimal_config()
    first_config.oauth_config = OAuthConfig(oauth_token_encryption_key="a" * 44)
    second_config.oauth_config = OAuthConfig(oauth_token_encryption_key="b" * 44)

    first_plugin = LitestarAuth(first_config)
    second_plugin = LitestarAuth(second_config)

    with oauth_token_encryption_scope(first_plugin):
        assert key_provider() == "a" * 44

    with oauth_token_encryption_scope(second_plugin):
        assert key_provider() == "b" * 44


@dataclass(slots=True)
class _FakeSessionBoundBackend:
    strategy: object
    bound_session: object | None = None

    def with_session(self, session: object) -> _FakeSessionBoundBackend:
        self.bound_session = session
        return self


@dataclass(slots=True)
class _InvalidationStrategy:
    invalidate_all_tokens: AsyncMock

    def with_session(self, _session: object) -> _InvalidationStrategy:
        return self


def test_build_user_manager_attaches_session_bound_backends() -> None:
    """_build_user_manager binds request-local backends onto manager.backends."""
    config = _minimal_config(
        backends=[
            cast("AuthenticationBackend[ExampleUser, UUID]", _FakeSessionBoundBackend(strategy=object())),
            cast("AuthenticationBackend[ExampleUser, UUID]", _FakeSessionBoundBackend(strategy=object())),
        ],
    )
    plugin = LitestarAuth(config)

    session = object()
    manager = plugin._build_user_manager(cast("Any", session))

    assert len(manager.backends) == EXPECTED_BACKEND_COUNT
    assert all(getattr(backend, "bound_session", None) is session for backend in manager.backends)


def test_build_user_manager_passes_login_identifier_from_config() -> None:
    """Default build_user_manager forwards LitestarAuthConfig.login_identifier into BaseUserManager."""
    config = _minimal_config(login_identifier="username")
    plugin = LitestarAuth(config)

    manager = plugin._build_user_manager(cast("Any", object()))

    assert manager.login_identifier == "username"


def test_build_user_manager_uses_explicit_password_validator_factory() -> None:
    """Explicit password-validator factories replace the legacy constructor-signature seam."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: lambda password: require_password_length(password, 10)
    plugin = LitestarAuth(config)

    manager = plugin._build_user_manager(cast("Any", object()))

    with pytest.raises(ValueError, match="at least 10"):
        manager.password_validator("short")


def test_build_user_manager_preserves_legacy_manager_without_password_validator_parameter() -> None:
    """Legacy manager classes without a password_validator parameter still build via the compatibility shim."""

    class LegacyManagerWithoutPasswordValidator(PluginUserManager):
        def __init__(
            self,
            user_db: object,
            *,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    config = _minimal_config(user_manager_class=LegacyManagerWithoutPasswordValidator)
    plugin = LitestarAuth(config)

    manager = plugin._build_user_manager(cast("Any", object()))

    assert isinstance(manager, LegacyManagerWithoutPasswordValidator)
    assert manager.password_validator is None


@pytest.mark.asyncio
async def test_session_bound_user_manager_update_triggers_strategy_invalidation_on_email_change() -> None:
    """Session-bound manager adapter revokes backend sessions on sensitive changes."""
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
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
    )
    plugin = LitestarAuth(config)

    manager = plugin._build_user_manager(cast("Any", DummySession()))
    await manager.update({"email": "updated@example.com"}, user)

    invalidate_mock.assert_awaited_once()


def test_session_bound_user_manager_uses_explicit_account_state_validator_contract() -> None:
    """Session-bound manager adapter exposes account-state validation without controller/plugin internals."""
    calls: list[tuple[ExampleUser, bool]] = []

    class _TrackingManager(PluginUserManager):
        def require_account_state(self, user: ExampleUser, *, require_verified: bool = False) -> None:
            del self
            calls.append((user, require_verified))

    config = _minimal_config(user_manager_class=_TrackingManager)
    plugin = LitestarAuth(config)
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=PasswordHelper().hash("correct-password"),
    )

    manager = plugin._build_user_manager(cast("Any", DummySession()))
    manager.require_account_state(user, require_verified=True)

    assert calls == [(user, True)]


def test_validate_config_raises_for_nondurable_jwt_strategy_by_default() -> None:
    """_validate_config fails fast for nondurable JWT revocation unless explicitly acknowledged."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="jwt-backend",
        transport=CookieTransport(),
        strategy=cast("Any", JWTStrategy(secret="a" * 32, algorithm="HS256")),
    )
    config = _minimal_config(backends=[backend])
    config.csrf_secret = "c" * 32

    with pytest.raises(ValueError, match=r"allow_nondurable_jwt_revocation=True"):
        LitestarAuth(config)


def test_validate_config_allows_nondurable_jwt_strategy_when_acknowledged() -> None:
    """Integrators can explicitly accept nondurable logout semantics for JWTStrategy."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="jwt-backend",
        transport=CookieTransport(),
        strategy=cast("Any", JWTStrategy(secret="a" * 32, algorithm="HS256")),
    )
    config = _minimal_config(backends=[backend])
    config.csrf_secret = "c" * 32
    config.allow_nondurable_jwt_revocation = True

    plugin = LitestarAuth(config)
    with pytest.warns(SecurityWarning, match="process-local in-memory denylist"):
        plugin.on_app_init(AppConfig())


def test_validate_config_rejects_non_boolean_trusted_proxy_rate_limit_setting() -> None:
    """_validate_config fails fast when trusted_proxy is not a boolean."""
    config = _minimal_config()
    config.rate_limit_config = AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
            scope="ip",
            namespace="login",
            trusted_proxy=cast("Any", "true"),
        ),
    )

    with _raises_configuration_error(match="trusted_proxy must be a boolean"):
        LitestarAuth(config)


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


def test_on_app_init_does_not_warn_for_redis_rate_limiter() -> None:
    """Shared Redis rate-limit state should not trigger the in-memory SecurityWarning."""

    class _RedisStub:
        async def delete(self, *names: str) -> int:
            return len(names)

        async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> int:
            return 0

    config = _minimal_config()
    config.rate_limit_config = AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=RedisRateLimiter(
                redis=_RedisStub(),
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

    assert not any(issubclass(r.category, SecurityWarning) for r in records)


def test_on_app_init_does_not_warn_for_inmemory_rate_limiter_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode suppresses SecurityWarning for process-local rate-limit backends."""
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/unit/test_plugin_config.py::test_validate_config")
    config = _minimal_config()
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

    assert not any(issubclass(r.category, SecurityWarning) for r in records)


def test_validate_config_requires_csrf_secret_for_cookie_transport() -> None:
    """Cookie transport usage requires a CSRF secret unless tests opt out explicitly."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-backend",
        transport=CookieTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie-config")),
    )
    config = _minimal_config(backends=[backend])

    with _raises_configuration_error(match="csrf_secret"):
        LitestarAuth(config)


def test_validate_config_rejects_mismatched_cookie_transport_settings() -> None:
    """Plugin-managed CSRF config requires consistent cookie transport settings."""
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
    """Multiple cookie backends with matching settings share one plugin-managed CSRF config."""
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


def test_warn_if_insecure_oauth_redirect_no_warning_when_host_not_localhost(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """_warn_if_insecure_oauth_redirect_in_production does not warn when redirect host is not localhost."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        include_oauth_associate=True,
        oauth_associate_providers=[("p", object())],
        oauth_associate_redirect_base_url="https://app.example.com/auth/associate",
    )
    plugin = LitestarAuth(config)

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        plugin._warn_if_insecure_oauth_redirect_in_production(AppConfig(debug=False))

    assert "localhost" not in caplog.text or "Insecure" not in caplog.text


def test_on_app_init_requires_oauth_token_encryption_key_for_oauth_providers() -> None:
    """OAuth-enabled plugin startup fails closed without an encryption key outside testing mode."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(oauth_providers=[("github", object())])
    plugin = LitestarAuth(config)

    with (
        pytest.warns(SecurityWarning, match="oauth_token_encryption_key is not set"),
        _raises_configuration_error(match=r"Fernet\.generate_key\(\)"),
    ):
        plugin.on_app_init(AppConfig())


def test_on_app_init_allows_oauth_providers_when_encryption_key_is_configured() -> None:
    """OAuth-enabled plugin startup succeeds when an encryption key is configured."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("github", object())],
        oauth_token_encryption_key="a" * 44,
    )
    plugin = LitestarAuth(config)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        result = plugin.on_app_init(AppConfig())

    assert result is not None
    assert not any(issubclass(r.category, SecurityWarning) for r in records)


def test_on_app_init_warns_security_warning_for_inmemory_totp_used_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production app init warns when TOTP replay store is process-local in-memory."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="x" * 32,
            totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
        ),
    )
    config.user_manager_kwargs["totp_secret_key"] = Fernet.generate_key().decode()
    plugin = LitestarAuth(config)

    with pytest.warns(SecurityWarning, match="InMemoryUsedTotpCodeStore"):
        plugin.on_app_init(AppConfig())


def test_warn_refresh_cookie_max_age_mismatch() -> None:
    """SecurityWarning is emitted when enable_refresh is True and CookieTransport has no refresh_max_age."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-backend",
        transport=CookieTransport(secure=False),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="refresh-warn")),
    )
    config = _minimal_config(backends=[backend])
    config.csrf_secret = "c" * 32
    config.enable_refresh = True

    with pytest.warns(SecurityWarning, match="refresh_max_age is not set"):
        warn_insecure_plugin_startup_defaults(config)


def test_no_refresh_cookie_warning_when_max_age_set() -> None:
    """No SecurityWarning when CookieTransport has explicit refresh_max_age."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-backend",
        transport=CookieTransport(secure=False, refresh_max_age=604800),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="refresh-ok")),
    )
    config = _minimal_config(backends=[backend])
    config.csrf_secret = "c" * 32
    config.enable_refresh = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    refresh_warnings = [
        r for r in records if issubclass(r.category, SecurityWarning) and "refresh_max_age" in str(r.message)
    ]
    assert not refresh_warnings


def test_no_refresh_cookie_warning_when_refresh_disabled() -> None:
    """No SecurityWarning when enable_refresh is False even without refresh_max_age."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-backend",
        transport=CookieTransport(secure=False),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="no-refresh")),
    )
    config = _minimal_config(backends=[backend])
    config.csrf_secret = "c" * 32
    config.enable_refresh = False

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    refresh_warnings = [
        r for r in records if issubclass(r.category, SecurityWarning) and "refresh_max_age" in str(r.message)
    ]
    assert not refresh_warnings


def test_on_app_init_allows_missing_oauth_token_encryption_key_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode bypasses the startup encryption-key requirement for OAuth providers."""
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    config = _minimal_config()
    config.oauth_config = OAuthConfig(oauth_providers=[("github", object())])
    plugin = LitestarAuth(config)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        result = plugin.on_app_init(AppConfig())

    assert result is not None
    assert not any(issubclass(r.category, SecurityWarning) for r in records)


def test_litestar_auth_config_declares_oauth_config_field() -> None:
    """The plugin config exposes an explicit nested OAuth config field."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "oauth_config" in dataclass_fields


def test_litestar_auth_config_declares_password_validator_factory_fields() -> None:
    """The plugin config exposes explicit password-validator and manager-builder seams."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "password_validator_factory" in dataclass_fields
    assert "user_manager_factory" in dataclass_fields


def test_litestar_auth_config_declares_db_session_dependency_fields() -> None:
    """The plugin config exposes db_session DI key and external-session declaration."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "db_session_dependency_key" in dataclass_fields
    assert "db_session_dependency_provided_externally" in dataclass_fields


def test_litestar_auth_config_declares_login_identifier_field() -> None:
    """The plugin config exposes login_identifier with a safe default."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "login_identifier" in dataclass_fields
    assert dataclass_fields["login_identifier"].default == "email"


def test_litestar_auth_config_login_identifier_defaults_to_email() -> None:
    """Default login mode is email."""
    config = _minimal_config()

    assert config.login_identifier == "email"


def test_litestar_auth_config_accepts_login_identifier_username() -> None:
    """Username mode is a valid explicit choice."""
    config = _minimal_config(login_identifier="username")

    assert config.login_identifier == "username"


def test_totp_config_defaults_match_expected_values() -> None:
    """TotpConfig exposes stable defaults for optional settings."""
    config = TotpConfig(totp_pending_secret="x" * 32)

    assert config.totp_backend_name is None
    assert config.totp_issuer == "litestar-auth"
    assert config.totp_algorithm == "SHA256"
    assert config.totp_used_tokens_store is None
    assert config.totp_require_replay_protection is True
    assert config.totp_enable_requires_password is True


def test_oauth_config_defaults_match_expected_values() -> None:
    """OAuthConfig exposes stable defaults for optional settings."""
    config = OAuthConfig()

    assert config.oauth_cookie_secure is True
    assert config.oauth_providers is None
    assert config.oauth_associate_by_email is False
    assert config.include_oauth_associate is False
    assert config.oauth_associate_providers is None
    assert not config.oauth_associate_redirect_base_url
    assert config.oauth_token_encryption_key is None


def test_user_manager_accepts_password_validator_prefers_explicit_class_attribute() -> None:
    """Explicit subclass metadata overrides constructor introspection for password validators."""

    class _ManagerWithExplicitFlag(PluginUserManager):
        accepts_password_validator = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_password_validator(_ManagerWithExplicitFlag) is False


def test_user_manager_accepts_password_validator_detects_kwargs_fallback() -> None:
    """Legacy managers using ``**kwargs`` still opt into password validators."""

    class _ManagerWithKwargs:
        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_password_validator(cast("Any", _ManagerWithKwargs)) is True


def test_user_manager_accepts_login_identifier_prefers_explicit_class_attribute() -> None:
    """Explicit subclass metadata overrides constructor introspection for login identifiers."""

    class _ManagerWithExplicitFlag(PluginUserManager):
        accepts_login_identifier = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_login_identifier(_ManagerWithExplicitFlag) is False


def test_user_manager_accepts_login_identifier_detects_kwargs_fallback() -> None:
    """Legacy managers using ``**kwargs`` still opt into login_identifier injection."""

    class _ManagerWithKwargs:
        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_login_identifier(cast("Any", _ManagerWithKwargs)) is True


def test_resolve_password_validator_prefers_explicit_validator_over_factory() -> None:
    """Legacy kwargs injection takes precedence over factory/default validator resolution."""

    def explicit_validator(password: str) -> None:
        require_password_length(password, 20)

    config = _minimal_config()
    config.user_manager_kwargs["password_validator"] = explicit_validator
    config.password_validator_factory = lambda _config: lambda password: require_password_length(password, 10)

    assert resolve_password_validator(config) is explicit_validator


def test_resolve_password_validator_uses_factory_before_default() -> None:
    """Explicit factories outrank the built-in password-length validator."""

    def factory_validator(password: str) -> None:
        require_password_length(password, 10)

    config = _minimal_config()
    config.password_validator_factory = lambda _config: factory_validator

    assert resolve_password_validator(config) is factory_validator


def test_resolve_password_validator_returns_default_for_supported_manager() -> None:
    """Managers that accept password_validator receive the built-in default policy."""
    config = _minimal_config()

    validator = resolve_password_validator(config)

    assert validator is not None
    with pytest.raises(ValueError, match=rf"at least {DEFAULT_MINIMUM_PASSWORD_LENGTH}"):
        validator("short")


def test_resolve_password_validator_returns_none_for_legacy_manager_without_support() -> None:
    """Managers that reject password_validator do not receive an implicit validator."""

    class _LegacyManagerWithoutPasswordValidator(PluginUserManager):
        accepts_password_validator = False

        def __init__(
            self,
            user_db: object,
            *,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    config = _minimal_config(user_manager_class=_LegacyManagerWithoutPasswordValidator)

    assert resolve_password_validator(config) is None


def test_default_password_validator_factory_enforces_repository_default_length() -> None:
    """The default factory uses the shared minimum-password constant."""
    validator = default_password_validator_factory(_minimal_config())

    with pytest.raises(ValueError, match=rf"at least {DEFAULT_MINIMUM_PASSWORD_LENGTH}"):
        validator("short")


def test_build_user_manager_respects_existing_password_validator_and_login_identifier_kwargs() -> None:
    """Explicit manager kwargs are preserved instead of being overwritten by helper defaults."""

    def explicit_password_validator(password: str) -> None:
        require_password_length(password, 10)

    user_db = InMemoryUserDatabase([])
    config = _minimal_config(login_identifier="username")
    config.user_manager_kwargs["password_validator"] = explicit_password_validator
    config.user_manager_kwargs["login_identifier"] = "email"

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=user_db,
        config=config,
        backends=("bound-backend",),
    )

    assert manager.password_validator is explicit_password_validator
    assert manager.login_identifier == "email"
    assert manager.backends == ("bound-backend",)


def test_build_user_manager_skips_login_identifier_for_legacy_manager_without_support() -> None:
    """Compatibility builders do not inject login_identifier into legacy manager constructors."""

    class _LegacyManagerWithoutLoginIdentifier(PluginUserManager):
        accepts_login_identifier = False

        def __init__(
            self,
            user_db: object,
            *,
            password_validator: object | None = None,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_validator=cast("Any", password_validator),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    config = _minimal_config(
        login_identifier="username",
        user_manager_class=_LegacyManagerWithoutLoginIdentifier,
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
    )

    assert manager.login_identifier == "email"


def test_require_session_maker_returns_configured_session_maker() -> None:
    """require_session_maker returns the configured factory unchanged on the success path."""
    config = _minimal_config()

    assert require_session_maker(config) is config.session_maker


def test_resolve_user_manager_factory_returns_explicit_factory_when_configured() -> None:
    """Explicit user_manager_factory overrides the module default builder."""
    factory = cast("Any", lambda **kwargs: kwargs["config"].user_manager_class(kwargs["user_db"], backends=()))
    config = _minimal_config()
    config.user_manager_factory = factory

    assert resolve_user_manager_factory(config) is factory


def test_resolve_user_manager_factory_defaults_to_build_user_manager() -> None:
    """Configs without an override use the module-level default builder."""
    config = _minimal_config()

    assert resolve_user_manager_factory(config) is plugin_config_module.build_user_manager


def _invalid_db_session_config_kwargs(invalid_db_session_key: str) -> dict[str, Any]:
    """Build kwargs for LitestarAuthConfig with an invalid ``db_session_dependency_key``.

    Returns:
        Keyword arguments dict suitable for ``LitestarAuthConfig(**kwargs)``.
    """
    user_db = InMemoryUserDatabase([])
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )
    return {
        "backends": [default_backend],
        "user_model": ExampleUser,
        "user_manager_class": PluginUserManager,
        "session_maker": cast("Any", DummySessionMaker()),
        "user_db_factory": lambda _session: user_db,
        "user_manager_kwargs": {
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
        "db_session_dependency_key": invalid_db_session_key,
    }


@pytest.mark.parametrize(
    "invalid_db_session_key",
    ["", "with space", "123abc", "for", "class", "return"],
)
def test_litestar_auth_config_rejects_invalid_db_session_dependency_key(
    invalid_db_session_key: str,
) -> None:
    """db_session_dependency_key must be a valid non-keyword identifier at construction."""
    with pytest.raises(ValueError, match="db_session_dependency_key must be a valid Python identifier"):
        LitestarAuthConfig[ExampleUser, UUID](**_invalid_db_session_config_kwargs(invalid_db_session_key))


def test_litestar_auth_config_rejects_invalid_login_identifier() -> None:
    """Unknown login_identifier values fail at construction with ConfigurationError."""
    user_db = InMemoryUserDatabase([])
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )
    with pytest.raises(plugin_config_module.ConfigurationError, match=r"Invalid login_identifier"):
        LitestarAuthConfig[ExampleUser, UUID](
            backends=[default_backend],
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            session_maker=cast("Any", DummySessionMaker()),
            user_db_factory=lambda _session: user_db,
            user_manager_kwargs={
                "verification_token_secret": "x" * 32,
                "reset_password_token_secret": "y" * 32,
            },
            login_identifier=cast("Any", "phone"),
        )


def test_validate_config_rejects_username_mode_when_user_model_lacks_username_field() -> None:
    """validate_config requires a username attribute on user_model when login_identifier is username."""
    config = _minimal_config(login_identifier="username")

    @dataclass
    class _UserEmailOnly:
        id: UUID
        email: str

    config.user_model = _UserEmailOnly  # ty: ignore[invalid-assignment]

    with _raises_configuration_error(match="username"):
        validate_config(config)


def test_validate_config_rejects_email_mode_when_user_model_lacks_email_field() -> None:
    """validate_config requires an email attribute on user_model when login_identifier is email."""
    config = _minimal_config(login_identifier="email")

    @dataclass
    class _UserUsernameOnly:
        id: UUID
        username: str

    config.user_model = _UserUsernameOnly  # ty: ignore[invalid-assignment]

    with _raises_configuration_error(match="email"):
        validate_config(config)


def test_validate_config_rejects_orm_user_without_username_when_login_identifier_username() -> None:
    """Mapped SQLAlchemy models are checked via the ORM mapper (not only hasattr)."""
    config = _minimal_config(login_identifier="username")
    config.user_model = OrmUser  # ty: ignore[invalid-assignment]

    with _raises_configuration_error(match="username"):
        validate_config(config)


def test_validate_config_allows_orm_user_with_email_when_login_identifier_email() -> None:
    """ORM-mapped ``User`` includes ``email``; email login mode passes startup validation."""
    config = _minimal_config(login_identifier="email")
    config.user_model = OrmUser  # ty: ignore[invalid-assignment]

    validate_config(config)


def test_validate_config_raises_when_session_maker_and_external_db_session_both_absent() -> None:
    """Startup validation requires either session_maker or external DB session DI."""
    config = _minimal_config()
    config.session_maker = None

    with pytest.raises(ValueError, match=r"session_maker or db_session_dependency_provided_externally"):
        LitestarAuth(config)


def test_validate_config_allows_external_db_session_without_session_maker() -> None:
    """Integrators may declare AsyncSession injection without a plugin-owned session_maker."""
    config = _minimal_config()
    config.session_maker = None
    config.db_session_dependency_provided_externally = True

    validate_config(config)


def test_require_session_maker_raises_value_error_when_session_maker_missing() -> None:
    """require_session_maker raises ValueError with a task-agnostic message."""
    config = _minimal_config()
    config.session_maker = None

    with pytest.raises(ValueError, match="LitestarAuth requires session_maker\\."):
        require_session_maker(config)


def test_register_dependencies_registers_db_session_when_using_builtin_session_maker() -> None:
    """When session_maker is owned by the plugin, register the db_session async generator."""
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
    """Do not register a conflicting Provide when the app supplies db_session externally."""
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


def test_validate_config_rejects_ambiguous_password_validator_configuration() -> None:
    """Explicit password-validator factories cannot be combined with legacy kwargs injection."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: lambda password: require_password_length(password, 10)
    config.user_manager_kwargs["password_validator"] = require_password_length

    with pytest.raises(ValueError, match="password_validator_factory or user_manager_kwargs"):
        LitestarAuth(config)


def test_validate_config_rejects_password_validator_factory_for_legacy_manager_without_explicit_builder() -> None:
    """A non-compatible legacy manager must provide an explicit user_manager_factory."""

    class LegacyManagerWithoutPasswordValidator(PluginUserManager):
        def __init__(
            self,
            user_db: object,
            *,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    config = _minimal_config(user_manager_class=LegacyManagerWithoutPasswordValidator)
    config.password_validator_factory = lambda _config: require_password_length

    with pytest.raises(ValueError, match="requires user_manager_class to accept password_validator"):
        LitestarAuth(config)


def test_validate_config_requires_totp_algorithm_when_pending_secret_is_set() -> None:
    """TOTP startup validation requires an explicit algorithm when pending JWTs are configured."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=cast("Any", object()),
            totp_algorithm=cast("Any", None),
        ),
    )

    with pytest.raises(ValueError, match="totp_algorithm must be configured"):
        LitestarAuth(config)


def test_validate_config_warns_for_sha1_totp_algorithm(caplog: pytest.LogCaptureFixture) -> None:
    """SHA1 TOTP configs are still allowed but log a production warning."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=cast("Any", object()),
            totp_algorithm="SHA1",
        ),
    )
    config.user_manager_kwargs["totp_secret_key"] = Fernet.generate_key().decode()

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        LitestarAuth(config)

    assert "SHA1" in caplog.text
    assert "SHA256 or SHA512" in caplog.text


def test_validate_config_requires_totp_replay_store_in_production() -> None:
    """Replay protection cannot be enabled without a used-token store outside tests."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=None,
        ),
    )

    with pytest.raises(ValueError, match="totp_used_tokens_store"):
        LitestarAuth(config)


def test_validate_config_requires_authenticate_for_totp_step_up_enrollment() -> None:
    """Default password-confirmed TOTP enrollment requires authenticate()."""

    class ManagerWithoutAuthenticate(PluginUserManager):
        authenticate = None

    config = _minimal_config(
        user_manager_class=ManagerWithoutAuthenticate,
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=cast("Any", object()),
        ),
    )

    with pytest.raises(ValueError, match="step-up enrollment is enabled by default"):
        LitestarAuth(config)


def test_provide_backends_returns_config_backends() -> None:
    """_provide_backends returns the configured backends list."""
    config = _minimal_config()
    plugin = LitestarAuth(config)

    result = plugin._provide_backends()

    assert result is config.backends


def test_provide_config_returns_config() -> None:
    """_provide_config returns the plugin config."""
    config = _minimal_config()
    plugin = LitestarAuth(config)

    result = plugin._provide_config()

    assert result is config


@pytest.mark.asyncio
async def test_provide_user_manager_respects_custom_db_session_key() -> None:
    """User manager provider parameter name follows ``db_session_dependency_key``."""
    config = _minimal_config()
    config.db_session_dependency_key = "custom_db"
    plugin = LitestarAuth(config)
    session = DummySession()

    gen = cast(
        "AsyncGenerator[object, None]",
        plugin._provide_user_manager(custom_db=session),
    )
    try:
        manager = await anext(gen)
        assert manager is not None
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_provide_user_manager_yields_request_scoped_manager() -> None:
    """_provide_user_manager yields one session-bound manager per injected AsyncSession."""
    config = _minimal_config()
    plugin = LitestarAuth(config)
    session = DummySession()

    gen = cast("AsyncGenerator[object, None]", plugin._provide_user_manager(session))
    try:
        manager = await anext(gen)
        assert manager is not None
        assert isinstance(manager, PluginUserManager)
    finally:
        await gen.aclose()


def test_provide_user_model_returns_config_user_model() -> None:
    """_provide_user_model returns the configured user model."""
    config = _minimal_config()
    plugin = LitestarAuth(config)

    result = plugin._provide_user_model()

    assert result is ExampleUser


@pytest.mark.asyncio
async def test_provide_oauth_associate_user_manager_yields_manager() -> None:
    """_provide_oauth_associate_user_manager yields a manager for the injected session."""
    config = _minimal_config()
    plugin = LitestarAuth(config)
    session = DummySession()

    gen = cast("AsyncGenerator[object, None]", plugin._provide_oauth_associate_user_manager(session))
    try:
        manager = await anext(gen)
        assert manager is not None
    finally:
        await gen.aclose()
