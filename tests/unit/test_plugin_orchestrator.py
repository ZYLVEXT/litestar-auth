"""Unit tests for the Litestar auth plugin orchestrator helpers."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch
from uuid import UUID

import pytest
from litestar.config.app import AppConfig
from litestar.config.csrf import CSRFConfig
from litestar.exceptions import ClientException
from litestar.middleware import DefineMiddleware

import litestar_auth.plugin as plugin_module
from litestar_auth._plugin import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
)
from litestar_auth.authentication import Authenticator, LitestarAuthMiddleware
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig, OAuthConfig, TotpConfig
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from litestar_auth._plugin.dependencies import DependencyProviders


def test_plugin_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records the module body."""
    reloaded_module = importlib.reload(plugin_module)

    assert reloaded_module.LitestarAuth.__name__ == LitestarAuth.__name__
    assert reloaded_module.LitestarAuthConfig.__name__ == LitestarAuthConfig.__name__
    assert reloaded_module.__all__ == ("LitestarAuth", "LitestarAuthConfig", "OAuthConfig", "TotpConfig")


def _minimal_config(
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    include_users: bool = False,
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
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "verification_token_secret": "verify-secret-12345678901234567890",
            "reset_password_token_secret": "reset-secret-123456789012345678901",
            "id_parser": UUID,
        },
        include_users=include_users,
    )


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
        "litestar_auth.plugin.warn_if_insecure_oauth_redirect_in_production",
        lambda **_kwargs: calls.append("warn-oauth-redirect"),
    )
    monkeypatch.setattr(plugin, "_register_dependencies", lambda _app_config: calls.append("dependencies"))
    monkeypatch.setattr(plugin, "_register_middleware", lambda _app_config: calls.append("middleware"))
    monkeypatch.setattr(plugin, "_register_controllers", lambda _app_config: calls.append("controllers"))
    monkeypatch.setattr(plugin, "_register_exception_handlers", lambda _app_config: calls.append("exceptions"))

    result = plugin.on_app_init(app_config)

    assert result is app_config
    assert calls == [
        "warn",
        "require-oauth-key",
        "warn-oauth-redirect",
        "dependencies",
        "middleware",
        "controllers",
        "exceptions",
    ]


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
    assert result.exception_handlers[ClientException]
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

    session_getter = middleware.kwargs["get_request_session"]
    assert isinstance(session_getter, partial)
    assert session_getter.func.__name__ == "get_or_create_scoped_session"


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
    assert cast("Any", providers.backends)() is plugin.config.backends
    assert cast("Any", providers.user_model)() is plugin.config.user_model
    assert providers.oauth_associate_user_manager is plugin._provide_oauth_associate_user_manager


def test_register_exception_handlers_delegates_to_shared_registration_function() -> None:
    """Exception-handler registration goes through the shared dependency helper."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig()

    with patch("litestar_auth.plugin.register_exception_handlers") as register_handlers_mock:
        plugin._register_exception_handlers(app_config)

    register_handlers_mock.assert_called_once_with(app_config)


def test_register_controllers_extends_route_handlers() -> None:
    """Controller registration appends the shared controller set onto AppConfig."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig()
    app_config.route_handlers.append(cast("Any", "existing"))

    with patch("litestar_auth.plugin.build_controllers", return_value=["new-controller"]) as build_controllers_mock:
        plugin._register_controllers(app_config)

    assert app_config.route_handlers == ["existing", "new-controller"]
    build_controllers_mock.assert_called_once_with(plugin.config)


@dataclass(slots=True)
class _ScopedProxyRecorder:
    user_db: object
    oauth_scope: object


def test_build_user_manager_wraps_user_db_and_passes_bound_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    """User-manager construction wraps the user DB and forwards session-bound backends."""
    plugin = LitestarAuth(_minimal_config())
    session = object()
    raw_user_db = object()
    captured: dict[str, object] = {}

    plugin.config.user_db_factory = lambda configured_session: raw_user_db if configured_session is session else None
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
    assert captured["session"] is session
    assert captured["config"] is plugin.config
    assert captured["user_db"] == _ScopedProxyRecorder(user_db=raw_user_db, oauth_scope=plugin)
    assert captured["backends"] == (f"backend-for-{id(session)}",)


def test_session_bound_backends_rebinds_each_backend_to_current_session() -> None:
    """Configured backends are rebound against the request-local session."""

    @dataclass(slots=True)
    class _BackendRecorder:
        name: str
        seen_sessions: list[object]

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


def test_resolve_account_state_validator_returns_manager_method() -> None:
    """The plugin exposes the configured manager-class account-state validator."""
    plugin = LitestarAuth(_minimal_config())

    validator = plugin._resolve_account_state_validator()

    assert validator is PluginUserManager.require_account_state


def test_resolve_account_state_validator_raises_for_missing_callable() -> None:
    """Manager classes without a callable validator fail with a contract error."""

    class _MissingValidatorManager(PluginUserManager):
        require_account_state = None

    plugin = LitestarAuth(_minimal_config())
    plugin.config.user_manager_class = _MissingValidatorManager

    with pytest.raises(TypeError, match="require_account_state"):
        plugin._resolve_account_state_validator()


@pytest.mark.parametrize(
    ("method_name", "patch_target", "expected"),
    [
        ("_build_controllers", "litestar_auth.plugin.build_controllers", ["controller"]),
        ("_build_totp_controller", "litestar_auth.plugin.build_totp_controller", "totp-controller"),
        ("_user_read_schema_kwargs", "litestar_auth.plugin.user_read_schema_kwargs", {"user": "read"}),
        ("_register_schema_kwargs", "litestar_auth.plugin.register_schema_kwargs", {"register": "schema"}),
        ("_users_schema_kwargs", "litestar_auth.plugin.users_schema_kwargs", {"users": "schema"}),
    ],
)
def test_wrapper_methods_delegate_to_shared_builders(
    method_name: str,
    patch_target: str,
    expected: object,
) -> None:
    """Thin wrapper helpers delegate to the shared builder utilities."""
    plugin = LitestarAuth(_minimal_config())

    with patch(patch_target, return_value=expected) as patched:
        result = getattr(plugin, method_name)()

    assert result == expected
    patched.assert_called_once_with(plugin.config)


def test_cookie_transports_wrapper_delegates_to_backend_filter() -> None:
    """Cookie transport helper forwards the configured backend collection."""
    plugin = LitestarAuth(_minimal_config())

    with patch("litestar_auth.plugin.get_cookie_transports", return_value=["cookie-transport"]) as patched:
        assert plugin._cookie_transports() == ["cookie-transport"]

    patched.assert_called_once_with(plugin.config.backends)


def test_provider_helpers_return_configured_objects() -> None:
    """Provider helpers expose the config values used by dependency registration."""
    plugin = LitestarAuth(_minimal_config())

    assert plugin._provide_backends() is plugin.config.backends
    assert plugin._provide_config() is plugin.config
    assert plugin._provide_user_model() is plugin.config.user_model


def test_wrapper_methods_delegate_with_explicit_arguments() -> None:
    """Argument-bearing helper wrappers forward their explicit parameters intact."""
    plugin = LitestarAuth(_minimal_config())

    with patch("litestar_auth.plugin.backend_auth_path", return_value="/auth/secondary") as backend_auth_path_mock:
        assert plugin._backend_auth_path(backend_name="secondary", index=1) == "/auth/secondary"
    backend_auth_path_mock.assert_called_once_with(
        auth_path=plugin.config.auth_path,
        backend_name="secondary",
        index=1,
    )

    with patch("litestar_auth.plugin.totp_backend", return_value="totp-backend") as totp_backend_mock:
        assert plugin._totp_backend() == "totp-backend"
    totp_backend_mock.assert_called_once_with(plugin.config)

    with patch("litestar_auth.plugin.totp_path", return_value="/auth/2fa") as totp_path_mock:
        assert plugin._totp_path() == "/auth/2fa"
    totp_path_mock.assert_called_once_with(plugin.config.auth_path)

    cookie_transports = [CookieTransport()]
    with patch("litestar_auth.plugin.build_csrf_config", return_value="csrf-config") as build_csrf_config_mock:
        assert plugin._build_csrf_config(cookie_transports) == "csrf-config"
    build_csrf_config_mock.assert_called_once_with(plugin.config, cookie_transports)

    with patch("litestar_auth.plugin.validate_config") as validate_config_mock:
        plugin._validate_config()
    validate_config_mock.assert_called_once_with(plugin.config)

    app_config = AppConfig()
    with patch("litestar_auth.plugin.warn_if_insecure_oauth_redirect_in_production") as warn_redirect_mock:
        plugin._warn_if_insecure_oauth_redirect_in_production(app_config)
    warn_redirect_mock.assert_called_once_with(config=plugin.config, app_config=app_config)


def test_non_none_schema_kwargs_filters_none_values() -> None:
    """Schema helper removes keys that are explicitly set to None."""
    assert LitestarAuth._non_none_schema_kwargs(email="value", username=None, active=False) == {
        "email": "value",
        "active": False,
    }


def test_public_aliases_reexport_nested_config_types() -> None:
    """Plugin module re-exports nested config dataclasses for public callers."""
    assert OAuthConfig.__name__ == "OAuthConfig"
    assert TotpConfig.__name__ == "TotpConfig"
