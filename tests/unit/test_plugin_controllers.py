"""Unit tests for plugin controller assembly helpers."""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID

import msgspec
import pytest
from cryptography.fernet import Fernet
from litestar.exceptions import ValidationException

import litestar_auth._plugin._oauth_controllers as oauth_controllers_module
import litestar_auth._plugin._totp_controller as totp_controllers_module
import litestar_auth._plugin.controllers as controllers_module
import litestar_auth._plugin.totp_route_handlers as totp_route_handlers_module
from litestar_auth._plugin._oauth_controllers import (
    _append_oauth_associate_controllers,
    _append_oauth_login_controllers,
)
from litestar_auth._plugin.config import (
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
    OAuthConfig,
    TotpConfig,
    resolve_backend_inventory,
)
from litestar_auth._plugin.controllers import (
    _append_optional_feature_controllers,
    _build_auth_controllers,
    build_controllers,
    build_totp_controller,
    register_schema_kwargs,
    totp_backend,
    user_read_schema_kwargs,
    users_schema_kwargs,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.manager import FernetKeyringConfig, UserManagerSecurity
from litestar_auth.totp import InMemoryTotpEnrollmentStore
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit
OAUTH_FLOW_COOKIE_SECRET = "oauth-flow-cookie-secret-1234567890"

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.types import ControllerRouterHandler

    from litestar_auth.config import OAuthProviderConfig


class _ReadSchema(msgspec.Struct):
    email: str


class _CreateSchema(msgspec.Struct, forbid_unknown_fields=True):
    email: str
    password: str


class _UpdateSchema(msgspec.Struct, forbid_unknown_fields=True):
    username: str


def _current_startup_backend_template_type() -> type[Any]:
    """Resolve the current StartupBackendTemplate class to survive cross-test module reloads.

    Returns:
        The current StartupBackendTemplate type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth._plugin.config").StartupBackendTemplate)


def _oauth_provider(*, name: str, client: object) -> OAuthProviderConfig:
    """Build an OAuthProviderConfig using the current runtime class.

    Returns:
        The current-runtime OAuthProviderConfig instance.
    """
    config_module = importlib.import_module("litestar_auth.config")
    oauth_provider_config_type = cast("type[Any]", config_module.OAuthProviderConfig)
    return oauth_provider_config_type(name=name, client=client)


def test_plugin_controllers_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(controllers_module)
    reloaded_oauth_module = importlib.reload(oauth_controllers_module)
    reloaded_totp_route_handlers_module = importlib.reload(totp_route_handlers_module)
    reloaded_totp_module = importlib.reload(totp_controllers_module)

    assert reloaded_module.build_controllers.__name__ == build_controllers.__name__
    assert reloaded_oauth_module.create_oauth_login_controller.__name__ == "create_oauth_login_controller"
    assert reloaded_totp_route_handlers_module.define_plugin_totp_controller_class.__name__ == (
        "define_plugin_totp_controller_class"
    )
    assert reloaded_totp_module.build_totp_controller.__name__ == build_totp_controller.__name__


def test_build_controllers_combines_auth_and_optional_controllers(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_controllers returns auth controllers plus appended optional controllers."""
    config = _minimal_config()
    optional_calls: list[tuple[list[object], LitestarAuthConfig[ExampleUser, UUID], object]] = []
    auth_inventory: object | None = None

    def _build_auth(
        *,
        config: LitestarAuthConfig[ExampleUser, UUID],
        backend_inventory: object | None = None,
        security: object | None = None,
    ) -> list[str]:
        nonlocal auth_inventory
        del config, security
        auth_inventory = backend_inventory
        return ["auth-controller"]

    monkeypatch.setattr(controllers_module, "_build_auth_controllers", _build_auth)

    def _append(
        *,
        controllers: list[object],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backend_inventory: object | None = None,
        security: object | None = None,
    ) -> None:
        del security
        optional_calls.append((list(controllers), config, backend_inventory))
        controllers.append("optional-controller")

    monkeypatch.setattr(controllers_module, "_append_optional_feature_controllers", _append)

    assert build_controllers(config) == ["auth-controller", "optional-controller"]
    assert auth_inventory is not None
    assert optional_calls == [(["auth-controller"], config, auth_inventory)]


def test_build_auth_controllers_builds_backend_specific_paths_and_totp_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mandatory controller assembly fans out across backends and forwards TOTP pending-secret config."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    secondary_backend = _backend(name="secondary", token_prefix="secondary")
    config = _minimal_config(
        backends=[primary_backend, secondary_backend],
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
    )
    calls: list[dict[str, object]] = []

    def _create_auth_controller(settings: Any) -> str:  # noqa: ANN401
        calls.append(
            {
                "backend": settings.backend,
                "totp_pending_secret": settings.totp_pending_secret,
                "unsafe_testing": settings.unsafe_testing,
                "path": settings.path,
            },
        )
        return cast("str", settings.path)

    monkeypatch.setattr(controllers_module, "create_auth_controller", _create_auth_controller)

    assert _build_auth_controllers(config=config) == ["/auth", "/auth/secondary"]
    assert isinstance(calls[0]["backend"], _current_startup_backend_template_type())
    assert calls[0]["backend"].name == primary_backend.name
    assert calls[0]["backend"].transport is primary_backend.transport
    assert calls[0]["backend"].strategy is primary_backend.strategy
    assert calls[0]["totp_pending_secret"] == "p" * 32
    assert calls[0]["unsafe_testing"] is False
    assert isinstance(calls[1]["backend"], _current_startup_backend_template_type())
    assert calls[1]["backend"].name == secondary_backend.name
    assert calls[1]["backend"].transport is secondary_backend.transport
    assert calls[1]["backend"].strategy is secondary_backend.strategy
    assert calls[1]["path"] == "/auth/secondary"
    assert calls[1]["unsafe_testing"] is False


def test_build_totp_controller_raises_when_totp_config_missing() -> None:
    """TOTP controller construction fails fast when no TOTP config is available."""
    with pytest.raises(ValueError, match="totp_config must be configured"):
        build_totp_controller(_minimal_config())


def test_build_totp_controller_forwards_named_backend_and_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """TOTP controller assembly uses the configured backend and forwards all plugin settings."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    secondary_backend = _backend(name="secondary", token_prefix="secondary")
    used_tokens_store = cast("Any", object())
    pending_jti_store = cast("Any", object())
    enrollment_store = cast("Any", object())
    config = _minimal_config(
        backends=[primary_backend, secondary_backend],
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_backend_name="secondary",
            totp_issuer="Example Issuer",
            totp_algorithm=cast("Any", "SHA512"),
            totp_used_tokens_store=used_tokens_store,
            totp_pending_jti_store=pending_jti_store,
            totp_enrollment_store=enrollment_store,
            totp_require_replay_protection=False,
            totp_enable_requires_password=False,
            totp_pending_require_client_binding=False,
        ),
    )
    captured: dict[str, object] = {}

    def _create_totp_controller(**kwargs: object) -> str:
        captured.update(kwargs)
        return "totp-controller"

    monkeypatch.setattr(totp_controllers_module, "create_totp_controller", _create_totp_controller)

    assert build_totp_controller(config) == "totp-controller"
    assert isinstance(captured["backend"], _current_startup_backend_template_type())
    assert captured["backend"].name == secondary_backend.name
    assert captured["backend"].transport is secondary_backend.transport
    assert captured["backend"].strategy is secondary_backend.strategy
    assert captured["user_manager_dependency_key"] == "litestar_auth_user_manager"
    assert captured["used_tokens_store"] is used_tokens_store
    assert captured["pending_jti_store"] is pending_jti_store
    assert captured["enrollment_store"] is enrollment_store
    assert captured["require_replay_protection"] is False
    assert captured["requires_verification"] is True
    assert captured["totp_pending_secret"] == "p" * 32
    assert captured["totp_secret_key"] is None
    assert captured["totp_secret_keyring"] is None
    assert captured["totp_enable_requires_password"] is False
    assert captured["totp_pending_require_client_binding"] is False
    assert captured["totp_issuer"] == "Example Issuer"
    assert captured["totp_algorithm"] == "SHA512"
    assert captured["path"] == "/auth/2fa"
    assert captured["unsafe_testing"] is False


def test_plugin_create_totp_controller_logs_when_pending_client_binding_is_disabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Plugin-owned TOTP controller construction logs the explicit weaker pending-token posture."""
    config = _minimal_config()
    inventory = resolve_backend_inventory(config)
    backend_index, backend = inventory.primary()

    with caplog.at_level(logging.WARNING, logger="litestar_auth.controllers.totp"):
        controller = controllers_module.create_totp_controller(
            backend=backend,
            backend_inventory=inventory,
            backend_index=backend_index,
            user_manager_dependency_key="litestar_auth_user_manager",
            require_replay_protection=False,
            totp_pending_secret="p" * 32,
            totp_enable_requires_password=False,
            totp_pending_require_client_binding=False,
            unsafe_testing=True,
        )

    assert controller.path == "/auth/2fa"
    assert any(getattr(record, "event", None) == "totp_pending_client_binding_disabled" for record in caplog.records)


def test_build_totp_controller_defaults_to_primary_backend_when_name_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TOTP controller assembly falls back to the primary startup backend when no name is configured."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    secondary_backend = _backend(name="secondary", token_prefix="secondary")
    config = _minimal_config(
        backends=[primary_backend, secondary_backend],
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
        ),
    )
    captured: dict[str, object] = {}

    def _create_totp_controller(**kwargs: object) -> str:
        captured.update(kwargs)
        return "totp-controller"

    monkeypatch.setattr(totp_controllers_module, "create_totp_controller", _create_totp_controller)

    assert build_totp_controller(config) == "totp-controller"
    assert isinstance(captured["backend"], _current_startup_backend_template_type())
    assert captured["backend"].name == primary_backend.name
    assert captured["backend_index"] == 0


def test_build_totp_controller_forwards_totp_secret_key_from_user_manager_security(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TOTP controller assembly forwards the Fernet key configured on UserManagerSecurity."""
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="p" * 32))
    config.user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_key="fernet-secret-key-for-plugin-wiring",
        id_parser=UUID,
    )
    captured: dict[str, object] = {}

    def _create_totp_controller(**kwargs: object) -> str:
        captured.update(kwargs)
        return "totp-controller"

    monkeypatch.setattr(totp_controllers_module, "create_totp_controller", _create_totp_controller)

    assert build_totp_controller(config) == "totp-controller"
    assert captured["totp_secret_key"] == "fernet-secret-key-for-plugin-wiring"
    assert captured["totp_secret_keyring"] is None


def test_build_totp_controller_forwards_totp_keyring_from_user_manager_security(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TOTP controller assembly forwards the configured versioned Fernet keyring."""
    keyring = FernetKeyringConfig(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="p" * 32))
    config.user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_keyring=keyring,
        id_parser=UUID,
    )
    captured: dict[str, object] = {}

    def _create_totp_controller(**kwargs: object) -> str:
        captured.update(kwargs)
        return "totp-controller"

    monkeypatch.setattr(totp_controllers_module, "create_totp_controller", _create_totp_controller)

    assert build_totp_controller(config) == "totp-controller"
    assert captured["totp_secret_key"] is None
    assert captured["totp_secret_keyring"] is keyring


def test_build_totp_controller_raises_for_unknown_named_backend_after_index_scan() -> None:
    """The TOTP controller path still fails closed after scanning startup backends for an index."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_backend_name="missing",
        ),
    )

    with pytest.raises(ValueError, match="Unknown TOTP backend: missing"):
        build_totp_controller(config)


def test_totp_backend_raises_for_unknown_backend_name() -> None:
    """Named TOTP backends must exist in the configured backend set."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_backend_name="missing",
        ),
    )

    with pytest.raises(ValueError, match="Unknown TOTP backend: missing"):
        totp_backend(config)


def test_totp_backend_defaults_to_primary_startup_backend() -> None:
    """Without a named override, TOTP uses the primary startup backend."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    secondary_backend = _backend(name="secondary", token_prefix="secondary")
    config = _minimal_config(
        backends=[primary_backend, secondary_backend],
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
        ),
    )

    startup_backend = totp_backend(config)

    assert isinstance(startup_backend, _current_startup_backend_template_type())
    assert startup_backend.name == primary_backend.name


def test_resolve_request_backend_raises_when_backend_index_is_missing() -> None:
    """Request backend resolution fails closed when the startup index is absent at runtime."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    secondary_backend = _backend(name="secondary", token_prefix="secondary")
    inventory = resolve_backend_inventory(_minimal_config(backends=[secondary_backend, primary_backend]))

    with pytest.raises(RuntimeError, match="Missing backend index 1 for 'primary'"):
        totp_controllers_module._resolve_request_backend(
            inventory,
            [secondary_backend],
            backend_index=1,
        )


def test_resolve_request_backend_raises_when_backend_name_changes() -> None:
    """Request backend resolution fails closed when backend ordering no longer matches startup."""
    backend = _backend(name="secondary", token_prefix="secondary")
    inventory = resolve_backend_inventory(_minimal_config(backends=[_backend(name="primary", token_prefix="primary")]))

    with pytest.raises(RuntimeError, match="Expected backend 'primary' at index 0, got 'secondary'"):
        totp_controllers_module._resolve_request_backend(
            inventory,
            [backend],
            backend_index=0,
        )


async def test_create_totp_controller_enable_validation_callback_runs_background_task() -> None:
    """Plugin TOTP enable handlers keep the invalid-payload background callback wired."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_enrollment_store=InMemoryTotpEnrollmentStore(),
        ),
    )
    inventory = resolve_backend_inventory(config)
    controller_cls = controllers_module.create_totp_controller(
        backend=config.resolve_startup_backends()[0],
        backend_inventory=inventory,
        backend_index=0,
        user_manager_dependency_key="litestar_auth_user_manager",
        pending_jti_store=cast("Any", object()),
        require_replay_protection=False,
        totp_pending_secret="p" * 32,
        totp_enable_requires_password=True,
        unsafe_testing=True,
    )
    controller_handler = cast("Any", controller_cls).enable
    exception_handler = controller_handler.exception_handlers[ValidationException]
    response = exception_handler(cast("Any", object()), object())

    assert response.background is not None
    await response.background()


async def test_create_totp_controller_regenerate_validation_callback_runs_background_task() -> None:
    """Plugin TOTP regenerate handlers keep the invalid-payload background callback wired."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_enrollment_store=InMemoryTotpEnrollmentStore(),
        ),
    )
    inventory = resolve_backend_inventory(config)
    controller_cls = controllers_module.create_totp_controller(
        backend=config.resolve_startup_backends()[0],
        backend_inventory=inventory,
        backend_index=0,
        user_manager_dependency_key="litestar_auth_user_manager",
        pending_jti_store=cast("Any", object()),
        require_replay_protection=False,
        totp_pending_secret="p" * 32,
        totp_enable_requires_password=True,
        unsafe_testing=True,
    )
    controller_handler = cast("Any", controller_cls).regenerate_recovery_codes
    exception_handler = controller_handler.exception_handlers[ValidationException]
    response = exception_handler(cast("Any", object()), object())

    assert response.background is not None
    await response.background()


async def test_plugin_totp_regenerate_route_delegates_with_step_up_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plugin TOTP regenerate route delegates to the shared handler with decoded payloads."""
    config = _minimal_config()
    inventory = resolve_backend_inventory(config)
    handler = AsyncMock(return_value="response")
    monkeypatch.setattr(totp_route_handlers_module, "_totp_handle_regenerate_recovery_codes", handler)
    controller_cls = totp_controllers_module.create_totp_controller(
        backend=config.resolve_startup_backends()[0],
        backend_inventory=inventory,
        backend_index=0,
        user_manager_dependency_key="litestar_auth_user_manager",
        pending_jti_store=cast("Any", object()),
        require_replay_protection=False,
        totp_pending_secret="p" * 32,
        totp_enable_requires_password=True,
        unsafe_testing=True,
    )
    data = object()
    request = object()
    user_manager = object()

    response = await cast("Any", controller_cls).regenerate_recovery_codes.fn(
        object(),
        request,
        user_manager,
        data,
    )

    assert response == "response"
    handler.assert_awaited_once()
    await_args = handler.await_args
    assert await_args is not None
    assert await_args.args == (request,)
    assert await_args.kwargs["data"] is data
    assert await_args.kwargs["user_manager"] is user_manager


async def test_plugin_totp_regenerate_route_delegates_without_step_up_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plugin TOTP regenerate no-body route delegates to the shared handler without data."""
    config = _minimal_config()
    inventory = resolve_backend_inventory(config)
    handler = AsyncMock(return_value="response")
    monkeypatch.setattr(totp_route_handlers_module, "_totp_handle_regenerate_recovery_codes", handler)
    controller_cls = totp_controllers_module.create_totp_controller(
        backend=config.resolve_startup_backends()[0],
        backend_inventory=inventory,
        backend_index=0,
        user_manager_dependency_key="litestar_auth_user_manager",
        pending_jti_store=cast("Any", object()),
        require_replay_protection=False,
        totp_pending_secret="p" * 32,
        totp_enable_requires_password=False,
        unsafe_testing=True,
    )
    request = object()
    user_manager = object()

    response = await cast("Any", controller_cls).regenerate_recovery_codes.fn(object(), request, user_manager)

    assert response == "response"
    handler.assert_awaited_once()
    await_args = handler.await_args
    assert await_args is not None
    assert await_args.args == (request,)
    assert "data" not in await_args.kwargs
    assert await_args.kwargs["user_manager"] is user_manager


def test_schema_kwargs_include_non_null_custom_schemas() -> None:
    """Schema-kwargs helpers include only explicitly configured custom schemas."""
    config = _minimal_config()
    config.user_read_schema = _ReadSchema
    config.user_create_schema = _CreateSchema
    config.user_update_schema = _UpdateSchema

    assert user_read_schema_kwargs(config) == {"user_read_schema": _ReadSchema}
    assert register_schema_kwargs(config) == {
        "user_read_schema": _ReadSchema,
        "user_create_schema": _CreateSchema,
    }
    assert users_schema_kwargs(config) == {
        "user_read_schema": _ReadSchema,
        "user_update_schema": _UpdateSchema,
    }


def test_append_optional_feature_controllers_skips_totp_and_oauth_when_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Optional-controller assembly remains empty when all optional features are disabled."""
    config = _minimal_config()
    config.include_register = False
    config.include_verify = False
    config.include_reset_password = False
    config.include_users = False
    controllers: list[ControllerRouterHandler] = []

    monkeypatch.setattr(
        controllers_module,
        "build_totp_controller",
        lambda _config, **_kwargs: pytest.fail("build_totp_controller should not be called"),
    )
    monkeypatch.setattr(
        oauth_controllers_module,
        "create_oauth_associate_controller",
        lambda **_kwargs: pytest.fail("create_oauth_associate_controller should not be called"),
    )
    monkeypatch.setattr(
        oauth_controllers_module,
        "create_oauth_login_controller",
        lambda **_kwargs: pytest.fail("create_oauth_login_controller should not be called"),
    )

    _append_optional_feature_controllers(controllers=controllers, config=config)

    assert controllers == []


def test_append_optional_feature_controllers_appends_enabled_features_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Optional-controller assembly includes enabled register, verify, reset, users, TOTP, and OAuth routes."""
    github_client = object()
    gitlab_client = object()
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[
                _oauth_provider(name="github", client=github_client),
                _oauth_provider(name="gitlab", client=gitlab_client),
            ],
            oauth_redirect_base_url="https://app.example/auth",
            include_oauth_associate=True,
            oauth_cookie_secure=False,
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
    )
    config.include_users = True
    config.user_read_schema = _ReadSchema
    config.user_create_schema = _CreateSchema
    config.user_update_schema = _UpdateSchema
    calls: list[tuple[str, dict[str, object]]] = []

    def _record(name: str) -> Callable[..., str]:
        def _factory(**kwargs: object) -> str:
            calls.append((name, dict(kwargs)))
            return name

        return _factory

    monkeypatch.setattr(controllers_module, "create_register_controller", _record("register"))
    monkeypatch.setattr(controllers_module, "create_verify_controller", _record("verify"))
    monkeypatch.setattr(controllers_module, "create_reset_password_controller", _record("reset"))
    monkeypatch.setattr(controllers_module, "create_users_controller", _record("users"))
    monkeypatch.setattr(controllers_module, "build_totp_controller", lambda _config, **_kwargs: "totp")

    def _create_oauth_login_controller(settings: Any) -> str:  # noqa: ANN401
        values = _settings_values(settings)
        calls.append(("oauth-login", values))
        return cast("str", values["provider_name"])

    def _create_oauth_associate_controller(settings: Any) -> str:  # noqa: ANN401
        values = _settings_values(settings)
        calls.append(("oauth-associate", values))
        return f"associate-{values['provider_name']}"

    monkeypatch.setattr(
        oauth_controllers_module,
        "create_oauth_login_controller",
        _create_oauth_login_controller,
    )

    monkeypatch.setattr(
        oauth_controllers_module,
        "create_oauth_associate_controller",
        _create_oauth_associate_controller,
    )

    controllers: list[ControllerRouterHandler] = []
    _append_optional_feature_controllers(controllers=controllers, config=config)

    assert controllers == [
        "register",
        "verify",
        "reset",
        "users",
        "totp",
        "github",
        "gitlab",
        "associate-github",
        "associate-gitlab",
    ]
    assert calls[0] == (
        "register",
        {
            "rate_limit_config": None,
            "path": "/auth",
            "register_minimum_response_seconds": 0.4,
            "unsafe_testing": False,
            "user_read_schema": _ReadSchema,
            "user_create_schema": _CreateSchema,
        },
    )
    assert calls[1] == (
        "verify",
        {
            "rate_limit_config": None,
            "path": "/auth",
            "unsafe_testing": False,
            "user_read_schema": _ReadSchema,
        },
    )
    assert calls[2] == (
        "reset",
        {
            "rate_limit_config": None,
            "path": "/auth",
            "unsafe_testing": False,
            "user_read_schema": _ReadSchema,
        },
    )
    assert calls[3] == (
        "users",
        {
            "id_parser": UUID,
            "rate_limit_config": None,
            "path": "/users",
            "hard_delete": False,
            "unsafe_testing": False,
            "security": None,
            "user_read_schema": _ReadSchema,
            "user_update_schema": _UpdateSchema,
        },
    )
    primary_backend = config.backends[0]
    assert calls[4] == ("oauth-login", _oauth_login_call("github", github_client, primary_backend))
    assert calls[5] == ("oauth-login", _oauth_login_call("gitlab", gitlab_client, primary_backend))
    assert calls[6] == ("oauth-associate", _oauth_associate_call("github", github_client))
    assert calls[7] == ("oauth-associate", _oauth_associate_call("gitlab", gitlab_client))


def test_append_oauth_login_controllers_uses_explicit_redirect_base_url_and_primary_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plugin OAuth login assembly uses the shared provider inventory and primary backend."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    secondary_backend = _backend(name="secondary", token_prefix="secondary")
    client = object()
    config = _minimal_config(
        backends=[primary_backend, secondary_backend],
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=client)],
            oauth_redirect_base_url="https://app.example/auth",
            oauth_cookie_secure=False,
            oauth_associate_by_email=True,
            oauth_trust_provider_email_verified=True,
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )
    captured: list[dict[str, object]] = []

    def _create_oauth_login_controller(settings: Any) -> str:  # noqa: ANN401
        captured.append(_settings_values(settings))
        return "github"

    monkeypatch.setattr(
        oauth_controllers_module,
        "create_oauth_login_controller",
        _create_oauth_login_controller,
    )

    controllers: list[ControllerRouterHandler] = []
    _append_oauth_login_controllers(controllers=controllers, config=config)

    assert controllers == ["github"]
    assert captured == [
        {
            "provider_name": "github",
            "oauth_client": client,
            "backend_inventory": resolve_backend_inventory(config),
            "backend_index": 0,
            "redirect_base_url": "https://app.example/auth/oauth",
            "oauth_flow_cookie_secret": OAUTH_FLOW_COOKIE_SECRET,
            "path": "/auth/oauth",
            "cookie_secure": False,
            "oauth_scopes": None,
            "associate_by_email": True,
            "trust_provider_email_verified": True,
        },
    ]


def test_append_oauth_login_controllers_forwards_per_provider_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plugin OAuth login assembly forwards configured server-owned scopes per provider."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    github_client = object()
    gitlab_client = object()
    config = _minimal_config(
        backends=[primary_backend],
        oauth_config=OAuthConfig(
            oauth_providers=[
                _oauth_provider(name="github", client=github_client),
                _oauth_provider(name="gitlab", client=gitlab_client),
            ],
            oauth_redirect_base_url="https://app.example/auth",
            oauth_provider_scopes={"github": ["openid", "email"]},
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )
    captured: list[dict[str, object]] = []

    def _create_oauth_login_controller(settings: Any) -> str:  # noqa: ANN401
        values = _settings_values(settings)
        captured.append(values)
        return cast("str", values["provider_name"])

    monkeypatch.setattr(oauth_controllers_module, "create_oauth_login_controller", _create_oauth_login_controller)

    controllers: list[ControllerRouterHandler] = []
    _append_oauth_login_controllers(controllers=controllers, config=config)

    assert controllers == ["github", "gitlab"]
    assert captured[0]["provider_name"] == "github"
    assert captured[0]["oauth_scopes"] == ("openid", "email")
    assert captured[1]["provider_name"] == "gitlab"
    assert captured[1]["oauth_scopes"] is None


def test_append_oauth_associate_controllers_uses_explicit_redirect_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OAuth associate assembly honors the explicit redirect-base override."""
    client = object()
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=client)],
            include_oauth_associate=True,
            oauth_redirect_base_url="https://app.example/auth",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )
    captured: list[dict[str, object]] = []

    def _create_oauth_associate_controller(settings: Any) -> str:  # noqa: ANN401
        captured.append(_settings_values(settings))
        return "github"

    monkeypatch.setattr(
        oauth_controllers_module,
        "create_oauth_associate_controller",
        _create_oauth_associate_controller,
    )

    controllers: list[ControllerRouterHandler] = []
    _append_oauth_associate_controllers(controllers=controllers, config=config)

    assert controllers == ["github"]
    assert captured == [
        {
            "provider_name": "github",
            "user_manager_dependency_key": OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
            "oauth_client": client,
            "redirect_base_url": "https://app.example/auth/associate",
            "oauth_flow_cookie_secret": OAUTH_FLOW_COOKIE_SECRET,
            "path": "/auth/associate",
            "cookie_secure": True,
            "security": None,
        },
    ]


def test_append_oauth_associate_controllers_uses_shared_provider_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plugin OAuth associate assembly reuses the single plugin-owned provider inventory."""
    oauth_client = object()
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=oauth_client)],
            include_oauth_associate=True,
            oauth_redirect_base_url="https://app.example/auth",
            oauth_cookie_secure=False,
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )
    captured: list[dict[str, object]] = []

    def _create_oauth_associate_controller(settings: Any) -> str:  # noqa: ANN401
        values = _settings_values(settings)
        captured.append(values)
        return cast("str", values["provider_name"])

    monkeypatch.setattr(
        oauth_controllers_module,
        "create_oauth_associate_controller",
        _create_oauth_associate_controller,
    )

    controllers: list[ControllerRouterHandler] = []
    _append_oauth_associate_controllers(controllers=controllers, config=config)

    assert controllers == ["github"]
    assert captured == [_oauth_associate_call("github", oauth_client)]


def _minimal_config(
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    oauth_config: OAuthConfig | None = None,
    totp_config: TotpConfig | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for controller-assembly unit tests.

    Returns:
        Config object with overridable backends plus optional OAuth and TOTP settings.
    """
    user_db = InMemoryUserDatabase([])
    configured_backends = (
        backends
        if backends is not None
        else [
            _backend(name="primary", token_prefix="plugin-controllers"),
        ]
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=configured_backends,
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
            id_parser=UUID,
        ),
        oauth_config=oauth_config,
        totp_config=totp_config,
    )


def _backend(*, name: str, token_prefix: str) -> AuthenticationBackend[ExampleUser, UUID]:
    """Build a bearer backend suitable for controller-assembly tests.

    Returns:
        Authentication backend using the in-memory strategy helper.
    """
    return AuthenticationBackend[ExampleUser, UUID](
        name=name,
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix=token_prefix)),
    )


def _oauth_login_call(
    provider_name: str,
    oauth_client: object,
    backend: AuthenticationBackend[ExampleUser, UUID],
    *,
    oauth_scopes: tuple[str, ...] | None = None,
) -> dict[str, object]:
    """Build the expected kwargs for plugin-owned OAuth login controller factories.

    Returns:
        Expected controller-factory keyword arguments for a provider binding.
    """
    return {
        "provider_name": provider_name,
        "oauth_client": oauth_client,
        "backend_inventory": resolve_backend_inventory(_minimal_config(backends=[backend])),
        "backend_index": 0,
        "redirect_base_url": "https://app.example/auth/oauth",
        "oauth_flow_cookie_secret": OAUTH_FLOW_COOKIE_SECRET,
        "path": "/auth/oauth",
        "cookie_secure": False,
        "oauth_scopes": oauth_scopes,
        "associate_by_email": False,
        "trust_provider_email_verified": False,
    }


def _settings_values(settings: Any) -> dict[str, object]:  # noqa: ANN401
    """Return dataclass settings fields as a plain dictionary.

    Returns:
        Field names and values from a controller settings dataclass.
    """
    return {field_name: getattr(settings, field_name) for field_name in settings.__dataclass_fields__}


def _oauth_associate_call(provider_name: str, oauth_client: object) -> dict[str, object]:
    """Build the expected kwargs for OAuth-associate controller factories.

    Returns:
        Expected controller-factory keyword arguments for a provider binding.
    """
    return {
        "provider_name": provider_name,
        "user_manager_dependency_key": OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
        "oauth_client": oauth_client,
        "redirect_base_url": "https://app.example/auth/associate",
        "oauth_flow_cookie_secret": OAUTH_FLOW_COOKIE_SECRET,
        "path": "/auth/associate",
        "cookie_secure": False,
        "security": None,
    }
