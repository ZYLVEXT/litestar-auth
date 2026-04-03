"""Unit tests for plugin controller assembly helpers."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import msgspec
import pytest

import litestar_auth._plugin.controllers as controllers_module
from litestar_auth._plugin.config import (
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
    OAuthConfig,
    TotpConfig,
)
from litestar_auth._plugin.controllers import (
    _append_oauth_associate_controllers,
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
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.types import ControllerRouterHandler


class _ReadSchema(msgspec.Struct):
    email: str


class _CreateSchema(msgspec.Struct):
    email: str
    password: str


class _UpdateSchema(msgspec.Struct):
    username: str


def test_plugin_controllers_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(controllers_module)

    assert reloaded_module.build_controllers.__name__ == build_controllers.__name__
    assert reloaded_module.build_totp_controller.__name__ == build_totp_controller.__name__


def test_build_controllers_combines_auth_and_optional_controllers(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_controllers returns auth controllers plus appended optional controllers."""
    config = _minimal_config()
    optional_calls: list[tuple[list[object], LitestarAuthConfig[ExampleUser, UUID]]] = []

    def _build_auth(*, config: LitestarAuthConfig[ExampleUser, UUID]) -> list[str]:
        del config
        return ["auth-controller"]

    monkeypatch.setattr(controllers_module, "_build_auth_controllers", _build_auth)

    def _append(
        *,
        controllers: list[object],
        config: LitestarAuthConfig[ExampleUser, UUID],
    ) -> None:
        optional_calls.append((list(controllers), config))
        controllers.append("optional-controller")

    monkeypatch.setattr(controllers_module, "_append_optional_feature_controllers", _append)

    assert build_controllers(config) == ["auth-controller", "optional-controller"]
    assert optional_calls == [(["auth-controller"], config)]


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

    def _create_auth_controller(**kwargs: object) -> str:
        calls.append(dict(kwargs))
        return cast("str", kwargs["path"])

    monkeypatch.setattr(controllers_module, "create_auth_controller", _create_auth_controller)

    assert _build_auth_controllers(config=config) == ["/auth", "/auth/secondary"]
    assert calls[0]["backend"] is primary_backend
    assert calls[0]["totp_pending_secret"] == "p" * 32
    assert calls[1]["backend"] is secondary_backend
    assert calls[1]["path"] == "/auth/secondary"


def test_build_totp_controller_raises_when_totp_config_missing() -> None:
    """TOTP controller construction fails fast when no TOTP config is available."""
    with pytest.raises(ValueError, match="totp_config must be configured"):
        build_totp_controller(_minimal_config())


def test_build_totp_controller_forwards_named_backend_and_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """TOTP controller assembly uses the configured backend and forwards all plugin settings."""
    primary_backend = _backend(name="primary", token_prefix="primary")
    secondary_backend = _backend(name="secondary", token_prefix="secondary")
    used_tokens_store = cast("Any", object())
    config = _minimal_config(
        backends=[primary_backend, secondary_backend],
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_backend_name="secondary",
            totp_issuer="Example Issuer",
            totp_algorithm=cast("Any", "SHA512"),
            totp_used_tokens_store=used_tokens_store,
            totp_require_replay_protection=False,
            totp_enable_requires_password=False,
        ),
    )
    captured: dict[str, object] = {}

    def _create_totp_controller(**kwargs: object) -> str:
        captured.update(kwargs)
        return "totp-controller"

    monkeypatch.setattr(controllers_module, "create_totp_controller", _create_totp_controller)

    assert build_totp_controller(config) == "totp-controller"
    assert captured["backend"] is secondary_backend
    assert captured["user_manager_dependency_key"] == "litestar_auth_user_manager"
    assert captured["used_tokens_store"] is used_tokens_store
    assert captured["require_replay_protection"] is False
    assert captured["requires_verification"] is False
    assert captured["totp_pending_secret"] == "p" * 32
    assert captured["totp_enable_requires_password"] is False
    assert captured["totp_issuer"] == "Example Issuer"
    assert captured["totp_algorithm"] == "SHA512"
    assert captured["path"] == "/auth/2fa"


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
        lambda _config: pytest.fail("build_totp_controller should not be called"),
    )
    monkeypatch.setattr(
        controllers_module,
        "create_oauth_associate_controller",
        lambda **_kwargs: pytest.fail("create_oauth_associate_controller should not be called"),
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
            include_oauth_associate=True,
            oauth_associate_providers=[
                ("github", github_client),
                ("gitlab", gitlab_client),
            ],
            oauth_cookie_secure=False,
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
    monkeypatch.setattr(controllers_module, "build_totp_controller", lambda _config: "totp")

    def _create_oauth_associate_controller(**kwargs: object) -> str:
        calls.append(("oauth", dict(kwargs)))
        return cast("str", kwargs["provider_name"])

    monkeypatch.setattr(
        controllers_module,
        "create_oauth_associate_controller",
        _create_oauth_associate_controller,
    )

    controllers: list[ControllerRouterHandler] = []
    _append_optional_feature_controllers(controllers=controllers, config=config)

    assert controllers == ["register", "verify", "reset", "users", "totp", "github", "gitlab"]
    assert calls[0] == (
        "register",
        {
            "rate_limit_config": None,
            "path": "/auth",
            "user_read_schema": _ReadSchema,
            "user_create_schema": _CreateSchema,
        },
    )
    assert calls[1] == (
        "verify",
        {
            "rate_limit_config": None,
            "path": "/auth",
            "user_read_schema": _ReadSchema,
        },
    )
    assert calls[2] == (
        "reset",
        {
            "rate_limit_config": None,
            "path": "/auth",
            "user_read_schema": _ReadSchema,
        },
    )
    assert calls[3] == (
        "users",
        {
            "id_parser": UUID,
            "path": "/users",
            "hard_delete": False,
            "user_read_schema": _ReadSchema,
            "user_update_schema": _UpdateSchema,
        },
    )
    assert calls[4] == ("oauth", _oauth_call("github", github_client))
    assert calls[5] == ("oauth", _oauth_call("gitlab", gitlab_client))


def test_append_oauth_associate_controllers_uses_explicit_redirect_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OAuth associate assembly honors the explicit redirect-base override."""
    client = object()
    config = _minimal_config(
        oauth_config=OAuthConfig(
            include_oauth_associate=True,
            oauth_associate_providers=[("github", client)],
            oauth_associate_redirect_base_url="https://app.example/auth/associate",
        ),
    )
    captured: list[dict[str, object]] = []

    def _create_oauth_associate_controller(**kwargs: object) -> str:
        captured.append(dict(kwargs))
        return "github"

    monkeypatch.setattr(
        controllers_module,
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
            "path": "/auth/associate",
            "cookie_secure": True,
        },
    ]


def test_append_oauth_associate_controllers_ignores_oauth_login_provider_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plugin OAuth route assembly reads only the associate-provider inventory."""
    login_client = object()
    associate_client = object()
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[("github", login_client)],
            include_oauth_associate=True,
            oauth_associate_providers=[("gitlab", associate_client)],
            oauth_cookie_secure=False,
        ),
    )
    captured: list[dict[str, object]] = []

    def _create_oauth_associate_controller(**kwargs: object) -> str:
        captured.append(dict(kwargs))
        return cast("str", kwargs["provider_name"])

    monkeypatch.setattr(
        controllers_module,
        "create_oauth_associate_controller",
        _create_oauth_associate_controller,
    )

    controllers: list[ControllerRouterHandler] = []
    _append_oauth_associate_controllers(controllers=controllers, config=config)

    assert controllers == ["gitlab"]
    assert captured == [_oauth_call("gitlab", associate_client)]


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
        user_manager_kwargs={
            "verification_token_secret": "v" * 32,
            "reset_password_token_secret": "r" * 32,
            "id_parser": UUID,
        },
        id_parser=UUID,
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


def _oauth_call(provider_name: str, oauth_client: object) -> dict[str, object]:
    """Build the expected kwargs for OAuth-associate controller factories.

    Returns:
        Expected controller-factory keyword arguments for a provider binding.
    """
    return {
        "provider_name": provider_name,
        "user_manager_dependency_key": OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
        "oauth_client": oauth_client,
        "redirect_base_url": "http://localhost/auth/associate",
        "path": "/auth/associate",
        "cookie_secure": False,
    }
