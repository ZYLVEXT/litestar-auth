"""Integration coverage for auth plugin extension wiring."""

from __future__ import annotations

from importlib import metadata
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar
from litestar.enums import MediaType
from litestar.openapi.config import OpenAPIConfig
from litestar.response import Response
from litestar.testing import AsyncTestClient

import litestar_auth._plugin.extensions._discovery as extension_discovery_module
from litestar_auth._plugin.extensions import EXTENSION_ENTRY_POINT_GROUP
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)
from tests.support import extensions as support_extensions
from tests.support.extensions import EXTENSION_HTTP_TEAPOT, ExtensionHeaderMiddleware, WiringProbeExtension

if TYPE_CHECKING:
    from litestar.middleware import DefineMiddleware

pytestmark = pytest.mark.integration
HTTP_OK = 200
HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404


def _build_config(
    *,
    extensions: tuple[object, ...] = (),
    auto_discover_extensions: bool = False,
    users: list[ExampleUser] | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase(
        users
        if users is not None
        else [
            ExampleUser(
                id=uuid4(),
                email="extension-user@example.com",
                hashed_password=password_helper.hash("user-password"),
                is_verified=True,
            ),
        ],
    )
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-extension-integration")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
            password_helper=password_helper,
        ),
        include_users=False,
        extensions=cast("Any", extensions),
        auto_discover_extensions=auto_discover_extensions,
    )


def _patch_external_extension_entry_points(
    monkeypatch: pytest.MonkeyPatch,
    *entries: tuple[str, str],
) -> None:
    # Installing an ad hoc distribution during the test would mutate shared interpreter metadata under xdist.
    # Real EntryPoint/EntryPoints objects still exercise the selectable importlib.metadata contract used by discovery.
    entry_points = metadata.EntryPoints(
        metadata.EntryPoint(name=name, value=value, group=EXTENSION_ENTRY_POINT_GROUP) for name, value in entries
    )

    def discoverable_entry_points() -> metadata.EntryPoints:
        return entry_points

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", discoverable_entry_points)


async def test_extension_contributions_are_wired_before_app_level_hooks() -> None:
    """Extension contributions are available before final controller/middleware/exception hooks run."""
    events: list[str] = []
    controller_hook_names: list[str] = []
    exception_hook_paths: list[str] = []

    disabled_events: list[str] = []
    enabled_extension = WiringProbeExtension(events)
    disabled_extension = WiringProbeExtension(disabled_events, enabled=False)
    config = _build_config(extensions=(enabled_extension, disabled_extension))

    def controller_hook(controllers: list[object]) -> list[object]:
        controller_hook_names.extend(
            name
            for controller in controllers
            if isinstance((name := getattr(controller, "handler_name", getattr(controller, "__name__", None))), str)
        )
        events.append("controller-hook")
        return controllers

    def middleware_hook(middleware: DefineMiddleware) -> DefineMiddleware:
        events.append("middleware-hook")
        return middleware

    def exception_response_hook(exc: object, request: object) -> Response[dict[str, object]]:
        exception_hook_paths.append(cast("Any", request).url.path)
        return Response(
            {"detail": str(exc), "code": getattr(exc, "code", None)},
            status_code=getattr(exc, "status_code", HTTP_BAD_REQUEST),
            media_type=MediaType.JSON,
        )

    config.controller_hook = cast("Any", controller_hook)
    config.middleware_hook = middleware_hook
    config.exception_response_hook = exception_response_hook
    openapi_config = OpenAPIConfig(title="Extension wiring", version="1.0.0")
    app = Litestar(openapi_config=openapi_config, plugins=[LitestarAuth(config)])

    assert "extension_value" in controller_hook_names
    extension_middleware = cast("DefineMiddleware", app.middleware[1])
    assert getattr(extension_middleware.middleware, "__name__", "") == ExtensionHeaderMiddleware.__name__
    security_schemes = cast("Any", app.openapi_schema.components.security_schemes)
    assert "primary" in security_schemes
    assert "extensionAuth" in security_schemes

    async with AsyncTestClient(app=app) as client:
        value_response = await client.get("/extension/value")
        failure_response = await client.get("/extension/failure")
        client_exception_response = await client.get("/extension/client-exception")

    assert value_response.status_code == HTTP_OK
    assert value_response.json() == {"value": "extension-value"}
    assert value_response.headers["x-extension-middleware"] == "enabled"
    assert failure_response.status_code == EXTENSION_HTTP_TEAPOT
    assert failure_response.json() == {"detail": "extension handler", "code": "EXTENSION_FAILURE"}
    assert client_exception_response.status_code == HTTP_BAD_REQUEST
    assert client_exception_response.json() == {
        "detail": "extension client exception",
        "code": "EXTENSION_CLIENT_EXCEPTION",
    }
    assert exception_hook_paths == ["/extension/client-exception"]
    assert events == [
        "validate",
        "register",
        "middleware-hook",
        "controller-hook",
        "startup",
        "dependency",
        "shutdown",
    ]
    assert disabled_events == []


async def test_disabled_extension_is_inert_for_app_wiring() -> None:
    """A disabled extension contributes no app config state or lifecycle hooks."""
    events: list[str] = []
    config = _build_config(extensions=(WiringProbeExtension(events, enabled=False),))
    openapi_config = OpenAPIConfig(title="Disabled extension wiring", version="1.0.0")
    app = Litestar(openapi_config=openapi_config, plugins=[LitestarAuth(config)])

    assert events == []
    assert all(
        getattr(cast("Any", middleware).middleware, "__name__", "") != ExtensionHeaderMiddleware.__name__
        for middleware in app.middleware
    )
    security_schemes = cast("Any", app.openapi_schema.components.security_schemes)
    assert "primary" in security_schemes
    assert "extensionAuth" not in security_schemes

    async with AsyncTestClient(app=app) as client:
        value_response = await client.get("/extension/value")

    assert value_response.status_code == HTTP_NOT_FOUND
    assert events == []


async def test_auto_discovered_external_extension_golden_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """A discovered external-style extension contributes app behavior and manager subscribers."""
    support_extensions.reset_external_extension_records()
    user = ExampleUser(
        id=uuid4(),
        email="external-unverified@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    _patch_external_extension_entry_points(
        monkeypatch,
        (
            "external_golden_path",
            "tests.support.extensions:create_external_golden_path_extension",
        ),
    )
    config = _build_config(auto_discover_extensions=True, users=[user])
    app = Litestar(plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        value_response = await client.get("/external-extension/value")
        verify_response = await client.post("/auth/request-verify-token", json={"email": user.email})

    assert value_response.status_code == HTTP_OK
    assert value_response.json() == {"value": "external-extension-value"}
    assert verify_response.status_code == HTTP_ACCEPTED
    assert support_extensions.EXTERNAL_DISCOVERED_EVENTS == ["validate", "register", "dependency"]
    assert len(support_extensions.EXTERNAL_DISCOVERED_MANAGER_EVENTS) == 1
    event = support_extensions.EXTERNAL_DISCOVERED_MANAGER_EVENTS[0]
    assert event.name == "after_request_verify_token"
    assert event.args[0] is user
    assert event.args[1] is None


def test_auto_discovered_incompatible_extension_fails_closed_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plugin startup path applies the API-version gate to discovered extensions."""
    support_extensions.reset_external_extension_records()
    _patch_external_extension_entry_points(
        monkeypatch,
        (
            "external_incompatible",
            "tests.support.extensions:create_incompatible_external_extension",
        ),
    )
    config = _build_config(auto_discover_extensions=True)

    with pytest.raises(ConfigurationError, match=r"requires extension API 999\.0, but litestar-auth provides 1\.0"):
        Litestar(plugins=[LitestarAuth(config)])

    assert support_extensions.EXTERNAL_DISCOVERED_EVENTS == []
    assert support_extensions.EXTERNAL_DISCOVERED_MANAGER_EVENTS == []


async def test_entry_point_discovery_disabled_leaves_external_extension_inert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registered entry points do not affect apps unless discovery is explicitly enabled."""
    support_extensions.reset_external_extension_records()
    _patch_external_extension_entry_points(
        monkeypatch,
        (
            "external_golden_path",
            "tests.support.extensions:create_external_golden_path_extension",
        ),
    )
    config = _build_config(auto_discover_extensions=False)
    app = Litestar(plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/external-extension/value")

    assert response.status_code == HTTP_NOT_FOUND
    assert support_extensions.EXTERNAL_DISCOVERED_EVENTS == []
    assert support_extensions.EXTERNAL_DISCOVERED_MANAGER_EVENTS == []
