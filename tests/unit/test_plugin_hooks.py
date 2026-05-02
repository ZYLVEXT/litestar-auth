"""Unit tests for plugin customization hooks."""

from __future__ import annotations

import importlib
import inspect
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Controller
from litestar.config.app import AppConfig
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.middleware import DefineMiddleware
from litestar.response import Response

from litestar_auth import plugin as plugin_module
from litestar_auth._plugin import _hooks as plugin_hooks
from litestar_auth._plugin import config as plugin_config
from litestar_auth._plugin.dependencies import client_exception_handler
from litestar_auth.authentication import LitestarAuthMiddleware
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers._utils import _mark_litestar_auth_route_handler
from litestar_auth.exceptions import (
    AuthorizationError,
    InsufficientRolesError,
    InvalidVerifyTokenError,
    LitestarAuthError,
)
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.unit
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_TOO_MANY_REQUESTS = 429


def test_hook_protocols_are_reexported_from_plugin_config() -> None:
    """Hook protocols keep the historical config-module import path."""
    reloaded_hooks = importlib.reload(plugin_hooks)
    reloaded_config = importlib.reload(plugin_config)
    reloaded_plugin_module = importlib.reload(plugin_module)

    assert reloaded_config.ExceptionResponseHook is reloaded_hooks.ExceptionResponseHook
    assert reloaded_config.MiddlewareHook is reloaded_hooks.MiddlewareHook
    assert reloaded_config.ControllerHook is reloaded_hooks.ControllerHook
    assert reloaded_config.ExceptionResponseHook.__module__ == "litestar_auth._plugin._hooks"
    assert reloaded_config.MiddlewareHook.__module__ == "litestar_auth._plugin._hooks"
    assert reloaded_config.ControllerHook.__module__ == "litestar_auth._plugin._hooks"
    assert reloaded_plugin_module.ExceptionResponseHook is reloaded_hooks.ExceptionResponseHook
    assert reloaded_plugin_module.MiddlewareHook is reloaded_hooks.MiddlewareHook
    assert reloaded_plugin_module.ControllerHook is reloaded_hooks.ControllerHook


def test_hook_protocol_call_signatures_stay_positional_only() -> None:
    """Relocated protocols preserve the operator hook structural-typing contract."""
    assert tuple(inspect.signature(plugin_hooks.ExceptionResponseHook.__call__).parameters) == (
        "self",
        "exc",
        "request",
    )
    assert tuple(inspect.signature(plugin_hooks.MiddlewareHook.__call__).parameters) == ("self", "middleware")
    assert tuple(inspect.signature(plugin_hooks.ControllerHook.__call__).parameters) == ("self", "controllers")
    assert inspect.signature(plugin_hooks.ExceptionResponseHook.__call__).parameters["request"].kind is (
        inspect.Parameter.POSITIONAL_ONLY
    )
    assert inspect.signature(plugin_hooks.MiddlewareHook.__call__).parameters["middleware"].kind is (
        inspect.Parameter.POSITIONAL_ONLY
    )
    assert inspect.signature(plugin_hooks.ControllerHook.__call__).parameters["controllers"].kind is (
        inspect.Parameter.POSITIONAL_ONLY
    )


def _minimal_config(
    *,
    backend: AuthenticationBackend[ExampleUser, UUID] | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for hook tests.

    Returns:
        Plugin config suitable for isolated hook-registration assertions.
    """
    user_db = InMemoryUserDatabase([])
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-hooks")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend or default_backend],
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
        ),
        include_users=False,
    )


def test_litestar_auth_config_hook_fields_default_to_none() -> None:
    """Hook fields are opt-in and preserve existing behavior by default."""
    config = _minimal_config()

    assert config.exception_response_hook is None
    assert config.middleware_hook is None
    assert config.controller_hook is None


def test_register_exception_handlers_without_custom_hook_keeps_default_handler() -> None:
    """Plugin-owned routes keep the default auth ClientException formatter when unset."""

    @_mark_litestar_auth_route_handler
    class PluginOwnedController(Controller):
        exception_handlers: dict[type[Exception], object] | None = None
        path = "/auth"

    plugin = LitestarAuth(_minimal_config())

    plugin._register_exception_handlers([PluginOwnedController])

    handlers = cast("dict[type[Exception], object]", PluginOwnedController.exception_handlers)
    response = cast("Any", handlers[ClientException])(
        cast("Any", None),
        ClientException(status_code=HTTP_BAD_REQUEST, detail="bad credentials", extra={"code": "AUTH_FAILED"}),
    )

    assert (
        response.content
        == client_exception_handler(
            cast("Any", None),
            ClientException(status_code=HTTP_BAD_REQUEST, detail="bad credentials", extra={"code": "AUTH_FAILED"}),
        ).content
    )
    assert response.status_code == HTTP_BAD_REQUEST


def test_register_exception_handlers_with_custom_hook_uses_hook_response() -> None:
    """Custom exception-response hooks receive auth error metadata and replace the default handler."""
    seen: dict[str, object] = {}

    def exception_response_hook(exc: object, request: object) -> Response[dict[str, object]]:
        seen["exc"] = exc
        seen["request"] = request
        return Response(
            content={
                "detail": str(exc),
                "code": getattr(exc, "code", None),
                "status_code": getattr(exc, "status_code", None),
            },
            status_code=getattr(exc, "status_code", HTTP_BAD_REQUEST),
            media_type=MediaType.JSON,
            headers=getattr(exc, "headers", None),
        )

    config = _minimal_config()
    config.exception_response_hook = exception_response_hook
    plugin = LitestarAuth(config)

    @_mark_litestar_auth_route_handler
    class PluginOwnedController(Controller):
        exception_handlers: dict[type[Exception], object] | None = None
        path = "/auth"

    plugin._register_exception_handlers([PluginOwnedController])

    handlers = cast("dict[type[Exception], object]", PluginOwnedController.exception_handlers)
    handler = cast("Any", handlers[ClientException])
    request = object()
    client_exc = ClientException(
        status_code=HTTP_BAD_REQUEST,
        detail="The email verification token is invalid.",
        extra={"code": "VERIFY_USER_BAD_TOKEN"},
        headers={"X-Auth": "1"},
    )
    auth_error = InvalidVerifyTokenError()
    client_exc.__cause__ = auth_error

    response = handler(request, client_exc)

    wrapped_error = seen["exc"]
    assert wrapped_error is not None
    assert seen["request"] is request
    assert str(wrapped_error) == str(auth_error)
    assert getattr(wrapped_error, "code", None) == auth_error.code
    assert getattr(wrapped_error, "status_code", None) == HTTP_BAD_REQUEST
    assert getattr(wrapped_error, "headers", None) == {"X-Auth": "1"}
    assert response.status_code == HTTP_BAD_REQUEST
    assert response.headers["X-Auth"] == "1"
    assert response.content == {
        "detail": "The email verification token is invalid.",
        "code": "VERIFY_USER_BAD_TOKEN",
        "status_code": HTTP_BAD_REQUEST,
    }


def test_register_exception_handlers_custom_hook_wraps_client_exceptions_without_auth_cause() -> None:
    """Custom hooks still receive a LitestarAuthError when no domain exception caused the client error."""
    seen: dict[str, object] = {}

    def exception_response_hook(exc: object, request: object) -> Response[dict[str, object]]:
        seen["exc"] = exc
        seen["request"] = request
        return Response(
            content={"code": getattr(exc, "code", None)},
            status_code=getattr(exc, "status_code", HTTP_BAD_REQUEST),
            media_type=MediaType.JSON,
        )

    config = _minimal_config()
    config.exception_response_hook = exception_response_hook
    plugin = LitestarAuth(config)

    @_mark_litestar_auth_route_handler
    class PluginOwnedController(Controller):
        exception_handlers: dict[type[Exception], object] | None = None
        path = "/auth"

    plugin._register_exception_handlers([PluginOwnedController])

    handlers = cast("dict[type[Exception], object]", PluginOwnedController.exception_handlers)
    handler = cast("Any", handlers[ClientException])
    request = object()

    response = handler(
        request,
        ClientException(
            status_code=HTTP_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded.",
            extra={"code": HTTP_TOO_MANY_REQUESTS},
        ),
    )

    assert seen["request"] is request
    assert getattr(seen["exc"], "code", None) == LitestarAuthError.default_code
    assert getattr(seen["exc"], "status_code", None) == HTTP_TOO_MANY_REQUESTS
    assert response.status_code == HTTP_TOO_MANY_REQUESTS
    assert response.content == {"code": LitestarAuthError.default_code}


def test_register_exception_handlers_custom_hook_wraps_authorization_errors_with_role_context() -> None:
    """Custom hooks receive 403 auth wrappers that preserve structured role-denial context."""
    seen: dict[str, object] = {}

    def exception_response_hook(exc: object, request: object) -> Response[dict[str, object]]:
        seen["exc"] = exc
        seen["request"] = request
        return Response(
            content={
                "code": getattr(exc, "code", None),
                "required_roles": sorted(getattr(exc, "required_roles", ())),
                "user_roles": sorted(getattr(exc, "user_roles", ())),
                "require_all": getattr(exc, "require_all", None),
            },
            status_code=getattr(exc, "status_code", HTTP_BAD_REQUEST),
            media_type=MediaType.JSON,
        )

    config = _minimal_config()
    config.exception_response_hook = exception_response_hook
    plugin = LitestarAuth(config)

    @_mark_litestar_auth_route_handler
    class PluginOwnedController(Controller):
        exception_handlers: dict[type[Exception], object] | None = None
        path = "/auth"

    plugin._register_exception_handlers([PluginOwnedController])

    handlers = cast("dict[type[Exception], object]", PluginOwnedController.exception_handlers)
    handler = cast("Any", handlers[AuthorizationError])
    request = object()
    exc = InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"support"}),
        require_all=True,
    )

    response = handler(request, exc)

    assert seen["request"] is request
    assert getattr(seen["exc"], "code", None) == exc.code
    assert getattr(seen["exc"], "status_code", None) == HTTP_FORBIDDEN
    assert getattr(seen["exc"], "required_roles", None) == exc.required_roles
    assert getattr(seen["exc"], "user_roles", None) == exc.user_roles
    assert getattr(seen["exc"], "require_all", None) is True
    assert response.status_code == HTTP_FORBIDDEN
    assert response.content == {
        "code": exc.code,
        "required_roles": ["admin", "billing"],
        "user_roles": ["support"],
        "require_all": True,
    }


def test_register_middleware_without_hook_keeps_default_definition() -> None:
    """Unset middleware hooks leave the constructed auth middleware untouched."""
    cookie_backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie",
        transport=CookieTransport(cookie_name="auth_cookie", secure=False, path="/", samesite="lax"),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-hooks-cookie")),
    )
    config = _minimal_config(backend=cookie_backend)
    config.csrf_secret = "c" * 32
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    plugin._register_middleware(app_config)

    assert isinstance(app_config.middleware[0], DefineMiddleware)
    assert getattr(app_config.middleware[0].middleware, "__name__", "") == "LitestarAuthMiddleware"
    assert app_config.csrf_config is not None
    assert app_config.csrf_config.cookie_path == "/"


def test_register_middleware_hook_uses_returned_definition() -> None:
    """Middleware hooks receive the constructed definition and can replace it."""
    seen: dict[str, object] = {}
    replacement = DefineMiddleware(LitestarAuthMiddleware, replacement=True)
    config = _minimal_config()

    def middleware_hook(middleware: DefineMiddleware) -> DefineMiddleware:
        seen["middleware"] = middleware
        return replacement

    config.middleware_hook = middleware_hook
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    plugin._register_middleware(app_config)

    seen_middleware = seen["middleware"]
    assert isinstance(seen_middleware, DefineMiddleware)
    assert getattr(seen_middleware.middleware, "__name__", "") == "LitestarAuthMiddleware"
    assert app_config.middleware[0] is replacement


def test_register_controllers_without_hook_uses_built_controllers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset controller hooks register the controller list exactly as built."""
    plugin = LitestarAuth(_minimal_config())
    app_config = AppConfig()

    class RegisterController(Controller):
        path = "/auth"

    built_controllers = [cast("Any", RegisterController)]
    monkeypatch.setattr("litestar_auth.plugin.build_controllers", lambda *_args, **_kwargs: built_controllers)

    result = plugin._register_controllers(app_config)

    assert result == built_controllers
    assert app_config.route_handlers == built_controllers


def test_register_controllers_hook_uses_hook_return_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Controller hooks can filter or replace the built controller list."""
    seen: dict[str, object] = {}
    config = _minimal_config()
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    class AuthController(Controller):
        path = "/auth"

    class VerifyController(Controller):
        path = "/auth"

    built_controllers = [cast("Any", AuthController), cast("Any", VerifyController)]

    def controller_hook(controllers: list[object]) -> list[object]:
        seen["controllers"] = list(controllers)
        return [controllers[0]]

    config.controller_hook = cast("Any", controller_hook)
    monkeypatch.setattr("litestar_auth.plugin.build_controllers", lambda *_args, **_kwargs: built_controllers)

    result = plugin._register_controllers(app_config)

    assert seen["controllers"] == built_controllers
    assert result == [AuthController]
    assert app_config.route_handlers == [AuthController]
