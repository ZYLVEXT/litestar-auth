"""Integration tests for plugin customization hooks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar
from litestar.enums import MediaType
from litestar.middleware import DefineMiddleware
from litestar.response import Response
from litestar.testing import AsyncTestClient

from litestar_auth.authentication import LitestarAuthMiddleware
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
    auth_state,
    non_auth_client_exception,
)

if TYPE_CHECKING:
    from litestar.types import Message, Receive, Scope, Send

pytestmark = [pytest.mark.integration]

HTTP_BAD_REQUEST = 400
HTTP_CREATED = 201
HTTP_NOT_FOUND = 404
HTTP_OK = 200


def _as_any(value: object) -> Any:  # noqa: ANN401
    """Return a value through the test-only dynamic type boundary."""
    return cast("Any", value)


class HeaderInjectingAuthMiddleware(LitestarAuthMiddleware[ExampleUser, UUID]):
    """Auth middleware wrapper used to prove middleware-hook replacement works."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Proxy to the auth middleware while adding a response header."""

        async def send_with_hook_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                start_message = _as_any(message)
                headers = list(start_message.get("headers", []))
                headers.append((b"x-auth-hook", b"enabled"))
                start_message["headers"] = headers
            await send(message)

        await super().__call__(scope, receive, send_with_hook_header)


def _build_config(
    *,
    backend: AuthenticationBackend[ExampleUser, UUID] | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a verified-user plugin config for hook integration tests.

    Returns:
        Plugin config with one verified user and one auth backend.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase(
        [
            ExampleUser(
                id=uuid4(),
                email="user@example.com",
                hashed_password=password_helper.hash("user-password"),
                is_verified=True,
            ),
        ],
    )
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-hooks")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend or default_backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=password_helper,
        ),
        include_users=False,
    )


async def test_exception_response_hook_customizes_auth_errors_only() -> None:
    """Custom exception-response hooks change plugin auth errors without affecting unrelated routes."""
    config = _build_config()

    def exception_response_hook(exc: object, request: object) -> Response[dict[str, object]]:
        return Response(
            content={
                "error": {
                    "code": getattr(exc, "code", None),
                    "message": str(exc),
                    "path": cast("Any", request).url.path,
                },
            },
            status_code=getattr(exc, "status_code", HTTP_BAD_REQUEST),
            media_type=MediaType.JSON,
            headers=getattr(exc, "headers", None),
        )

    config.exception_response_hook = exception_response_hook
    app = Litestar(route_handlers=[non_auth_client_exception], plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        auth_response = await client.post("/auth/verify", json={"token": "not-a-valid-token"})
        non_auth_response = await client.get("/non-auth-client-exception")

    assert auth_response.status_code == HTTP_BAD_REQUEST
    assert auth_response.json() == {
        "error": {
            "code": "VERIFY_USER_BAD_TOKEN",
            "message": "The email verification token is invalid.",
            "path": "/auth/verify",
        },
    }

    assert non_auth_response.status_code == HTTP_BAD_REQUEST
    assert non_auth_response.json()["status_code"] == HTTP_BAD_REQUEST
    assert non_auth_response.json()["detail"] == "Outside auth routes."
    assert non_auth_response.json()["extra"]["code"] == "NON_AUTH_ROUTE"


async def test_middleware_hook_can_wrap_auth_middleware_without_breaking_cookie_auth() -> None:
    """Middleware hooks can replace the inserted auth middleware while preserving plugin wiring."""
    cookie_backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie",
        transport=CookieTransport(cookie_name="auth_cookie", secure=False, path="/", samesite="lax"),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-hooks-cookie")),
    )
    config = _build_config(backend=cookie_backend)
    config.csrf_secret = "c" * 32

    def middleware_hook(middleware: DefineMiddleware) -> DefineMiddleware:
        return DefineMiddleware(HeaderInjectingAuthMiddleware, *middleware.args, **middleware.kwargs)

    config.middleware_hook = middleware_hook
    plugin = LitestarAuth(config)
    app = Litestar(route_handlers=[auth_state], plugins=[plugin])

    assert app.csrf_config is not None
    assert app.csrf_config.cookie_path == "/"
    csrf_cookie_name = app.csrf_config.cookie_name

    async with AsyncTestClient(app=app) as client:
        csrf_probe_response = await client.get("/auth-state")
        csrf_cookie = client.cookies[csrf_cookie_name]
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
            headers={"X-CSRF-Token": csrf_cookie},
        )
        auth_state_response = await client.get("/auth-state")

    assert csrf_probe_response.status_code == HTTP_OK
    assert login_response.status_code == HTTP_CREATED
    assert auth_state_response.status_code == HTTP_OK
    assert auth_state_response.headers["x-auth-hook"] == "enabled"
    assert auth_state_response.json() == {"email": "user@example.com"}


async def test_controller_hook_can_filter_registered_plugin_routes() -> None:
    """Controller hooks can remove generated controllers before Litestar registers them."""
    config = _build_config()

    def controller_hook(controllers: list[object]) -> list[object]:
        return [controller for controller in controllers if getattr(controller, "__name__", "") != "VerifyController"]

    config.controller_hook = cast("Any", controller_hook)
    app = Litestar(route_handlers=[auth_state], plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        verify_response = await client.post("/auth/verify", json={"token": "not-a-valid-token"})
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
        )

    assert verify_response.status_code == HTTP_NOT_FOUND
    assert login_response.status_code == HTTP_CREATED
