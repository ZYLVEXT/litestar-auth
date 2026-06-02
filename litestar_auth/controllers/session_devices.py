"""Session/device management controller factory."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, NotRequired, Protocol, Required, TypedDict, Unpack, overload

from litestar import Controller, Request, delete, get, post
from litestar.di import NamedDependency
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example
from litestar.params import PathParameter

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers._utils import (
    _build_controller_name,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import RefreshSessionListResponse, RefreshTokenRequest  # noqa: TC001
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.authentication.strategy.base import RefreshSessionManagementStrategy

_OptionalBackendsDep = NamedDependency[Sequence[AuthenticationBackend[Any, Any]] | None]

SESSION_MANAGEMENT_UNSUPPORTED_DETAIL = "The configured auth strategy does not support refresh-session management."
REFRESH_SESSION_NOT_FOUND_DETAIL = "Refresh session not found."

_SessionIdPath = Annotated[str, PathParameter()]

_SESSION_DEVICES_OPENAPI_RESPONSES = {
    400: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description="The configured backend strategy does not support refresh-session management.",
        examples=[
            Example(
                id="session_management_unsupported",
                summary="Unsupported strategy",
                value={
                    "detail": SESSION_MANAGEMENT_UNSUPPORTED_DETAIL,
                    "code": ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED.value,
                },
            ),
        ],
    ),
    401: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description="Unauthenticated requests are rejected before refresh-session management runs.",
    ),
    404: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description="The requested refresh session does not exist for the authenticated user.",
        examples=[
            Example(
                id="refresh_session_not_found",
                summary="Missing refresh session",
                value={
                    "detail": REFRESH_SESSION_NOT_FOUND_DETAIL,
                    "code": ErrorCode.REFRESH_SESSION_NOT_FOUND.value,
                },
            ),
        ],
    ),
}

from litestar_auth.controllers._session_devices_handlers import (  # noqa: E402
    _handle_list_refresh_sessions,
    _handle_revoke_other_refresh_sessions,
    _handle_revoke_refresh_session,
    _require_session_management_strategy,
)


class SessionDevicesControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :func:`create_session_devices_controller`."""

    backend: Required[AuthenticationBackend[UP, ID]]
    path: NotRequired[str]
    security: NotRequired[Sequence[SecurityRequirement] | None]


@dataclass(frozen=True, slots=True)
class SessionDevicesControllerConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :func:`create_session_devices_controller`."""

    backend: AuthenticationBackend[UP, ID]
    path: str = "/auth"
    security: Sequence[SecurityRequirement] | None = None


class _SessionDevicesControllerContext[UP: UserProtocol[Any]]:
    """Runtime context for session/device route handlers."""

    def __init__(
        self,
        strategy: RefreshSessionManagementStrategy[UP],
        *,
        cookie_transport: CookieTransport | None,
    ) -> None:
        """Store the refresh-session management strategy."""
        self.strategy = strategy
        self.cookie_transport = cookie_transport


class _RuntimeContextBuilder[UP: UserProtocol[Any]](Protocol):
    """Build a request-scoped session/device controller context."""

    def __call__(self, request_backends: object | None = None) -> _SessionDevicesControllerContext[UP]:
        """Return a context for one request."""


@overload
def create_session_devices_controller[UP: UserProtocol[Any], ID](
    config: SessionDevicesControllerConfig[UP, ID],
) -> type[Controller]: ...


@overload
def create_session_devices_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[SessionDevicesControllerOptions[UP, ID]],
) -> type[Controller]: ...


def create_session_devices_controller[UP: UserProtocol[Any], ID](
    config: SessionDevicesControllerConfig[UP, ID] | None = None,
    **options: Unpack[SessionDevicesControllerOptions[UP, ID]],
) -> type[Controller]:
    """Return a controller exposing authenticated refresh-session management routes.

    Raises:
        TypeError: If both ``config`` and keyword options are supplied.
    """
    if config is not None and options:
        msg = "Pass either SessionDevicesControllerConfig or keyword options, not both."
        raise TypeError(msg)
    settings = SessionDevicesControllerConfig(**options) if config is None else config
    generated_controller = _define_session_devices_controller_class(
        _build_static_context(settings.backend),
        security=settings.security,
    )
    generated_controller.__name__ = f"{_build_controller_name(settings.backend.name)}SessionDevicesController"
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.path = settings.path.rstrip("/") or "/"
    return _mark_litestar_auth_route_handler(generated_controller)


def _build_static_context[UP: UserProtocol[Any], ID](
    backend: AuthenticationBackend[UP, ID],
) -> _RuntimeContextBuilder[UP]:
    """Build a context factory for manually mounted session/device controllers.

    Returns:
        Context builder using the configured strategy.
    """

    def _build_context(request_backends: object | None = None) -> _SessionDevicesControllerContext[UP]:  # noqa: ARG001
        strategy = backend.strategy
        transport = getattr(backend, "transport", None)
        return _SessionDevicesControllerContext(
            _require_session_management_strategy(strategy),
            cookie_transport=transport if isinstance(transport, CookieTransport) else None,
        )

    return _build_context


def _create_list_refresh_sessions_handler[UP: UserProtocol[Any]](
    build_context: _RuntimeContextBuilder[UP],
    *,
    security: Sequence[SecurityRequirement] | None,
) -> Callable[..., object]:
    """Return the GET refresh-session listing handler."""

    @get("/sessions", guards=[is_authenticated], security=security, responses=_SESSION_DEVICES_OPENAPI_RESPONSES)
    async def list_refresh_sessions(
        self: Controller,  # noqa: ARG001
        request: Request[Any, Any, Any],
        litestar_auth_backends: _OptionalBackendsDep = None,
    ) -> RefreshSessionListResponse:
        ctx = build_context(litestar_auth_backends)
        return await _handle_list_refresh_sessions(request, None, ctx=ctx)

    return list_refresh_sessions


def _create_list_refresh_sessions_with_token_handler[UP: UserProtocol[Any]](
    build_context: _RuntimeContextBuilder[UP],
    *,
    security: Sequence[SecurityRequirement] | None,
) -> Callable[..., object]:
    """Return the POST refresh-session listing handler."""

    @post(
        "/sessions",
        guards=[is_authenticated],
        security=security,
        status_code=200,
        responses=_SESSION_DEVICES_OPENAPI_RESPONSES,
    )
    async def list_refresh_sessions_with_refresh_token(
        self: Controller,  # noqa: ARG001
        request: Request[Any, Any, Any],
        data: RefreshTokenRequest,
        litestar_auth_backends: _OptionalBackendsDep = None,
    ) -> RefreshSessionListResponse:
        ctx = build_context(litestar_auth_backends)
        return await _handle_list_refresh_sessions(request, data, ctx=ctx)

    return list_refresh_sessions_with_refresh_token


def _create_revoke_refresh_session_handler[UP: UserProtocol[Any]](
    build_context: _RuntimeContextBuilder[UP],
    *,
    security: Sequence[SecurityRequirement] | None,
) -> Callable[..., object]:
    """Return the single refresh-session revoke handler."""

    @delete(
        "/sessions/{session_id:str}",
        guards=[is_authenticated],
        security=security,
        status_code=204,
        responses=_SESSION_DEVICES_OPENAPI_RESPONSES,
    )
    async def revoke_refresh_session(
        self: Controller,  # noqa: ARG001
        request: Request[Any, Any, Any],
        session_id: _SessionIdPath,
        litestar_auth_backends: _OptionalBackendsDep = None,
    ) -> None:
        ctx = build_context(litestar_auth_backends)
        await _handle_revoke_refresh_session(request, session_id, ctx=ctx)

    return revoke_refresh_session


def _create_revoke_other_refresh_sessions_handler[UP: UserProtocol[Any]](
    build_context: _RuntimeContextBuilder[UP],
    *,
    security: Sequence[SecurityRequirement] | None,
) -> Callable[..., object]:
    """Return the other refresh-sessions revoke handler."""

    @post(
        "/sessions/revoke-others",
        guards=[is_authenticated],
        security=security,
        status_code=204,
        responses=_SESSION_DEVICES_OPENAPI_RESPONSES,
    )
    async def revoke_other_refresh_sessions(
        self: Controller,  # noqa: ARG001
        request: Request[Any, Any, Any],
        litestar_auth_backends: _OptionalBackendsDep = None,
        data: RefreshTokenRequest | None = None,
    ) -> None:
        ctx = build_context(litestar_auth_backends)
        await _handle_revoke_other_refresh_sessions(request, data, ctx=ctx)

    return revoke_other_refresh_sessions


def _define_session_devices_controller_class[UP: UserProtocol[Any]](
    build_context: _RuntimeContextBuilder[UP],
    *,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Define a session/device management controller class.

    Returns:
        Generated controller class.
    """

    class SessionDevicesController(Controller):
        """Authenticated refresh-session management endpoints."""

        list_refresh_sessions = _create_list_refresh_sessions_handler(build_context, security=security)
        list_refresh_sessions_with_refresh_token = _create_list_refresh_sessions_with_token_handler(
            build_context,
            security=security,
        )
        revoke_refresh_session = _create_revoke_refresh_session_handler(build_context, security=security)
        revoke_other_refresh_sessions = _create_revoke_other_refresh_sessions_handler(
            build_context,
            security=security,
        )

    return SessionDevicesController
