"""Session/device management controller factory."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Protocol, Required, TypedDict, TypeGuard, Unpack, cast, overload

from litestar import Controller, Request, delete, get, post
from litestar.exceptions import ClientException
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example

from litestar_auth.authentication.strategy.base import (
    RefreshSession,
    RefreshSessionIdentifierStrategy,
    RefreshSessionManagementStrategy,
)
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers._auth_helpers import _resolve_refresh_token_value
from litestar_auth.controllers._utils import _build_controller_name, _mark_litestar_auth_route_handler
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import RefreshSessionListResponse, RefreshSessionRead, RefreshTokenRequest
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.authentication.backend import AuthenticationBackend

SESSION_MANAGEMENT_UNSUPPORTED_DETAIL = "The configured auth strategy does not support refresh-session management."
REFRESH_SESSION_NOT_FOUND_DETAIL = "Refresh session not found."
_SESSION_CLIENT_METADATA_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_SESSION_CLIENT_METADATA_KEY_MAX_LENGTH = 64
_SESSION_CLIENT_METADATA_VALUE_MAX_LENGTH = 255

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
) -> type[Controller]:
    pass  # pragma: no cover


@overload
def create_session_devices_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[SessionDevicesControllerOptions[UP, ID]],
) -> type[Controller]:
    pass  # pragma: no cover


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

    def _build_context(request_backends: object | None = None) -> _SessionDevicesControllerContext[UP]:
        del request_backends
        strategy = backend.strategy
        transport = getattr(backend, "transport", None)
        return _SessionDevicesControllerContext(
            _require_session_management_strategy(strategy),
            cookie_transport=transport if isinstance(transport, CookieTransport) else None,
        )

    return _build_context


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

        @get("/sessions", guards=[is_authenticated], security=security, responses=_SESSION_DEVICES_OPENAPI_RESPONSES)
        async def list_refresh_sessions(
            self,
            request: Request[Any, Any, Any],
            litestar_auth_backends: Any = None,  # noqa: ANN401
        ) -> RefreshSessionListResponse:
            del self
            ctx = build_context(litestar_auth_backends)
            return await _handle_list_refresh_sessions(request, None, ctx=ctx)

        @post(
            "/sessions",
            guards=[is_authenticated],
            security=security,
            status_code=200,
            responses=_SESSION_DEVICES_OPENAPI_RESPONSES,
        )
        async def list_refresh_sessions_with_refresh_token(
            self,
            request: Request[Any, Any, Any],
            data: RefreshTokenRequest,
            litestar_auth_backends: Any = None,  # noqa: ANN401
        ) -> RefreshSessionListResponse:
            del self
            ctx = build_context(litestar_auth_backends)
            return await _handle_list_refresh_sessions(request, data, ctx=ctx)

        @delete(
            "/sessions/{session_id:str}",
            guards=[is_authenticated],
            security=security,
            status_code=204,
            responses=_SESSION_DEVICES_OPENAPI_RESPONSES,
        )
        async def revoke_refresh_session(
            self,
            request: Request[Any, Any, Any],
            session_id: str,
            litestar_auth_backends: Any = None,  # noqa: ANN401
        ) -> None:
            del self
            ctx = build_context(litestar_auth_backends)
            await _handle_revoke_refresh_session(request, session_id, ctx=ctx)

        @post(
            "/sessions/revoke-others",
            guards=[is_authenticated],
            security=security,
            status_code=204,
            responses=_SESSION_DEVICES_OPENAPI_RESPONSES,
        )
        async def revoke_other_refresh_sessions(
            self,
            request: Request[Any, Any, Any],
            litestar_auth_backends: Any = None,  # noqa: ANN401
            data: RefreshTokenRequest | None = None,
        ) -> None:
            del self
            ctx = build_context(litestar_auth_backends)
            await _handle_revoke_other_refresh_sessions(request, data, ctx=ctx)

    return SessionDevicesController


def _require_session_management_strategy[UP: UserProtocol[Any]](
    strategy: object,
) -> RefreshSessionManagementStrategy[UP]:
    """Return ``strategy`` narrowed to the refresh-session management protocol.

    Raises:
        ClientException: If the strategy does not support refresh-session management.
    """
    if isinstance(strategy, RefreshSessionManagementStrategy):
        return cast("RefreshSessionManagementStrategy[UP]", strategy)
    raise ClientException(
        status_code=400,
        detail=SESSION_MANAGEMENT_UNSUPPORTED_DETAIL,
        extra={"code": ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED},
    )


def _refresh_session_to_read(session: RefreshSession, *, is_current: bool | None) -> RefreshSessionRead:
    """Convert strategy metadata into the public response payload.

    Returns:
        Public refresh-session response item.
    """
    return RefreshSessionRead(
        session_id=session.session_id,
        created_at=session.created_at,
        last_used_at=session.last_used_at,
        is_current=is_current,
        client_metadata=_sanitize_session_client_metadata(session.client_metadata),
    )


def _sanitize_session_client_metadata(metadata: object) -> dict[str, str] | None:
    """Return response-safe session client metadata."""
    if not isinstance(metadata, dict):
        return None

    safe_metadata: dict[str, str] = {}
    for key, value in metadata.items():
        if not _is_safe_session_client_metadata_key(key) or not isinstance(value, str):
            continue
        normalized_value = " ".join(value.split())
        if not normalized_value:
            continue
        safe_metadata[key] = normalized_value[:_SESSION_CLIENT_METADATA_VALUE_MAX_LENGTH]

    return safe_metadata or None


def _is_safe_session_client_metadata_key(key: object) -> TypeGuard[str]:
    """Return whether ``key`` is allowed in public session metadata."""
    return (
        isinstance(key, str)
        and len(key) <= _SESSION_CLIENT_METADATA_KEY_MAX_LENGTH
        and _SESSION_CLIENT_METADATA_KEY_PATTERN.fullmatch(key) is not None
    )


async def _handle_list_refresh_sessions[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    data: RefreshTokenRequest | None,
    *,
    ctx: _SessionDevicesControllerContext[UP],
) -> RefreshSessionListResponse:
    """Return active refresh sessions for the authenticated user."""
    user = cast("UP", request.user)
    current_session_id = await _resolve_current_refresh_session_id(request, user, data, ctx=ctx)
    sessions = await ctx.strategy.list_refresh_sessions(user)
    return RefreshSessionListResponse(
        sessions=[
            _refresh_session_to_read(
                session,
                is_current=None if current_session_id is None else session.session_id == current_session_id,
            )
            for session in sessions
        ],
    )


async def _handle_revoke_refresh_session[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    session_id: str,
    *,
    ctx: _SessionDevicesControllerContext[UP],
) -> None:
    """Revoke one refresh session owned by the authenticated user.

    Raises:
        ClientException: If ``session_id`` is absent or foreign to the authenticated user.
    """
    user = cast("UP", request.user)
    revoked = await ctx.strategy.revoke_refresh_session(user, session_id)
    if revoked:
        return
    raise ClientException(
        status_code=404,
        detail=REFRESH_SESSION_NOT_FOUND_DETAIL,
        extra={"code": ErrorCode.REFRESH_SESSION_NOT_FOUND},
    )


async def _handle_revoke_other_refresh_sessions[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    data: RefreshTokenRequest | None,
    *,
    ctx: _SessionDevicesControllerContext[UP],
) -> None:
    """Revoke all refresh sessions for the authenticated user except the current one when known."""
    user = cast("UP", request.user)
    current_session_id = await _resolve_current_refresh_session_id(request, user, data, ctx=ctx)
    await ctx.strategy.revoke_other_refresh_sessions(user, current_session_id=current_session_id)


async def _resolve_current_refresh_session_id[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    user: UP,
    data: RefreshTokenRequest | None,
    *,
    ctx: _SessionDevicesControllerContext[UP],
) -> str | None:
    """Resolve the public session id for the request's current refresh credential.

    Returns:
        Public refresh-session id when the current refresh token can be identified.
    """
    if not isinstance(ctx.strategy, RefreshSessionIdentifierStrategy):
        return None
    identifier_strategy = cast("RefreshSessionIdentifierStrategy[UP]", ctx.strategy)
    refresh_token = await _resolve_refresh_token_value(request, data, cookie_transport=ctx.cookie_transport)
    if refresh_token is None:
        return None
    return await identifier_strategy.identify_refresh_session(user, refresh_token)
