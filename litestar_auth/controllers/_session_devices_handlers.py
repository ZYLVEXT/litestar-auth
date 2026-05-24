"""Business handlers for session/device management controllers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, TypeGuard, cast

from litestar_auth.authentication.strategy.base import (
    RefreshSession,
    RefreshSessionIdentifierStrategy,
    RefreshSessionManagementStrategy,
)
from litestar_auth.controllers._auth_helpers import _resolve_refresh_token_value
from litestar_auth.controllers._error_responses import raise_client_error
from litestar_auth.controllers.session_devices import (
    REFRESH_SESSION_NOT_FOUND_DETAIL,
    SESSION_MANAGEMENT_UNSUPPORTED_DETAIL,
)
from litestar_auth.exceptions import ErrorCode
from litestar_auth.payloads import RefreshSessionListResponse, RefreshSessionRead
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers.session_devices import _SessionDevicesControllerContext
    from litestar_auth.payloads import RefreshTokenRequest

_SESSION_CLIENT_METADATA_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_SESSION_CLIENT_METADATA_KEY_MAX_LENGTH = 64
_SESSION_CLIENT_METADATA_VALUE_MAX_LENGTH = 255


def _require_session_management_strategy[UP: UserProtocol[Any]](
    strategy: object,
) -> RefreshSessionManagementStrategy[UP]:
    """Return ``strategy`` narrowed to the refresh-session management protocol."""
    if isinstance(strategy, RefreshSessionManagementStrategy):
        return cast("RefreshSessionManagementStrategy[UP]", strategy)
    return raise_client_error(
        status_code=400,
        detail=SESSION_MANAGEMENT_UNSUPPORTED_DETAIL,
        error_code=ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED,
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
    """Revoke one refresh session owned by the authenticated user."""
    user = cast("UP", request.user)
    revoked = await ctx.strategy.revoke_refresh_session(user, session_id)
    if revoked:
        return
    raise_client_error(
        status_code=404,
        detail=REFRESH_SESSION_NOT_FOUND_DETAIL,
        error_code=ErrorCode.REFRESH_SESSION_NOT_FOUND,
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
