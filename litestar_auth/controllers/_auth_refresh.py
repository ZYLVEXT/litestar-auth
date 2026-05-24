"""Refresh-token rotation handler for generated auth controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar.exceptions import ClientException

from litestar_auth.authentication.strategy.base import TokenInvalidationCapable
from litestar_auth.controllers._auth_helpers import (
    _attach_refresh_token,
    _record_refresh_token_request_context,
    _resolve_cookie_transport,
)
from litestar_auth.controllers._error_responses import raise_client_error
from litestar_auth.controllers._utils import _require_account_state
from litestar_auth.controllers.auth import INVALID_REFRESH_TOKEN_DETAIL
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar import Request
    from litestar.response import Response

    from litestar_auth.controllers.auth import AuthControllerUserManagerProtocol, _AuthControllerContext
    from litestar_auth.payloads import RefreshTokenRequest


async def _handle_auth_refresh[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _AuthControllerContext[UP, ID],
    data: RefreshTokenRequest,
    user_manager: AuthControllerUserManagerProtocol[UP, ID],
) -> Response[Any]:
    """Rotate a refresh token and issue a new access token.

    Returns:
        Response containing rotated access and refresh material.

    Raises:
        ConfigurationError: When refresh support is missing despite handler wiring.
        ClientException: When the refresh token is invalid or account state checks fail after rotation.
    """
    refresh_strategy = ctx.refresh_strategy
    if refresh_strategy is None:  # pragma: no cover - guarded by controller wiring
        msg = "Refresh is not configured."
        raise ConfigurationError(msg)

    _record_refresh_token_request_context(refresh_strategy, request)
    refreshed = await refresh_strategy.rotate_refresh_token(data.refresh_token, user_manager)
    if refreshed is None:
        await ctx.refresh_inc(request)
        raise_client_error(
            status_code=400,
            detail=INVALID_REFRESH_TOKEN_DETAIL,
            error_code=ErrorCode.REFRESH_TOKEN_INVALID,
        )

    user, rotated_refresh_token = refreshed
    try:
        await _require_account_state(
            user,
            require_verified=ctx.requires_verification,
            user_manager=user_manager,
        )
    except ClientException:
        if isinstance(refresh_strategy, TokenInvalidationCapable):
            await cast("TokenInvalidationCapable[UP]", refresh_strategy).invalidate_all_tokens(user)
        raise
    response = await ctx.backend.login(user)
    cookie_transport = _resolve_cookie_transport(ctx.backend)
    await ctx.refresh_reset(request)
    return _attach_refresh_token(response, rotated_refresh_token, cookie_transport=cookie_transport)
