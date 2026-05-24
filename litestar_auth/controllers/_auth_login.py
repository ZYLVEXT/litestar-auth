"""Login pipeline handlers for generated auth controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar.enums import MediaType
from litestar.response import Response

from litestar_auth.controllers._auth_helpers import (
    _attach_refresh_token,
    _record_refresh_token_request_context,
    _resolve_cookie_transport,
    _resolve_login_identifier,
)
from litestar_auth.controllers._error_responses import raise_login_bad_credentials
from litestar_auth.controllers._response_timing import await_minimum_response_seconds
from litestar_auth.controllers._utils import _require_account_state
from litestar_auth.totp_flow import (
    TotpFlowUserManagerProtocol,
    TotpLoginFlowConfig,
    TotpLoginFlowService,
    build_pending_totp_client_binding,
)
from litestar_auth.types import TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers.auth import AuthControllerUserManagerProtocol, _AuthControllerContext
    from litestar_auth.payloads import LoginCredentials


async def _handle_auth_login[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    data: LoginCredentials,
    *,
    ctx: _AuthControllerContext[UP, ID],
    user_manager: AuthControllerUserManagerProtocol[UP, ID],
) -> object:
    """Run the login pipeline: authenticate, enforce account state, optional TOTP pending, tokens.

    Returns:
        Litestar response carrying access (and optionally refresh) tokens, or a 202 pending-2FA payload.
    """

    async def _login_work() -> object:
        user = await _authenticate_login_request(request, data, ctx=ctx, user_manager=user_manager)
        await _require_account_state(
            user,
            require_verified=ctx.requires_verification,
            user_manager=user_manager,
            on_failure=lambda: ctx.login_inc(request),
        )

        pending_response = await _maybe_issue_totp_pending_response(
            request,
            user,
            ctx=ctx,
            user_manager=user_manager,
        )
        if pending_response is not None:
            return pending_response

        return await _build_authenticated_login_response(
            request,
            user,
            ctx=ctx,
            user_manager=user_manager,
        )

    return await await_minimum_response_seconds(
        minimum_seconds=ctx.login_minimum_response_seconds,
        work=_login_work,
    )


async def _authenticate_login_request[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    data: LoginCredentials,
    *,
    ctx: _AuthControllerContext[UP, ID],
    user_manager: AuthControllerUserManagerProtocol[UP, ID],
) -> UP:
    """Resolve credentials and return the authenticated user.

    Returns:
        Authenticated user resolved from the supplied login payload.

    """
    resolved_identifier = _resolve_login_identifier(data.identifier, ctx.login_identifier)
    user = await user_manager.authenticate(
        resolved_identifier,
        data.password,
        login_identifier=ctx.login_identifier,
    )
    if user is None:
        await ctx.login_inc(request)
        raise_login_bad_credentials()

    return user


async def _maybe_issue_totp_pending_response[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    user: UP,
    *,
    ctx: _AuthControllerContext[UP, ID],
    user_manager: AuthControllerUserManagerProtocol[UP, ID],
) -> Response[Any] | None:
    """Return a pending-2FA response when TOTP is configured for this login."""
    totp_login_flow = (
        TotpLoginFlowService[TotpUserProtocol[Any], ID](
            user_manager=cast(
                "TotpFlowUserManagerProtocol[TotpUserProtocol[Any], ID]",
                user_manager,
            ),
            config=TotpLoginFlowConfig(
                totp_pending_secret=ctx.totp_pending_secret,
                totp_pending_lifetime=ctx.totp_pending_lifetime,
                require_client_binding=ctx.totp_pending_require_client_binding,
            ),
        )
        if ctx.totp_pending_secret is not None
        else None
    )
    if totp_login_flow is None:
        return None

    totp_user = cast("TotpUserProtocol[Any]", user)
    client_binding = (
        build_pending_totp_client_binding(
            request,
            pending_secret=cast("str", ctx.totp_pending_secret),
            trusted_proxy=ctx.totp_pending_client_binding_trusted_proxy,
            trusted_headers=ctx.totp_pending_client_binding_trusted_headers,
        )
        if ctx.totp_pending_require_client_binding
        else None
    )
    pending_token = await totp_login_flow.issue_pending_token(totp_user, client_binding=client_binding)
    if pending_token is None:
        return None

    await ctx.login_reset(request)
    return Response(
        content={"totp_required": True, "pending_token": pending_token},
        status_code=202,
        media_type=MediaType.JSON,
    )


async def _build_authenticated_login_response[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    user: UP,
    *,
    ctx: _AuthControllerContext[UP, ID],
    user_manager: AuthControllerUserManagerProtocol[UP, ID],
) -> Response[Any]:
    """Issue a full login response and attach refresh credentials when configured.

    Returns:
        Backend login response with a refresh token attached when refresh support is enabled.
    """
    await ctx.login_reset(request)
    response = await ctx.backend.login(user)
    await user_manager.on_after_login(user)
    if ctx.refresh_strategy is None:
        return response
    _record_refresh_token_request_context(ctx.refresh_strategy, request)
    cookie_transport = _resolve_cookie_transport(ctx.backend)
    return _attach_refresh_token(
        response,
        await ctx.refresh_strategy.write_refresh_token(user),
        cookie_transport=cookie_transport,
    )
