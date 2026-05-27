"""OAuth authorize route handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar import Request, get, post
from litestar.openapi.datastructures import ResponseSpec
from litestar.response import Redirect

from litestar_auth.controllers._oauth_helpers import (
    _OAuthCookieSettings,
    _reject_runtime_oauth_scope_override,
    _set_state_cookie,
)
from litestar_auth.oauth._flow_cookie import _OAuthFlowCookie
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import Guard

    from litestar_auth.controllers._oauth_assembly import _OAuthControllerAssembly

type OAuthResponses = Mapping[int, ResponseSpec] | None


async def _perform_authorize_redirect[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
) -> Redirect:
    """Mint OAuth state + PKCE material, set the flow cookie, and redirect to the provider.

    Returns:
        Litestar redirect carrying the encrypted state cookie and pointing at
        the provider authorization URL.
    """
    _reject_runtime_oauth_scope_override(request)
    authorization = await assembly.oauth_service.authorize(
        redirect_uri=assembly.callback_url,
        scopes=list(assembly.oauth_scopes) if assembly.oauth_scopes is not None else None,
    )
    response = Redirect(authorization.authorization_url)
    _set_state_cookie(
        response,
        flow_cookie=_OAuthFlowCookie(
            state=authorization.state,
            code_verifier=authorization.code_verifier,
        ),
        cookie_settings=_cookie_settings_from_assembly(assembly),
    )
    return response


def _create_authorize_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    responses: OAuthResponses,
    security: Sequence[SecurityRequirement] | None = None,
) -> object:
    """Create the GET authorize route handler for the provider-scoped login flow.

    Returns:
        Decorated Litestar route handler for the provider login authorize endpoint.
    """

    @get("/authorize", security=security, responses=responses)
    async def authorize(
        self: object,  # noqa: ARG001
        request: Request[Any, Any, Any],
    ) -> Redirect:
        return await _perform_authorize_redirect(request, assembly=assembly)

    return authorize


def _create_associate_authorize_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    responses: OAuthResponses,
    guards: Sequence[Guard] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> object:
    """Create the POST authorize route handler for the provider-scoped associate flow.

    Returns:
        Decorated Litestar route handler for the provider associate authorize endpoint.
    """

    @post("/authorize", guards=guards, security=security, responses=responses)
    async def authorize(
        self: object,  # noqa: ARG001
        request: Request[Any, Any, Any],
    ) -> Redirect:
        return await _perform_authorize_redirect(request, assembly=assembly)

    return authorize


def _cookie_settings_from_assembly(assembly: _OAuthControllerAssembly[Any, Any]) -> _OAuthCookieSettings:
    """Return cookie settings from provider-scoped assembly state."""
    return _OAuthCookieSettings(
        cookie_name=assembly.cookie_name,
        cookie_path=assembly.cookie_path,
        cookie_secure=assembly.cookie_secure,
        flow_cookie_cipher=assembly.flow_cookie_cipher,
    )
