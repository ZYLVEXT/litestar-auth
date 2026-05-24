"""OAuth login callback handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, cast

from litestar import Request, get
from litestar.params import QueryParameter
from litestar.response import Response  # noqa: TC002

from litestar_auth.controllers._oauth_assembly import _OAuthLoginCallbackInputs
from litestar_auth.controllers._oauth_helpers import (
    _clear_state_cookie_on_callback_exit,
    _decode_oauth_flow_cookie,
    _validate_state,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar.openapi.datastructures import ResponseSpec

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.controllers._oauth_assembly import _OAuthControllerAssembly
    from litestar_auth.controllers.oauth import OAuthControllerUserManagerProtocol


_OAuthCodeQuery = Annotated[str, QueryParameter()]
_OAuthStateQuery = Annotated[str, QueryParameter(name="state")]


async def _complete_login_callback[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    callback_inputs: _OAuthLoginCallbackInputs[UP, ID],
) -> Response[Any]:
    """Complete the PKCE-bound OAuth login callback using the shared assembly state.

    Returns:
        Login response produced by the configured local authentication backend.
    """
    async with _clear_state_cookie_on_callback_exit(
        cookie_name=assembly.cookie_name,
        cookie_path=assembly.cookie_path,
        cookie_secure=assembly.cookie_secure,
    ) as clear_state_cookie:
        flow_cookie = _decode_oauth_flow_cookie(
            callback_inputs.request.cookies.get(assembly.cookie_name),
            flow_cookie_cipher=assembly.flow_cookie_cipher,
        )
        _validate_state(flow_cookie.state, callback_inputs.oauth_state)
        user = await assembly.oauth_service.complete_login(
            code=callback_inputs.code,
            redirect_uri=assembly.callback_url,
            code_verifier=flow_cookie.code_verifier,
            user_manager=callback_inputs.user_manager,
        )
        response = await callback_inputs.backend.login(user)
        clear_state_cookie(response)
        await callback_inputs.user_manager.on_after_login(user)
        return response


def _create_login_callback_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    backend: AuthenticationBackend[UP, ID],
    responses: Mapping[int, ResponseSpec],
) -> object:
    """Create the callback route handler for OAuth login controllers.

    Returns:
        Decorated Litestar route handler for the provider callback endpoint.
    """
    user_manager = cast(
        "OAuthControllerUserManagerProtocol[UP, ID]",
        assembly.user_manager_binding.user_manager,
    )

    @get("/callback", responses=responses)
    async def callback(
        self: object,
        request: Request[Any, Any, Any],
        code: _OAuthCodeQuery,
        oauth_state: _OAuthStateQuery,
    ) -> Response[Any]:
        del self
        return await _complete_login_callback(
            assembly=assembly,
            callback_inputs=_OAuthLoginCallbackInputs(
                request=request,
                code=code,
                oauth_state=oauth_state,
                user_manager=user_manager,
                backend=backend,
            ),
        )

    return callback
