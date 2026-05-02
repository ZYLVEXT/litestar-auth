"""OAuth account-association callback route helpers."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, cast

from litestar import Request, get
from litestar.enums import MediaType
from litestar.params import Parameter
from litestar.response import Response

from litestar_auth.controllers._oauth_helpers import _clear_state_cookie, _decode_oauth_flow_cookie, _validate_state
from litestar_auth.guards import is_authenticated
from litestar_auth.oauth.service import (
    OAuthServiceUserManagerProtocol as OAuthControllerUserManagerProtocol,
)
from litestar_auth.oauth.service import _require_account_state as _require_service_account_state
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.openapi.datastructures import ResponseSpec
    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.controllers._oauth_assembly import _OAuthControllerAssembly


def _make_associate_callback_signature(parameter_name: str) -> inspect.Signature:
    """Build the Litestar-visible signature for an associate callback dependency key.

    Returns:
        Signature exposing the configured dependency key as a callback parameter.
    """
    return inspect.Signature(
        parameters=[
            inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=object),
            inspect.Parameter(
                "request",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Request[Any, Any, Any],
            ),
            inspect.Parameter("code", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str),
            inspect.Parameter(
                parameter_name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=OAuthControllerUserManagerProtocol[Any, Any],
            ),
            inspect.Parameter(
                "oauth_state",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=str,
                default=Parameter(query="state"),
            ),
        ],
        return_annotation=Response[Any],
    )


def _bind_associate_callback_inputs[UP: UserProtocol[Any], ID](
    *,
    signature: inspect.Signature,
    dependency_parameter_name: str,
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> tuple[Request[Any, Any, Any], str, str, OAuthControllerUserManagerProtocol[UP, ID]]:
    """Bind an associate callback invocation to the configured dependency key.

    Returns:
        Bound request, code, OAuth state, and user manager for the shared callback body.
    """
    bound_arguments = signature.bind(*args, **kwargs)
    bound_arguments.apply_defaults()
    arguments = bound_arguments.arguments
    return (
        cast("Request[Any, Any, Any]", arguments["request"]),
        cast("str", arguments["code"]),
        cast("str", arguments["oauth_state"]),
        cast("OAuthControllerUserManagerProtocol[UP, ID]", arguments[dependency_parameter_name]),
    )


async def _complete_associate_callback[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    request: Request[Any, Any, Any],
    code: str,
    oauth_state: str,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
) -> Response[Any]:
    """Complete the PKCE-bound OAuth associate callback using the shared assembly state.

    Returns:
        JSON response confirming the authenticated account link completed.
    """
    flow_cookie = _decode_oauth_flow_cookie(
        request.cookies.get(assembly.cookie_name),
        flow_cookie_cipher=assembly.flow_cookie_cipher,
    )
    _validate_state(flow_cookie.state, oauth_state)
    user = cast("UP", request.user)
    _require_service_account_state(user, user_manager=user_manager)
    await assembly.oauth_service.associate_account(
        user=user,
        code=code,
        redirect_uri=assembly.callback_url,
        code_verifier=flow_cookie.code_verifier,
        user_manager=user_manager,
    )
    response = Response(content={"linked": True}, media_type=MediaType.JSON)
    _clear_state_cookie(
        response,
        cookie_name=assembly.cookie_name,
        cookie_path=assembly.cookie_path,
        cookie_secure=assembly.cookie_secure,
    )
    return response


def _create_associate_callback_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    responses: dict[int, ResponseSpec],
    security: Sequence[SecurityRequirement] | None = None,
) -> object:
    """Create the callback route handler for OAuth account-association controllers.

    Returns:
        Decorated Litestar route handler for the provider associate callback endpoint.
    """
    dependency_parameter_name = assembly.user_manager_binding.dependency_parameter_name
    if dependency_parameter_name is not None:
        return _create_associate_dependency_callback_handler(
            assembly=assembly,
            dependency_parameter_name=dependency_parameter_name,
            responses=responses,
            security=security,
        )

    user_manager = cast("OAuthControllerUserManagerProtocol[UP, ID]", assembly.user_manager_binding.user_manager)
    return _create_associate_direct_callback_handler(
        assembly=assembly,
        user_manager=user_manager,
        responses=responses,
        security=security,
    )


def _create_associate_dependency_callback_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    dependency_parameter_name: str,
    responses: dict[int, ResponseSpec],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create an associate callback handler using a request-scoped manager dependency.

    Returns:
        Decorated Litestar route handler for the provider associate callback endpoint.
    """
    signature = _make_associate_callback_signature(dependency_parameter_name)

    async def callback(*args: object, **kwargs: object) -> Response[Any]:
        request, code, oauth_state, user_manager = _bind_associate_callback_inputs(
            signature=signature,
            dependency_parameter_name=dependency_parameter_name,
            args=args,
            kwargs=kwargs,
        )
        return await _complete_associate_callback(
            assembly=assembly,
            request=request,
            code=code,
            oauth_state=oauth_state,
            user_manager=user_manager,
        )

    cast("Any", callback).__signature__ = signature
    cast("Any", callback).__annotations__ = _associate_dependency_callback_annotations(dependency_parameter_name)
    return get("/callback", guards=[is_authenticated], security=security, responses=responses)(callback)


def _associate_dependency_callback_annotations(dependency_parameter_name: str) -> dict[str, object]:
    """Return annotations for a generated associate callback dependency signature.

    Returns:
        Runtime annotation mapping assigned to the generated callback.
    """
    return {
        "self": object,
        "request": Request[Any, Any, Any],
        "code": str,
        dependency_parameter_name: OAuthControllerUserManagerProtocol[Any, Any],
        "oauth_state": str,
        "return": Response[Any],
    }


def _create_associate_direct_callback_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
    responses: dict[int, ResponseSpec],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create an associate callback handler with a directly supplied manager.

    Returns:
        Decorated Litestar route handler for the provider associate callback endpoint.
    """

    @get("/callback", guards=[is_authenticated], security=security, responses=responses)
    async def callback(
        self: object,
        request: Request[Any, Any, Any],
        code: str,
        oauth_state: str = Parameter(query="state"),
    ) -> Response[Any]:
        del self
        return await _complete_associate_callback(
            assembly=assembly,
            request=request,
            code=code,
            oauth_state=oauth_state,
            user_manager=user_manager,
        )

    return callback
