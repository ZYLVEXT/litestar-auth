"""OAuth account-association callback route helpers."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, cast

from litestar import Request, get
from litestar.enums import MediaType
from litestar.params import QueryParameter
from litestar.response import Response

from litestar_auth.controllers._oauth_helpers import (
    _clear_state_cookie_on_callback_exit,
    _decode_oauth_flow_cookie,
    _validate_state,
)
from litestar_auth.controllers._request_body import _attach_handler_signature
from litestar_auth.controllers._step_up import TotpStepUpCheck, TotpStepUpVerifierProtocol, require_totp_stepup
from litestar_auth.guards import is_authenticated
from litestar_auth.oauth._account_state import require_account_state as _require_oauth_account_state
from litestar_auth.oauth.service import (
    OAuthServiceUserManagerProtocol as OAuthControllerUserManagerProtocol,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.openapi.datastructures import ResponseSpec
    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import Guard

    from litestar_auth.controllers._oauth_assembly import _OAuthControllerAssembly


type _AssociateCallbackBody = Callable[..., Awaitable[Response[Any]]]

_OAuthCodeQuery = Annotated[str, QueryParameter()]
_OAuthStateQuery = Annotated[str, QueryParameter(name="state")]


@dataclass(frozen=True, slots=True)
class _OAuthCallbackRouteParamsSpec:
    """Route metadata applied to a generated OAuth callback handler."""

    path: str
    responses: dict[int, ResponseSpec]
    guards: Sequence[Guard] | None = None
    security: Sequence[SecurityRequirement] | None = None


def _make_oauth_callback_signature(dependency_parameter_name: str | None) -> inspect.Signature:
    """Build the Litestar-visible signature for an associate callback dependency key.

    Returns:
        Signature exposing the configured dependency key as a callback parameter when needed.
    """
    parameters = [
        inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=object),
        inspect.Parameter(
            "request",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=Request[Any, Any, Any],
        ),
        inspect.Parameter("code", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=_OAuthCodeQuery),
    ]
    if dependency_parameter_name is not None:
        parameters.append(
            inspect.Parameter(
                dependency_parameter_name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=OAuthControllerUserManagerProtocol[Any, Any],
            ),
        )
    parameters.append(
        inspect.Parameter(
            "oauth_state",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=_OAuthStateQuery,
        ),
    )
    return inspect.Signature(
        parameters=parameters,
        return_annotation=Response[Any],
    )


def _bind_oauth_callback_inputs[UP: UserProtocol[Any], ID](
    *,
    signature: inspect.Signature,
    dependency_parameter_name: str | None,
    direct_user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None,
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
        cast(
            "OAuthControllerUserManagerProtocol[UP, ID]",
            direct_user_manager if dependency_parameter_name is None else arguments[dependency_parameter_name],
        ),
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
    async with _clear_state_cookie_on_callback_exit(
        cookie_name=assembly.cookie_name,
        cookie_path=assembly.cookie_path,
        cookie_secure=assembly.cookie_secure,
    ) as clear_state_cookie:
        flow_cookie = _decode_oauth_flow_cookie(
            request.cookies.get(assembly.cookie_name),
            flow_cookie_cipher=assembly.flow_cookie_cipher,
        )
        _validate_state(flow_cookie.state, oauth_state)
        user = cast("UP", request.user)
        _require_oauth_account_state(user, user_manager=user_manager)
        await require_totp_stepup(
            request,
            TotpStepUpCheck(
                endpoint="oauth.associate",
                policy=assembly.totp_stepup_policy,
                user_manager=cast("TotpStepUpVerifierProtocol[UP]", user_manager),
            ),
        )
        await assembly.oauth_service.associate_account(
            user=user,
            code=code,
            redirect_uri=assembly.callback_url,
            code_verifier=flow_cookie.code_verifier,
            user_manager=user_manager,
        )
        response = Response(content={"linked": True}, media_type=MediaType.JSON)
        clear_state_cookie(response)
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
    return _create_oauth_callback_handler(
        assembly=assembly,
        route_params_spec=_OAuthCallbackRouteParamsSpec(
            path="/callback",
            guards=[is_authenticated],
            security=security,
            responses=responses,
        ),
        body_async_fn=_complete_associate_callback,
    )


def _create_oauth_callback_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    route_params_spec: _OAuthCallbackRouteParamsSpec,
    body_async_fn: _AssociateCallbackBody,
) -> object:
    """Create an OAuth callback handler from a shared signature/binding primitive.

    Returns:
        Decorated Litestar route handler for the provider associate callback endpoint.
    """
    dependency_parameter_name = assembly.user_manager_binding.dependency_parameter_name
    signature = _make_oauth_callback_signature(dependency_parameter_name)

    async def callback(*args: object, **kwargs: object) -> Response[Any]:
        request, code, oauth_state, user_manager = _bind_oauth_callback_inputs(
            signature=signature,
            dependency_parameter_name=dependency_parameter_name,
            direct_user_manager=assembly.user_manager_binding.user_manager,
            args=args,
            kwargs=kwargs,
        )
        return await body_async_fn(
            assembly=assembly,
            request=request,
            code=code,
            oauth_state=oauth_state,
            user_manager=user_manager,
        )

    _attach_handler_signature(
        callback,
        signature=signature,
        annotations=_oauth_callback_annotations(dependency_parameter_name),
    )
    return get(
        route_params_spec.path,
        guards=route_params_spec.guards,
        security=route_params_spec.security,
        responses=route_params_spec.responses,
    )(callback)


def _oauth_callback_annotations(dependency_parameter_name: str | None) -> dict[str, object]:
    """Return annotations for a generated associate callback dependency signature.

    Returns:
        Runtime annotation mapping assigned to the generated callback.
    """
    annotations: dict[str, object] = {
        "self": object,
        "request": Request[Any, Any, Any],
        "code": _OAuthCodeQuery,
        "oauth_state": _OAuthStateQuery,
        "return": Response[Any],
    }
    if dependency_parameter_name is not None:
        annotations[dependency_parameter_name] = OAuthControllerUserManagerProtocol[Any, Any]
    return annotations
