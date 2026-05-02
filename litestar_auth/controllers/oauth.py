"""OAuth controller factory for provider-specific authorize/callback flows.

Generated controllers enforce RFC 7636 PKCE S256 for OAuth authorization-code flows. The authorize endpoint stores
the generated ``state`` and ``code_verifier`` in an encrypted, authenticated, httpOnly flow cookie; callbacks decrypt
that envelope, validate ``state`` in constant time, and pass the verifier into the provider token exchange.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, Unpack, cast, overload

from litestar import Controller, Request, get
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example
from litestar.params import Parameter
from litestar.response import Response
from litestar.response.redirect import Redirect

from litestar_auth.controllers._oauth_assembly import (
    _build_associate_user_manager_binding,
    _build_direct_user_manager_binding,
    _build_oauth_controller_assembly,
    _OAuthAssociateControllerSettings,
    _OAuthClientBinding,
    _OAuthControllerAssembly,
    _OAuthControllerAssemblySettings,
    _OAuthLoginCallbackInputs,
    _OAuthLoginControllerSettings,
    _OAuthServiceSettings,
)
from litestar_auth.controllers._oauth_associate_routes import _create_associate_callback_handler
from litestar_auth.controllers._oauth_helpers import (
    STATE_COOKIE_MAX_AGE,  # noqa: F401
    _build_callback_url_from_base,  # noqa: F401
    _clear_state_cookie,
    _decode_oauth_flow_cookie,
    _encode_oauth_flow_cookie,  # noqa: F401
    _OAuthCookieSettings,
    _reject_runtime_oauth_scope_override,
    _require_verified_email_evidence,  # noqa: F401
    _set_state_cookie,
    _validate_manual_oauth_redirect_base_url,  # noqa: F401
    _validate_state,
)
from litestar_auth.controllers._utils import _mark_litestar_auth_route_handler
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.oauth import service as _oauth_service
from litestar_auth.oauth._flow_cookie import _OAuthFlowCookie
from litestar_auth.oauth.client_adapter import OAuthClientProtocol, _build_oauth_client_adapter
from litestar_auth.oauth.service import OAuthService  # noqa: F401
from litestar_auth.types import UserProtocol

OAuthControllerUserManagerProtocol = _oauth_service.OAuthServiceUserManagerProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.openapi.spec import SecurityRequirement
    from litestar.response import Response
    from litestar.types import Guard

    from litestar_auth.authentication.backend import AuthenticationBackend

STATE_COOKIE_PREFIX = "__oauth_state_"
ASSOCIATE_STATE_COOKIE_PREFIX = "__oauth_associate_state_"
_OAUTH_OPENAPI_RESPONSES = {
    400: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description=(
            "Invalid OAuth callback state or missing/tampered PKCE flow-cookie evidence uses "
            "`OAUTH_STATE_INVALID`. Runtime scope overrides on authorize are also rejected."
        ),
        examples=[
            Example(
                id="oauth_state_invalid",
                summary="Invalid OAuth state or PKCE evidence",
                value={
                    "status_code": 400,
                    "detail": "Invalid OAuth state.",
                    "extra": {"code": ErrorCode.OAUTH_STATE_INVALID.value},
                },
            ),
        ],
    ),
}


@dataclass(frozen=True, slots=True)
class OAuthControllerConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :func:`create_oauth_controller`."""

    provider_name: str
    backend: AuthenticationBackend[UP, ID]
    user_manager: OAuthControllerUserManagerProtocol[UP, ID]
    oauth_client: OAuthClientProtocol
    redirect_base_url: str
    oauth_flow_cookie_secret: str
    path: str = "/auth/oauth"
    cookie_secure: bool = True
    oauth_scopes: Sequence[str] | None = None
    associate_by_email: bool = False
    trust_provider_email_verified: bool = False


class OAuthControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :func:`create_oauth_controller`."""

    provider_name: Required[str]
    backend: Required[AuthenticationBackend[UP, ID]]
    user_manager: Required[OAuthControllerUserManagerProtocol[UP, ID]]
    oauth_client: Required[OAuthClientProtocol]
    redirect_base_url: Required[str]
    oauth_flow_cookie_secret: Required[str]
    path: NotRequired[str]
    cookie_secure: NotRequired[bool]
    oauth_scopes: NotRequired[Sequence[str] | None]
    associate_by_email: NotRequired[bool]
    trust_provider_email_verified: NotRequired[bool]


@dataclass(frozen=True, slots=True)
class OAuthAssociateControllerConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :func:`create_oauth_associate_controller`."""

    provider_name: str
    oauth_client: OAuthClientProtocol
    redirect_base_url: str
    oauth_flow_cookie_secret: str
    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None = None
    user_manager_dependency_key: str | None = None
    path: str = "/auth/associate"
    cookie_secure: bool = True
    security: Sequence[SecurityRequirement] | None = None


class OAuthAssociateControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :func:`create_oauth_associate_controller`."""

    provider_name: Required[str]
    user_manager: NotRequired[OAuthControllerUserManagerProtocol[UP, ID] | None]
    user_manager_dependency_key: NotRequired[str | None]
    oauth_client: Required[OAuthClientProtocol]
    redirect_base_url: Required[str]
    oauth_flow_cookie_secret: Required[str]
    path: NotRequired[str]
    cookie_secure: NotRequired[bool]
    security: NotRequired[Sequence[SecurityRequirement] | None]


def _create_oauth_controller_type(
    *,
    assembly: _OAuthControllerAssembly[Any, Any],
    authorize_handler: object,
    callback_handler: object,
    docstring: str,
) -> type[Controller]:
    """Materialize the final provider-specific controller subclass.

    Returns:
        Generated controller type with provider-scoped metadata and handlers attached.
    """

    class OAuthController(Controller):
        """Generated OAuth controller."""

        authorize = authorize_handler
        callback = callback_handler

    OAuthController.__doc__ = docstring
    OAuthController.__name__ = assembly.controller_name
    OAuthController.__qualname__ = assembly.controller_name
    OAuthController.path = assembly.controller_path
    return _mark_litestar_auth_route_handler(OAuthController)


def _create_authorize_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    guards: Sequence[Guard] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> object:
    """Create the authorize route handler for a provider-scoped OAuth controller.

    Returns:
        Decorated Litestar route handler for the provider authorize endpoint.
    """

    @get("/authorize", guards=guards, security=security, responses=_OAUTH_OPENAPI_RESPONSES)
    async def authorize(
        self: object,
        request: Request[Any, Any, Any],
    ) -> Redirect:
        del self
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

    return authorize


async def _complete_login_callback[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    callback_inputs: _OAuthLoginCallbackInputs[UP, ID],
) -> Response[Any]:
    """Complete the PKCE-bound OAuth login callback using the shared assembly state.

    Returns:
        Login response produced by the configured local authentication backend.
    """
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
    await callback_inputs.user_manager.on_after_login(user)
    _clear_state_cookie(
        response,
        cookie_name=assembly.cookie_name,
        cookie_path=assembly.cookie_path,
        cookie_secure=assembly.cookie_secure,
    )
    return response


def _create_login_callback_handler[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    backend: AuthenticationBackend[UP, ID],
) -> object:
    """Create the callback route handler for OAuth login controllers.

    Returns:
        Decorated Litestar route handler for the provider callback endpoint.
    """
    user_manager = cast(
        "OAuthControllerUserManagerProtocol[UP, ID]",
        assembly.user_manager_binding.user_manager,
    )

    @get("/callback", responses=_OAUTH_OPENAPI_RESPONSES)
    async def callback(
        self: object,
        request: Request[Any, Any, Any],
        code: str,
        oauth_state: str = Parameter(query="state"),
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


def _create_login_oauth_controller[UP: UserProtocol[Any], ID](
    settings: _OAuthLoginControllerSettings[UP, ID],
) -> type[Controller]:
    """Return a provider-specific login controller from a resolved client adapter."""
    assembly = _build_oauth_controller_assembly(
        settings=_OAuthControllerAssemblySettings(
            provider_name=settings.provider_name,
            redirect_base_url=settings.redirect_base_url,
            path=settings.path,
            cookie_secure=settings.cookie_secure,
            oauth_flow_cookie_secret=settings.oauth_flow_cookie_secret,
            state_cookie_prefix=STATE_COOKIE_PREFIX,
            controller_name_suffix="OAuthController",
            validate_redirect_base_url=settings.validate_redirect_base_url,
        ),
        client_binding=_OAuthClientBinding(oauth_client_adapter=settings.oauth_client_adapter),
        user_manager_binding=_build_direct_user_manager_binding(settings.user_manager),
        service_settings=_OAuthServiceSettings(
            oauth_scopes=settings.oauth_scopes,
            associate_by_email=settings.associate_by_email,
            trust_provider_email_verified=settings.trust_provider_email_verified,
        ),
    )
    return _create_oauth_controller_type(
        assembly=assembly,
        authorize_handler=_create_authorize_handler(
            assembly=assembly,
        ),
        callback_handler=_create_login_callback_handler(
            assembly=assembly,
            backend=settings.backend,
        ),
        docstring="Provider-specific OAuth authorize/callback endpoints.",
    )


@overload
def create_oauth_controller[UP: UserProtocol[Any], ID](
    *,
    config: OAuthControllerConfig[UP, ID],
) -> type[Controller]: ...  # pragma: no cover


@overload
def create_oauth_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[OAuthControllerOptions[UP, ID]],
) -> type[Controller]: ...  # pragma: no cover


def create_oauth_controller[UP: UserProtocol[Any], ID](
    *,
    config: OAuthControllerConfig[UP, ID] | None = None,
    **options: Unpack[OAuthControllerOptions[UP, ID]],
) -> type[Controller]:
    """Return a controller subclass bound to one OAuth provider.

    The authorize endpoint uses only server-configured ``oauth_scopes``. Runtime
    scope-query overrides are rejected. ``redirect_base_url`` must use a
    non-loopback ``https://`` origin; the manual controller API does not expose
    a debug or testing override for insecure callback origins. The generated
    flow enforces RFC 7636 PKCE S256: manual clients must accept
    ``code_challenge`` / ``code_challenge_method`` on authorization and
    ``code_verifier`` on token exchange.

    Returns:
        Generated controller class mounted under the provider-specific path.

    Raises:
        ValueError: If ``config`` and keyword options are combined.
    """
    if config is not None and options:
        msg = "Pass either OAuthControllerConfig or keyword options, not both."
        raise ValueError(msg)
    settings = OAuthControllerConfig(**options) if config is None else config

    return _create_login_oauth_controller(
        _OAuthLoginControllerSettings(
            provider_name=settings.provider_name,
            backend=settings.backend,
            user_manager=settings.user_manager,
            oauth_client_adapter=_build_oauth_client_adapter(oauth_client=settings.oauth_client),
            redirect_base_url=settings.redirect_base_url,
            oauth_flow_cookie_secret=settings.oauth_flow_cookie_secret,
            path=settings.path,
            cookie_secure=settings.cookie_secure,
            oauth_scopes=settings.oauth_scopes,
            associate_by_email=settings.associate_by_email,
            trust_provider_email_verified=settings.trust_provider_email_verified,
        ),
    )


def _create_oauth_associate_controller[UP: UserProtocol[Any], ID](
    settings: _OAuthAssociateControllerSettings[UP, ID],
) -> type[Controller]:
    """Build an OAuth associate controller with optional redirect-origin validation.

    Returns:
        Generated controller class mounted under the provider-specific path.
    """
    assembly = _build_oauth_controller_assembly(
        settings=_OAuthControllerAssemblySettings(
            provider_name=settings.provider_name,
            redirect_base_url=settings.redirect_base_url,
            path=settings.path,
            cookie_secure=settings.cookie_secure,
            oauth_flow_cookie_secret=settings.oauth_flow_cookie_secret,
            state_cookie_prefix=ASSOCIATE_STATE_COOKIE_PREFIX,
            controller_name_suffix="OAuthAssociateController",
            validate_redirect_base_url=settings.validate_redirect_base_url,
        ),
        client_binding=_OAuthClientBinding(
            oauth_client_adapter=_build_oauth_client_adapter(oauth_client=settings.oauth_client),
        ),
        user_manager_binding=_build_associate_user_manager_binding(
            user_manager=settings.user_manager,
            user_manager_dependency_key=settings.user_manager_dependency_key,
        ),
    )
    return _create_oauth_controller_type(
        assembly=assembly,
        authorize_handler=_create_authorize_handler(
            assembly=assembly,
            guards=[is_authenticated],
            security=settings.security,
        ),
        callback_handler=_create_associate_callback_handler(
            assembly=assembly,
            responses=_OAUTH_OPENAPI_RESPONSES,
            security=settings.security,
        ),
        docstring="Provider-specific OAuth associate authorize/callback endpoints.",
    )


@overload
def create_oauth_associate_controller[UP: UserProtocol[Any], ID](
    *,
    config: OAuthAssociateControllerConfig[UP, ID],
) -> type[Controller]: ...  # pragma: no cover


@overload
def create_oauth_associate_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[OAuthAssociateControllerOptions[UP, ID]],
) -> type[Controller]: ...  # pragma: no cover


def create_oauth_associate_controller[UP: UserProtocol[Any], ID](
    *,
    config: OAuthAssociateControllerConfig[UP, ID] | None = None,
    **options: Unpack[OAuthAssociateControllerOptions[UP, ID]],
) -> type[Controller]:
    """Return a controller for linking an OAuth account to the authenticated user.

    Both /authorize and /callback are protected by is_authenticated. Callback
    validates account state, then upserts the OAuth account for request.user and
    does not create new users. The generated flow enforces RFC 7636 PKCE S256:
    manual clients must accept ``code_challenge`` / ``code_challenge_method`` on
    authorization and ``code_verifier`` on token exchange.

    Provide either user_manager (for direct use) or user_manager_dependency_key
    (for plugin use with a request-scoped dependency). ``user_manager_dependency_key``
    must be a valid non-keyword Python identifier because Litestar injects
    dependencies by matching keys to callback parameter names.
    ``redirect_base_url`` must use a non-loopback ``https://`` origin; the
    manual controller API does not expose a debug or testing override for
    insecure callback origins.

    Returns:
        Generated controller class mounted under the provider-specific path.

    Raises:
        ValueError: If ``config`` and keyword options are combined.
    """
    if config is not None and options:
        msg = "Pass either OAuthAssociateControllerConfig or keyword options, not both."
        raise ValueError(msg)
    settings = OAuthAssociateControllerConfig(**options) if config is None else config

    return _create_oauth_associate_controller(
        _OAuthAssociateControllerSettings(
            provider_name=settings.provider_name,
            user_manager=settings.user_manager,
            user_manager_dependency_key=settings.user_manager_dependency_key,
            oauth_client=settings.oauth_client,
            redirect_base_url=settings.redirect_base_url,
            oauth_flow_cookie_secret=settings.oauth_flow_cookie_secret,
            path=settings.path,
            cookie_secure=settings.cookie_secure,
            security=settings.security,
        ),
    )


def _cookie_settings_from_assembly(assembly: _OAuthControllerAssembly[Any, Any]) -> _OAuthCookieSettings:
    """Return cookie settings from provider-scoped assembly state."""
    return _OAuthCookieSettings(
        cookie_name=assembly.cookie_name,
        cookie_path=assembly.cookie_path,
        cookie_secure=assembly.cookie_secure,
        flow_cookie_cipher=assembly.flow_cookie_cipher,
    )
