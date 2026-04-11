"""OAuth controller factory for provider-specific authorize/callback flows."""

from __future__ import annotations

import hmac
import inspect
import keyword
from dataclasses import dataclass
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from litestar import Controller, Request, get
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.params import Parameter
from litestar.response import Response
from litestar.response.redirect import Redirect

from litestar_auth.controllers._utils import _build_controller_name, _mark_litestar_auth_route_handler
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.oauth.client_adapter import (
    OAuthClientAdapter,
    OAuthClientProtocol,
    OAuthTokenPayload,
    _build_oauth_client_adapter,
)
from litestar_auth.oauth.client_adapter import (
    _as_mapping as _client_as_mapping,
)
from litestar_auth.oauth.service import OAuthService
from litestar_auth.oauth.service import (
    OAuthServiceUserManagerProtocol as OAuthControllerUserManagerProtocol,
)
from litestar_auth.oauth.service import (
    _require_account_state as _require_service_account_state,
)
from litestar_auth.oauth.service import (
    _require_verified_email_evidence as _service_require_verified_email_evidence,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import Guard

    from litestar_auth.authentication.backend import AuthenticationBackend

STATE_COOKIE_PREFIX = "__oauth_state_"
ASSOCIATE_STATE_COOKIE_PREFIX = "__oauth_associate_state_"
STATE_COOKIE_MAX_AGE = 300


@dataclass(frozen=True, slots=True)
class _OAuthUserManagerBinding[UP: UserProtocol[Any], ID]:
    """Manager binding used by generated OAuth callback handlers."""

    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None
    dependency_parameter_name: str | None = None


@dataclass(frozen=True, slots=True)
class _OAuthControllerAssembly[UP: UserProtocol[Any], ID]:
    """Shared provider-scoped controller assembly details."""

    controller_name: str
    controller_path: str
    callback_url: str
    cookie_name: str
    cookie_path: str
    cookie_secure: bool
    oauth_scopes: tuple[str, ...] | None
    oauth_service: OAuthService[UP, ID]
    user_manager_binding: _OAuthUserManagerBinding[UP, ID]


def _build_callback_url_from_base(redirect_base_url: str, provider_name: str) -> str:
    """Return the absolute callback URL for the authorize/callback pair.

    Returns:
        redirect_base_url with trailing slash stripped, plus /{provider_name}/callback.
    """
    return f"{redirect_base_url.rstrip('/')}/{provider_name}/callback"


def _validate_manual_oauth_redirect_base_url(redirect_base_url: str) -> None:
    """Validate the fail-closed redirect-origin contract for manual OAuth controllers.

    Raises:
        ConfigurationError: If the redirect base does not use a non-loopback public
            HTTPS origin or includes unsupported URL components.
    """
    parsed_redirect_base_url = urlsplit(redirect_base_url)
    if parsed_redirect_base_url.scheme.casefold() != "https":
        msg = (
            "Manual/custom OAuth controllers require redirect_base_url to use a public HTTPS origin. "
            f"Received {redirect_base_url!r}."
        )
        raise ConfigurationError(msg)

    host = parsed_redirect_base_url.hostname
    if host is None or _is_loopback_host(host):
        msg = (
            "Manual/custom OAuth controllers require redirect_base_url to use a non-loopback public HTTPS origin. "
            f"Received {redirect_base_url!r}."
        )
        raise ConfigurationError(msg)
    if (
        parsed_redirect_base_url.username is not None
        or parsed_redirect_base_url.password is not None
        or parsed_redirect_base_url.query
        or parsed_redirect_base_url.fragment
    ):
        msg = (
            "Manual/custom OAuth controllers require redirect_base_url to be a clean HTTPS callback base without "
            "userinfo, query, or fragment components. "
            f"Received {redirect_base_url!r}."
        )
        raise ConfigurationError(msg)


def _is_loopback_host(host: str) -> bool:
    """Return whether ``host`` is a localhost or loopback IP literal."""
    if host.casefold() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _build_direct_user_manager_binding[UP: UserProtocol[Any], ID](
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
) -> _OAuthUserManagerBinding[UP, ID]:
    """Return a binding for a directly supplied user manager."""
    return _OAuthUserManagerBinding(user_manager=user_manager)


def _build_associate_user_manager_binding[UP: UserProtocol[Any], ID](
    *,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None,
    user_manager_dependency_key: str | None,
) -> _OAuthUserManagerBinding[UP, ID]:
    """Return the manager binding for OAuth account-association controllers.

    Raises:
        ConfigurationError: If neither or both user-manager inputs are provided.
    """
    if (user_manager is None) == (user_manager_dependency_key is None):
        msg = "Provide exactly one of user_manager or user_manager_dependency_key."
        raise ConfigurationError(msg)

    if user_manager is not None:
        return _OAuthUserManagerBinding(user_manager=user_manager)

    dependency_parameter_name = cast("str", user_manager_dependency_key)
    if not dependency_parameter_name.isidentifier() or keyword.iskeyword(dependency_parameter_name):
        msg = (
            "user_manager_dependency_key must be a valid Python identifier because Litestar matches dependency "
            "keys to callback parameter names."
        )
        raise ConfigurationError(msg)

    return _OAuthUserManagerBinding(
        user_manager=None,
        dependency_parameter_name=dependency_parameter_name,
    )


def _build_oauth_controller_assembly[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    oauth_client: OAuthClientProtocol | None = None,
    oauth_client_adapter: OAuthClientAdapter | None = None,
    redirect_base_url: str,
    path: str,
    cookie_secure: bool,
    state_cookie_prefix: str,
    controller_name_suffix: str,
    user_manager_binding: _OAuthUserManagerBinding[UP, ID],
    oauth_scopes: Sequence[str] | None = None,
    associate_by_email: bool = False,
    trust_provider_email_verified: bool = False,
    validate_redirect_base_url: bool = True,
) -> _OAuthControllerAssembly[UP, ID]:
    """Build the shared provider-scoped OAuth controller assembly state.

    Returns:
        Shared controller metadata, callback details, cookie scope, and manager binding.

    Raises:
        ValueError: If internal callers provide neither or both client inputs.
    """
    if oauth_client is None and oauth_client_adapter is None:
        msg = "Provide oauth_client or oauth_client_adapter."
        raise ValueError(msg)
    if oauth_client is not None and oauth_client_adapter is not None:
        msg = "Provide only one of oauth_client or oauth_client_adapter."
        raise ValueError(msg)

    if oauth_client_adapter is None:
        oauth_client_adapter = _build_oauth_client_adapter(oauth_client=oauth_client)

    if validate_redirect_base_url:
        _validate_manual_oauth_redirect_base_url(redirect_base_url)
    controller_path = _build_cookie_path(path=path, provider_name=provider_name)
    return _OAuthControllerAssembly(
        controller_name=f"{_build_controller_name(provider_name)}{controller_name_suffix}",
        controller_path=controller_path,
        callback_url=_build_callback_url_from_base(redirect_base_url, provider_name),
        cookie_name=f"{state_cookie_prefix}{provider_name}",
        cookie_path=controller_path,
        cookie_secure=cookie_secure,
        oauth_scopes=_normalize_oauth_scopes(oauth_scopes),
        oauth_service=OAuthService(
            provider_name=provider_name,
            client=oauth_client_adapter,
            associate_by_email=associate_by_email,
            trust_provider_email_verified=trust_provider_email_verified,
        ),
        user_manager_binding=user_manager_binding,
    )


def _make_associate_callback_signature(parameter_name: str) -> inspect.Signature:
    """Build the Litestar-visible signature for an associate callback dependency key.

    Returns:
        Signature exposing the configured dependency key as a callback parameter.
    """
    return inspect.Signature(
        parameters=[
            inspect.Parameter(
                name="self",
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=object,
            ),
            inspect.Parameter(
                name="request",
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Request[Any, Any, Any],
            ),
            inspect.Parameter(
                name="code",
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=str,
            ),
            inspect.Parameter(
                name=parameter_name,
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Any,
            ),
            inspect.Parameter(
                name="oauth_state",
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
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
) -> tuple[
    Request[Any, Any, Any],
    str,
    str,
    OAuthControllerUserManagerProtocol[UP, ID],
]:
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

    @get("/authorize", guards=guards, security=security)
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
            cookie_name=assembly.cookie_name,
            state=authorization.state,
            cookie_path=assembly.cookie_path,
            cookie_secure=assembly.cookie_secure,
        )
        return response

    return authorize


async def _complete_login_callback[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    request: Request[Any, Any, Any],
    code: str,
    oauth_state: str,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
    backend: AuthenticationBackend[UP, ID],
) -> Response[Any]:
    """Complete the OAuth login callback using the shared assembly state.

    Returns:
        Login response produced by the configured local authentication backend.
    """
    _validate_state(request.cookies.get(assembly.cookie_name), oauth_state)
    user = await assembly.oauth_service.complete_login(
        code=code,
        redirect_uri=assembly.callback_url,
        user_manager=user_manager,
    )
    response = await backend.login(user)
    await user_manager.on_after_login(user)
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

    @get("/callback")
    async def callback(
        self: object,
        request: Request[Any, Any, Any],
        code: str,
        oauth_state: str = Parameter(query="state"),
    ) -> Response[Any]:
        del self
        return await _complete_login_callback(
            assembly=assembly,
            request=request,
            code=code,
            oauth_state=oauth_state,
            user_manager=user_manager,
            backend=backend,
        )

    return callback


async def _complete_associate_callback[UP: UserProtocol[Any], ID](
    *,
    assembly: _OAuthControllerAssembly[UP, ID],
    request: Request[Any, Any, Any],
    code: str,
    oauth_state: str,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
) -> Response[Any]:
    """Complete the OAuth associate callback using the shared assembly state.

    Returns:
        JSON response confirming the authenticated account link completed.
    """
    _validate_state(request.cookies.get(assembly.cookie_name), oauth_state)
    # Litestar does not narrow ``Request.user`` to ``UP``; associate routes use ``is_authenticated``.
    user = cast("UP", request.user)
    _require_service_account_state(user, user_manager=user_manager)
    await assembly.oauth_service.associate_account(
        user=user,
        code=code,
        redirect_uri=assembly.callback_url,
        user_manager=user_manager,
    )
    response = Response(
        content={"linked": True},
        media_type=MediaType.JSON,
    )
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
    security: Sequence[SecurityRequirement] | None = None,
) -> object:
    """Create the callback route handler for OAuth account-association controllers.

    Returns:
        Decorated Litestar route handler for the provider associate callback endpoint.
    """
    dependency_parameter_name = assembly.user_manager_binding.dependency_parameter_name
    if dependency_parameter_name is not None:
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
        cast("Any", callback).__annotations__ = {
            "self": object,
            "request": Request[Any, Any, Any],
            "code": str,
            dependency_parameter_name: Any,
            "oauth_state": str,
            "return": Response[Any],
        }
        return get("/callback", guards=[is_authenticated], security=security)(callback)

    user_manager = cast(
        "OAuthControllerUserManagerProtocol[UP, ID]",
        assembly.user_manager_binding.user_manager,
    )

    @get("/callback", guards=[is_authenticated], security=security)
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


def _create_login_oauth_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    backend: AuthenticationBackend[UP, ID],
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
    oauth_client_adapter: OAuthClientAdapter,
    redirect_base_url: str,
    path: str = "/auth/oauth",
    cookie_secure: bool = True,
    oauth_scopes: Sequence[str] | None = None,
    associate_by_email: bool = False,
    trust_provider_email_verified: bool = False,
    validate_redirect_base_url: bool = True,
) -> type[Controller]:
    """Return a provider-specific login controller from a resolved client adapter."""
    assembly = _build_oauth_controller_assembly(
        provider_name=provider_name,
        oauth_client_adapter=oauth_client_adapter,
        redirect_base_url=redirect_base_url,
        path=path,
        cookie_secure=cookie_secure,
        state_cookie_prefix=STATE_COOKIE_PREFIX,
        controller_name_suffix="OAuthController",
        user_manager_binding=_build_direct_user_manager_binding(user_manager),
        oauth_scopes=oauth_scopes,
        associate_by_email=associate_by_email,
        trust_provider_email_verified=trust_provider_email_verified,
        validate_redirect_base_url=validate_redirect_base_url,
    )
    return _create_oauth_controller_type(
        assembly=assembly,
        authorize_handler=_create_authorize_handler(
            assembly=assembly,
        ),
        callback_handler=_create_login_callback_handler(
            assembly=assembly,
            backend=backend,
        ),
        docstring="Provider-specific OAuth authorize/callback endpoints.",
    )


def create_oauth_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    backend: AuthenticationBackend[UP, ID],
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
    oauth_client: OAuthClientProtocol,
    redirect_base_url: str,
    path: str = "/auth/oauth",
    cookie_secure: bool = True,
    oauth_scopes: Sequence[str] | None = None,
    associate_by_email: bool = False,
    trust_provider_email_verified: bool = False,
) -> type[Controller]:
    """Return a controller subclass bound to one OAuth provider.

    The authorize endpoint uses only server-configured ``oauth_scopes``. Runtime
    scope-query overrides are rejected. ``redirect_base_url`` must use a
    non-loopback ``https://`` origin; the manual controller API does not expose
    a debug or testing escape hatch for insecure callback origins.

    Returns:
        Generated controller class mounted under the provider-specific path.
    """
    return _create_login_oauth_controller(
        provider_name=provider_name,
        backend=backend,
        user_manager=user_manager,
        oauth_client_adapter=_build_oauth_client_adapter(oauth_client=oauth_client),
        redirect_base_url=redirect_base_url,
        path=path,
        cookie_secure=cookie_secure,
        oauth_scopes=oauth_scopes,
        associate_by_email=associate_by_email,
        trust_provider_email_verified=trust_provider_email_verified,
    )


def _create_oauth_associate_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None = None,
    user_manager_dependency_key: str | None = None,
    oauth_client: OAuthClientProtocol,
    redirect_base_url: str,
    path: str = "/auth/associate",
    cookie_secure: bool = True,
    validate_redirect_base_url: bool = True,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Build an OAuth associate controller with optional redirect-origin validation.

    Returns:
        Generated controller class mounted under the provider-specific path.
    """
    assembly = _build_oauth_controller_assembly(
        provider_name=provider_name,
        oauth_client_adapter=_build_oauth_client_adapter(oauth_client=oauth_client),
        redirect_base_url=redirect_base_url,
        path=path,
        cookie_secure=cookie_secure,
        state_cookie_prefix=ASSOCIATE_STATE_COOKIE_PREFIX,
        controller_name_suffix="OAuthAssociateController",
        user_manager_binding=_build_associate_user_manager_binding(
            user_manager=user_manager,
            user_manager_dependency_key=user_manager_dependency_key,
        ),
        validate_redirect_base_url=validate_redirect_base_url,
    )
    return _create_oauth_controller_type(
        assembly=assembly,
        authorize_handler=_create_authorize_handler(
            assembly=assembly,
            guards=[is_authenticated],
            security=security,
        ),
        callback_handler=_create_associate_callback_handler(assembly=assembly, security=security),
        docstring="Provider-specific OAuth associate authorize/callback endpoints.",
    )


def create_oauth_associate_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None = None,
    user_manager_dependency_key: str | None = None,
    oauth_client: OAuthClientProtocol,
    redirect_base_url: str,
    path: str = "/auth/associate",
    cookie_secure: bool = True,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Return a controller for linking an OAuth account to the authenticated user.

    Both /authorize and /callback are protected by is_authenticated. Callback
    validates account state, then upserts the OAuth account for request.user and
    does not create new users.

    Provide either user_manager (for direct use) or user_manager_dependency_key
    (for plugin use with a request-scoped dependency). ``user_manager_dependency_key``
    must be a valid non-keyword Python identifier because Litestar injects
    dependencies by matching keys to callback parameter names.
    ``redirect_base_url`` must use a non-loopback ``https://`` origin; the
    manual controller API does not expose a debug or testing escape hatch for
    insecure callback origins.

    Returns:
        Generated controller class mounted under the provider-specific path.
    """
    return _create_oauth_associate_controller(
        provider_name=provider_name,
        user_manager=user_manager,
        user_manager_dependency_key=user_manager_dependency_key,
        oauth_client=oauth_client,
        redirect_base_url=redirect_base_url,
        path=path,
        cookie_secure=cookie_secure,
        security=security,
    )


def _normalize_oauth_scopes(scopes: Sequence[str] | None) -> tuple[str, ...] | None:
    """Return normalized server-owned OAuth scopes, or ``None`` when unset.

    Raises:
        ConfigurationError: If any configured scope is empty or contains whitespace.
    """
    if scopes is None:
        return None

    normalized_scopes: list[str] = []
    seen_scopes: set[str] = set()
    for raw_scope in scopes:
        if not isinstance(raw_scope, str):
            msg = "OAuth scopes must be strings."
            raise ConfigurationError(msg)
        scope = raw_scope.strip()
        if not scope:
            msg = "OAuth scopes must be non-empty strings."
            raise ConfigurationError(msg)
        if any(character.isspace() for character in scope):
            msg = "OAuth scopes must be provided as individual tokens without embedded whitespace."
            raise ConfigurationError(msg)
        if scope not in seen_scopes:
            normalized_scopes.append(scope)
            seen_scopes.add(scope)

    return tuple(normalized_scopes) if normalized_scopes else None


def _reject_runtime_oauth_scope_override(request: Request[Any, Any, Any]) -> None:
    """Reject caller-controlled scope overrides on OAuth authorize endpoints.

    Raises:
        ClientException: If the request attempts to override OAuth scopes.
    """
    query_params = getattr(request, "query_params", None)
    if query_params is None or query_params.get("scopes") is None:
        return

    msg = "OAuth scopes must be configured on the server."
    raise ClientException(status_code=400, detail=msg)


def _build_cookie_path(*, path: str, provider_name: str) -> str:
    """Return the cookie path for a provider-specific OAuth controller.

    Returns:
        Provider-specific cookie path used for OAuth state cookies.
    """
    return f"{path.rstrip('/')}/{provider_name}"


def _set_state_cookie(
    response: Response[Any],
    *,
    cookie_name: str,
    state: str,
    cookie_path: str,
    cookie_secure: bool,
) -> None:
    """Store the OAuth state value in the provider-scoped cookie."""
    response.set_cookie(
        key=cookie_name,
        value=state,
        max_age=STATE_COOKIE_MAX_AGE,
        path=cookie_path,
        secure=cookie_secure,
        httponly=True,
        samesite="lax",
    )


def _clear_state_cookie(
    response: Response[Any],
    *,
    cookie_name: str,
    cookie_path: str,
    cookie_secure: bool,
) -> None:
    """Expire the provider-scoped OAuth state cookie."""
    response.set_cookie(
        key=cookie_name,
        value="",
        max_age=0,
        path=cookie_path,
        secure=cookie_secure,
        httponly=True,
        samesite="lax",
    )


def _validate_state(cookie_state: str | None, query_state: str) -> None:
    """Validate the callback ``state`` against the secure cookie value.

    Raises:
        ClientException: If the OAuth callback state is missing or does not match the cookie.
    """
    # Security: reject empty values before constant-time comparison to prevent
    # trivial empty-string matching (hmac.compare_digest("", "") == True).
    if not cookie_state or not query_state or not hmac.compare_digest(cookie_state, query_state):
        msg = "Invalid OAuth state."
        raise ClientException(status_code=400, detail=msg, extra={"code": ErrorCode.OAUTH_STATE_INVALID})


async def _get_authorization_url(
    *,
    oauth_client: OAuthClientProtocol,
    redirect_uri: str,
    state: str,
    scopes: list[str] | None = None,
) -> str:
    """Return the provider authorization URL for the given callback state.

    Returns:
        Absolute provider authorization URL.

    """
    return await _build_oauth_client_adapter(oauth_client=oauth_client).get_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
        scopes=scopes,
    )


async def _get_access_token(
    *,
    oauth_client: OAuthClientProtocol,
    code: str,
    redirect_uri: str,
) -> OAuthTokenPayload:
    """Exchange the provider callback code for an OAuth access token.

    Returns:
        Normalized access-token payload with `access_token`, `expires_at`, and `refresh_token`.

    """
    return await _build_oauth_client_adapter(oauth_client=oauth_client).get_access_token(
        code=code,
        redirect_uri=redirect_uri,
    )


async def _get_account_identity(oauth_client: OAuthClientProtocol, access_token: str) -> tuple[str, str]:
    """Return the upstream account identifier and email for the access token.

    Returns:
        Tuple containing the provider account id and email address.

    """
    return await _build_oauth_client_adapter(oauth_client=oauth_client).get_account_identity(access_token)


async def _get_email_verified(oauth_client: OAuthClientProtocol, access_token: str) -> bool | None:
    """Return a provider asserted email-verification signal for the access token."""
    return await _build_oauth_client_adapter(oauth_client=oauth_client).get_email_verified(access_token)


def _as_mapping(raw_payload: object, *, message: str) -> Mapping[str, object]:
    """Normalize an arbitrary payload object into a mapping.

    Returns:
        Mapping view over the payload.
    """
    return _client_as_mapping(raw_payload, message=message)


def _require_verified_email_evidence(*, email_verified: bool | None) -> None:
    """Require explicit provider-verified email evidence for new-account OAuth sign-in."""
    _service_require_verified_email_evidence(email_verified=email_verified)
