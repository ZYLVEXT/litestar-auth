"""OAuth controller factory for provider-specific authorize/callback flows."""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING, Any, cast

from litestar import Controller, Request, get
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.params import Parameter
from litestar.response import Response
from litestar.response.redirect import Redirect

from litestar_auth.controllers._utils import _build_controller_name
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.oauth.client_adapter import (
    OAuthClientAdapter,
    OAuthTokenPayload,
)
from litestar_auth.oauth.client_adapter import (
    _as_mapping as _client_as_mapping,
)
from litestar_auth.oauth.service import OAuthService
from litestar_auth.oauth.service import (
    OAuthServiceUserManagerProtocol as OAuthControllerUserManagerProtocol,
)
from litestar_auth.oauth.service import (
    _require_verified_email_evidence as _service_require_verified_email_evidence,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_auth.authentication.backend import AuthenticationBackend

STATE_COOKIE_PREFIX = "__oauth_state_"
ASSOCIATE_STATE_COOKIE_PREFIX = "__oauth_associate_state_"
STATE_COOKIE_MAX_AGE = 300


def _build_callback_url_from_base(redirect_base_url: str, provider_name: str) -> str:
    """Return the absolute callback URL for the authorize/callback pair.

    Returns:
        redirect_base_url with trailing slash stripped, plus /{provider_name}/callback.
    """
    return f"{redirect_base_url.rstrip('/')}/{provider_name}/callback"


def create_oauth_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    backend: AuthenticationBackend[UP, ID],
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
    oauth_client: object,
    redirect_base_url: str,
    path: str = "/auth/oauth",
    cookie_secure: bool = True,
    associate_by_email: bool = False,
    trust_provider_email_verified: bool = False,
) -> type[Controller]:
    """Return a controller subclass bound to one OAuth provider.

    Returns:
        Generated controller class mounted under the provider-specific path.
    """
    client_adapter = OAuthClientAdapter(oauth_client)
    oauth_service = OAuthService(
        provider_name=provider_name,
        client=client_adapter,
        associate_by_email=associate_by_email,
        trust_provider_email_verified=trust_provider_email_verified,
    )
    state_cookie_name = f"{STATE_COOKIE_PREFIX}{provider_name}"
    callback_url = _build_callback_url_from_base(redirect_base_url, provider_name)
    cookie_path = _build_cookie_path(path=path, provider_name=provider_name)

    class OAuthController(Controller):
        """Provider-specific OAuth authorize/callback endpoints."""

        @get("/authorize")
        async def authorize(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],  # noqa: ARG002
            scopes: list[str] | None = Parameter(query="scopes", default=None),  # noqa: B008
        ) -> Redirect:
            """Redirect the user to the upstream OAuth provider.

            Optional query parameter ``scopes``: list of scope strings to request
            from the provider (e.g. ``?scopes=openid&scopes=email``).

            Returns:
                Redirect response with the provider authorization URL and a secure state cookie.
            """
            authorization = await oauth_service.authorize(redirect_uri=callback_url, scopes=scopes)
            response = Redirect(authorization.authorization_url)
            _set_state_cookie(
                response,
                cookie_name=state_cookie_name,
                state=authorization.state,
                cookie_path=cookie_path,
                cookie_secure=cookie_secure,
            )
            return response

        @get("/callback")
        async def callback(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            code: str,
            oauth_state: str = Parameter(query="state"),
        ) -> Response[Any]:
            """Exchange the authorization code, resolve the user, and issue a local token.

            Returns:
                Login response from the configured local authentication backend.

            """
            _validate_state(request.cookies.get(state_cookie_name), oauth_state)
            user = await oauth_service.complete_login(
                code=code,
                redirect_uri=callback_url,
                user_manager=user_manager,
            )
            response = await backend.login(user)
            await user_manager.on_after_login(user)
            _clear_state_cookie(
                response,
                cookie_name=state_cookie_name,
                cookie_path=cookie_path,
                cookie_secure=cookie_secure,
            )
            return response

    OAuthController.__name__ = f"{_build_controller_name(provider_name)}OAuthController"
    OAuthController.__qualname__ = OAuthController.__name__
    OAuthController.path = f"{path.rstrip('/')}/{provider_name}"
    return OAuthController


def create_oauth_associate_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None = None,
    user_manager_dependency_key: str | None = None,
    oauth_client: object,
    redirect_base_url: str,
    path: str = "/auth/associate",
    cookie_secure: bool = True,
) -> type[Controller]:
    """Return a controller for linking an OAuth account to the authenticated user.

    Both /authorize and /callback are protected by is_authenticated. Callback
    upserts the OAuth account for request.user and does not create new users.

    Provide either user_manager (for direct use) or user_manager_dependency_key
    (for plugin use with a request-scoped dependency).

    Returns:
        Generated controller class mounted under the provider-specific path.

    Raises:
        ConfigurationError: If neither or both user-manager inputs are provided.

    """
    if (user_manager is None) == (user_manager_dependency_key is None):
        msg = "Provide exactly one of user_manager or user_manager_dependency_key."
        raise ConfigurationError(msg)

    state_cookie_name = f"{ASSOCIATE_STATE_COOKIE_PREFIX}{provider_name}"
    associate_callback_url = _build_callback_url_from_base(redirect_base_url, provider_name)
    cookie_path = _build_cookie_path(path=path, provider_name=provider_name)
    client_adapter = OAuthClientAdapter(oauth_client)
    oauth_service = OAuthService(
        provider_name=provider_name,
        client=client_adapter,
    )

    async def _callback_impl(
        request: Request[Any, Any, Any],
        code: str,
        oauth_state: str,
        manager: OAuthControllerUserManagerProtocol[UP, ID],
    ) -> Response[Any]:
        _validate_state(request.cookies.get(state_cookie_name), oauth_state)
        # Litestar does not narrow ``Request.user`` to ``UP``; associate routes use ``is_authenticated``.
        user = cast("UP", request.user)
        await oauth_service.associate_account(
            user=user,
            code=code,
            redirect_uri=associate_callback_url,
            user_manager=manager,
        )
        response = Response(
            content={"linked": True},
            media_type=MediaType.JSON,
        )
        _clear_state_cookie(
            response,
            cookie_name=state_cookie_name,
            cookie_path=cookie_path,
            cookie_secure=cookie_secure,
        )
        return response

    @get("/authorize", guards=[is_authenticated])
    async def _authorize(
        self: object,
        request: Request[Any, Any, Any],
    ) -> Redirect:
        del self, request
        authorization = await oauth_service.authorize(redirect_uri=associate_callback_url)
        response = Redirect(authorization.authorization_url)
        _set_state_cookie(
            response,
            cookie_name=state_cookie_name,
            state=authorization.state,
            cookie_path=cookie_path,
            cookie_secure=cookie_secure,
        )
        return response

    if user_manager_dependency_key is not None:

        @get("/callback", guards=[is_authenticated])
        async def _callback(
            self: object,
            request: Request[Any, Any, Any],
            code: str,
            litestar_auth_oauth_associate_user_manager: OAuthControllerUserManagerProtocol[
                UP,
                ID,
            ],
            oauth_state: str = Parameter(query="state"),
        ) -> Response[Any]:
            del self
            return await _callback_impl(
                request,
                code,
                oauth_state,
                litestar_auth_oauth_associate_user_manager,
            )

    else:
        bound_manager = cast("OAuthControllerUserManagerProtocol[UP, ID]", user_manager)

        @get("/callback", guards=[is_authenticated])
        async def _callback(
            self: object,
            request: Request[Any, Any, Any],
            code: str,
            oauth_state: str = Parameter(query="state"),
        ) -> Response[Any]:
            del self
            return await _callback_impl(
                request,
                code,
                oauth_state,
                bound_manager,
            )

    class OAuthAssociateController(Controller):
        """Provider-specific OAuth associate authorize/callback endpoints."""

        authorize = _authorize
        callback = _callback

    OAuthAssociateController.__name__ = f"{_build_controller_name(provider_name)}OAuthAssociateController"
    OAuthAssociateController.__qualname__ = OAuthAssociateController.__name__
    OAuthAssociateController.path = f"{path.rstrip('/')}/{provider_name}"
    return OAuthAssociateController


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
    oauth_client: object,
    redirect_uri: str,
    state: str,
    scopes: list[str] | None = None,
) -> str:
    """Return the provider authorization URL for the given callback state.

    Returns:
        Absolute provider authorization URL.

    """
    return await OAuthClientAdapter(oauth_client).get_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
        scopes=scopes,
    )


async def _get_access_token(*, oauth_client: object, code: str, redirect_uri: str) -> OAuthTokenPayload:
    """Exchange the provider callback code for an OAuth access token.

    Returns:
        Normalized access-token payload with `access_token`, `expires_at`, and `refresh_token`.

    """
    return await OAuthClientAdapter(oauth_client).get_access_token(code=code, redirect_uri=redirect_uri)


async def _get_account_identity(oauth_client: object, access_token: str) -> tuple[str, str]:
    """Return the upstream account identifier and email for the access token.

    Returns:
        Tuple containing the provider account id and email address.

    """
    return await OAuthClientAdapter(oauth_client).get_account_identity(access_token)


async def _get_email_verified(oauth_client: object, access_token: str) -> bool | None:
    """Return a provider asserted email-verification signal for the access token."""
    return await OAuthClientAdapter(oauth_client).get_email_verified(access_token)


def _as_mapping(raw_payload: object, *, message: str) -> Mapping[str, object]:
    """Normalize an arbitrary payload object into a mapping.

    Returns:
        Mapping view over the payload.
    """
    return _client_as_mapping(raw_payload, message=message)


def _require_verified_email_evidence(*, email_verified: bool | None) -> None:
    """Require explicit provider-verified email evidence for new-account OAuth sign-in."""
    _service_require_verified_email_evidence(email_verified=email_verified)
