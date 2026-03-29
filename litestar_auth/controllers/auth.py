"""Authentication controller factory for backend-bound login/logout routes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Annotated, Any, Protocol, cast

import msgspec
from litestar import Controller, Request, post
from litestar.enums import MediaType
from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.response import Response

from litestar_auth.authentication.strategy.base import (
    RefreshableStrategy,
    TokenInvalidationCapable,
    UserManagerProtocol,
)
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.config import is_testing, validate_secret_length
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    RequestHandler,
    _build_controller_name,
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _decode_request_body,
    _require_account_state,
)
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.totp_flow import TOTP_PENDING_AUDIENCE as _TOTP_PENDING_AUDIENCE
from litestar_auth.totp_flow import TotpFlowUserManagerProtocol, TotpLoginFlowService
from litestar_auth.types import LoginIdentifier, TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.ratelimit import AuthRateLimitConfig

INVALID_CREDENTIALS_DETAIL = "Invalid credentials."
INVALID_REFRESH_TOKEN_DETAIL = "The refresh token is invalid."  # noqa: S105
TOTP_PENDING_AUDIENCE = _TOTP_PENDING_AUDIENCE
_DEFAULT_PENDING_TOKEN_LIFETIME = timedelta(minutes=5)
_LOGIN_EMAIL_MAX_LENGTH = 320
_LOGIN_USERNAME_MAX_LENGTH = 150
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class LoginCredentials(msgspec.Struct):
    """Login payload accepted by the auth controller."""

    identifier: Annotated[str, msgspec.Meta(min_length=1, max_length=_LOGIN_EMAIL_MAX_LENGTH)]
    password: Annotated[str, msgspec.Meta(min_length=1, max_length=128)]


class RefreshTokenRequest(msgspec.Struct):
    """Refresh payload accepted by the auth controller."""

    refresh_token: Annotated[str, msgspec.Meta(min_length=1, max_length=512)]


class AuthControllerUserManagerProtocol[UP: UserProtocol[Any], ID](
    UserManagerProtocol[UP, ID],
    AccountStateValidatorProvider[UP],
    Protocol,
):
    """User-manager behavior required by the auth controller."""

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: LoginIdentifier | None = None,
    ) -> UP | None:
        """Return the authenticated user for valid credentials."""

    async def on_after_login(self, user: UP) -> None:
        """Run post-login side effects for a fully authenticated user."""

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return a plain-text TOTP secret from storage."""


@dataclass(slots=True)
class _AuthControllerContext[UP: UserProtocol[Any], ID]:
    """Runtime dependencies shared by generated auth controller handlers."""

    backend: AuthenticationBackend[UP, ID]
    refresh_strategy: RefreshableStrategy[UP, ID] | None
    requires_verification: bool
    login_identifier: LoginIdentifier
    login_before: RequestHandler | None
    refresh_before: RequestHandler | None
    login_inc: RequestHandler
    login_reset: RequestHandler
    refresh_inc: RequestHandler
    refresh_reset: RequestHandler
    totp_pending_secret: str | None
    totp_pending_lifetime: timedelta


def _make_auth_controller_context[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    backend: AuthenticationBackend[UP, ID],
    rate_limit_config: AuthRateLimitConfig | None,
    enable_refresh: bool,
    requires_verification: bool,
    login_identifier: LoginIdentifier,
    totp_pending_secret: str | None,
    totp_pending_lifetime: timedelta,
) -> _AuthControllerContext[UP, ID]:
    """Assemble rate-limit handlers, optional refresh strategy, and TOTP settings.

    Returns:
        Frozen context passed into generated auth controller handlers.
    """
    refresh_strategy = _get_refresh_strategy(backend.strategy) if enable_refresh else None
    login_rate_limit = rate_limit_config.login if rate_limit_config else None
    refresh_rate_limit = rate_limit_config.refresh if rate_limit_config else None
    login_inc, login_reset = _create_rate_limit_handlers(login_rate_limit)
    refresh_inc, refresh_reset = _create_rate_limit_handlers(refresh_rate_limit)
    return _AuthControllerContext(
        backend=backend,
        refresh_strategy=refresh_strategy,
        requires_verification=requires_verification,
        login_identifier=login_identifier,
        login_before=_create_before_request_handler(login_rate_limit),
        refresh_before=_create_before_request_handler(refresh_rate_limit),
        login_inc=login_inc,
        login_reset=login_reset,
        refresh_inc=refresh_inc,
        refresh_reset=refresh_reset,
        totp_pending_secret=totp_pending_secret,
        totp_pending_lifetime=totp_pending_lifetime,
    )


async def _handle_auth_login[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _AuthControllerContext[UP, ID],
    user_manager: AuthControllerUserManagerProtocol[UP, ID],
) -> object:
    """Run the login pipeline: authenticate, enforce account state, optional TOTP pending, tokens.

    Returns:
        Litestar response carrying access (and optionally refresh) tokens, or a 202 pending-2FA payload.

    Raises:
        ClientException: On invalid credentials, invalid login payload, or failed account-state checks.
        ConfigurationError: When TOTP is enabled but the authenticated user model does not implement
            ``TotpUserProtocol`` (misconfiguration).
    """
    decoded = await _decode_request_body(
        request,
        schema=LoginCredentials,
        validation_detail="Invalid login payload.",
        validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
    )
    if not isinstance(decoded, LoginCredentials):
        msg = "Invalid login payload."
        raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})
    data = decoded
    resolved_identifier = _resolve_login_identifier(data.identifier, ctx.login_identifier)
    user = await user_manager.authenticate(
        resolved_identifier,
        data.password,
        login_identifier=ctx.login_identifier,
    )
    if user is None:
        await ctx.login_inc(request)
        msg = INVALID_CREDENTIALS_DETAIL
        raise ClientException(status_code=400, detail=msg, extra={"code": ErrorCode.LOGIN_BAD_CREDENTIALS})

    await _require_account_state(
        user,
        require_verified=ctx.requires_verification,
        user_manager=user_manager,
        prioritize_unverified=True,
    )

    totp_login_flow = (
        TotpLoginFlowService[TotpUserProtocol[Any], ID](
            user_manager=cast(
                "TotpFlowUserManagerProtocol[TotpUserProtocol[Any], ID]",
                user_manager,
            ),
            totp_pending_secret=ctx.totp_pending_secret,
            totp_pending_lifetime=ctx.totp_pending_lifetime,
        )
        if ctx.totp_pending_secret is not None
        else None
    )
    if totp_login_flow is not None:
        if not isinstance(user, TotpUserProtocol):
            msg = "TOTP is configured but the authenticated user does not implement TOTP fields."
            raise ConfigurationError(msg)
        pending_token = await totp_login_flow.issue_pending_token(user)
        if pending_token is not None:
            await ctx.login_reset(request)
            return Response(
                content={"totp_required": True, "pending_token": pending_token},
                status_code=202,
                media_type=MediaType.JSON,
            )

    await ctx.login_reset(request)
    response = await ctx.backend.login(user)
    await user_manager.on_after_login(user)
    if ctx.refresh_strategy is None:
        return response
    cookie_transport = ctx.backend.transport if isinstance(ctx.backend.transport, CookieTransport) else None
    return _attach_refresh_token(
        response,
        await ctx.refresh_strategy.write_refresh_token(user),
        cookie_transport=cookie_transport,
    )


async def _handle_auth_logout[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _AuthControllerContext[UP, ID],
) -> object:
    """Invalidate the session and clear refresh cookies when configured.

    Returns:
        Response from the configured backend transport.

    Raises:
        NotAuthorizedException: When no authenticated user is present on the request.
    """
    user: UP | None = request.user
    if user is None:
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)

    response = await ctx.backend.terminate_session(request, user)
    cookie_transport = ctx.backend.transport if isinstance(ctx.backend.transport, CookieTransport) else None
    if ctx.refresh_strategy is not None and cookie_transport is not None:
        cookie_transport.clear_refresh_token(response)
    return response


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

    refreshed = await refresh_strategy.rotate_refresh_token(data.refresh_token, user_manager)
    if refreshed is None:
        await ctx.refresh_inc(request)
        msg = INVALID_REFRESH_TOKEN_DETAIL
        raise ClientException(
            status_code=400,
            detail=msg,
            extra={"code": ErrorCode.REFRESH_TOKEN_INVALID},
        )

    user, rotated_refresh_token = refreshed
    try:
        await _require_account_state(
            user,
            require_verified=ctx.requires_verification,
            user_manager=user_manager,
            prioritize_unverified=True,
        )
    except ClientException:
        if isinstance(refresh_strategy, TokenInvalidationCapable):
            await refresh_strategy.invalidate_all_tokens(cast("Any", user))
        raise
    response = await ctx.backend.login(user)
    cookie_transport = ctx.backend.transport if isinstance(ctx.backend.transport, CookieTransport) else None
    await ctx.refresh_reset(request)
    return _attach_refresh_token(response, rotated_refresh_token, cookie_transport=cookie_transport)


def _define_auth_controller_class_di[UP: UserProtocol[Any], ID](
    ctx: _AuthControllerContext[UP, ID],
) -> type[Controller]:
    """Build the base auth controller with login and logout routes (DI user manager).

    Returns:
        Controller subclass implementing ``POST /login`` and ``POST /logout``.
    """

    class AuthController(Controller):
        """Backend-bound authentication endpoints."""

        @post("/login", before_request=ctx.login_before)
        async def login(
            self,
            request: Request[Any, Any, Any],
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> object:
            del self
            return await _handle_auth_login(request, ctx=ctx, user_manager=litestar_auth_user_manager)

        @post("/logout", guards=[is_authenticated])
        async def logout(self, request: Request[Any, Any, Any]) -> object:
            del self
            return await _handle_auth_logout(request, ctx=ctx)

    auth_cls = AuthController
    auth_cls.__module__ = __name__
    auth_cls.__qualname__ = auth_cls.__name__
    return auth_cls


def _define_refresh_auth_controller_class_di[UP: UserProtocol[Any], ID](
    base_cls: type[Controller],
    ctx: _AuthControllerContext[UP, ID],
) -> type[Controller]:
    """Extend the base auth controller with a refresh-token rotation route.

    Returns:
        Controller subclass adding ``POST /refresh`` to the provided base class.

    Raises:
        ConfigurationError: When the context is missing a refresh strategy.
    """
    if ctx.refresh_strategy is None:  # pragma: no cover - guarded by caller
        msg = "Refresh strategy is required."
        raise ConfigurationError(msg)

    # Dynamic controller base: erase to ``Any`` so type checkers accept the MRO (``base_cls`` is runtime-only).
    refresh_base = cast("Any", base_cls)

    class RefreshAuthController(refresh_base):
        """Backend-bound authentication endpoints with refresh-token rotation."""

        @post("/refresh", before_request=ctx.refresh_before)
        async def refresh(
            self,
            request: Request[Any, Any, Any],
            data: RefreshTokenRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> Response[Any]:
            del self
            return await _handle_auth_refresh(
                request,
                ctx=ctx,
                data=data,
                user_manager=litestar_auth_user_manager,
            )

    refresh_cls = RefreshAuthController
    refresh_cls.__module__ = __name__
    refresh_cls.__qualname__ = refresh_cls.__name__
    return refresh_cls


def create_auth_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    backend: AuthenticationBackend[UP, ID],
    rate_limit_config: AuthRateLimitConfig | None = None,
    enable_refresh: bool = False,
    requires_verification: bool = False,
    login_identifier: LoginIdentifier = "email",
    totp_pending_secret: str | None = None,
    totp_pending_lifetime: timedelta = _DEFAULT_PENDING_TOKEN_LIFETIME,
    path: str = "/auth",
) -> type[Controller]:
    """Return a controller subclass bound to the provided backend (DI user manager).

    Args:
        backend: Auth backend used to issue and invalidate tokens.
        rate_limit_config: Optional auth-endpoint rate-limiter configuration.
        enable_refresh: When ``True``, issue refresh tokens on login and add
            ``POST /refresh`` for refresh-token rotation.
        requires_verification: When ``True``, unverified users receive
            ``LOGIN_USER_NOT_VERIFIED`` (400) instead of a token.
        login_identifier: Which user attribute is used to interpret the login
            ``identifier`` field (``email`` or ``username``). Must match
            ``LitestarAuthConfig.login_identifier`` when using the plugin.
        totp_pending_secret: When set, enables 2FA support. Login returns an
            intermediate pending token when the user has TOTP configured.
            Must match the value passed to ``create_totp_controller``.
        totp_pending_lifetime: Maximum age of the intermediate pending token.
        path: Base route prefix for the generated controller.

    Returns:
        Controller subclass with backend-specific login and logout handlers.

    Examples:
        ```python
        from litestar_auth.controllers.auth import create_auth_controller

        AuthController = create_auth_controller(
            backend=backend,
            path="/auth",
        )
        ```
    """
    if totp_pending_secret is not None and not is_testing():
        validate_secret_length(totp_pending_secret, label="totp_pending_secret")
    ctx = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=rate_limit_config,
        enable_refresh=enable_refresh,
        requires_verification=requires_verification,
        login_identifier=login_identifier,
        totp_pending_secret=totp_pending_secret,
        totp_pending_lifetime=totp_pending_lifetime,
    )
    base_cls = _define_auth_controller_class_di(ctx)
    generated_controller: type[Controller] = (
        _define_refresh_auth_controller_class_di(base_cls, ctx) if ctx.refresh_strategy is not None else base_cls
    )
    generated_controller.__name__ = f"{_build_controller_name(backend.name)}AuthController"
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.path = path
    return generated_controller


def _get_refresh_strategy[UP: UserProtocol[Any], ID](strategy: object) -> RefreshableStrategy[UP, ID]:
    """Return the refresh-capable strategy or raise a configuration error.

    Raises:
        ConfigurationError: If the configured strategy does not support refresh tokens.
    """
    if isinstance(strategy, RefreshableStrategy):
        return cast("RefreshableStrategy[UP, ID]", strategy)

    msg = "enable_refresh=True requires a strategy with refresh-token support."
    raise ConfigurationError(msg)


def _attach_refresh_token(
    response: Response[Any],
    refresh_token: str,
    *,
    cookie_transport: CookieTransport | None = None,
) -> Response[Any]:
    """Merge a refresh token into the controller response payload.

    Returns:
        Response containing the existing access-token payload plus the refresh token.
    """
    if cookie_transport is not None:
        return cookie_transport.set_refresh_token(response, refresh_token)

    content = response.content
    payload = dict(content) if isinstance(content, Mapping) else {}
    payload["refresh_token"] = refresh_token
    response.content = payload
    response.media_type = MediaType.JSON
    return response


def _resolve_login_identifier(raw_identifier: str, login_identifier: LoginIdentifier) -> str:
    """Normalize and validate the login ``identifier`` for the configured mode.

    In ``email`` mode, enforces the historical email regex and max length (320).
    In ``username`` mode, enforces a stripped string length between 1 and 150.

    Returns:
        The validated identifier string (stripped in username mode).

    Raises:
        ClientException: If validation fails for the selected mode.
    """
    if login_identifier == "email":
        if len(raw_identifier) > _LOGIN_EMAIL_MAX_LENGTH or _EMAIL_PATTERN.fullmatch(raw_identifier) is None:
            msg = "Invalid login payload."
            raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})
        return raw_identifier

    stripped = raw_identifier.strip()
    if not stripped or len(stripped) > _LOGIN_USERNAME_MAX_LENGTH:
        msg = "Invalid login payload."
        raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})
    return stripped
