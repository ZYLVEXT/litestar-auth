"""Authentication controller factory for backend-bound login/logout routes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import (
    TYPE_CHECKING,
    Any,
    NotRequired,
    Protocol,
    Required,
    TypedDict,
    Unpack,
    cast,
    overload,
    runtime_checkable,
)

from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.response import Response

from litestar_auth.authentication.strategy.base import (
    RefreshableStrategy,
    TokenInvalidationCapable,
    UserManagerProtocol,
)
from litestar_auth.config import validate_secret_length
from litestar_auth.controllers._auth_helpers import (
    _LOGIN_EMAIL_MAX_LENGTH as _AUTH_LOGIN_EMAIL_MAX_LENGTH,
)
from litestar_auth.controllers._auth_helpers import (
    _LOGIN_USERNAME_MAX_LENGTH as _AUTH_LOGIN_USERNAME_MAX_LENGTH,
)
from litestar_auth.controllers._auth_helpers import (
    _attach_refresh_token,
    _get_refresh_strategy,
    _resolve_cookie_transport,
    _resolve_login_identifier,
    _validate_manual_cookie_auth_contract,
)
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    RequestHandler,
    _build_controller_name,
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _mark_litestar_auth_route_handler,
    _require_account_state,
)
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.payloads import LoginCredentials, RefreshTokenRequest  # noqa: TC001
from litestar_auth.totp_flow import TOTP_PENDING_AUDIENCE as _TOTP_PENDING_AUDIENCE
from litestar_auth.totp_flow import (
    TotpFlowUserManagerProtocol,
    TotpLoginFlowConfig,
    TotpLoginFlowService,
    build_pending_totp_client_binding,
)
from litestar_auth.types import LoginIdentifier, TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar import Controller, Request
    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.ratelimit import AuthRateLimitConfig

INVALID_CREDENTIALS_DETAIL = "Invalid credentials."
INVALID_REFRESH_TOKEN_DETAIL = "The refresh token is invalid."  # noqa: S105
TOTP_PENDING_AUDIENCE = _TOTP_PENDING_AUDIENCE
_DEFAULT_PENDING_TOKEN_LIFETIME = timedelta(minutes=5)
_LOGIN_EMAIL_MAX_LENGTH = _AUTH_LOGIN_EMAIL_MAX_LENGTH
_LOGIN_USERNAME_MAX_LENGTH = _AUTH_LOGIN_USERNAME_MAX_LENGTH


@runtime_checkable
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
    totp_pending_require_client_binding: bool
    totp_pending_client_binding_trusted_proxy: bool
    totp_pending_client_binding_trusted_headers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthControllerConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :func:`create_auth_controller`."""

    backend: AuthenticationBackend[UP, ID]
    rate_limit_config: AuthRateLimitConfig | None = None
    enable_refresh: bool = False
    requires_verification: bool = True
    login_identifier: LoginIdentifier = "email"
    totp_pending_secret: str | None = None
    totp_pending_lifetime: timedelta = _DEFAULT_PENDING_TOKEN_LIFETIME
    totp_pending_require_client_binding: bool = True
    path: str = "/auth"
    unsafe_testing: bool = False
    csrf_protection_managed_externally: bool = False
    security: Sequence[SecurityRequirement] | None = None


class AuthControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :func:`create_auth_controller`."""

    backend: Required[AuthenticationBackend[UP, ID]]
    rate_limit_config: NotRequired[AuthRateLimitConfig | None]
    enable_refresh: NotRequired[bool]
    requires_verification: NotRequired[bool]
    login_identifier: NotRequired[LoginIdentifier]
    totp_pending_secret: NotRequired[str | None]
    totp_pending_lifetime: NotRequired[timedelta]
    totp_pending_require_client_binding: NotRequired[bool]
    path: NotRequired[str]
    unsafe_testing: NotRequired[bool]
    csrf_protection_managed_externally: NotRequired[bool]
    security: NotRequired[Sequence[SecurityRequirement] | None]


@dataclass(frozen=True, slots=True)
class _AuthControllerSettings[UP: UserProtocol[Any], ID]:
    """Static settings used to assemble generated auth controller context."""

    backend: AuthenticationBackend[UP, ID]
    rate_limit_config: AuthRateLimitConfig | None
    enable_refresh: bool
    requires_verification: bool
    login_identifier: LoginIdentifier
    totp_pending_secret: str | None
    totp_pending_lifetime: timedelta
    totp_pending_require_client_binding: bool = True


def _make_auth_controller_context[UP: UserProtocol[Any], ID](
    settings: _AuthControllerSettings[UP, ID],
) -> _AuthControllerContext[UP, ID]:
    """Assemble rate-limit handlers, optional refresh strategy, and TOTP settings.

    Returns:
        Frozen context passed into generated auth controller handlers.
    """
    refresh_strategy = _get_refresh_strategy(settings.backend.strategy) if settings.enable_refresh else None
    login_rate_limit = settings.rate_limit_config.login if settings.rate_limit_config else None
    refresh_rate_limit = settings.rate_limit_config.refresh if settings.rate_limit_config else None
    totp_verify_rate_limit = settings.rate_limit_config.totp_verify if settings.rate_limit_config else None
    login_inc, login_reset = _create_rate_limit_handlers(login_rate_limit)
    refresh_inc, refresh_reset = _create_rate_limit_handlers(refresh_rate_limit)
    return _AuthControllerContext(
        backend=settings.backend,
        refresh_strategy=refresh_strategy,
        requires_verification=settings.requires_verification,
        login_identifier=settings.login_identifier,
        login_before=_create_before_request_handler(login_rate_limit),
        refresh_before=_create_before_request_handler(refresh_rate_limit),
        login_inc=login_inc,
        login_reset=login_reset,
        refresh_inc=refresh_inc,
        refresh_reset=refresh_reset,
        totp_pending_secret=settings.totp_pending_secret,
        totp_pending_lifetime=settings.totp_pending_lifetime,
        totp_pending_require_client_binding=settings.totp_pending_require_client_binding,
        totp_pending_client_binding_trusted_proxy=(
            False if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_proxy
        ),
        totp_pending_client_binding_trusted_headers=(
            ("X-Forwarded-For",) if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_headers
        ),
    )


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
    user = await _authenticate_login_request(request, data, ctx=ctx, user_manager=user_manager)
    await _require_account_state(
        user,
        require_verified=ctx.requires_verification,
        user_manager=user_manager,
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

    Raises:
        ClientException: On invalid credentials or invalid login payload.
    """
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
    cookie_transport = _resolve_cookie_transport(ctx.backend)
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

    """
    # Litestar does not narrow ``Request.user`` to ``UP``; this handler is mounted behind ``is_authenticated``.
    user = cast("UP", request.user)
    response = await ctx.backend.terminate_session(request, user)
    cookie_transport = _resolve_cookie_transport(ctx.backend)
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
        )
    except ClientException:
        if isinstance(refresh_strategy, TokenInvalidationCapable):
            await refresh_strategy.invalidate_all_tokens(cast("Any", user))
        raise
    response = await ctx.backend.login(user)
    cookie_transport = _resolve_cookie_transport(ctx.backend)
    await ctx.refresh_reset(request)
    return _attach_refresh_token(response, rotated_refresh_token, cookie_transport=cookie_transport)


from litestar_auth.controllers._auth_routes import (  # noqa: E402
    _define_auth_controller_class_di,
    _define_refresh_auth_controller_class_di,
)


@overload
def create_auth_controller[UP: UserProtocol[Any], ID](
    *,
    config: AuthControllerConfig[UP, ID],
) -> type[Controller]: ...  # pragma: no cover


@overload
def create_auth_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[AuthControllerOptions[UP, ID]],
) -> type[Controller]: ...  # pragma: no cover


def create_auth_controller[UP: UserProtocol[Any], ID](
    *,
    config: AuthControllerConfig[UP, ID] | None = None,
    **options: Unpack[AuthControllerOptions[UP, ID]],
) -> type[Controller]:
    """Return a controller subclass bound to the provided backend (DI user manager).

    Args:
        config: Auth controller configuration.
        **options: Individual auth controller settings. Do not combine with
            ``config``.

    Returns:
        Controller subclass with backend-specific login and logout handlers.

    Raises:
        ValueError: If ``config`` and keyword options are combined.
    """
    if config is not None and options:
        msg = "Pass either AuthControllerConfig or keyword options, not both."
        raise ValueError(msg)
    settings = AuthControllerConfig(**options) if config is None else config

    _validate_manual_cookie_auth_contract(
        settings.backend,
        csrf_protection_managed_externally=settings.csrf_protection_managed_externally,
        unsafe_testing=settings.unsafe_testing,
    )
    if settings.totp_pending_secret is not None and not settings.unsafe_testing:
        validate_secret_length(settings.totp_pending_secret, label="totp_pending_secret")
    ctx = _make_auth_controller_context(
        _AuthControllerSettings(
            backend=settings.backend,
            rate_limit_config=settings.rate_limit_config,
            enable_refresh=settings.enable_refresh,
            requires_verification=settings.requires_verification,
            login_identifier=settings.login_identifier,
            totp_pending_secret=settings.totp_pending_secret,
            totp_pending_lifetime=settings.totp_pending_lifetime,
            totp_pending_require_client_binding=settings.totp_pending_require_client_binding,
        ),
    )
    base_cls = _define_auth_controller_class_di(ctx, security=settings.security)
    generated_controller: type[Controller] = (
        _define_refresh_auth_controller_class_di(base_cls, ctx) if ctx.refresh_strategy is not None else base_cls
    )
    generated_controller.__name__ = f"{_build_controller_name(settings.backend.name)}AuthController"
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.path = settings.path
    return _mark_litestar_auth_route_handler(generated_controller)
