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

from litestar_auth.authentication.strategy.base import (
    RefreshableStrategy,
    UserManagerProtocol,
)
from litestar_auth.config import validate_production_secret
from litestar_auth.controllers._auth_helpers import (
    _attach_refresh_token,  # noqa: F401
    _get_refresh_strategy,
    _record_refresh_token_request_context,  # noqa: F401
    _resolve_cookie_transport,
    _resolve_login_identifier,  # noqa: F401
    _validate_manual_cookie_auth_contract,
)
from litestar_auth.controllers._response_timing import (
    DEFAULT_MINIMUM_RESPONSE_SECONDS,
    validate_minimum_response_seconds,
)
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    RequestHandler,
    _build_controller_name,
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.payloads import LoginCredentials, RefreshTokenRequest  # noqa: F401
from litestar_auth.totp_flow import TOTP_PENDING_AUDIENCE as _TOTP_PENDING_AUDIENCE
from litestar_auth.types import LoginIdentifier, UserProtocol

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
DEFAULT_LOGIN_MINIMUM_RESPONSE_SECONDS = DEFAULT_MINIMUM_RESPONSE_SECONDS


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
    login_minimum_response_seconds: float
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
    login_minimum_response_seconds: float = DEFAULT_LOGIN_MINIMUM_RESPONSE_SECONDS
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
    login_minimum_response_seconds: NotRequired[float]
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
    login_minimum_response_seconds: float = DEFAULT_LOGIN_MINIMUM_RESPONSE_SECONDS


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
        login_minimum_response_seconds=validate_minimum_response_seconds(
            settings.login_minimum_response_seconds,
            field_name="login_minimum_response_seconds",
        ),
        totp_pending_client_binding_trusted_proxy=(
            False if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_proxy
        ),
        totp_pending_client_binding_trusted_headers=(
            ("X-Forwarded-For",) if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_headers
        ),
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


from litestar_auth.controllers._auth_login import _handle_auth_login  # noqa: E402, F401
from litestar_auth.controllers._auth_refresh import _handle_auth_refresh  # noqa: E402, F401
from litestar_auth.controllers._auth_routes import (  # noqa: E402
    _define_auth_controller_class_di,
    _define_refresh_auth_controller_class_di,
)


@overload
def create_auth_controller[UP: UserProtocol[Any], ID](
    *,
    config: AuthControllerConfig[UP, ID],
) -> type[Controller]:
    pass  # pragma: no cover


@overload
def create_auth_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[AuthControllerOptions[UP, ID]],
) -> type[Controller]:
    pass  # pragma: no cover


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
    if settings.totp_pending_secret is not None:
        validate_production_secret(
            settings.totp_pending_secret,
            label="totp_pending_secret",
            unsafe_testing=settings.unsafe_testing,
        )
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
            login_minimum_response_seconds=settings.login_minimum_response_seconds,
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
