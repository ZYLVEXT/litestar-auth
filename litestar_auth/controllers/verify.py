"""Verification controller factory for email-verification flows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import msgspec  # noqa: TC002
from litestar import Controller, Request, post
from litestar.exceptions import ClientException
from litestar.status_codes import HTTP_200_OK, HTTP_202_ACCEPTED

from litestar_auth.controllers._utils import (
    RequestHandler,
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _mark_litestar_auth_route_handler,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.exceptions import ErrorCode, InvalidVerifyTokenError
from litestar_auth.payloads import RequestVerifyToken, VerifyToken  # noqa: TC001
from litestar_auth.schemas import UserRead
from litestar_auth.types import RoleCapableUserProtocol

if TYPE_CHECKING:
    from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit


class VerifyControllerUserProtocol[ID](RoleCapableUserProtocol[ID], Protocol):
    """Protocol describing the public user fields returned after verification."""

    email: str
    is_active: bool
    is_verified: bool


@runtime_checkable
class VerifyControllerUserManagerProtocol[UP: VerifyControllerUserProtocol[Any], ID](Protocol):
    """User-manager behavior required by the verify controller."""

    async def verify(self, token: str) -> UP:
        """Verify a user from the provided token."""

    async def request_verify_token(self, email: str) -> None:
        """Request a new verification token for the provided email."""


@dataclass(frozen=True, slots=True)
class _VerifyControllerContext:
    """Runtime settings captured by generated verification handlers."""

    user_read_schema: type[msgspec.Struct]
    unsafe_testing: bool
    verify_before_request: RequestHandler | None
    request_verify_before_request: RequestHandler | None
    verify_increment: RequestHandler
    verify_reset: RequestHandler
    request_verify_rate_limit: EndpointRateLimit | None


def create_verify_controller[UP: VerifyControllerUserProtocol[Any], ID](
    *,
    rate_limit_config: AuthRateLimitConfig | None = None,
    path: str = "/auth",
    user_read_schema: type[msgspec.Struct] = UserRead,
    unsafe_testing: bool = False,
) -> type[Controller]:
    """Return a controller subclass that resolves the user manager via Litestar DI.

    Args:
        rate_limit_config: Optional auth-endpoint rate-limiter configuration. When provided,
            ``request_verify_token`` requests are subject to rate limiting.
        path: Base route prefix for the generated controller.
        user_read_schema: Custom msgspec struct used for public verification responses.
        unsafe_testing: Explicit test-only override that allows response
            schemas with sensitive fields for isolated fixtures.

    Returns:
        Controller subclass exposing verification-related endpoints.
    """
    _require_msgspec_struct(user_read_schema, parameter_name="user_read_schema")
    verify_rate_limit = rate_limit_config.verify_token if rate_limit_config else None
    request_verify_rate_limit = rate_limit_config.request_verify_token if rate_limit_config else None
    verify_rate_limit_increment, verify_rate_limit_reset = _create_rate_limit_handlers(verify_rate_limit)
    verify_cls = _define_verify_controller_class(
        _VerifyControllerContext(
            user_read_schema=user_read_schema,
            unsafe_testing=unsafe_testing,
            verify_before_request=_create_before_request_handler(verify_rate_limit),
            request_verify_before_request=_create_before_request_handler(request_verify_rate_limit),
            verify_increment=verify_rate_limit_increment,
            verify_reset=verify_rate_limit_reset,
            request_verify_rate_limit=request_verify_rate_limit,
        ),
    )
    verify_cls.path = path
    return _mark_litestar_auth_route_handler(verify_cls)


def _define_verify_controller_class(ctx: _VerifyControllerContext) -> type[Controller]:
    class VerifyController(Controller):
        """Endpoints for email verification."""

        @post("/verify", status_code=HTTP_200_OK, before_request=ctx.verify_before_request)
        async def verify(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: VerifyToken,
            litestar_auth_user_manager: VerifyControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            try:
                user = await litestar_auth_user_manager.verify(data.token)
            except InvalidVerifyTokenError as exc:
                await ctx.verify_increment(request)
                raise ClientException(
                    status_code=400,
                    detail="The email verification token is invalid.",
                    extra={"code": ErrorCode.VERIFY_USER_BAD_TOKEN},
                ) from exc

            await ctx.verify_reset(request)
            return _to_user_schema(user, ctx.user_read_schema, unsafe_testing=ctx.unsafe_testing)

        @post("/request-verify-token", status_code=HTTP_202_ACCEPTED, before_request=ctx.request_verify_before_request)
        async def request_verify_token(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: RequestVerifyToken,
            litestar_auth_user_manager: VerifyControllerUserManagerProtocol[Any, Any],
        ) -> None:
            await litestar_auth_user_manager.request_verify_token(data.email)
            if ctx.request_verify_rate_limit is not None:
                await ctx.request_verify_rate_limit.increment(request)

    verify_cls = VerifyController
    verify_cls.__module__ = __name__
    verify_cls.__qualname__ = verify_cls.__name__
    return verify_cls
