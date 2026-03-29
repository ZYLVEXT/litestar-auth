"""Verification controller factory for email-verification flows."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Protocol, cast

import msgspec
from litestar import Controller, Request, post
from litestar.exceptions import ClientException
from litestar.status_codes import HTTP_200_OK, HTTP_202_ACCEPTED

from litestar_auth.controllers._utils import (
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.exceptions import ErrorCode, InvalidVerifyTokenError
from litestar_auth.schemas import UserRead
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth.ratelimit import AuthRateLimitConfig


class VerifyToken(msgspec.Struct):
    """Payload used to complete an email-verification flow."""

    token: Annotated[str, msgspec.Meta(min_length=1, max_length=2048)]


class RequestVerifyToken(msgspec.Struct):
    """Payload used to request a fresh email-verification token."""

    email: Annotated[
        str,
        msgspec.Meta(max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    ]


class VerifyControllerUserProtocol[ID](UserProtocol[ID], Protocol):
    """Protocol describing the public user fields returned after verification."""

    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool


class VerifyControllerUserManagerProtocol[UP: VerifyControllerUserProtocol[Any], ID](Protocol):
    """User-manager behavior required by the verify controller."""

    async def verify(self, token: str) -> UP:
        """Verify a user from the provided token."""

    async def request_verify_token(self, email: str) -> None:
        """Request a new verification token for the provided email."""


def create_verify_controller[UP: VerifyControllerUserProtocol[Any], ID](
    *,
    rate_limit_config: AuthRateLimitConfig | None = None,
    path: str = "/auth",
    user_read_schema: type[msgspec.Struct] = UserRead,
) -> type[Controller]:
    """Return a controller subclass that resolves the user manager via Litestar DI.

    Args:
        rate_limit_config: Optional auth-endpoint rate-limiter configuration. When provided,
            ``request_verify_token`` requests are subject to rate limiting.
        path: Base route prefix for the generated controller.
        user_read_schema: Custom msgspec struct used for public verification responses.

    Returns:
        Controller subclass exposing verification-related endpoints.
    """
    _require_msgspec_struct(user_read_schema, parameter_name="user_read_schema")
    user_read_schema_type = user_read_schema

    verify_rate_limit = rate_limit_config.verify_token if rate_limit_config else None
    request_verify_rate_limit = rate_limit_config.request_verify_token if rate_limit_config else None
    verify_rate_limit_before_request = _create_before_request_handler(verify_rate_limit)
    request_verify_rate_limit_before_request = _create_before_request_handler(request_verify_rate_limit)

    verify_rate_limit_increment, verify_rate_limit_reset = _create_rate_limit_handlers(verify_rate_limit)

    class VerifyController(Controller):
        """Endpoints for email verification."""

        @post(
            "/verify",
            status_code=HTTP_200_OK,
            before_request=verify_rate_limit_before_request,
        )
        async def verify(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: VerifyToken,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> msgspec.Struct:
            try:
                user = await litestar_auth_user_manager.verify(data.token)
            except InvalidVerifyTokenError as exc:
                await verify_rate_limit_increment(request)
                raise ClientException(
                    status_code=400,
                    detail=str(exc),
                    extra={"code": ErrorCode.VERIFY_USER_BAD_TOKEN},
                ) from exc

            await verify_rate_limit_reset(request)
            return _to_user_schema(user, user_read_schema_type)

        @post(
            "/request-verify-token",
            status_code=HTTP_202_ACCEPTED,
            before_request=request_verify_rate_limit_before_request,
        )
        async def request_verify_token(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: RequestVerifyToken,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> None:
            await litestar_auth_user_manager.request_verify_token(data.email)
            if request_verify_rate_limit is not None:
                await request_verify_rate_limit.increment(request)

    verify_cls = VerifyController
    verify_cls.path = path
    return cast("type[Controller]", verify_cls)
