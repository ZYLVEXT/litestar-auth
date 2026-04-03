"""Reset-password controller factory for forgot/reset password flows."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

import msgspec  # noqa: TC002
from litestar import Controller, Request, post
from litestar.status_codes import HTTP_200_OK, HTTP_202_ACCEPTED

from litestar_auth.controllers._utils import (
    _configure_request_body_handler,
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _map_domain_exceptions,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError, InvalidResetPasswordTokenError
from litestar_auth.payloads import ForgotPassword, ResetPassword
from litestar_auth.schemas import UserRead
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth.ratelimit import AuthRateLimitConfig


class ResetPasswordControllerUserProtocol[ID](UserProtocol[ID], Protocol):
    """Protocol describing the public user fields returned after password reset."""

    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool


class ResetPasswordControllerUserManagerProtocol[UP: ResetPasswordControllerUserProtocol[Any], ID](Protocol):
    """User-manager behavior required by the reset-password controller."""

    async def forgot_password(self, email: str) -> None:
        """Generate a reset token when the provided email exists."""

    async def reset_password(self, token: str, password: str) -> UP:
        """Reset a user's password from a valid token."""


def create_reset_password_controller[UP: ResetPasswordControllerUserProtocol[Any], ID](
    *,
    rate_limit_config: AuthRateLimitConfig | None = None,
    path: str = "/auth",
    user_read_schema: type[msgspec.Struct] = UserRead,
) -> type[Controller]:
    """Return a controller subclass that resolves the user manager via Litestar DI.

    Args:
        rate_limit_config: Optional auth-endpoint rate-limiter configuration.
        path: Base route prefix for the generated controller.
        user_read_schema: Custom msgspec struct used for public reset-password responses.

    Returns:
        Controller subclass exposing reset-password endpoints.
    """
    _require_msgspec_struct(user_read_schema, parameter_name="user_read_schema")
    forgot_password_rate_limit = rate_limit_config.forgot_password if rate_limit_config else None
    reset_password_rate_limit = rate_limit_config.reset_password if rate_limit_config else None
    user_read_schema_type = user_read_schema
    forgot_password_rate_limit_before_request = _create_before_request_handler(forgot_password_rate_limit)
    reset_password_rate_limit_before_request = _create_before_request_handler(reset_password_rate_limit)

    reset_password_rate_limit_increment, reset_password_rate_limit_reset = _create_rate_limit_handlers(
        reset_password_rate_limit,
    )

    class ResetPasswordController(Controller):
        """Endpoints for password reset flows."""

        @post(
            "/forgot-password",
            status_code=HTTP_202_ACCEPTED,
            before_request=forgot_password_rate_limit_before_request,
        )
        async def forgot_password(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: ForgotPassword,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> None:
            await litestar_auth_user_manager.forgot_password(data.email)
            # Rate limit increments only after successful dispatch — intentional.
            # Counting failures would let attackers distinguish "email not found"
            # from "email sent", enabling account enumeration.
            if forgot_password_rate_limit is not None:
                await forgot_password_rate_limit.increment(request)

        @post(
            "/reset-password",
            status_code=HTTP_200_OK,
            before_request=reset_password_rate_limit_before_request,
        )
        async def reset_password(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: ResetPassword,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> msgspec.Struct:
            async def _increment_rate_limit() -> None:
                await reset_password_rate_limit_increment(request)

            async with _map_domain_exceptions(
                {
                    InvalidResetPasswordTokenError: (400, ErrorCode.RESET_PASSWORD_BAD_TOKEN),
                    InvalidPasswordError: (400, ErrorCode.RESET_PASSWORD_INVALID_PASSWORD),
                },
                on_error=_increment_rate_limit,
            ):
                user = await litestar_auth_user_manager.reset_password(data.token, data.password)

            await reset_password_rate_limit_reset(request)
            return _to_user_schema(user, user_read_schema_type)

    reset_cls = ResetPasswordController
    _configure_request_body_handler(reset_cls.reset_password, schema=ResetPassword)
    reset_cls.path = path
    return reset_cls
