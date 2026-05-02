"""Generated route handlers for auth controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar import Controller, Request, post
from litestar.response import Response  # noqa: TC002

from litestar_auth.controllers._utils import (
    RequestBodyErrorConfig,
    _create_request_body_exception_handlers,
)
from litestar_auth.controllers.auth import (
    AuthControllerUserManagerProtocol,
    _handle_auth_login,
    _handle_auth_logout,
    _handle_auth_refresh,
)
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import LoginCredentials, RefreshTokenRequest  # noqa: TC001

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.controllers.auth import _AuthControllerContext
    from litestar_auth.types import UserProtocol


def _define_auth_controller_class_di[UP: UserProtocol[Any], ID](
    ctx: _AuthControllerContext[UP, ID],
    *,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Build the base auth controller with login and logout routes (DI user manager).

    Returns:
        Controller subclass implementing ``POST /login`` and ``POST /logout``.
    """
    login_exception_handlers = _create_request_body_exception_handlers(
        RequestBodyErrorConfig(
            validation_detail="Invalid login payload.",
            validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
        ),
    )

    class AuthController(Controller):
        """Backend-bound authentication endpoints."""

        @post(
            "/login",
            before_request=ctx.login_before,
            exception_handlers=login_exception_handlers,
        )
        async def login(
            self,
            request: Request[Any, Any, Any],
            data: LoginCredentials,
            litestar_auth_user_manager: AuthControllerUserManagerProtocol[Any, Any],
        ) -> object:
            del self
            return await _handle_auth_login(
                request,
                data,
                ctx=ctx,
                user_manager=litestar_auth_user_manager,
            )

        @post("/logout", guards=[is_authenticated], security=security)
        async def logout(self, request: Request[Any, Any, Any]) -> object:
            del self
            return await _handle_auth_logout(request, ctx=ctx)

    auth_cls = AuthController
    auth_cls.__module__ = "litestar_auth.controllers.auth"
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

    refresh_base = cast("Any", base_cls)

    class RefreshAuthController(refresh_base):
        """Backend-bound authentication endpoints with refresh-token rotation."""

        @post("/refresh", before_request=ctx.refresh_before)
        async def refresh(
            self,
            request: Request[Any, Any, Any],
            data: RefreshTokenRequest,
            litestar_auth_user_manager: AuthControllerUserManagerProtocol[Any, Any],
        ) -> Response[Any]:
            del self
            return await _handle_auth_refresh(
                request,
                ctx=ctx,
                data=data,
                user_manager=litestar_auth_user_manager,
            )

    refresh_cls = RefreshAuthController
    refresh_cls.__module__ = "litestar_auth.controllers.auth"
    refresh_cls.__qualname__ = refresh_cls.__name__
    return refresh_cls
