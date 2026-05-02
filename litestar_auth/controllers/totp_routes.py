"""Generated route-handler assembly for TOTP controllers."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, cast

import msgspec  # noqa: TC002
from litestar import Controller, Request, post

from litestar_auth.controllers._utils import (
    RequestBodyErrorConfig,
    RequestBodyRouteHandler,
    _configure_request_body_handler,
)
from litestar_auth.controllers.totp_contracts import TotpUserManagerProtocol  # noqa: TC001
from litestar_auth.controllers.totp_handlers import (
    _totp_handle_confirm_enable,
    _totp_handle_enable,
)
from litestar_auth.controllers.totp_session_handlers import (
    _totp_handle_disable,
    _totp_handle_regenerate_recovery_codes,
    _totp_handle_verify,
)
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import (
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpEnableResponse,
    TotpRecoveryCodesResponse,
    TotpRegenerateRecoveryCodesRequest,
    TotpVerifyRequest,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.controllers.totp_context import _TotpControllerContext


def _remove_request_body_handler_data_parameter(route_handler: RequestBodyRouteHandler) -> None:
    """Remove ``data`` from a handler signature when no request body is accepted."""
    handler_fn = route_handler.fn
    signature = inspect.signature(handler_fn)
    adapted_handler = cast("Any", handler_fn)
    adapted_handler.__signature__ = inspect.Signature(
        parameters=[parameter for parameter in signature.parameters.values() if parameter.name != "data"],
        return_annotation=signature.return_annotation,
    )
    adapted_handler.__annotations__ = {
        key: value for key, value in getattr(handler_fn, "__annotations__", {}).items() if key != "data"
    }


def _create_totp_enable_handler[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> RequestBodyRouteHandler:
    """Create the TOTP enable route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/enable", guards=[is_authenticated], security=security)
    async def enable(
        self: object,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: TotpUserManagerProtocol[Any, Any],
        data: msgspec.Struct | None = None,
    ) -> TotpEnableResponse:
        del self
        return await _totp_handle_enable(
            request,
            ctx=ctx,
            data=cast("TotpEnableRequest | None", data),
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", enable)


def _create_totp_confirm_enable_handler[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create the TOTP enrollment confirmation route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/enable/confirm", guards=[is_authenticated], security=security)
    async def confirm_enable(
        self: object,
        request: Request[Any, Any, Any],
        data: TotpConfirmEnableRequest,
        litestar_auth_user_manager: TotpUserManagerProtocol[Any, Any],
    ) -> TotpConfirmEnableResponse:
        del self
        return await _totp_handle_confirm_enable(
            request,
            ctx=ctx,
            data=data,
            user_manager=litestar_auth_user_manager,
        )

    return confirm_enable


def _create_totp_verify_handler[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], Any] | None,
) -> object:
    """Create the pending-login TOTP verification route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/verify", before_request=totp_verify_before_request)
    async def verify(
        self: object,
        request: Request[Any, Any, Any],
        data: TotpVerifyRequest,
        litestar_auth_user_manager: TotpUserManagerProtocol[Any, Any],
    ) -> object:
        del self
        return await _totp_handle_verify(
            request,
            ctx=ctx,
            data=data,
            user_manager=litestar_auth_user_manager,
        )

    return verify


def _create_totp_disable_handler[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create the TOTP disable route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/disable", guards=[is_authenticated], security=security)
    async def disable(
        self: object,
        request: Request[Any, Any, Any],
        data: TotpDisableRequest,
        litestar_auth_user_manager: TotpUserManagerProtocol[Any, Any],
    ) -> None:
        del self
        await _totp_handle_disable(
            request,
            ctx=ctx,
            data=data,
            user_manager=litestar_auth_user_manager,
        )

    return disable


def _create_totp_regenerate_recovery_codes_handler[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> RequestBodyRouteHandler:
    """Create the TOTP recovery-code regeneration route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/recovery-codes/regenerate", guards=[is_authenticated], security=security)
    async def regenerate_recovery_codes(
        self: object,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: TotpUserManagerProtocol[Any, Any],
        data: msgspec.Struct | None = None,
    ) -> TotpRecoveryCodesResponse:
        del self
        return await _totp_handle_regenerate_recovery_codes(
            request,
            ctx=ctx,
            data=cast("TotpRegenerateRecoveryCodesRequest | None", data),
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", regenerate_recovery_codes)


def _create_totp_controller_type[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    *,
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], Any] | None,
    security: Sequence[SecurityRequirement] | None,
) -> type[Controller]:
    """Create the generated TOTP controller class.

    Returns:
        Controller subclass with decorated route handlers attached.
    """
    controller_cls = type(
        "TotpController",
        (Controller,),
        {
            "__module__": "litestar_auth.controllers.totp",
            "__doc__": "TOTP 2FA management endpoints.",
            "enable": _create_totp_enable_handler(ctx, security),
            "confirm_enable": _create_totp_confirm_enable_handler(ctx, security),
            "verify": _create_totp_verify_handler(ctx, totp_verify_before_request),
            "disable": _create_totp_disable_handler(ctx, security),
            "regenerate_recovery_codes": _create_totp_regenerate_recovery_codes_handler(ctx, security),
        },
    )
    controller_cls.__qualname__ = controller_cls.__name__
    return controller_cls


def _define_totp_controller_class_di[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    *,
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], Any] | None,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Build the TOTP controller with enable, confirm, verify, and disable routes (DI user manager).

    Returns:
        Controller subclass exposing ``/enable``, ``/enable/confirm``, ``/verify``,
        and ``/disable`` routes.
    """
    controller_cls = _create_totp_controller_type(
        ctx,
        totp_verify_before_request=totp_verify_before_request,
        security=security,
    )
    controller = cast("Any", controller_cls)

    if ctx.security.totp_enable_requires_password:

        async def _on_enable_request_body_error(request: Request[Any, Any, Any]) -> None:
            await ctx.runtime.rate_limit.on_invalid_attempt("enable", request)

        async def _on_regenerate_request_body_error(request: Request[Any, Any, Any]) -> None:
            await ctx.runtime.rate_limit.on_invalid_attempt("regenerate_recovery_codes", request)

        _configure_request_body_handler(
            controller.enable,
            schema=TotpEnableRequest,
            error_config=RequestBodyErrorConfig(
                validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
                on_validation_error=_on_enable_request_body_error,
                on_decode_error=_on_enable_request_body_error,
            ),
        )
        _configure_request_body_handler(
            controller.regenerate_recovery_codes,
            schema=TotpRegenerateRecoveryCodesRequest,
            error_config=RequestBodyErrorConfig(
                validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
                on_validation_error=_on_regenerate_request_body_error,
                on_decode_error=_on_regenerate_request_body_error,
            ),
        )
    else:
        _remove_request_body_handler_data_parameter(controller.enable)
        _remove_request_body_handler_data_parameter(controller.regenerate_recovery_codes)

    return controller_cls
