"""Plugin-managed TOTP route handler assembly."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

import msgspec  # noqa: TC002
from litestar import Controller, Request, post

from litestar_auth.controllers._utils import (
    RequestBodyErrorConfig,
    RequestBodyRouteHandler,
    _configure_request_body_handler,
)
from litestar_auth.controllers.totp import (
    _totp_handle_confirm_enable,
    _totp_handle_disable,
    _totp_handle_enable,
    _totp_handle_regenerate_recovery_codes,
    _totp_handle_verify,
    _TotpControllerContext,
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

    from litestar_auth._plugin.backend_inventory import StartupBackendInventory


def _plugin_runtime_context[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    *,
    backend_inventory: StartupBackendInventory[UP, ID],
    backend_index: int,
    request_backends: object,
) -> _TotpControllerContext[UP, ID]:
    """Return request-scoped TOTP context with the resolved backend.

    Returns:
        Startup context with the runtime backend replaced for this request.
    """
    return replace(
        startup_ctx,
        runtime=replace(
            startup_ctx.runtime,
            backend=backend_inventory.resolve_request_backend(
                request_backends,
                backend_index=backend_index,
            ),
        ),
    )


def _create_plugin_totp_confirm_enable_handler[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create the plugin-owned TOTP confirmation route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/enable/confirm", guards=[is_authenticated], security=security)
    async def confirm_enable(
        self: object,
        request: Request[Any, Any, Any],
        data: TotpConfirmEnableRequest,
        litestar_auth_user_manager: Any,  # noqa: ANN401
    ) -> TotpConfirmEnableResponse:
        del self
        return await _totp_handle_confirm_enable(
            request,
            ctx=startup_ctx,
            data=data,
            user_manager=litestar_auth_user_manager,
        )

    return confirm_enable


def _create_plugin_totp_verify_handler[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    *,
    backend_inventory: StartupBackendInventory[UP, ID],
    backend_index: int,
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], object] | None,
) -> object:
    """Create the plugin-owned TOTP pending-login verification route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/verify", before_request=totp_verify_before_request)
    async def verify(
        self: object,
        request: Request[Any, Any, Any],
        data: TotpVerifyRequest,
        litestar_auth_user_manager: Any,  # noqa: ANN401
        litestar_auth_backends: Any,  # noqa: ANN401
    ) -> object:
        del self
        return await _totp_handle_verify(
            request,
            ctx=_plugin_runtime_context(
                startup_ctx,
                backend_inventory=backend_inventory,
                backend_index=backend_index,
                request_backends=litestar_auth_backends,
            ),
            data=data,
            user_manager=litestar_auth_user_manager,
        )

    return verify


def _create_plugin_totp_disable_handler[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create the plugin-owned TOTP disable route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/disable", guards=[is_authenticated], security=security)
    async def disable(
        self: object,
        request: Request[Any, Any, Any],
        data: TotpDisableRequest,
        litestar_auth_user_manager: Any,  # noqa: ANN401
    ) -> None:
        del self
        await _totp_handle_disable(
            request,
            ctx=startup_ctx,
            data=data,
            user_manager=litestar_auth_user_manager,
        )

    return disable


def _create_plugin_totp_enable_handler[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> RequestBodyRouteHandler:
    """Create the plugin-owned TOTP enable route handler with a body parameter.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/enable", guards=[is_authenticated], security=security)
    async def enable(
        self: object,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: Any,  # noqa: ANN401
        data: msgspec.Struct | None = None,
    ) -> TotpEnableResponse:
        del self
        return await _totp_handle_enable(
            request,
            ctx=startup_ctx,
            data=cast("TotpEnableRequest | None", data),
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", enable)


def _create_plugin_totp_regenerate_handler[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> RequestBodyRouteHandler:
    """Create the plugin-owned recovery-code regeneration handler with a body parameter.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/recovery-codes/regenerate", guards=[is_authenticated], security=security)
    async def regenerate_recovery_codes(
        self: object,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: Any,  # noqa: ANN401
        data: msgspec.Struct | None = None,
    ) -> TotpRecoveryCodesResponse:
        del self
        return await _totp_handle_regenerate_recovery_codes(
            request,
            ctx=startup_ctx,
            data=cast("TotpRegenerateRecoveryCodesRequest | None", data),
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", regenerate_recovery_codes)


def _create_plugin_totp_enable_no_body_handler[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create the plugin-owned TOTP enable route handler without a body parameter.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/enable", guards=[is_authenticated], security=security)
    async def enable(
        self: object,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: Any,  # noqa: ANN401
    ) -> TotpEnableResponse:
        del self
        return await _totp_handle_enable(
            request,
            ctx=startup_ctx,
            user_manager=litestar_auth_user_manager,
        )

    return enable


def _create_plugin_totp_regenerate_no_body_handler[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> object:
    """Create the plugin-owned recovery-code regeneration handler without a body parameter.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/recovery-codes/regenerate", guards=[is_authenticated], security=security)
    async def regenerate_recovery_codes(
        self: object,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: Any,  # noqa: ANN401
    ) -> TotpRecoveryCodesResponse:
        del self
        return await _totp_handle_regenerate_recovery_codes(
            request,
            ctx=startup_ctx,
            user_manager=litestar_auth_user_manager,
        )

    return regenerate_recovery_codes


def _plugin_totp_controller_attrs[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    *,
    backend_inventory: StartupBackendInventory[UP, ID],
    backend_index: int,
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], object] | None,
    security: Sequence[SecurityRequirement] | None = None,
) -> dict[str, object]:
    """Return generated plugin TOTP controller class attributes.

    Returns:
        Class attribute mapping for ``type(...)``.
    """
    return {
        "__module__": __name__,
        "__doc__": "TOTP 2FA management endpoints.",
        "confirm_enable": _create_plugin_totp_confirm_enable_handler(startup_ctx, security),
        "verify": _create_plugin_totp_verify_handler(
            startup_ctx,
            backend_inventory=backend_inventory,
            backend_index=backend_index,
            totp_verify_before_request=totp_verify_before_request,
        ),
        "disable": _create_plugin_totp_disable_handler(startup_ctx, security),
        "enable": (
            _create_plugin_totp_enable_handler(startup_ctx, security)
            if startup_ctx.security.totp_enable_requires_password
            else _create_plugin_totp_enable_no_body_handler(startup_ctx, security)
        ),
        "regenerate_recovery_codes": (
            _create_plugin_totp_regenerate_handler(startup_ctx, security)
            if startup_ctx.security.totp_enable_requires_password
            else _create_plugin_totp_regenerate_no_body_handler(startup_ctx, security)
        ),
    }


def define_plugin_totp_controller_class[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    *,
    backend_inventory: StartupBackendInventory[UP, ID],
    backend_index: int,
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], object] | None,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Build the plugin TOTP controller with request-scoped backend resolution.

    Returns:
        Controller subclass whose verify route resolves the request-scoped backend from DI.
    """
    controller_cls = type(
        "TotpController",
        (Controller,),
        _plugin_totp_controller_attrs(
            startup_ctx,
            backend_inventory=backend_inventory,
            backend_index=backend_index,
            totp_verify_before_request=totp_verify_before_request,
            security=security,
        ),
    )
    controller = cast("Any", controller_cls)

    if startup_ctx.security.totp_enable_requires_password:

        async def _on_enable_request_body_error(request: Request[Any, Any, Any]) -> None:
            await startup_ctx.runtime.rate_limit.on_invalid_attempt("enable", request)

        async def _on_regenerate_request_body_error(request: Request[Any, Any, Any]) -> None:
            await startup_ctx.runtime.rate_limit.on_invalid_attempt("regenerate_recovery_codes", request)

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

    controller_cls.__qualname__ = controller_cls.__name__
    return controller_cls
