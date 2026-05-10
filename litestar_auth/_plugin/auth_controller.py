"""Plugin-owned auth controller assembly."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast

from litestar import Controller, Request, post
from litestar.response import Response  # noqa: TC002 - Litestar resolves route annotations at runtime.

from litestar_auth._plugin._totp_controller import _resolve_request_backend
from litestar_auth.config import validate_production_secret
from litestar_auth.controllers._utils import (
    RequestBodyErrorConfig,
    RequestHandler,
    _build_controller_name,
    _create_before_request_handler,
    _create_request_body_exception_handlers,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.controllers.auth import (
    _AuthControllerSettings,
    _handle_auth_login,
    _handle_auth_logout,
    _handle_auth_refresh,
    _make_auth_controller_context,
)
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import LoginCredentials, RefreshTokenRequest  # noqa: TC001
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import ExceptionHandlersMap

    from litestar_auth._plugin.config import StartupBackendInventory, StartupBackendTemplate
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.types import LoginIdentifier


@dataclass(frozen=True, slots=True)
class PluginAuthControllerSettings[UP: UserProtocol[Any], ID]:
    """Static settings for a plugin-owned auth controller."""

    backend: StartupBackendTemplate[UP, ID]
    backend_inventory: StartupBackendInventory[UP, ID]
    backend_index: int
    rate_limit_config: AuthRateLimitConfig | None = None
    enable_refresh: bool = False
    requires_verification: bool = True
    login_identifier: LoginIdentifier = "email"
    totp_pending_secret: str | None = None
    totp_pending_lifetime: timedelta = timedelta(minutes=5)
    totp_pending_require_client_binding: bool = True
    path: str = "/auth"
    unsafe_testing: bool = False
    security: Sequence[SecurityRequirement] | None = None


@dataclass(frozen=True, slots=True)
class _PluginAuthControllerAssembly[UP: UserProtocol[Any], ID]:
    """Runtime pieces used to define a plugin-owned auth controller class."""

    settings: PluginAuthControllerSettings[UP, ID]
    login_before: RequestHandler | None
    refresh_before: RequestHandler | None
    login_exception_handlers: ExceptionHandlersMap
    build_runtime_context: Callable[[object], object]


def create_auth_controller[UP: UserProtocol[Any], ID](
    settings: PluginAuthControllerSettings[UP, ID],
) -> type[Controller]:
    """Return a plugin auth controller bound to request-scoped backends via DI."""
    if settings.totp_pending_secret is not None:
        validate_production_secret(
            settings.totp_pending_secret,
            label="totp_pending_secret",
            unsafe_testing=settings.unsafe_testing,
        )
    assembly = _build_plugin_auth_controller_assembly(settings)
    generated_controller = _define_plugin_auth_controller_class(assembly)
    if settings.enable_refresh:
        generated_controller = _define_plugin_refresh_auth_controller_class(generated_controller, assembly)

    generated_controller.__module__ = __name__
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.__name__ = f"{_build_controller_name(settings.backend.name)}AuthController"
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.path = settings.path
    return _mark_litestar_auth_route_handler(generated_controller)


def _build_plugin_auth_controller_assembly[UP: UserProtocol[Any], ID](
    settings: PluginAuthControllerSettings[UP, ID],
) -> _PluginAuthControllerAssembly[UP, ID]:
    """Assemble request handlers and runtime context builder for plugin auth routes.

    Returns:
        Controller assembly state used by class-definition helpers.
    """

    def _build_runtime_context(litestar_auth_backends: object) -> object:
        request_backend = _resolve_request_backend(
            settings.backend_inventory,
            litestar_auth_backends,
            backend_index=settings.backend_index,
        )
        return _make_auth_controller_context(
            _AuthControllerSettings(
                backend=request_backend,
                rate_limit_config=settings.rate_limit_config,
                enable_refresh=settings.enable_refresh,
                requires_verification=settings.requires_verification,
                login_identifier=settings.login_identifier,
                totp_pending_secret=settings.totp_pending_secret,
                totp_pending_lifetime=settings.totp_pending_lifetime,
                totp_pending_require_client_binding=settings.totp_pending_require_client_binding,
            ),
        )

    return _PluginAuthControllerAssembly[UP, ID](
        settings=settings,
        login_before=_create_before_request_handler(
            settings.rate_limit_config.login if settings.rate_limit_config else None,
        ),
        refresh_before=_create_before_request_handler(
            settings.rate_limit_config.refresh if settings.rate_limit_config else None,
        ),
        login_exception_handlers=_create_request_body_exception_handlers(
            RequestBodyErrorConfig(
                validation_detail="Invalid login payload.",
                validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
            ),
        ),
        build_runtime_context=_build_runtime_context,
    )


def _define_plugin_auth_controller_class[UP: UserProtocol[Any], ID](
    assembly: _PluginAuthControllerAssembly[UP, ID],
) -> type[Controller]:
    """Define the plugin auth controller without refresh-token routes.

    Returns:
        Generated controller class.
    """

    class AuthController(Controller):
        """Backend-bound authentication endpoints."""

        @post(
            "/login",
            before_request=assembly.login_before,
            exception_handlers=assembly.login_exception_handlers,
        )
        async def login(
            self,
            request: Request[Any, Any, Any],
            data: LoginCredentials,
            litestar_auth_user_manager: Any,  # noqa: ANN401
            litestar_auth_backends: Any,  # noqa: ANN401
        ) -> object:
            del self
            return await _handle_auth_login(
                request,
                data,
                ctx=cast("Any", assembly.build_runtime_context(litestar_auth_backends)),
                user_manager=litestar_auth_user_manager,
            )

        @post("/logout", guards=[is_authenticated], security=assembly.settings.security)
        async def logout(
            self,
            request: Request[Any, Any, Any],
            litestar_auth_backends: Any,  # noqa: ANN401
        ) -> object:
            del self
            return await _handle_auth_logout(
                request,
                ctx=cast("Any", assembly.build_runtime_context(litestar_auth_backends)),
            )

    return AuthController


def _define_plugin_refresh_auth_controller_class[UP: UserProtocol[Any], ID](
    base_controller: type[Controller],
    assembly: _PluginAuthControllerAssembly[UP, ID],
) -> type[Controller]:
    """Define the plugin auth controller with refresh-token routes.

    Returns:
        Generated refresh-capable controller class.
    """
    refresh_base = cast("Any", base_controller)

    class RefreshAuthController(refresh_base):
        """Backend-bound authentication endpoints with refresh-token rotation."""

        @post("/refresh", before_request=assembly.refresh_before)
        async def refresh(
            self,
            request: Request[Any, Any, Any],
            data: RefreshTokenRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
            litestar_auth_backends: Any,  # noqa: ANN401
        ) -> Response[Any]:
            del self
            return await _handle_auth_refresh(
                request,
                ctx=cast("Any", assembly.build_runtime_context(litestar_auth_backends)),
                data=data,
                user_manager=litestar_auth_user_manager,
            )

    return RefreshAuthController
