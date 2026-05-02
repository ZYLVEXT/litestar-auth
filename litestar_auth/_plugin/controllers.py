"""Controller assembly helpers for the auth plugin façade."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, TypedDict, cast

import msgspec  # noqa: TC002
from litestar import Controller, Request, post
from litestar.response import Response  # noqa: TC002

from litestar_auth._plugin._oauth_controllers import (
    _append_oauth_associate_controllers,
    _append_oauth_login_controllers,
    create_oauth_associate_controller,
    create_oauth_login_controller,
)
from litestar_auth._plugin._totp_controller import (
    _resolve_request_backend,
    build_totp_controller,
    create_totp_controller,
    totp_backend,
    totp_path,
)
from litestar_auth._plugin.config import (
    LitestarAuthConfig,
    StartupBackendInventory,
    StartupBackendTemplate,
    require_session_maker,
    resolve_backend_inventory,
)
from litestar_auth.config import validate_secret_length
from litestar_auth.controllers import (
    create_register_controller,
    create_reset_password_controller,
    create_users_controller,
    create_verify_controller,
)
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
    from litestar.types import ControllerRouterHandler, ExceptionHandlersMap

    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.types import LoginIdentifier

__all__ = (
    "build_controllers",
    "build_totp_controller",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_login_controller",
    "create_totp_controller",
    "totp_backend",
    "totp_path",
)


class _UserReadSchemaKwargs(TypedDict, total=False):
    """Optional read-schema kwargs accepted by controller factories."""

    user_read_schema: type[msgspec.Struct]


class _RegisterSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the register controller factory."""

    user_create_schema: type[msgspec.Struct]


class _UsersSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the users controller factory."""

    user_update_schema: type[msgspec.Struct]


@dataclass(frozen=True, slots=True)
class _PluginAuthControllerSettings[UP: UserProtocol[Any], ID]:
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

    settings: _PluginAuthControllerSettings[UP, ID]
    login_before: RequestHandler | None
    refresh_before: RequestHandler | None
    login_exception_handlers: ExceptionHandlersMap
    build_runtime_context: Callable[[object], object]


def create_auth_controller[UP: UserProtocol[Any], ID](
    settings: _PluginAuthControllerSettings[UP, ID],
) -> type[Controller]:
    """Return a plugin auth controller bound to request-scoped backends via DI."""
    if settings.totp_pending_secret is not None and not settings.unsafe_testing:
        validate_secret_length(settings.totp_pending_secret, label="totp_pending_secret")
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
    settings: _PluginAuthControllerSettings[UP, ID],
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
    # Dynamic controller base: erase to ``Any`` so type checkers accept the MRO (``base_controller`` is runtime-only).
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


def build_controllers[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    security: Sequence[SecurityRequirement] | None = None,
) -> list[ControllerRouterHandler]:
    """Build the controller set for the configured plugin surface.

    Returns:
        Controllers matching the enabled auth features.
    """
    backend_inventory = resolve_backend_inventory(config)
    controllers = _build_auth_controllers(config=config, backend_inventory=backend_inventory, security=security)
    _append_optional_feature_controllers(
        controllers=controllers,
        config=config,
        backend_inventory=backend_inventory,
        security=security,
    )
    return controllers


def _build_auth_controllers[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: StartupBackendInventory[UP, ID] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> list[ControllerRouterHandler]:
    """Build mandatory auth controllers per configured backend.

    Returns:
        Auth controllers corresponding to configured backends.
    """
    controllers: list[ControllerRouterHandler] = []
    require_session_maker(config)
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    for backend_index, backend in enumerate(inventory.startup_backends()):
        totp_pending_secret = config.totp_config.totp_pending_secret if config.totp_config is not None else None
        controllers.append(
            create_auth_controller(
                _PluginAuthControllerSettings(
                    backend=backend,
                    backend_inventory=inventory,
                    backend_index=backend_index,
                    rate_limit_config=config.rate_limit_config,
                    enable_refresh=config.enable_refresh,
                    requires_verification=config.requires_verification,
                    login_identifier=config.login_identifier,
                    totp_pending_secret=totp_pending_secret,
                    totp_pending_require_client_binding=(
                        True if config.totp_config is None else config.totp_config.totp_pending_require_client_binding
                    ),
                    path=backend_auth_path(
                        auth_path=config.auth_path,
                        backend_name=backend.name,
                        index=backend_index,
                    ),
                    unsafe_testing=config.unsafe_testing,
                    security=security,
                ),
            ),
        )
    return controllers


def _append_optional_feature_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: StartupBackendInventory[UP, ID] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> None:
    """Append optional controllers enabled by plugin flags."""
    if config.include_register:
        controllers.append(
            create_register_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                register_minimum_response_seconds=config.register_minimum_response_seconds,
                unsafe_testing=config.unsafe_testing,
                **register_schema_kwargs(config),
            ),
        )
    if config.include_verify:
        controllers.append(
            create_verify_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                unsafe_testing=config.unsafe_testing,
                **user_read_schema_kwargs(config),
            ),
        )
    if config.include_reset_password:
        controllers.append(
            create_reset_password_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                unsafe_testing=config.unsafe_testing,
                **user_read_schema_kwargs(config),
            ),
        )
    if config.include_users:
        controllers.append(
            create_users_controller(
                id_parser=config.id_parser,
                rate_limit_config=config.rate_limit_config,
                path=config.users_path,
                hard_delete=config.hard_delete,
                unsafe_testing=config.unsafe_testing,
                security=security,
                **users_schema_kwargs(config),
            ),
        )
    if config.totp_config is not None:
        controllers.append(build_totp_controller(config, backend_inventory=backend_inventory, security=security))
    _append_oauth_login_controllers(
        controllers=controllers,
        config=config,
        backend_inventory=backend_inventory,
    )
    _append_oauth_associate_controllers(controllers=controllers, config=config, security=security)


def user_read_schema_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _UserReadSchemaKwargs:
    """Return non-null read-schema kwargs for controller factories."""
    result: _UserReadSchemaKwargs = {}
    if config.user_read_schema is not None:
        result["user_read_schema"] = config.user_read_schema
    return result


def register_schema_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _RegisterSchemaKwargs:
    """Return non-null register-schema kwargs for controller factories."""
    result: _RegisterSchemaKwargs = {}
    if config.user_read_schema is not None:
        result["user_read_schema"] = config.user_read_schema
    if config.user_create_schema is not None:
        result["user_create_schema"] = config.user_create_schema
    return result


def users_schema_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _UsersSchemaKwargs:
    """Return non-null users-schema kwargs for controller factories."""
    result: _UsersSchemaKwargs = {}
    if config.user_read_schema is not None:
        result["user_read_schema"] = config.user_read_schema
    if config.user_update_schema is not None:
        result["user_update_schema"] = config.user_update_schema
    return result


def backend_auth_path(*, auth_path: str, backend_name: str, index: int) -> str:
    """Return the public auth path for a backend-specific controller."""
    base_path = auth_path.rstrip("/") or "/"
    if index == 0:
        return base_path

    return f"{base_path}/{backend_name}"
