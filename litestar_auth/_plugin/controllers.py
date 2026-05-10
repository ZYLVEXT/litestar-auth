"""Controller assembly helpers for the auth plugin façade."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypedDict, cast

import msgspec  # noqa: TC002

from litestar_auth._plugin._oauth_controllers import (
    _append_oauth_associate_controllers,
    _append_oauth_login_controllers,
    create_oauth_associate_controller,
    create_oauth_login_controller,
)
from litestar_auth._plugin._totp_controller import (
    build_totp_controller,
    create_totp_controller,
    totp_backend,
    totp_path,
)
from litestar_auth._plugin.auth_controller import PluginAuthControllerSettings, create_auth_controller
from litestar_auth._plugin.config import (
    LitestarAuthConfig,
    StartupBackendInventory,
    StartupBackendTemplate,
    require_session_maker,
    resolve_backend_inventory,
)
from litestar_auth.authentication.transport.api_key import ApiKeyTransport
from litestar_auth.controllers import (
    create_api_keys_controllers,
    create_register_controller,
    create_reset_password_controller,
    create_users_controller,
    create_verify_controller,
)
from litestar_auth.controllers._auth_helpers import _resolve_cookie_transport
from litestar_auth.controllers._utils import (
    _build_controller_name,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.controllers.session_devices import (
    _define_session_devices_controller_class,
    _require_session_management_strategy,
    _SessionDevicesControllerContext,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar import Controller
    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import ControllerRouterHandler

    from litestar_auth.authentication.backend import AuthenticationBackend

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
        if isinstance(backend.transport, ApiKeyTransport):
            continue
        totp_pending_secret = config.totp_config.totp_pending_secret if config.totp_config is not None else None
        controllers.append(
            create_auth_controller(
                PluginAuthControllerSettings(
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
    _append_account_feature_controllers(controllers=controllers, config=config, security=security)
    _append_session_feature_controllers(
        controllers=controllers,
        config=config,
        backend_inventory=backend_inventory,
        security=security,
    )
    _append_oauth_login_controllers(
        controllers=controllers,
        config=config,
        backend_inventory=backend_inventory,
    )
    _append_oauth_associate_controllers(controllers=controllers, config=config, security=security)


def _append_account_feature_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
    security: Sequence[SecurityRequirement] | None,
) -> None:
    """Append optional account-management controllers."""
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


def _append_session_feature_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: StartupBackendInventory[UP, ID] | None,
    security: Sequence[SecurityRequirement] | None,
) -> None:
    """Append optional session, API-key, and TOTP controllers."""
    if config.include_session_devices:
        controllers.append(
            create_session_devices_controller(
                config=config,
                backend_inventory=backend_inventory,
                security=security,
            ),
        )
    if config.api_keys.enabled:
        controllers.extend(
            create_api_keys_controllers(
                id_parser=config.id_parser,
                rate_limit_config=config.rate_limit_config,
                security=security,
                users_path=config.users_path,
                require_step_up_on_create=config.api_keys.require_step_up_on_create,
                signing_enabled=config.api_keys.signing_enabled,
            ),
        )
    if config.totp_config is not None:
        controllers.append(build_totp_controller(config, backend_inventory=backend_inventory, security=security))


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


def create_session_devices_controller[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: StartupBackendInventory[UP, ID] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Return the plugin-owned session/device management controller."""
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    backend_index, backend = inventory.primary()

    def _build_context(request_backends: object | None = None) -> _SessionDevicesControllerContext[UP]:
        request_backend = _resolve_session_devices_request_backend(
            inventory,
            backend,
            backend_index=backend_index,
            litestar_auth_backends=request_backends,
        )
        return _SessionDevicesControllerContext(
            _require_session_management_strategy(request_backend.strategy),
            cookie_transport=_resolve_cookie_transport(cast("Any", request_backend)),
        )

    generated_controller = _define_session_devices_controller_class(_build_context, security=security)
    generated_controller.__module__ = __name__
    generated_controller.__name__ = f"{_build_controller_name(backend.name)}SessionDevicesController"
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.path = config.auth_path.rstrip("/") or "/"
    return _mark_litestar_auth_route_handler(generated_controller)


def _resolve_session_devices_request_backend[UP: UserProtocol[Any], ID](
    inventory: StartupBackendInventory[UP, ID],
    startup_backend: StartupBackendTemplate[UP, ID],
    *,
    backend_index: int,
    litestar_auth_backends: object | None,
) -> AuthenticationBackend[UP, ID] | StartupBackendTemplate[UP, ID]:
    """Return a request-scoped backend when DI supplied one, otherwise the startup backend."""
    if litestar_auth_backends is None:
        return startup_backend
    return inventory.resolve_request_backend(litestar_auth_backends, backend_index=backend_index)
