"""Factory helper kit for plugin controller assembly."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypedDict, cast

import msgspec  # noqa: TC002

from litestar_auth._plugin.config import (
    LitestarAuthConfig,
    StartupBackendInventory,
    StartupBackendTemplate,
    resolve_backend_inventory,
)
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers._utils import _build_controller_name, _mark_litestar_auth_route_handler
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

    from litestar_auth._plugin._protocols import AuthBackendProto
    from litestar_auth.authentication.backend import AuthenticationBackend


class _UserReadSchemaKwargs(TypedDict, total=False):
    """Optional read-schema kwargs accepted by controller factories."""

    user_read_schema: type[msgspec.Struct]


class _RegisterSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the register controller factory."""

    user_create_schema: type[msgspec.Struct]


class _UsersSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the users controller factory."""

    user_update_schema: type[msgspec.Struct]


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
            cookie_transport=_resolve_plugin_cookie_transport(cast("AuthBackendProto[UP, ID]", request_backend)),
        )

    generated_controller = _define_session_devices_controller_class(_build_context, security=security)
    generated_controller.__module__ = __name__
    generated_controller.__name__ = f"{_build_controller_name(backend.name)}SessionDevicesController"
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.path = config.auth_path.rstrip("/") or "/"
    return _mark_litestar_auth_route_handler(generated_controller)


def _resolve_plugin_cookie_transport[UP: UserProtocol[Any], ID](
    backend: AuthBackendProto[UP, ID],
) -> CookieTransport | None:
    """Return the backend cookie transport when refresh-cookie behavior is available."""
    transport = backend.transport
    return transport if isinstance(transport, CookieTransport) else None


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
