"""Shared scaffolding for plugin-owned controller factories."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from litestar import Controller

from litestar_auth.controllers._auth_helpers import _resolve_cookie_transport
from litestar_auth.controllers._utils import _mark_litestar_auth_route_handler
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.types import ExceptionHandlersMap

    from litestar_auth._plugin.config import StartupBackendInventory
    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.transport.cookie import CookieTransport


@dataclass(frozen=True, slots=True)
class ControllerFactoryKit[UP: UserProtocol[Any], ID]:
    """Common request-backend and generated-controller helpers for plugin factories."""

    backend_inventory: StartupBackendInventory[UP, ID]
    backend_index: int
    runtime_context_factory: Callable[[AuthenticationBackend[UP, ID]], object] | None = None

    def resolve_backend(self, request_backends: object) -> AuthenticationBackend[UP, ID]:
        """Return the request-scoped backend for this generated controller."""
        return self.backend_inventory.resolve_request_backend(request_backends, backend_index=self.backend_index)

    def runtime_context(self, request_backends: object) -> Any:  # noqa: ANN401
        """Build a runtime context from the request-scoped backend.

        Returns:
            Runtime controller context produced by ``runtime_context_factory``.

        Raises:
            RuntimeError: If no runtime context factory was configured.
        """
        if self.runtime_context_factory is None:
            msg = "runtime_context_factory is required for runtime_context()."
            raise RuntimeError(msg)
        return cast("Any", self.runtime_context_factory(self.resolve_backend(request_backends)))

    @staticmethod
    def cookie_transport(backend: AuthenticationBackend[Any, Any]) -> CookieTransport | None:
        """Return the backend cookie transport when refresh-cookie behavior is available.

        Returns:
            Cookie transport when the backend uses one, otherwise ``None``.
        """
        return _resolve_cookie_transport(cast("Any", backend))

    @staticmethod
    def controller_base(controller_cls: type[Controller]) -> Any:  # noqa: ANN401
        """Return a generated controller class as a dynamic subclass base."""
        return cast("Any", controller_cls)

    @staticmethod
    def controller_handler(controller_cls: type[Controller], handler_name: str) -> Any:  # noqa: ANN401
        """Return a generated route handler for post-definition configuration."""
        return getattr(cast("Any", controller_cls), handler_name)

    @staticmethod
    def create_controller_type(
        *,
        name: str,
        attrs: dict[str, object],
        bases: tuple[type[Controller], ...] = (Controller,),
    ) -> type[Controller]:
        """Create a generated controller subclass.

        Returns:
            Generated controller class with the provided attributes.
        """
        return type(name, bases, attrs)

    @staticmethod
    def finalize_controller(
        controller_cls: type[Controller],
        *,
        module: str,
        name: str,
        path: str,
        mark_litestar_auth: bool = True,
    ) -> type[Controller]:
        """Apply stable metadata and optionally mark a generated controller as litestar-auth owned.

        Returns:
            The finalized controller class.
        """
        controller_cls.__module__ = module
        controller_cls.__name__ = name
        controller_cls.__qualname__ = name
        controller_cls.path = path
        if mark_litestar_auth:
            return _mark_litestar_auth_route_handler(controller_cls)
        return controller_cls


def merge_exception_handlers(
    existing: ExceptionHandlersMap | None,
    extra: ExceptionHandlersMap,
) -> ExceptionHandlersMap:
    """Return exception handlers with controller-factory overrides applied last."""
    return {**(existing or {}), **extra}
