"""Plugin customization hook protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from litestar.connection import Request
    from litestar.middleware import DefineMiddleware
    from litestar.response import Response
    from litestar.types import ControllerRouterHandler

    from litestar_auth.exceptions import LitestarAuthError


class ExceptionResponseHook(Protocol):
    """Format plugin-owned auth errors as Litestar responses."""

    def __call__(
        self,
        exc: LitestarAuthError,
        request: Request[Any, Any, Any],
        /,
    ) -> Response[Any]:
        pass  # pragma: no cover


class MiddlewareHook(Protocol):
    """Adjust the constructed auth middleware before plugin insertion."""

    def __call__(self, middleware: DefineMiddleware, /) -> DefineMiddleware:
        pass  # pragma: no cover


class ControllerHook(Protocol):
    """Adjust the built plugin controller list before registration."""

    def __call__(
        self,
        controllers: list[ControllerRouterHandler],
        /,
    ) -> list[ControllerRouterHandler]:
        pass  # pragma: no cover
