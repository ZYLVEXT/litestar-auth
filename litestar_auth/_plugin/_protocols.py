"""Structural typing helpers for plugin assembly boundaries."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    import inspect

    from litestar.types import ExceptionHandlersMap

    from litestar_auth.types import TransportProtocol


class StrategyProto[UP: UserProtocol[Any], ID](Protocol):
    """Narrow strategy contract consumed by plugin backend factories."""

    async def read_token(
        self,
        token: str | None,
        user_manager: object,
    ) -> UP | None:
        """Resolve a user from a transport token."""

    async def write_token(self, user: UP) -> str:
        """Create a transport token for ``user``."""

    async def destroy_token(
        self,
        token: str,
        user: UP,
    ) -> None:
        """Invalidate ``token`` for ``user``."""


class AuthBackendProto[UP: UserProtocol[Any], ID](Protocol):
    """Narrow authentication-backend shape used by plugin controller helpers."""

    name: str
    transport: TransportProtocol
    strategy: StrategyProto[UP, ID]


class RouteHandlerWithHandlers(Protocol):
    """Route-handler object exposing mutable exception handlers."""

    exception_handlers: ExceptionHandlersMap | None


class DependencyProvider(Protocol):
    """Callable dependency provider with Litestar signature metadata."""

    __signature__: inspect.Signature
    __annotations__: dict[str, object]

    def __call__(
        self,
        *args: object,
        **kwargs: object,
    ) -> object:
        """Return the dependency value."""
