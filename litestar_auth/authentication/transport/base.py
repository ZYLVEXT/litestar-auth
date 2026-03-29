"""Base transport abstractions for authentication backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.response import Response


@runtime_checkable
class LogoutTokenReadable(Protocol):
    """Protocol for transports with an explicit logout-token source."""

    async def read_logout_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Extract the token that should be invalidated on logout."""


class Transport(ABC):
    """Abstract base class for moving auth tokens through HTTP requests."""

    @abstractmethod
    async def read_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Extract an authentication token from the incoming connection."""

    @abstractmethod
    def set_login_token(self, response: Response[Any], token: str) -> Response[Any]:
        """Attach an authentication token to the login response."""

    @abstractmethod
    def set_logout(self, response: Response[Any]) -> Response[Any]:
        """Clear any transport-managed authentication state on logout."""
