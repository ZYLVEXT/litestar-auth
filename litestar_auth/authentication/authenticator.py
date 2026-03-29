"""Authentication coordinator for multiple backends."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.base import UserManagerProtocol


class Authenticator[UP: UserProtocol[Any], ID]:
    """Try configured authentication backends in order."""

    def __init__(
        self,
        backends: list[AuthenticationBackend[UP, ID]],
        user_manager: UserManagerProtocol[UP, ID],
    ) -> None:
        """Store backends and the user manager used for token resolution."""
        self.backends = backends
        self.user_manager = user_manager

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
    ) -> tuple[UP | None, str | None]:
        """Return the first authenticated user and backend name.

        Returns:
            Tuple of authenticated user and backend name, or ``(None, None)``
            when no backend resolves the request.
        """
        for backend in self.backends:
            user = await backend.authenticate(connection, self.user_manager)
            if user is not None:
                return user, backend.name

        return None, None
