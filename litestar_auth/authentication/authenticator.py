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
    ) -> tuple[UP | None, object | None]:
        """Return the first authenticated user and request auth context.

        Returns:
            Tuple of authenticated user and request auth context, or ``(None, None)``
            when no backend resolves the request.
        """
        for backend in self.backends:
            if callable(getattr(type(backend), "authenticate_with_context", None)):
                result = await backend.authenticate_with_context(connection, self.user_manager)
            else:
                user = await backend.authenticate(connection, self.user_manager)
                result = None if user is None else (user, backend.name)
            if result is not None:
                return result

        return None, None
