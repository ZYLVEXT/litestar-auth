"""Bearer token transport implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

from litestar.enums import MediaType

from litestar_auth.authentication.transport.base import Transport

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.response import Response


class BearerTransport(Transport):
    """Transport that reads tokens from the ``Authorization`` header."""

    scheme = "bearer"

    @override
    async def read_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return the bearer token from the Authorization header when present."""
        authorization = connection.headers.get("Authorization")
        if authorization is None:
            return None

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != self.scheme:
            return None
        token = token.strip()
        if not token:
            return None
        return token

    @override
    def set_login_token(self, response: Response[Any], token: str) -> Response[Any]:
        """Store the issued bearer token in the response body.

        Returns:
            The mutated response.
        """
        response.content = {"access_token": token, "token_type": self.scheme}
        response.media_type = MediaType.JSON
        return response

    @override
    def set_logout(self, response: Response[Any]) -> Response[Any]:
        """Clear the response body because bearer transport keeps no client state.

        Returns:
            The mutated response.
        """
        response.content = None
        return response
