"""API-key transport implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

from litestar_auth.authentication.strategy._api_key_format import API_KEY_PREFIX
from litestar_auth.authentication.transport._api_key_signing import read_signed_api_key_request
from litestar_auth.authentication.transport.base import Transport
from litestar_auth.exceptions import TokenError

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.response import Response

API_KEY_HEADER_NAME = "X-API-Key"


class ApiKeyTransport(Transport):
    """Transport that reads canonical API keys from bearer auth or ``X-API-Key``."""

    scheme = "bearer"

    def __init__(self, *, prefix: str = API_KEY_PREFIX) -> None:
        """Store the accepted API-key prefix."""
        self.prefix = prefix

    @override
    async def read_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return an API-key token from ``Authorization`` or ``X-API-Key`` headers."""
        signed_request_scheme = read_signed_api_key_request(connection)
        if signed_request_scheme is not None:
            return signed_request_scheme

        bearer_token = self._read_bearer_token(connection)
        if bearer_token is not None:
            return bearer_token

        header_token = connection.headers.get(API_KEY_HEADER_NAME)
        if header_token is None:
            return None
        token = header_token.strip()
        if not token.startswith(f"{self.prefix}_"):
            return None
        return token

    @override
    def set_login_token(self, response: Response[Any], token: str) -> Response[Any]:  # noqa: ARG002, RUF100
        """Reject login issuance because API keys are not login-flow tokens.

        Raises:
            TokenError: Always, because API keys are not issued by login.
        """
        msg = "API-key transport cannot issue login tokens."
        raise TokenError(msg)

    @override
    def set_logout(self, response: Response[Any]) -> Response[Any]:
        """Leave logout responses unchanged because API keys keep no client state.

        Returns:
            The original response.
        """
        return response

    def _read_bearer_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        authorization = connection.headers.get("Authorization")
        if authorization is None:
            return None
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != self.scheme:
            return None
        token = token.strip()
        if not token.startswith(f"{self.prefix}_"):
            return None
        return token
