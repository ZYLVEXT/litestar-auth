"""Tests for shared typing protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.response import Response

from litestar_auth.models import User
from litestar_auth.types import GuardedUserProtocol, StrategyProtocol, TransportProtocol
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar.datastructures.state import State
    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit


class ExampleTransport:
    """Transport implementation that stores a token in headers."""

    header_name = "authorization"

    async def read_token(self, connection: ASGIConnection[Any, Any, Any, State]) -> str | None:
        """Return the authorization header value when present.

        Returns:
            The header value or ``None`` when absent.
        """
        return connection.headers.get(self.header_name)

    def set_login_token(self, response: Response[str], token: str) -> Response[str]:
        """Attach the token to the response headers.

        Returns:
            The mutated response instance.
        """
        response.headers[self.header_name] = token
        return response

    def set_logout(self, response: Response[str]) -> Response[str]:
        """Clear the stored token marker.

        Returns:
            The mutated response instance.
        """
        response.headers[self.header_name] = ""
        return response


class ExampleStrategy:
    """Strategy implementation that derives tokens from a user id."""

    token_prefix = "token:"

    async def read_token(self, token: str | None, user_manager: object) -> ExampleUser | None:
        """Decode a user id from a token-like string.

        Returns:
            A user when a token is present, otherwise ``None``.
        """
        del user_manager
        if token is None:
            return None
        return ExampleUser(id=UUID(token.removeprefix(self.token_prefix)))

    async def write_token(self, user: ExampleUser) -> str:
        """Encode a token-like string for a user.

        Returns:
            A token string derived from the user id.
        """
        return f"{self.token_prefix}{user.id}"

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """Accept token invalidation without side effects."""
        assert token.startswith(self.token_prefix)
        del user


class IncompleteGuardedUser:
    """Object missing one required account-state attribute."""

    id = uuid4()
    is_active = True
    is_verified = False


def _build_connection(token: str) -> ASGIConnection[Any, Any, Any, State]:
    """Create a minimal ASGI connection with auth headers.

    Returns:
        A connection object with a single authorization header.
    """
    scope: Any = {
        "type": "http",
        "headers": [(b"authorization", token.encode())],
        "path_params": {},
        "query_string": b"",
    }
    return ASGIConnection(scope=cast("HTTPScope", scope))


async def test_transport_protocol_conformance() -> None:
    """Transport protocol exposes the expected behavior."""
    transport = ExampleTransport()
    response = Response("ok")

    assert isinstance(transport, TransportProtocol)
    assert await transport.read_token(_build_connection("Bearer abc")) == "Bearer abc"
    assert transport.set_login_token(response, "Bearer new").headers["authorization"] == "Bearer new"
    assert not transport.set_logout(response).headers["authorization"]


async def test_strategy_protocol_conformance() -> None:
    """Strategy protocol resolves, writes, and destroys tokens."""
    user = ExampleUser(id=uuid4())
    strategy = ExampleStrategy()

    assert isinstance(strategy, StrategyProtocol)
    assert await strategy.write_token(user) == f"token:{user.id}"
    assert await strategy.read_token(f"token:{user.id}", object()) == user
    assert await strategy.read_token(None, object()) is None
    assert await strategy.destroy_token(f"token:{user.id}", user) is None


def test_guarded_user_protocol_runtime_check() -> None:
    """Guarded users support runtime protocol checks for account-state fields."""
    assert isinstance(ExampleUser(id=uuid4()), GuardedUserProtocol)
    assert not isinstance(IncompleteGuardedUser(), GuardedUserProtocol)


def test_guarded_user_protocol_orm_user_model() -> None:
    """Bundled SQLAlchemy ``User`` model satisfies `GuardedUserProtocol` at runtime."""
    uid = uuid4()
    user = User(
        email="orm@example.com",
        hashed_password="hashed",
        is_active=True,
        is_verified=False,
        is_superuser=False,
    )
    user.id = uid
    assert isinstance(user, GuardedUserProtocol)
