"""Base abstractions for authentication token strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable

from litestar_auth.types import ID, UserProtocol


class UserManagerProtocol[UP: UserProtocol[Any], ID](Protocol):
    """Protocol for user manager lookups used by token strategies."""

    async def get(self, user_id: ID) -> UP | None:
        """Return the user for the given identifier."""


class Strategy[UP: UserProtocol[Any], ID](ABC):
    """Abstract base class for token storage and validation strategies."""

    @abstractmethod
    async def read_token(self, token: str | None, user_manager: UserManagerProtocol[UP, ID]) -> UP | None:
        """Resolve a user from a token."""

    @abstractmethod
    async def write_token(self, user: UP) -> str:
        """Issue a token for the provided user."""

    @abstractmethod
    async def destroy_token(self, token: str, user: UP) -> None:
        """Invalidate a token for the provided user."""


@runtime_checkable
class SessionBindable[UP: UserProtocol[Any], ID, S](Protocol):
    """Protocol for strategies that can be rebound to a request-local session."""

    def with_session(self, session: S) -> Strategy[UP, ID]:
        """Return a strategy instance bound to the provided session."""


@runtime_checkable
class RefreshableStrategy[UP: UserProtocol[Any], ID](Protocol):
    """Protocol for strategies that support refresh-token rotation.

    Note:
        Refresh tokens are intentionally modeled as a separate lifecycle artifact from
        access tokens. In particular, `Strategy.destroy_token()` only targets the access
        token used for request authentication; refresh-token invalidation (if any) is
        managed by the refresh strategy itself.
    """

    async def write_refresh_token(self, user: UP) -> str:
        """Issue a refresh token for the provided user."""

    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> tuple[UP, str] | None:
        """Consume a refresh token and return the user plus a rotated replacement."""


@runtime_checkable
class TokenInvalidationCapable[UP: UserProtocol[Any]](Protocol):
    """Protocol for strategies that can revoke all user-managed session artifacts."""

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Invalidate all session artifacts for the given user."""
