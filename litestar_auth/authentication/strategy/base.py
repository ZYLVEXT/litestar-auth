"""Base abstractions for authentication token strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from litestar_auth.types import ID, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from litestar_auth.types import StrategyProtocol


@dataclass(frozen=True, slots=True)
class RefreshSession:
    """Public refresh-session metadata exposed by session-management strategies."""

    session_id: str
    created_at: datetime
    last_used_at: datetime | None
    client_metadata: Mapping[str, str] | None


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
class ContextualStrategy[UP: UserProtocol[Any], ID, AuthT](Protocol):
    """Protocol for strategies that return custom request auth context."""

    async def read_token_with_context(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> AuthT | None:
        """Resolve a user plus strategy-specific authentication context."""


@runtime_checkable
class SessionBindable[UP: UserProtocol[Any], ID, S](Protocol):
    """Protocol for strategies that can be rebound to a request-local session."""

    def with_session(self, session: S) -> StrategyProtocol[UP, ID]:
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


@runtime_checkable
class RefreshSessionManagementStrategy[UP: UserProtocol[Any]](Protocol):
    """Protocol for strategies that support user-scoped refresh-session management."""

    async def list_refresh_sessions(self, user: UP) -> Sequence[RefreshSession]:
        """Return active refresh sessions belonging to the given user."""

    async def revoke_refresh_session(self, user: UP, session_id: str) -> bool:
        """Revoke one refresh session by public session id.

        Returns:
            ``True`` when a matching active session was revoked, otherwise ``False``.
        """

    async def revoke_other_refresh_sessions(self, user: UP, current_session_id: str | None) -> int:
        """Revoke active refresh sessions except the supplied current session.

        Returns:
            Number of active refresh sessions revoked.
        """


@runtime_checkable
class RefreshSessionIdentifierStrategy[UP: UserProtocol[Any]](Protocol):
    """Protocol for strategies that can identify a refresh session from a raw refresh token."""

    async def identify_refresh_session(self, user: UP, refresh_token: str) -> str | None:
        """Return the user's public refresh-session id for ``refresh_token`` when it can be resolved."""


@runtime_checkable
class RefreshSessionAccessTokenStrategy[UP: UserProtocol[Any]](Protocol):
    """Protocol for strategies that can bind an access token to a refresh session."""

    async def write_token_for_session(self, user: UP, session_id: str) -> str:
        """Issue an access token linked to ``session_id`` for targeted revocation."""


@runtime_checkable
class TotpStepUpStrategy[UP: UserProtocol[Any]](Protocol):
    """Protocol for strategies that persist recent TOTP verification markers."""

    async def issue_totp_stepup(self, user: UP, session_id: str, *, ttl_seconds: int) -> None:
        """Store a short-lived TOTP step-up marker for ``user`` and ``session_id``."""

    async def has_recent_totp_verification(self, user: UP, session_id: str) -> bool:
        """Return whether ``session_id`` has a live TOTP step-up marker for ``user``."""
