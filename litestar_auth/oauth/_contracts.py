"""Typed contracts shared by OAuth orchestration collaborators."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_auth.db import OAuthAccountData


class OAuthServiceUserStoreProtocol[UP: UserProtocol[Any], ID](Protocol):
    """User persistence operations required by OAuth flow orchestration."""

    async def get_by_email(self, email: str) -> UP | None:
        """Return a user by email address."""


class OAuthAccountStoreProtocol[UP: UserProtocol[Any], ID](Protocol):
    """OAuth-account persistence operations required by OAuth flow orchestration."""

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Return a user linked to the given provider account."""

    async def upsert_oauth_account(
        self,
        user: UP,
        *,
        account: OAuthAccountData,
    ) -> None:
        """Create or update the linked OAuth account."""


@runtime_checkable
class OAuthServiceUserManagerProtocol[UP: UserProtocol[Any], ID](Protocol):
    """User-manager behavior required by OAuth service orchestration."""

    user_db: OAuthServiceUserStoreProtocol[UP, ID]
    oauth_account_store: OAuthAccountStoreProtocol[UP, ID] | None

    async def create(
        self,
        user_create: Mapping[str, Any],
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> UP:
        """Create and return a new user."""

    async def update(
        self,
        user_update: Mapping[str, Any],
        user: UP,
        *,
        allow_privileged: bool = False,
    ) -> UP:
        """Persist and return updates for an existing user."""

    async def on_after_login(self, user: UP) -> None:
        """Run post-login side effects for a fully authenticated user."""

    def require_account_state(self, user: UP, *, require_verified: bool = False) -> None:
        """Validate active and optionally verified account state."""
