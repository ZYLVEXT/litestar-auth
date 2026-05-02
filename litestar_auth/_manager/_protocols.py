"""Shared manager protocols for internal service modules."""

from __future__ import annotations

from typing import Any, Protocol

from litestar_auth.types import GuardedUserProtocol


class ManagedUserProtocol[ID](GuardedUserProtocol[ID], Protocol):
    """User fields required by password-sensitive manager flows."""

    email: str
    hashed_password: str


class AccountStateUserProtocol[ID](GuardedUserProtocol[ID], Protocol):
    """User fields required by account-state checks."""


class UserDatabaseManagerProtocol[UP](Protocol):
    """Manager surface exposing the user persistence boundary."""

    user_db: Any


class UserManagerHooksProtocol[UP](Protocol):
    """Lifecycle-hook surface exposed by manager implementations."""

    async def on_after_register(self, user: UP, token: str) -> None:  # pragma: no cover
        """Run after a new user has been persisted and a verification token has been issued."""

    async def on_after_register_duplicate(self, user: UP) -> None:  # pragma: no cover
        """Run after duplicate registration handling completes for an existing user."""

    async def on_after_login(self, user: UP) -> None:  # pragma: no cover
        """Run after a user successfully authenticates."""

    async def on_after_verify(self, user: UP) -> None:  # pragma: no cover
        """Run after a user's email verification succeeds."""

    async def on_after_request_verify_token(self, user: UP | None, token: str | None) -> None:  # pragma: no cover
        """Run after verification-token request handling, including enumeration-safe misses."""

    async def on_after_forgot_password(self, user: UP | None, token: str | None) -> None:  # pragma: no cover
        """Run after forgot-password handling, including enumeration-safe misses."""

    async def on_after_reset_password(self, user: UP) -> None:  # pragma: no cover
        """Run after a user's password has been reset."""

    async def on_after_update(self, user: UP, update_dict: dict[str, Any]) -> None:  # pragma: no cover
        """Run after a user update has been persisted."""

    async def on_before_delete(self, user: UP) -> None:  # pragma: no cover
        """Run before deleting a user."""

    async def on_after_delete(self, user: UP) -> None:  # pragma: no cover
        """Run after deleting a user."""
