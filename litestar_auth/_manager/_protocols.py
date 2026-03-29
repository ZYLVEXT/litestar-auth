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


class PasswordManagedUserManagerProtocol[UP](UserDatabaseManagerProtocol[UP], Protocol):
    """Manager surface shared by services that normalize and hash passwords."""

    password_helper: Any

    @staticmethod
    def _normalize_email(email: str) -> str: ...  # pragma: no cover

    def _validate_password(self, password: str) -> None: ...  # pragma: no cover
