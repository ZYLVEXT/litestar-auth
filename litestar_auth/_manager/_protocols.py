"""Shared manager protocols for internal service modules."""

from __future__ import annotations

from collections.abc import Hashable
from typing import Any, Protocol

from litestar_auth.types import GuardedUserProtocol


class ManagedUserProtocol[ID: Hashable](GuardedUserProtocol[ID], Protocol):
    """User fields required by password-sensitive manager flows."""

    email: str
    hashed_password: str


class AccountStateUserProtocol[ID: Hashable](GuardedUserProtocol[ID], Protocol):
    """User fields required by account-state checks."""


class UserDatabaseManagerProtocol[UP](Protocol):
    """Manager surface exposing the user persistence boundary."""

    user_db: Any
