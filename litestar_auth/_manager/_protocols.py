"""Shared manager protocols for internal service modules."""

from __future__ import annotations

from typing import Any, Protocol

from litestar_auth._manager.hooks import ManagerHookBus, ManagerHookTarget
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


class UserManagerHooksProtocol[UP](ManagerHookTarget[UP], Protocol):
    """Lifecycle-hook surface exposed by manager implementations."""


class ManagerHookBusProtocol[UP](Protocol):
    """Manager surface exposing lifecycle-hook dispatch."""

    hook_bus: ManagerHookBus[UP]
