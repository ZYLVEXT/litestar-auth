"""Protocol contracts for plugin configuration callbacks."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth.db.base import BaseUserStore
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config._core import LitestarAuthConfig
    from litestar_auth.manager import BaseUserManager

type UserDatabaseFactory[UP: UserProtocol[Any], ID] = Callable[[AsyncSession], BaseUserStore[UP, ID]]


class PasswordValidatorFactory[UP: UserProtocol[Any], ID](Protocol):
    """Build a password validator callable for a plugin configuration."""

    def __call__(
        self,
        config: LitestarAuthConfig[UP, ID],
        /,
    ) -> Callable[[str], None] | None:
        pass  # pragma: no cover - Protocol method body - pure type contract


class UserManagerFactory[UP: UserProtocol[Any], ID](Protocol):
    """Build a request-scoped user manager for the plugin.

    Implementations receive ``backends`` session-bound to the current request; pass them
    through to ``BaseUserManager`` (or equivalent) so credential changes revoke persisted
    sessions consistently. Plugin validation remains authoritative for the
    ``user_manager_security`` surface. If a factory builds ``BaseUserManager`` with a
    divergent manager-owned secret surface, the manager constructor enforces the same
    distinct-secret validation for the roles it actually wires.
    """

    def __call__(
        self,
        *,
        session: AsyncSession,
        user_db: BaseUserStore[UP, ID],
        config: LitestarAuthConfig[UP, ID],
        backends: tuple[object, ...] = (),
    ) -> BaseUserManager[UP, ID]:
        pass  # pragma: no cover - Protocol method body - pure type contract
