"""Invariant guards for SQLAlchemy-backed role administration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.role_admin_contracts import SystemManagedRoleError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class _RoleAdminInvariantMixin[UP: UserProtocol[Any]]:
    """Fail-closed role catalog and superuser invariants."""

    def _require_not_system_managed_role(self: Any, *, role_name: str) -> None:
        """Reject destructive operations against the configured superuser role.

        Raises:
            SystemManagedRoleError: If ``role_name`` is the configured
                superuser role.
        """
        if role_name != self._superuser_role_name:
            return

        msg = f"Role admin will not modify system-managed superuser role {role_name!r}."
        raise SystemManagedRoleError(msg)

    async def _require_remaining_superuser(self: Any, session: AsyncSession) -> None:
        """Reject role removal that would leave no configured superusers.

        Raises:
            SystemManagedRoleError: If fewer than two users currently hold the
                configured superuser role.
        """
        superusers = await self._load_users_with_role(session, role_name=self._superuser_role_name)
        if len(superusers) > 1:
            return

        msg = (
            f"Role admin will not remove the final assignment of system-managed superuser role "
            f"{self._superuser_role_name!r}."
        )
        raise SystemManagedRoleError(msg)
