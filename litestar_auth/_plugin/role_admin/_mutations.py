"""Mutation helpers for SQLAlchemy-backed role administration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_auth._plugin.role_admin_contracts import UserRoleMembership


class _RoleLifecycleManager[UP: UserProtocol[Any]](Protocol):
    """Manager surface required to preserve update-hook parity for CLI role work."""

    async def update(
        self: Any,
        user_update: Mapping[str, Any],
        user: UP,
        *,
        allow_privileged: bool = False,
    ) -> UP:
        """Apply a role-related update through the normal manager lifecycle hooks."""


class _RoleAdminMutationMixin[UP: UserProtocol[Any]]:
    """Catalog and membership mutation helpers for role administration."""

    async def create_role(
        self: Any,
        *,
        role: str,
        description: str | None = None,
        fail_if_exists: bool = False,
    ) -> list[str]:
        """Create one normalized role catalog row when it does not already exist.

        Returns:
            The deterministic normalized role catalog after the create attempt.

        Raises:
            IntegrityError: If ``fail_if_exists`` is ``True`` and the normalized
                role already exists.
        """
        normalized_role_name = self.normalized_role_name(role)
        async with self.session() as session:
            role_payload: dict[str, object] = {"name": normalized_role_name}
            if hasattr(self.role_model, "description"):
                role_payload["description"] = description
            session.add(self.role_model(**role_payload))
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                if fail_if_exists:
                    raise
            return await self._list_role_names(session)

    async def delete_role(self: Any, *, role: str, force: bool = False) -> list[str]:
        """Delete one normalized role catalog row with explicit assignment safeguards.

        Returns:
            The deterministic normalized role catalog after the delete attempt.

        Raises:
            ValueError: If user assignments still reference the role and ``force`` is ``False``.
        """
        normalized_role_name = self.normalized_role_name(role)
        self._require_not_system_managed_role(role_name=normalized_role_name)
        async with self.session() as session:
            await self._require_role_by_name(session, role_name=normalized_role_name)
            assigned_users = await self._load_users_with_role(session, role_name=normalized_role_name)
            if assigned_users and not force:
                msg = (
                    f"Role admin will not delete role {normalized_role_name!r} while assignments still exist. "
                    "Re-run with --force to remove dependent user-role assignments."
                )
                raise ValueError(msg)

            if assigned_users:
                manager = self._role_lifecycle_updater.build_manager(session)
                for user in assigned_users:
                    remaining_roles = [role_name for role_name in user.roles if role_name != normalized_role_name]
                    await self._update_user_roles(manager=manager, user=user, roles=remaining_roles)
            await session.execute(
                delete(self.role_model).where(
                    self.role_model.name == normalized_role_name,
                ),
            )
            await session.commit()
            return await self._list_role_names(session)

    async def assign_user_roles(
        self: Any,
        *,
        roles: object,
        email: str | None = None,
        user_id: object | None = None,
        require_existing_roles: bool = False,
    ) -> UserRoleMembership:
        """Assign normalized roles to one configured user.

        Returns:
            The updated normalized role membership visible on the user boundary.
        """
        requested_roles = self.normalized_role_names(roles)
        async with self.session() as session:
            if require_existing_roles:
                for role_name in requested_roles:
                    await self._require_role_by_name(session, role_name=role_name)
            user = await self._require_user(session, email=email, user_id=user_id)
            current_roles = self.normalized_role_names(user.roles)
            updated_roles = self.normalized_role_names([*current_roles, *requested_roles])
            if updated_roles == current_roles:
                return self._user_role_membership(user)
            manager = self._role_lifecycle_updater.build_manager(session)
            updated_user = await self._update_user_roles(
                manager=manager,
                user=user,
                roles=updated_roles,
            )
            await session.commit()
            return self._user_role_membership(updated_user)

    async def unassign_user_roles(
        self: Any,
        *,
        roles: object,
        email: str | None = None,
        user_id: object | None = None,
        require_existing_roles: bool = False,
    ) -> UserRoleMembership:
        """Remove selected normalized roles from one configured user.

        Returns:
            The remaining normalized role membership visible on the user boundary.
        """
        requested_roles = set(self.normalized_role_names(roles))
        async with self.session() as session:
            if require_existing_roles:
                for role_name in sorted(requested_roles):
                    await self._require_role_by_name(session, role_name=role_name)
            user = await self._require_user(session, email=email, user_id=user_id)
            current_roles = self.normalized_role_names(user.roles)
            remaining_roles = [role_name for role_name in current_roles if role_name not in requested_roles]
            if remaining_roles == current_roles:
                return self._user_role_membership(user)
            if self._superuser_role_name in current_roles and self._superuser_role_name not in remaining_roles:
                await self._require_remaining_superuser(session)
            manager = self._role_lifecycle_updater.build_manager(session)
            updated_user = await self._update_user_roles(manager=manager, user=user, roles=remaining_roles)
            await session.commit()
            return self._user_role_membership(updated_user)

    async def _update_user_roles(
        self: Any,
        *,
        manager: _RoleLifecycleManager[UP],
        user: UP,
        roles: object,
    ) -> UP:
        """Update one user's roles through the manager lifecycle.

        Returns:
            The updated user returned by the manager lifecycle.
        """
        normalized_roles = self.normalized_role_names(roles)
        return await manager.update({"roles": normalized_roles}, user, allow_privileged=True)
