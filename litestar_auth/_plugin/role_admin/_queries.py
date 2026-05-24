"""Query helpers for SQLAlchemy-backed role administration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from litestar_auth._plugin.role_admin_contracts import (
    RoleAdminRoleNotFoundError,
    RoleAdminUserNotFoundError,
    UserRoleMembership,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql import Select


class _RoleAdminQueryMixin[UP: UserProtocol[Any]]:
    """Query and read-model helpers for role administration."""

    async def list_roles(self: Any) -> list[str]:
        """Return the deterministic normalized role catalog."""
        async with self.session() as session:
            return await self._list_role_names(session)

    async def show_user_roles(
        self: Any,
        *,
        email: str | None = None,
        user_id: object | None = None,
    ) -> UserRoleMembership:
        """Return the current normalized role snapshot for one configured user."""
        async with self.session() as session:
            user = await self._require_user(session, email=email, user_id=user_id)
            return self._user_role_membership(user)

    async def list_role_users(self: Any, *, role: str) -> list[UP]:
        """Return users currently assigned one normalized role in deterministic order."""
        normalized_role_name = self.normalized_role_name(role)
        async with self.session() as session:
            await self._require_role_by_name(session, role_name=normalized_role_name)
            return await self._load_users_with_role(session, role_name=normalized_role_name)

    def _with_role_membership(self: Any, statement: Select[tuple[UP]]) -> Select[tuple[UP]]:
        """Return ``statement`` with async-safe preloading for ``user.roles`` reads."""
        return statement.options(selectinload(self.user_model.role_assignments))

    async def _require_user_by_email(self: Any, session: AsyncSession, *, email: str) -> UP:
        """Return the configured user or raise when the email is unknown.

        Raises:
            RoleAdminUserNotFoundError: If no configured user exists for the
                requested email.
        """
        statement = self._with_role_membership(
            select(self.user_model).where(self.user_model.email == email),
        )
        user = await session.scalar(statement)
        if user is None:
            msg = f"Role admin could not find a user with email {email!r}."
            raise RoleAdminUserNotFoundError(msg)
        return user

    async def _require_user_by_id(self: Any, session: AsyncSession, *, user_id: object) -> UP:
        """Return the configured user or raise when the identifier is unknown.

        Raises:
            RoleAdminUserNotFoundError: If no configured user exists for the
                requested identifier.
        """
        statement = self._with_role_membership(
            select(self.user_model).where(self.user_model.id == user_id),
        )
        user = await session.scalar(statement)
        if user is None:
            msg = f"Role admin could not find a user with id {user_id!r}."
            raise RoleAdminUserNotFoundError(msg)
        return user

    async def _require_user(
        self: Any,
        session: AsyncSession,
        *,
        email: str | None = None,
        user_id: object | None = None,
    ) -> UP:
        """Return one configured user selected by email or identifier.

        Raises:
            TypeError: If the caller passes neither or both lookup selectors.
        """
        if (email is None) == (user_id is None):
            msg = "Role admin user lookup requires exactly one of email or user_id."
            raise TypeError(msg)
        if email is not None:
            return await self._require_user_by_email(session, email=email)
        return await self._require_user_by_id(session, user_id=user_id)

    async def _find_role_by_name(self: Any, session: AsyncSession, *, role_name: str) -> object | None:
        """Return one configured role row by normalized role name."""
        statement = select(self.role_model).where(self.role_model.name == role_name)
        return await session.scalar(statement)

    async def _require_role_by_name(self: Any, session: AsyncSession, *, role_name: str) -> object:
        """Return the configured role row or raise when the catalog entry is unknown.

        Raises:
            RoleAdminRoleNotFoundError: If the normalized role name does not
                exist in the active catalog.
        """
        role = await self._find_role_by_name(session, role_name=role_name)
        if role is None:
            msg = f"Role admin could not find role {role_name!r} in the configured catalog."
            raise RoleAdminRoleNotFoundError(msg)
        return role

    async def _list_role_names(self: Any, session: AsyncSession) -> list[str]:
        """Return all normalized role catalog names in deterministic order."""
        statement = select(self.role_model.name).order_by(self.role_model.name)
        return list(cast("Any", await session.scalars(statement)))

    async def _load_users_with_role(self: Any, session: AsyncSession, *, role_name: str) -> list[UP]:
        """Return users currently assigned ``role_name`` in deterministic order."""
        statement = self._with_role_membership(
            select(self.user_model)
            .join(self.user_model.role_assignments)
            .where(self.user_role_model.role_name == role_name)
            .order_by(self.user_model.email),
        )
        return list(cast("Any", await session.scalars(statement)))

    def _user_role_membership(self: Any, user: UP) -> UserRoleMembership:
        """Return the normalized role snapshot for one configured user instance."""
        return UserRoleMembership(
            email=cast("str", cast("Any", user).email),
            roles=self.normalized_role_names(cast("Any", user).roles),
        )
