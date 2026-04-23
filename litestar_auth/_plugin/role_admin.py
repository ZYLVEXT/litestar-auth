"""Internal SQLAlchemy helpers for plugin-managed role administration."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Any, Protocol, cast
from uuid import UUID

from sqlalchemy import delete, inspect, select
from sqlalchemy.exc import IntegrityError, NoInspectionAvailable
from sqlalchemy.orm import selectinload

from litestar_auth._plugin.session_binding import _ScopedUserDatabaseProxy
from litestar_auth._plugin.user_manager_builder import resolve_user_manager_factory
from litestar_auth._roles import normalize_role_name, normalize_roles
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.oauth_encryption import OAuthTokenEncryption
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql import Select

    from litestar_auth._plugin.config import LitestarAuthConfig, UserDatabaseFactory, UserManagerFactory
    from litestar_auth._plugin.scoped_session import SessionFactory
    from litestar_auth.manager import BaseUserManager

_ROLE_ASSIGNMENTS_RELATIONSHIP_NAME = "role_assignments"
_ROLE_RELATIONSHIP_NAME = "role"
_REQUIRED_SESSION_METHODS = (
    "add",
    "execute",
    "scalar",
    "scalars",
    "merge",
    "refresh",
    "flush",
    "commit",
    "rollback",
)
_REQUIRED_SESSION_ATTRIBUTES = ("no_autoflush",)


def _model_name(model: object) -> str:
    """Return a stable display name for a configured model class."""
    return cast("str", getattr(model, "__name__", repr(model)))


def _role_contract_error(
    user_model: object,
    detail: str,
) -> str:
    """Build one fail-closed error message for incompatible role contracts.

    Returns:
        The error message describing the incompatible role contract.
    """
    return (
        "Role admin requires LitestarAuthConfig.user_model "
        f"{_model_name(user_model)!r} to compose UserRoleRelationshipMixin or an equivalent "
        f"relational role contract. {detail}"
    )


def _session_factory_error(detail: str) -> str:
    """Build one fail-closed error message for unusable session factories.

    Returns:
        The error message describing the unusable session factory.
    """
    return (
        "Role admin requires LitestarAuthConfig.session_maker to open AsyncSession work for CLI role commands. "
        f"{detail}"
    )


@dataclass(frozen=True, slots=True)
class RoleModelFamily[UP: UserProtocol[Any]]:
    """Resolved SQLAlchemy model family behind the flat user-role contract."""

    user_model: type[UP]
    role_model: type[Any]
    user_role_model: type[Any]


@dataclass(frozen=True, slots=True)
class UserRoleMembership:
    """Normalized role membership for one CLI-targeted user."""

    email: str
    roles: list[str]


class RoleAdminRoleNotFoundError(LookupError):
    """Raised when the configured role catalog does not contain the requested role."""


class RoleAdminUserNotFoundError(LookupError):
    """Raised when the configured user lookup target does not exist."""


class _RoleLifecycleManager[UP: UserProtocol[Any]](Protocol):
    """Manager surface required to preserve update-hook parity for CLI role work."""

    async def update(
        self,
        user_update: Mapping[str, Any],
        user: UP,
        *,
        allow_privileged: bool = False,
    ) -> UP: ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class _ManagerLifecycleRoleUpdater[UP: UserProtocol[Any]]:
    """Build request-scoped user managers for CLI role mutations."""

    config: LitestarAuthConfig[UP, Any]
    _user_db_factory: UserDatabaseFactory[UP, Any]
    _user_manager_factory: UserManagerFactory[UP, Any]
    _oauth_token_encryption: OAuthTokenEncryption | None

    @classmethod
    def from_config(
        cls,
        config: LitestarAuthConfig[UP, Any],
    ) -> _ManagerLifecycleRoleUpdater[UP]:
        """Build the manager-backed role updater from plugin configuration.

        Returns:
            The configured lifecycle-preserving role updater.
        """
        oauth_token_encryption = None
        if config.oauth_config is not None:
            oauth_token_encryption = OAuthTokenEncryption(
                config.oauth_config.oauth_token_encryption_key,
                unsafe_testing=config.unsafe_testing,
            )

        return cls(
            config=config,
            _user_db_factory=config.resolve_user_db_factory(),
            _user_manager_factory=resolve_user_manager_factory(config),
            _oauth_token_encryption=oauth_token_encryption,
        )

    def build_manager(self, session: AsyncSession) -> BaseUserManager[UP, Any]:
        """Return a request-scoped manager bound to ``session``."""
        user_db = _ScopedUserDatabaseProxy(
            self._user_db_factory(session),
            oauth_token_encryption=self._oauth_token_encryption,
        )
        bound_backends = self.config.resolve_backends(session)
        return self._user_manager_factory(
            session=session,
            user_db=user_db,
            config=self.config,
            backends=bound_backends,
        )


@cache
def resolve_role_model_family[UP: UserProtocol[Any]](
    user_model: type[UP],
) -> RoleModelFamily[UP]:
    """Resolve the active relational role model family from ``user_model``.

    Returns:
        The resolved SQLAlchemy user, role, and association models.

    Raises:
        ConfigurationError: If the configured user model does not expose the
            documented relational role contract.
    """
    if not hasattr(user_model, "roles"):
        msg = _role_contract_error(
            user_model,
            "Expected a normalized flat 'roles' attribute on the user model.",
        )
        raise ConfigurationError(msg)

    try:
        user_relationships = inspect(user_model).relationships
    except NoInspectionAvailable as exc:
        msg = _role_contract_error(
            user_model,
            "Expected a SQLAlchemy mapped class, but mapper inspection is unavailable.",
        )
        raise ConfigurationError(msg) from exc

    if _ROLE_ASSIGNMENTS_RELATIONSHIP_NAME not in user_relationships:
        msg = _role_contract_error(
            user_model,
            "Expected a mapped 'role_assignments' relationship on the user model.",
        )
        raise ConfigurationError(msg)

    user_role_model = cast(
        "type[Any]",
        user_relationships[_ROLE_ASSIGNMENTS_RELATIONSHIP_NAME].mapper.class_,
    )
    if not hasattr(user_role_model, "role_name"):
        msg = _role_contract_error(
            user_model,
            "Expected role-assignment rows with a normalized 'role_name' attribute.",
        )
        raise ConfigurationError(msg)

    user_role_relationships = inspect(user_role_model).relationships
    if _ROLE_RELATIONSHIP_NAME not in user_role_relationships:
        msg = _role_contract_error(
            user_model,
            "Expected role-assignment rows with a mapped 'role' relationship.",
        )
        raise ConfigurationError(msg)

    role_model = cast(
        "type[Any]",
        user_role_relationships[_ROLE_RELATIONSHIP_NAME].mapper.class_,
    )
    if not hasattr(role_model, "name"):
        msg = _role_contract_error(
            user_model,
            "Expected related role rows with a normalized 'name' attribute.",
        )
        raise ConfigurationError(msg)

    return RoleModelFamily(
        user_model=user_model,
        role_model=role_model,
        user_role_model=user_role_model,
    )


def _require_role_admin_session_maker[UP: UserProtocol[Any]](
    config: LitestarAuthConfig[UP, Any],
) -> SessionFactory:
    """Return the configured session maker or fail closed for CLI role work.

    Returns:
        The configured session factory for role-admin commands.

    Raises:
        ConfigurationError: If the config omits ``session_maker``.
    """
    session_maker = config.session_maker
    if session_maker is None:
        detail = "Configure session_maker explicitly for role-admin support."
        msg = _session_factory_error(detail)
        raise ConfigurationError(msg)
    return session_maker


def _is_async_context_manager(candidate: object) -> bool:
    """Return whether ``candidate`` exposes the async context-manager protocol."""
    return hasattr(candidate, "__aenter__") and hasattr(candidate, "__aexit__")


def _require_async_session_like(session: object) -> AsyncSession:
    """Return ``session`` when it satisfies the AsyncSession surface used by role admin.

    Returns:
        The validated AsyncSession-compatible object.

    Raises:
        ConfigurationError: If ``session`` does not expose the methods used by
            the role-admin helper.
    """
    missing_methods = [name for name in _REQUIRED_SESSION_METHODS if not hasattr(session, name)]
    missing_attributes = [name for name in _REQUIRED_SESSION_ATTRIBUTES if not hasattr(session, name)]
    if missing_methods or missing_attributes:
        missing_members = [*sorted(missing_methods), *sorted(missing_attributes)]
        detail = f"session_maker() must yield an AsyncSession-compatible object exposing {', '.join(missing_members)}."
        msg = _session_factory_error(detail)
        raise ConfigurationError(msg)
    return cast("AsyncSession", session)


@dataclass(slots=True)
class SQLAlchemyRoleAdmin[UP: UserProtocol[Any]]:
    """Internal role-admin helper for SQLAlchemy-backed user models."""

    model_family: RoleModelFamily[UP]
    _session_maker: SessionFactory
    _role_lifecycle_updater: _ManagerLifecycleRoleUpdater[UP]

    @classmethod
    def from_config(
        cls,
        config: LitestarAuthConfig[UP, Any],
    ) -> SQLAlchemyRoleAdmin[UP]:
        """Build a role-admin helper from the active plugin configuration.

        Returns:
            The configured role-admin helper.
        """
        return cls(
            model_family=resolve_role_model_family(config.user_model),
            _session_maker=_require_role_admin_session_maker(config),
            _role_lifecycle_updater=_ManagerLifecycleRoleUpdater.from_config(config),
        )

    @property
    def user_model(self) -> type[UP]:
        """Return the configured SQLAlchemy user model."""
        return self.model_family.user_model

    @property
    def role_model(self) -> type[Any]:
        """Return the resolved SQLAlchemy role model."""
        return self.model_family.role_model

    @property
    def user_role_model(self) -> type[Any]:
        """Return the resolved SQLAlchemy user-role association model."""
        return self.model_family.user_role_model

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield one AsyncSession opened from the configured ``session_maker``.

        Raises:
            ConfigurationError: If ``session_maker()`` does not return an
                AsyncSession-compatible async context manager.
        """
        session_context = cast("Any", self._session_maker())
        if not _is_async_context_manager(session_context):
            detail = "session_maker() must return an async context manager."
            msg = _session_factory_error(detail)
            raise ConfigurationError(msg)

        async with session_context as session:
            yield _require_async_session_like(session)

    @staticmethod
    def normalized_role_names(roles: object) -> list[str]:
        """Return the normalized role-name snapshot used by the user contract."""
        return normalize_roles(roles)

    @staticmethod
    def normalized_role_name(role: str) -> str:
        """Return one normalized role name using the shared flat-role helper."""
        return normalize_role_name(role)

    def parse_user_id(self, raw_user_id: str) -> object:
        """Parse one HTTP path user identifier for the configured user model.

        The controller surface preserves the cookbook's UUID-first behavior and
        then falls back to the mapped primary-key type when available so
        integer-keyed custom models keep working without a separate ``id_parser``.

        Returns:
            The parsed identifier object suitable for querying ``user_model``.
        """
        try:
            return UUID(raw_user_id)
        except ValueError:
            pass

        try:
            primary_key_column = inspect(self.user_model).primary_key[0]
        except (IndexError, NoInspectionAvailable):
            return raw_user_id

        try:
            primary_key_type = primary_key_column.type.python_type
        except NotImplementedError:
            return raw_user_id

        if primary_key_type in {str, UUID}:
            return raw_user_id

        try:
            return primary_key_type(raw_user_id)
        except (TypeError, ValueError):
            return raw_user_id

    def replace_user_roles(self, user: UP, roles: object) -> list[str]:
        """Persist normalized membership through the configured user model's ``roles`` boundary.

        Returns:
            The normalized role membership now visible on ``user.roles``.

        Raises:
            TypeError: If ``user`` is not an instance of the configured
                ``user_model``.
        """
        if not isinstance(user, self.user_model):
            msg = (
                "Role admin can only mutate instances of the configured user_model "
                f"{_model_name(self.user_model)!r}, got {_model_name(type(user))!r}."
            )
            raise TypeError(msg)

        cast("Any", user).roles = self.normalized_role_names(roles)
        return cast("list[str]", cast("Any", user).roles)

    async def list_roles(self) -> list[str]:
        """Return the deterministic normalized role catalog."""
        async with self.session() as session:
            return await self._list_role_names(session)

    async def create_role(
        self,
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

    async def delete_role(self, *, role: str, force: bool = False) -> list[str]:
        """Delete one normalized role catalog row with explicit assignment safeguards.

        Returns:
            The deterministic normalized role catalog after the delete attempt.

        Raises:
            ValueError: If user assignments still reference the role and ``force`` is ``False``.
        """
        normalized_role_name = self.normalized_role_name(role)
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
                    remaining_roles = [
                        role_name for role_name in cast("Any", user).roles if role_name != normalized_role_name
                    ]
                    await self._update_user_roles(manager=manager, user=user, roles=remaining_roles)
            await session.execute(
                delete(self.role_model).where(
                    cast("Any", self.role_model).name == normalized_role_name,
                ),
            )
            await session.commit()
            return await self._list_role_names(session)

    async def show_user_roles(
        self,
        *,
        email: str | None = None,
        user_id: object | None = None,
    ) -> UserRoleMembership:
        """Return the current normalized role snapshot for one configured user."""
        async with self.session() as session:
            user = await self._require_user(session, email=email, user_id=user_id)
            return self._user_role_membership(user)

    async def list_role_users(self, *, role: str) -> list[UP]:
        """Return users currently assigned one normalized role in deterministic order."""
        normalized_role_name = self.normalized_role_name(role)
        async with self.session() as session:
            await self._require_role_by_name(session, role_name=normalized_role_name)
            return await self._load_users_with_role(session, role_name=normalized_role_name)

    async def assign_user_roles(
        self,
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
            current_roles = self.normalized_role_names(cast("Any", user).roles)
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
        self,
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
            current_roles = self.normalized_role_names(cast("Any", user).roles)
            remaining_roles = [role_name for role_name in current_roles if role_name not in requested_roles]
            if remaining_roles == current_roles:
                return self._user_role_membership(user)
            manager = self._role_lifecycle_updater.build_manager(session)
            updated_user = await self._update_user_roles(manager=manager, user=user, roles=remaining_roles)
            await session.commit()
            return self._user_role_membership(updated_user)

    def _with_role_membership(self, statement: Select[tuple[UP]]) -> Select[tuple[UP]]:
        """Return ``statement`` with async-safe preloading for ``user.roles`` reads."""
        return statement.options(selectinload(cast("Any", self.user_model).role_assignments))

    async def _require_user_by_email(self, session: AsyncSession, *, email: str) -> UP:
        """Return the configured user or raise when the email is unknown.

        Raises:
            RoleAdminUserNotFoundError: If no configured user exists for the
                requested email.
        """
        statement = self._with_role_membership(
            select(self.user_model).where(cast("Any", self.user_model).email == email),
        )
        user = await session.scalar(statement)
        if user is None:
            msg = f"Role admin could not find a user with email {email!r}."
            raise RoleAdminUserNotFoundError(msg)
        return user

    async def _require_user_by_id(self, session: AsyncSession, *, user_id: object) -> UP:
        """Return the configured user or raise when the identifier is unknown.

        Raises:
            RoleAdminUserNotFoundError: If no configured user exists for the
                requested identifier.
        """
        statement = self._with_role_membership(
            select(self.user_model).where(cast("Any", self.user_model).id == user_id),
        )
        user = await session.scalar(statement)
        if user is None:
            msg = f"Role admin could not find a user with id {user_id!r}."
            raise RoleAdminUserNotFoundError(msg)
        return user

    async def _require_user(
        self,
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

    async def _find_role_by_name(self, session: AsyncSession, *, role_name: str) -> object | None:
        """Return one configured role row by normalized role name."""
        statement = select(self.role_model).where(cast("Any", self.role_model).name == role_name)
        return await session.scalar(statement)

    async def _require_role_by_name(self, session: AsyncSession, *, role_name: str) -> object:
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

    async def _list_role_names(self, session: AsyncSession) -> list[str]:
        """Return all normalized role catalog names in deterministic order."""
        statement = select(cast("Any", self.role_model).name).order_by(cast("Any", self.role_model).name)
        return list(cast("Any", await session.scalars(statement)))

    async def _load_users_with_role(self, session: AsyncSession, *, role_name: str) -> list[UP]:
        """Return users currently assigned ``role_name`` in deterministic order."""
        statement = self._with_role_membership(
            select(self.user_model)
            .join(cast("Any", self.user_model).role_assignments)
            .where(cast("Any", self.user_role_model).role_name == role_name)
            .order_by(cast("Any", self.user_model).email),
        )
        return list(cast("Any", await session.scalars(statement)))

    async def _update_user_roles(
        self,
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

    def _user_role_membership(self, user: UP) -> UserRoleMembership:
        """Return the normalized role snapshot for one configured user instance."""
        return UserRoleMembership(
            email=cast("str", cast("Any", user).email),
            roles=self.normalized_role_names(cast("Any", user).roles),
        )
