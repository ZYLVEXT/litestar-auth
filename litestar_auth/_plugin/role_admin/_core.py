"""Internal SQLAlchemy helpers for plugin-managed role administration."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from sqlalchemy import inspect
from sqlalchemy.exc import NoInspectionAvailable

from litestar_auth._plugin.role_admin._invariants import _RoleAdminInvariantMixin
from litestar_auth._plugin.role_admin._mutations import _RoleAdminMutationMixin, _RoleLifecycleManager
from litestar_auth._plugin.role_admin._queries import _RoleAdminQueryMixin
from litestar_auth._plugin.role_admin_contracts import (
    RoleAdminRoleNotFoundError,
    RoleAdminUserNotFoundError,
    SystemManagedRoleError,
    UserRoleMembership,
)
from litestar_auth._plugin.role_lifecycle import _ManagerLifecycleRoleUpdater
from litestar_auth._plugin.role_model_family import RoleModelFamily, _model_name, resolve_role_model_family
from litestar_auth._roles import normalize_role_name, normalize_roles
from litestar_auth._superuser_role import DEFAULT_SUPERUSER_ROLE_NAME
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth._plugin.scoped_session import SessionFactory

__all__ = (
    "RoleAdminRoleNotFoundError",
    "RoleAdminUserNotFoundError",
    "SystemManagedRoleError",
    "UserRoleMembership",
    "_RoleLifecycleManager",
)

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


def _session_factory_error(detail: str) -> str:
    """Build one fail-closed error message for unusable session factories.

    Returns:
        The error message describing the unusable session factory.
    """
    return (
        "Role admin requires LitestarAuthConfig.session_maker to open AsyncSession work for CLI role commands. "
        f"{detail}"
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
class SQLAlchemyRoleAdmin[UP: UserProtocol[Any]](
    _RoleAdminMutationMixin[UP],
    _RoleAdminInvariantMixin[UP],
    _RoleAdminQueryMixin[UP],
):
    """Internal role-admin helper for SQLAlchemy-backed user models."""

    model_family: RoleModelFamily[UP]
    _session_maker: SessionFactory
    _role_lifecycle_updater: _ManagerLifecycleRoleUpdater[UP]
    _superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME

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
            _superuser_role_name=config.superuser_role_name,
        )

    @property
    def user_model(self) -> type[UP]:
        """The configured SQLAlchemy user model."""
        return self.model_family.user_model

    @property
    def role_model(self) -> type[Any]:
        """The resolved SQLAlchemy role model."""
        return self.model_family.role_model

    @property
    def user_role_model(self) -> type[Any]:
        """The resolved SQLAlchemy user-role association model."""
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
