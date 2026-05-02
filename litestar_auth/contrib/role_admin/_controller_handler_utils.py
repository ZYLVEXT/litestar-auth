"""Shared helpers for generated contrib role-admin handlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, cast

import msgspec
from litestar import Controller, Request
from sqlalchemy import select

from litestar_auth._plugin.role_admin import (
    RoleAdminRoleNotFoundError,
    RoleAdminUserNotFoundError,
    RoleModelFamily,
    SQLAlchemyRoleAdmin,
    _ManagerLifecycleRoleUpdater,
)
from litestar_auth.contrib.role_admin._error_responses import (
    _invalid_role_name,
    _normalize_input_role_name,
    _role_assignment_user_not_found,
    _role_not_found,
)
from litestar_auth.contrib.role_admin._schemas import RoleRead, UserBrief
from litestar_auth.contrib.role_admin._session_wiring import (
    _build_request_bound_role_admin,
    _ProvidedUserManagerLifecycleUpdater,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.types import Guard
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig


@dataclass(frozen=True, slots=True)
class RoleAdminControllerContext[UP: UserProtocol[Any]]:
    """Resolved controller assembly context for later role-admin handlers."""

    config: LitestarAuthConfig[UP, Any] | None
    model_family: RoleModelFamily[UP]
    route_prefix: str
    guards: tuple[Guard, ...]
    role_page_schema_type: type[msgspec.Struct]
    role_user_page_schema_type: type[msgspec.Struct]
    db_session_dependency_key: str


class RoleAdminControllerBase(Controller):
    """Typed base class for generated role-admin controllers."""

    role_admin_context: ClassVar[object]


def _role_admin_context[UP: UserProtocol[Any]](controller: RoleAdminControllerBase) -> RoleAdminControllerContext[UP]:
    """Return the typed role-admin controller context."""
    return cast("RoleAdminControllerContext[UP]", controller.role_admin_context)


def _resolve_role_admin[UP: UserProtocol[Any]](
    context: RoleAdminControllerContext[UP],
    *,
    db_session: AsyncSession | None = None,
    request_user_manager: object | None = None,
) -> SQLAlchemyRoleAdmin[UP]:
    """Return the configured role-admin helper for the current handler invocation.

    Raises:
        ConfigurationError: If no request-scoped session is available when the
            controller cannot open its own sessions from ``config``.
    """
    if context.config is not None and context.config.session_maker is not None:
        return SQLAlchemyRoleAdmin.from_config(context.config)

    if db_session is None:
        msg = "Role admin controller requires a request-scoped AsyncSession when config.session_maker is unavailable."
        raise ConfigurationError(msg)
    role_lifecycle_updater = (
        _ManagerLifecycleRoleUpdater.from_config(context.config)
        if context.config is not None
        else _ProvidedUserManagerLifecycleUpdater(request_user_manager)
    )
    return _build_request_bound_role_admin(
        model_family=context.model_family,
        session=db_session,
        role_lifecycle_updater=role_lifecycle_updater,
    )


def _to_role_read(role: object) -> RoleRead:
    """Convert one ORM role row into the public response schema.

    Returns:
        The serialized public role payload.
    """
    role_name = cast("Any", role).name
    return RoleRead(
        name=cast("str", role_name),
        description=cast("str | None", getattr(role, "description", None)),
    )


def _to_user_brief(user: object) -> UserBrief:
    """Convert one ORM user row into the public role-user listing schema.

    Returns:
        The serialized public user payload.
    """
    return UserBrief(
        id=str(cast("Any", user).id),
        email=cast("str", cast("Any", user).email),
        is_active=cast("bool", cast("Any", user).is_active),
        is_verified=cast("bool", cast("Any", user).is_verified),
    )


async def _reject_role_name_mutation(request: Request[Any, Any, Any]) -> None:
    """Reject PATCH payloads that attempt to mutate the immutable role name.

    Raises:
        _invalid_role_name: If the request payload includes a ``name`` field.
    """
    payload = msgspec.json.decode(await request.body())
    if isinstance(payload, dict) and "name" in payload:
        msg = "Role names are immutable."
        raise _invalid_role_name(msg)


async def _load_role_row[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    normalized_role_name: str,
) -> object:
    """Load one role row by normalized name.

    Returns:
        The loaded ORM role row.

    Raises:
        _role_not_found: If the normalized role does not exist.
    """
    async with role_admin.session() as session:
        role = await session.scalar(
            select(role_admin.role_model).where(cast("Any", role_admin.role_model).name == normalized_role_name),
        )
        if role is not None:
            return role

    msg = f"Role {normalized_role_name!r} not found."
    raise _role_not_found(msg)


async def _list_role_page[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    page_schema_type: type[msgspec.Struct],
    limit: int,
    offset: int,
) -> msgspec.Struct:
    """Return the paginated role-catalog response."""
    role_names = await role_admin.list_roles()
    total = len(role_names)
    page_names = role_names[offset : offset + limit]
    if not page_names:
        return page_schema_type(items=[], total=total, limit=limit, offset=offset)

    async with role_admin.session() as session:
        statement = (
            select(role_admin.role_model)
            .where(cast("Any", role_admin.role_model).name.in_(page_names))
            .order_by(cast("Any", role_admin.role_model).name)
        )
        roles = list(cast("Any", await session.scalars(statement)))

    return page_schema_type(
        items=[_to_role_read(role) for role in roles],
        total=total,
        limit=limit,
        offset=offset,
    )


async def _assign_role_user[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    role_name: str,
    user_id: str,
) -> RoleRead:
    """Assign one normalized role to one user selected by the HTTP path id.

    Returns:
        The public role payload for the assigned role.

    Raises:
        _role_not_found: If the normalized role does not exist.
        _role_assignment_user_not_found: If the target user does not exist.
    """
    normalized_role_name = _normalize_input_role_name(role_name)
    parsed_user_id = role_admin.parse_user_id(user_id)
    try:
        await role_admin.assign_user_roles(
            user_id=parsed_user_id,
            roles=[normalized_role_name],
            require_existing_roles=True,
        )
    except RoleAdminRoleNotFoundError as exc:
        raise _role_not_found(str(exc)) from exc
    except RoleAdminUserNotFoundError as exc:
        raise _role_assignment_user_not_found(str(exc)) from exc

    role = await _load_role_row(role_admin, normalized_role_name=normalized_role_name)
    return _to_role_read(role)


async def _unassign_role_user[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    role_name: str,
    user_id: str,
) -> None:
    """Remove one normalized role from one user selected by the HTTP path id.

    Raises:
        _role_assignment_user_not_found: If the target user does not exist.
    """
    normalized_role_name = _normalize_input_role_name(role_name)
    parsed_user_id = role_admin.parse_user_id(user_id)
    try:
        await role_admin.unassign_user_roles(
            user_id=parsed_user_id,
            roles=[normalized_role_name],
        )
    except RoleAdminUserNotFoundError as exc:
        raise _role_assignment_user_not_found(str(exc)) from exc


async def _list_role_user_page[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    page_schema_type: type[msgspec.Struct],
    role_name: str,
    limit: int,
    offset: int,
) -> msgspec.Struct:
    """Return the paginated user listing for one normalized role.

    Raises:
        _role_not_found: If the normalized role does not exist.
    """
    normalized_role_name = _normalize_input_role_name(role_name)
    try:
        users = await role_admin.list_role_users(role=normalized_role_name)
    except RoleAdminRoleNotFoundError as exc:
        raise _role_not_found(str(exc)) from exc

    total = len(users)
    page_users = users[offset : offset + limit]
    return page_schema_type(
        items=[_to_user_brief(user) for user in page_users],
        total=total,
        limit=limit,
        offset=offset,
    )
