"""Generated route factories for the contrib role-admin controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, cast

import msgspec  # noqa: TC002
from litestar import Request, delete, get, patch, post
from litestar.params import Parameter
from sqlalchemy import select

from litestar_auth.contrib.role_admin._controller_handler_utils import (
    RoleAdminControllerBase,
    _assign_role_user,
    _list_role_page,
    _list_role_user_page,
    _load_role_row,
    _reject_role_name_mutation,
    _resolve_role_admin,
    _role_admin_context,
    _to_role_read,
    _unassign_role_user,
)
from litestar_auth.contrib.role_admin._error_responses import (
    _normalize_input_role_name,
    _role_already_exists,
    _role_not_found,
    _role_still_assigned,
)
from litestar_auth.contrib.role_admin._schemas import RoleCreate, RoleRead, RoleUpdate  # noqa: TC001
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth.controllers._utils import RequestBodyRouteHandler

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 100
_LimitQuery = Annotated[int, Parameter(query="limit", ge=1, le=_MAX_LIMIT)]
_OffsetQuery = Annotated[int, Parameter(query="offset", ge=0)]


def create_list_roles_handler() -> RequestBodyRouteHandler:
    """Create the generated ``GET /roles`` handler.

    Returns:
        Generated route handler.
    """

    @get()
    async def list_roles(
        self: RoleAdminControllerBase,
        db_session: AsyncSession | None = None,
        limit: _LimitQuery = _DEFAULT_LIMIT,
        offset: _OffsetQuery = 0,
    ) -> msgspec.Struct:
        """Return a paginated list of role summaries."""
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(context, db_session=db_session)
        return await _list_role_page(
            role_admin,
            page_schema_type=context.role_page_schema_type,
            limit=limit,
            offset=offset,
        )

    return cast("RequestBodyRouteHandler", list_roles)


def create_create_role_handler() -> RequestBodyRouteHandler:
    """Create the generated ``POST /roles`` handler.

    Returns:
        Generated route handler.
    """

    @post(status_code=201)
    async def create_role(
        self: RoleAdminControllerBase,
        data: msgspec.Struct,
        db_session: AsyncSession | None = None,
    ) -> RoleRead:
        """Create a role and return its summary.

        Returns:
            Created role summary.

        Raises:
            _role_already_exists: If the role already exists.
        """
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(context, db_session=db_session)
        payload = cast("RoleCreate", data)
        normalized_role_name = _normalize_input_role_name(payload.name)
        try:
            await role_admin.create_role(
                role=normalized_role_name,
                description=payload.description,
                fail_if_exists=True,
            )
        except Exception as exc:
            from sqlalchemy.exc import IntegrityError  # noqa: PLC0415

            if isinstance(exc, IntegrityError):
                msg = f"Role {normalized_role_name!r} already exists."
                raise _role_already_exists(msg) from exc
            raise
        role = await _load_role_row(role_admin, normalized_role_name=normalized_role_name)
        return _to_role_read(role)

    return cast("RequestBodyRouteHandler", create_role)


def create_get_role_handler() -> RequestBodyRouteHandler:
    """Create the generated ``GET /roles/{role_name}`` handler.

    Returns:
        Generated route handler.
    """

    @get("/{role_name:str}")
    async def get_role(
        self: RoleAdminControllerBase,
        role_name: str,
        db_session: AsyncSession | None = None,
    ) -> RoleRead:
        """Return one role by name."""
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(context, db_session=db_session)
        role = await _load_role_row(role_admin, normalized_role_name=_normalize_input_role_name(role_name))
        return _to_role_read(role)

    return cast("RequestBodyRouteHandler", get_role)


def create_update_role_handler() -> RequestBodyRouteHandler:
    """Create the generated ``PATCH /roles/{role_name}`` handler.

    Returns:
        Generated route handler.
    """

    @patch("/{role_name:str}")
    async def update_role(
        self: RoleAdminControllerBase,
        request: Request[Any, Any, Any],
        role_name: str,
        data: msgspec.Struct,
        db_session: AsyncSession | None = None,
    ) -> RoleRead:
        """Update mutable role fields and return the updated role.

        Returns:
            Updated role summary.

        Raises:
            _role_not_found: If the role does not exist.
            ConfigurationError: If the configured role model cannot store the requested fields.
        """
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(context, db_session=db_session)
        normalized_role_name = _normalize_input_role_name(role_name)
        payload = cast("RoleUpdate", data)
        await _reject_role_name_mutation(request)
        async with role_admin.session() as session:
            role = await session.scalar(
                select(role_admin.role_model).where(
                    cast("Any", role_admin.role_model).name == normalized_role_name,
                ),
            )
            if role is None:
                msg = f"Role {normalized_role_name!r} not found."
                raise _role_not_found(msg)
            if hasattr(role, "description"):
                role.description = payload.description
            elif payload.description is not None:
                msg = "The configured role model does not expose a 'description' attribute required by RoleUpdate."
                raise ConfigurationError(msg)
            await session.commit()
        return _to_role_read(role)

    return cast("RequestBodyRouteHandler", update_role)


def create_delete_role_handler() -> RequestBodyRouteHandler:
    """Create the generated ``DELETE /roles/{role_name}`` handler.

    Returns:
        Generated route handler.
    """

    @delete("/{role_name:str}", status_code=204)
    async def delete_role(
        self: RoleAdminControllerBase,
        role_name: str,
        db_session: AsyncSession | None = None,
    ) -> None:
        """Delete a role by name.

        Raises:
            _role_not_found: If the role does not exist.
            _role_still_assigned: If the role is still assigned to at least one user.
        """
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(context, db_session=db_session)
        normalized_role_name = _normalize_input_role_name(role_name)
        try:
            await role_admin.delete_role(role=normalized_role_name)
        except LookupError as exc:
            msg = f"Role {normalized_role_name!r} not found."
            raise _role_not_found(msg) from exc
        except ValueError as exc:
            raise _role_still_assigned(str(exc)) from exc

    return cast("RequestBodyRouteHandler", delete_role)


def create_assign_role_handler() -> RequestBodyRouteHandler:
    """Create the generated ``POST /roles/{role_name}/users/{user_id}`` handler.

    Returns:
        Generated route handler.
    """

    @post("/{role_name:str}/users/{user_id:str}", status_code=200)
    async def assign_role(
        self: RoleAdminControllerBase,
        role_name: str,
        user_id: str,
        db_session: AsyncSession | None = None,
        litestar_auth_user_manager: object | None = None,
    ) -> RoleRead:
        """Assign a role to a user and return the role summary.

        Returns:
            Updated role summary.
        """
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(
            context,
            db_session=db_session,
            request_user_manager=litestar_auth_user_manager,
        )
        return await _assign_role_user(role_admin, role_name=role_name, user_id=user_id)

    return cast("RequestBodyRouteHandler", assign_role)


def create_unassign_role_handler() -> RequestBodyRouteHandler:
    """Create the generated ``DELETE /roles/{role_name}/users/{user_id}`` handler.

    Returns:
        Generated route handler.
    """

    @delete("/{role_name:str}/users/{user_id:str}", status_code=204)
    async def unassign_role(
        self: RoleAdminControllerBase,
        role_name: str,
        user_id: str,
        db_session: AsyncSession | None = None,
        litestar_auth_user_manager: object | None = None,
    ) -> None:
        """Remove a role assignment from a user."""
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(
            context,
            db_session=db_session,
            request_user_manager=litestar_auth_user_manager,
        )
        await _unassign_role_user(role_admin, role_name=role_name, user_id=user_id)

    return cast("RequestBodyRouteHandler", unassign_role)


def create_list_role_users_handler() -> RequestBodyRouteHandler:
    """Create the generated ``GET /roles/{role_name}/users`` handler.

    Returns:
        Generated route handler.
    """

    @get("/{role_name:str}/users")
    async def list_role_users(
        self: RoleAdminControllerBase,
        role_name: str,
        db_session: AsyncSession | None = None,
        limit: _LimitQuery = _DEFAULT_LIMIT,
        offset: _OffsetQuery = 0,
    ) -> msgspec.Struct:
        """Return a paginated list of users assigned to a role."""
        context = _role_admin_context(self)
        role_admin = _resolve_role_admin(context, db_session=db_session)
        return await _list_role_user_page(
            role_admin,
            page_schema_type=context.role_user_page_schema_type,
            role_name=role_name,
            limit=limit,
            offset=offset,
        )

    return cast("RequestBodyRouteHandler", list_role_users)
