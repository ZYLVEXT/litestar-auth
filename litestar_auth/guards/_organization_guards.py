"""Organization-scoped authorization guards."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Never, TypeVar

from litestar.exceptions import PermissionDeniedException

from litestar_auth._current_organization import read_scope_current_organization_context
from litestar_auth._organization_authz import resolve_current_organization_roles
from litestar_auth._permissions import resolve_connection_permissions
from litestar_auth.exceptions import (
    ErrorCode,
    InsufficientOrganizationPermissionsError,
    InsufficientOrganizationRolesError,
)
from litestar_auth.guards._api_key_guards import api_key_delegation_scopes
from litestar_auth.guards._guards import _normalize_required_roles, _roles_include_all_fixed_work
from litestar_auth.guards._permission_guards import _normalize_required_permissions, _permissions_include_all
from litestar_auth.guards._protocol_narrowing import _require_active_guarded_user, _require_role_capable_user

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Guard

OrganizationPermissionNameT = TypeVar("OrganizationPermissionNameT", bound=str)
OrganizationRoleNameT = TypeVar("OrganizationRoleNameT", bound=str)

_ORGANIZATION_MEMBERSHIP_REQUIRED_DETAIL = "The route requires a verified organization membership."


def _raise_organization_membership_denied() -> Never:
    raise PermissionDeniedException(
        detail=_ORGANIZATION_MEMBERSHIP_REQUIRED_DETAIL,
        extra={"code": ErrorCode.AUTHORIZATION_DENIED},
    )


def requires_organization_membership(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Require the authenticated active user to have a verified current organization."""
    _require_active_guarded_user(connection, guard_name="requires_organization_membership")
    if read_scope_current_organization_context(connection) is not None:
        return
    _raise_organization_membership_denied()


def has_organization_role[OrganizationRoleNameT: str](*roles: OrganizationRoleNameT) -> Guard:
    """Return a guard that requires organization-scoped membership roles."""
    required_roles = _normalize_required_roles(roles)
    required_role_set = frozenset(required_roles)

    def _guard(
        connection: ASGIConnection[Any, Any, Any, Any],
        _handler: BaseRouteHandler,
    ) -> None:
        _require_active_guarded_user(connection, guard_name="has_organization_role")
        organization_roles = resolve_current_organization_roles(connection)
        if organization_roles is not None and _roles_include_all_fixed_work(organization_roles, required_roles):
            return
        raise InsufficientOrganizationRolesError(
            required_roles=required_role_set,
            user_roles=organization_roles or frozenset(),
            require_all=True,
        )

    return _guard


def has_organization_permission[OrganizationPermissionNameT: str](
    *permissions: OrganizationPermissionNameT,
) -> Guard:
    """Return a guard that requires organization-scoped effective permissions."""
    required_permissions = _normalize_required_permissions(permissions)
    required_permission_set = frozenset(required_permissions)

    def _guard(
        connection: ASGIConnection[Any, Any, Any, Any],
        _handler: BaseRouteHandler,
    ) -> None:
        guarded = _require_active_guarded_user(connection, guard_name="has_organization_permission")
        _require_role_capable_user(guarded, guard_name="has_organization_permission")
        if resolve_current_organization_roles(connection) is None:
            raise InsufficientOrganizationPermissionsError(
                required_permissions=required_permission_set,
                granted_permissions=frozenset(),
                require_all=True,
            )

        granted_permissions = resolve_connection_permissions(connection)
        if _permissions_include_all(granted_permissions, api_key_delegation_scopes(connection), required_permissions):
            return
        raise InsufficientOrganizationPermissionsError(
            required_permissions=required_permission_set,
            granted_permissions=granted_permissions,
            require_all=True,
        )

    return _guard


__all__ = ("has_organization_permission", "has_organization_role", "requires_organization_membership")
