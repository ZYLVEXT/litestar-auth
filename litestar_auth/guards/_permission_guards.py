"""Permission-based authorization guard factories."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from litestar_auth._permissions import (
    normalize_permission_name,
    permission_grants_fixed_work,
    resolve_connection_permissions,
)
from litestar_auth.exceptions import InsufficientPermissionsError
from litestar_auth.guards._protocol_narrowing import _require_active_guarded_user, _require_role_capable_user

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Guard

PermissionNameT = TypeVar("PermissionNameT", bound=str)


def _normalize_required_permissions(permissions: tuple[object, ...]) -> tuple[str, ...]:
    """Normalize configured permission names for a permission guard factory.

    Returns:
        Deterministically normalized permission names.

    Raises:
        TypeError: If any configured permission is not a string.
        ValueError: If no permissions are provided or any permission is malformed.
    """
    if not permissions:
        msg = "Permission guards require at least one permission."
        raise ValueError(msg)

    normalized_permissions: set[str] = set()
    for raw_permission in permissions:
        if not isinstance(raw_permission, str):
            msg = "Permissions must be provided as non-empty strings."
            raise TypeError(msg)
        try:
            normalized_permissions.add(normalize_permission_name(raw_permission))
        except ValueError as exc:
            msg = f"Permission guards do not accept invalid permission names: {raw_permission!r}."
            raise ValueError(msg) from exc

    return tuple(sorted(normalized_permissions))


def _requirement_satisfied(
    granted_permissions: frozenset[str],
    required_permission: str,
) -> bool:
    """Return whether one requirement is satisfied by the authenticated human."""
    return permission_grants_fixed_work(granted_permissions, required_permission)


def _permissions_include_all(
    granted_permissions: frozenset[str],
    required_permissions: tuple[str, ...],
) -> bool:
    """Return whether every required permission is satisfied, without early exit.

    Mirrors ``_roles_include_all_fixed_work``: every requirement is evaluated so
    authorization timing does not depend on which requirement first fails.
    """
    includes_all = True
    for required_permission in required_permissions:
        requirement_satisfied = _requirement_satisfied(granted_permissions, required_permission)
        includes_all = bool(int(includes_all) * int(requirement_satisfied))
    return includes_all


def _permissions_intersect(
    granted_permissions: frozenset[str],
    required_permissions: tuple[str, ...],
) -> bool:
    """Return whether any required permission is satisfied, without early exit.

    Mirrors ``_roles_intersect_fixed_work``: every requirement is evaluated so
    authorization timing does not depend on which requirement first succeeds.
    """
    intersects = False
    for required_permission in required_permissions:
        requirement_satisfied = _requirement_satisfied(granted_permissions, required_permission)
        intersects = bool(int(intersects) + int(requirement_satisfied))
    return intersects


def _build_permission_guard(
    *,
    required_permissions: tuple[str, ...],
    require_all: bool,
    guard_name: str,
) -> Guard:
    """Build a Litestar-compatible guard for effective permission membership.

    Returns:
        Guard callable suitable for Litestar ``guards=[...]`` lists.
    """
    required_permission_set = frozenset(required_permissions)

    def _guard(
        connection: ASGIConnection[Any, Any, Any, Any],
        _handler: BaseRouteHandler,
    ) -> None:
        """Enforce resolved effective permissions on an authenticated active user.

        Raises:
            InsufficientPermissionsError: When the user does not satisfy the configured permission requirement.
        """
        guarded = _require_active_guarded_user(connection, guard_name=guard_name)
        _require_role_capable_user(guarded, guard_name=guard_name)
        granted_permissions = resolve_connection_permissions(connection)
        if require_all:
            if _permissions_include_all(granted_permissions, required_permissions):
                return
            raise InsufficientPermissionsError(
                required_permissions=required_permission_set,
                granted_permissions=granted_permissions,
                require_all=True,
            )

        if _permissions_intersect(granted_permissions, required_permissions):
            return
        raise InsufficientPermissionsError(
            required_permissions=required_permission_set,
            granted_permissions=granted_permissions,
            require_all=False,
        )

    return _guard


def has_permission[PermissionNameT: str](*permissions: PermissionNameT) -> Guard:
    """Return a guard that requires every configured permission.

    Conjunctive permission check: the request is allowed only when the user's
    effective permissions satisfy every argument. :func:`has_all_permissions` is
    the explicit-name alias provided for symmetry with :func:`has_any_permission`.
    """
    return _build_permission_guard(
        required_permissions=_normalize_required_permissions(permissions),
        require_all=True,
        guard_name="has_permission",
    )


def has_all_permissions[PermissionNameT: str](*permissions: PermissionNameT) -> Guard:
    """Return a guard that requires every configured permission.

    Explicit-name alias of :func:`has_permission` that reads symmetrically next to
    :func:`has_any_permission`; both apply identical conjunctive semantics.
    """
    return _build_permission_guard(
        required_permissions=_normalize_required_permissions(permissions),
        require_all=True,
        guard_name="has_all_permissions",
    )


def has_any_permission[PermissionNameT: str](*permissions: PermissionNameT) -> Guard:
    """Return a guard that requires at least one configured permission."""
    return _build_permission_guard(
        required_permissions=_normalize_required_permissions(permissions),
        require_all=False,
        guard_name="has_any_permission",
    )
