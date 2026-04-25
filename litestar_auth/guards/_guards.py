"""Authorization guards for Litestar route handlers."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from litestar_auth._roles import normalize_role_name as _normalize_role_name
from litestar_auth._roles import normalize_roles as _normalize_roles
from litestar_auth._superuser_role import (
    DEFAULT_SUPERUSER_ROLE_NAME,
    SUPERUSER_ROLE_NAME_SENTINEL,
    normalize_superuser_role_name,
)
from litestar_auth.exceptions import InsufficientRolesError
from litestar_auth.types import GuardedUserProtocol, RoleCapableUserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Guard

RoleNameT = TypeVar("RoleNameT", bound=str)


def _guarded_protocol_denial_detail(guard_name: str) -> str:
    """Build a 403 detail for users that do not implement :class:`GuardedUserProtocol`.

    Returns:
        Human-readable denial message including ``guard_name`` and protocol requirements.
    """
    return (
        f"{guard_name} guard requires GuardedUserProtocol (is_active, is_verified). "
        "The authenticated user does not expose account state required by this guard."
    )


def _role_capable_protocol_denial_detail(guard_name: str) -> str:
    """Build a 403 detail for users that do not implement :class:`RoleCapableUserProtocol`.

    Returns:
        Human-readable denial message including ``guard_name`` and protocol requirements.
    """
    return (
        f"{guard_name} guard requires RoleCapableUserProtocol (roles: Sequence[str]). "
        "The authenticated user does not expose role membership required by this guard."
    )


def _require_guarded_user(user: object, *, guard_name: str = "guard") -> GuardedUserProtocol[Any]:
    """Narrow ``user`` to :class:`GuardedUserProtocol` or raise 403.

    Args:
        user: Connection user object.
        guard_name: Label for the guard or check (included in the denial detail).

    Returns:
        The same instance, narrowed for typed account-state access.

    Raises:
        PermissionDeniedException: When the user is not a guarded-user protocol instance.
    """
    if not isinstance(user, GuardedUserProtocol):
        raise PermissionDeniedException(detail=_guarded_protocol_denial_detail(guard_name))
    return user


def _require_role_capable_user(user: object, *, guard_name: str = "guard") -> RoleCapableUserProtocol[Any]:
    """Narrow ``user`` to :class:`RoleCapableUserProtocol` or raise 403.

    Args:
        user: Connection user object.
        guard_name: Label for the guard or check (included in the denial detail).

    Returns:
        The same instance, narrowed for typed role access.

    Raises:
        PermissionDeniedException: When the user is not a role-capable protocol instance.
    """
    if not isinstance(user, RoleCapableUserProtocol):
        raise PermissionDeniedException(detail=_role_capable_protocol_denial_detail(guard_name))
    return user


def _normalize_required_roles(roles: tuple[object, ...]) -> tuple[str, ...]:
    """Normalize configured role names for a role guard factory.

    Args:
        roles: Raw role names passed to ``has_any_role()`` / ``has_all_roles()``.

    Returns:
        Deterministically normalized role names.

    Raises:
        TypeError: If any provided role is not a string.
        ValueError: If no roles were provided or any role normalizes to an empty string.
    """
    if not roles:
        msg = "Role guards require at least one role."
        raise ValueError(msg)

    normalized_roles: set[str] = set()
    for raw_role in roles:
        if not isinstance(raw_role, str):
            msg = "Roles must be provided as an iterable of non-empty strings."
            raise TypeError(msg)
        try:
            normalized_roles.add(_normalize_role_name(raw_role))
        except ValueError as exc:
            msg = f"Role guards do not accept empty role names after normalization: {raw_role!r}."
            raise ValueError(msg) from exc

    return tuple(sorted(normalized_roles))


def _normalized_user_roles(user: object, *, guard_name: str) -> frozenset[str]:
    """Return normalized role membership for a runtime request user.

    Args:
        user: Connection user object.
        guard_name: Label for the enclosing role guard (included in denial details).

    Returns:
        Normalized flat role membership.

    Raises:
        PermissionDeniedException: When the user is missing the role-capable contract or exposes
            invalid role data.
    """
    role_capable_user = _require_role_capable_user(user, guard_name=guard_name)
    try:
        return frozenset(_normalize_roles(role_capable_user.roles))
    except (TypeError, ValueError) as exc:
        raise PermissionDeniedException(detail=_role_capable_protocol_denial_detail(guard_name)) from exc


def _roles_intersect_fixed_work(user_roles: frozenset[str], required_roles: tuple[str, ...]) -> bool:
    """Return whether any normalized user role matches a required role without early exit."""
    roles_intersect = False
    for required_role in required_roles:
        for user_role in user_roles:
            role_matches = hmac.compare_digest(user_role, required_role)
            roles_intersect = bool(int(roles_intersect) + int(role_matches))
    return roles_intersect


def _roles_include_all_fixed_work(user_roles: frozenset[str], required_roles: tuple[str, ...]) -> bool:
    """Return whether every required role is present in normalized user roles without early exit."""
    includes_all_roles = True
    for required_role in required_roles:
        role_is_present = False
        for user_role in user_roles:
            role_matches = hmac.compare_digest(user_role, required_role)
            role_is_present = bool(int(role_is_present) + int(role_matches))
        includes_all_roles = bool(int(includes_all_roles) * int(role_is_present))
    return includes_all_roles


def _connection_superuser_role_name(connection: ASGIConnection[Any, Any, Any, Any]) -> str:
    """Return the normalized superuser role name from request scope state.

    Plugin-managed requests store the configured value in ``scope["state"]``. Direct
    guard usage outside the plugin falls back to the canonical default.

    Raises:
        PermissionDeniedException: When plugin state contains an invalid role name.
    """
    scope_state = connection.scope.get("state")
    if not isinstance(scope_state, Mapping):
        return DEFAULT_SUPERUSER_ROLE_NAME

    raw_role_name = scope_state.get(SUPERUSER_ROLE_NAME_SENTINEL, DEFAULT_SUPERUSER_ROLE_NAME)
    if not isinstance(raw_role_name, str):
        msg = "The configured superuser role name is invalid."
        raise PermissionDeniedException(detail=msg)

    try:
        return normalize_superuser_role_name(raw_role_name)
    except ValueError as exc:
        msg = "The configured superuser role name is invalid."
        raise PermissionDeniedException(detail=msg) from exc


def _require_active_guarded_user(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    guard_name: str = "guard",
) -> GuardedUserProtocol[Any]:
    """Enforce authenticated, guard-protocol, and active-user contract.

    Centralizes the logic shared by :func:`is_active`, :func:`is_verified`,
    :func:`is_superuser`, and role guards: require ``connection.user``, narrow to
    :class:`GuardedUserProtocol`, and assert ``is_active``.

    Args:
        connection: Incoming ASGI connection (Litestar request scope).
        guard_name: Label for the guard (included when the user lacks :class:`GuardedUserProtocol`).

    Returns:
        The connection user narrowed to an active :class:`GuardedUserProtocol`.

    Raises:
        NotAuthorizedException: When no authenticated user is attached to the connection.
        PermissionDeniedException: When the user does not expose guard account state, or is
            inactive.
    """
    user = connection.user
    if user is None:
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)

    guarded = _require_guarded_user(user, guard_name=guard_name)
    if guarded.is_active:
        return guarded

    msg = "The authenticated user is inactive."
    raise PermissionDeniedException(detail=msg)


def _build_role_guard(
    *,
    required_roles: tuple[str, ...],
    require_all: bool,
    guard_name: str,
) -> Guard:
    """Build a Litestar-compatible guard for normalized flat role membership.

    Args:
        required_roles: Normalized role names required by the guard.
        require_all: When ``True``, every configured role must be present.
        guard_name: ``has_any_role`` or ``has_all_roles`` (included in protocol denial details).

    Returns:
        Guard callable suitable for Litestar ``guards=[...]`` lists.
    """
    required_role_set = frozenset(required_roles)

    def _guard(
        connection: ASGIConnection[Any, Any, Any, Any],
        _handler: BaseRouteHandler,
    ) -> None:
        """Enforce normalized flat role membership on an authenticated active user.

        Raises:
            InsufficientRolesError: When the user does not satisfy the configured role
                requirement.

        Note:
            :func:`_require_active_guarded_user` may raise :exc:`NotAuthorizedException` when no user
            is present on the connection, and downstream helpers may raise
            :exc:`PermissionDeniedException` for inactive users or invalid role-capable contracts.
        """
        guarded = _require_active_guarded_user(connection, guard_name=guard_name)
        user_roles = _normalized_user_roles(guarded, guard_name=guard_name)
        if require_all:
            if _roles_include_all_fixed_work(user_roles, required_roles):
                return
            raise InsufficientRolesError(
                required_roles=required_role_set,
                user_roles=user_roles,
                require_all=True,
            )

        if _roles_intersect_fixed_work(user_roles, required_roles):
            return
        raise InsufficientRolesError(
            required_roles=required_role_set,
            user_roles=user_roles,
            require_all=False,
        )

    return _guard


def is_authenticated(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Ensure the request has an authenticated user.

    Args:
        connection: Incoming ASGI connection (Litestar request scope).
        _handler: Route handler being guarded; unused but required by Litestar guard signature.

    Raises:
        NotAuthorizedException: Raised when no authenticated user is attached to the connection.
    """
    if connection.user is not None:
        return

    msg = "Authentication credentials were not provided."
    raise NotAuthorizedException(detail=msg)


def is_active(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Ensure the authenticated user is active.

    Args:
        connection: Incoming ASGI connection (Litestar request scope).
        _handler: Route handler being guarded; unused but required by Litestar guard signature.

    Note:
        Delegates to :func:`_require_active_guarded_user` for exceptions.
    """
    _require_active_guarded_user(connection, guard_name="is_active")


def is_verified(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Ensure the authenticated user has a verified account.

    Args:
        connection: Incoming ASGI connection (Litestar request scope).
        _handler: Route handler being guarded; unused but required by Litestar guard signature.

    Raises:
        PermissionDeniedException: Raised when the user is unverified.

    Note:
        :func:`_require_active_guarded_user` may raise :exc:`NotAuthorizedException` when no user is
        present, or :exc:`PermissionDeniedException` for missing account state or inactive users.
    """
    guarded = _require_active_guarded_user(connection, guard_name="is_verified")
    if guarded.is_verified:
        return

    msg = "The authenticated user is not verified."
    raise PermissionDeniedException(detail=msg)


def is_superuser(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Ensure the authenticated user has superuser privileges.

    Args:
        connection: Incoming ASGI connection (Litestar request scope).
        _handler: Route handler being guarded; unused but required by Litestar guard signature.

    Raises:
        PermissionDeniedException: Raised when the user lacks superuser privileges.

    Note:
        :func:`_require_active_guarded_user` may raise :exc:`NotAuthorizedException` when no user is
        present, or :exc:`PermissionDeniedException` for missing account state or inactive users.
    """
    guarded = _require_active_guarded_user(connection, guard_name="is_superuser")
    user_roles = _normalized_user_roles(guarded, guard_name="is_superuser")
    superuser_role_name = _connection_superuser_role_name(connection)
    if _roles_intersect_fixed_work(user_roles, (superuser_role_name,)):
        return

    msg = "The authenticated user does not have sufficient privileges."
    raise PermissionDeniedException(detail=msg)


def has_any_role[RoleNameT: str](*roles: RoleNameT) -> Guard:
    """Return a guard that requires any configured normalized role.

    The returned guard first enforces the same authenticated-active user contract as
    :func:`is_active`, then compares the normalized flat role membership exposed by
    the authenticated user against the configured roles. Both sides use the same
    trim/lowercase/deduplicate/sort semantics as the model and manager layers.

    Args:
        *roles: Required role names. At least one role must be provided. Each value is
            normalized with trim/lowercase/deduplicate/sort semantics, and empty or
            whitespace-only role names are rejected at guard-build time.

    Returns:
        Litestar-compatible guard callable for route ``guards=[...]`` lists.
    """
    return _build_role_guard(
        required_roles=_normalize_required_roles(roles),
        require_all=False,
        guard_name="has_any_role",
    )


def has_all_roles[RoleNameT: str](*roles: RoleNameT) -> Guard:
    """Return a guard that requires all configured normalized roles.

    The returned guard first enforces the same authenticated-active user contract as
    :func:`is_active`, then compares the normalized flat role membership exposed by
    the authenticated user against the configured roles. Both sides use the same
    trim/lowercase/deduplicate/sort semantics as the model and manager layers.

    Args:
        *roles: Required role names. At least one role must be provided. Each value is
            normalized with trim/lowercase/deduplicate/sort semantics, and empty or
            whitespace-only role names are rejected at guard-build time.

    Returns:
        Litestar-compatible guard callable for route ``guards=[...]`` lists.
    """
    return _build_role_guard(
        required_roles=_normalize_required_roles(roles),
        require_all=True,
        guard_name="has_all_roles",
    )
