"""Protocol-narrowing helpers for authorization guards."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from litestar_auth.types import GuardedUserProtocol, RoleCapableUserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection


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
