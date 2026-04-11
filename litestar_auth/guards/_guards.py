"""Authorization guards for Litestar route handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from litestar_auth._roles import normalize_roles as _normalize_roles
from litestar_auth.types import GuardedUserProtocol, RoleCapableUserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Guard

_ACCOUNT_STATE_DETAIL = "The authenticated user does not expose account state required by this guard."
_ROLE_MEMBERSHIP_DETAIL = "The authenticated user does not expose role membership required by this guard."
_MISSING_ANY_ROLE_DETAIL = "The authenticated user does not have any of the required roles."
_MISSING_ALL_ROLE_DETAIL = "The authenticated user does not have all of the required roles."


def _require_guarded_user(user: object) -> GuardedUserProtocol[Any]:
    """Narrow ``user`` to :class:`GuardedUserProtocol` or raise 403.

    Args:
        user: Connection user object.

    Returns:
        The same instance, narrowed for typed account-state access.

    Raises:
        PermissionDeniedException: When the user is not a guarded-user protocol instance.
    """
    if not isinstance(user, GuardedUserProtocol):
        raise PermissionDeniedException(detail=_ACCOUNT_STATE_DETAIL)
    return user


def _require_role_capable_user(user: object) -> RoleCapableUserProtocol[Any]:
    """Narrow ``user`` to :class:`RoleCapableUserProtocol` or raise 403.

    Args:
        user: Connection user object.

    Returns:
        The same instance, narrowed for typed role access.

    Raises:
        PermissionDeniedException: When the user is not a role-capable protocol instance.
    """
    if not isinstance(user, RoleCapableUserProtocol):
        raise PermissionDeniedException(detail=_ROLE_MEMBERSHIP_DETAIL)
    return user


def _normalize_required_roles(roles: tuple[object, ...]) -> tuple[str, ...]:
    """Normalize configured role names for a role guard factory.

    Args:
        roles: Raw role names passed to ``has_any_role()`` / ``has_all_roles()``.

    Returns:
        Deterministically normalized role names.

    Raises:
        ValueError: If no roles were provided.
    """
    normalized_roles = tuple(_normalize_roles(roles))
    if normalized_roles:
        return normalized_roles

    msg = "Role guards require at least one role."
    raise ValueError(msg)


def _normalized_user_roles(user: object) -> frozenset[str]:
    """Return normalized role membership for a runtime request user.

    Args:
        user: Connection user object.

    Returns:
        Normalized flat role membership.

    Raises:
        PermissionDeniedException: When the user is missing the role-capable contract or exposes
            invalid role data.
    """
    role_capable_user = _require_role_capable_user(user)
    try:
        return frozenset(_normalize_roles(role_capable_user.roles))
    except (TypeError, ValueError) as exc:
        raise PermissionDeniedException(detail=_ROLE_MEMBERSHIP_DETAIL) from exc


def _build_role_guard(*, required_roles: tuple[str, ...], require_all: bool) -> Guard:
    """Build a Litestar-compatible guard for normalized flat role membership.

    Args:
        required_roles: Normalized role names required by the guard.
        require_all: When ``True``, every configured role must be present.

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
            NotAuthorizedException: When no authenticated user is attached to the connection.
            PermissionDeniedException: When the user is inactive, lacks role membership support,
                exposes invalid role data, or does not satisfy the configured role requirement.
        """
        is_active(connection, _handler)
        user = connection.user
        if user is None:
            msg = "Authentication credentials were not provided."
            raise NotAuthorizedException(detail=msg)

        user_roles = _normalized_user_roles(user)
        if require_all:
            if required_role_set.issubset(user_roles):
                return
            raise PermissionDeniedException(detail=_MISSING_ALL_ROLE_DETAIL)

        if user_roles & required_role_set:
            return
        raise PermissionDeniedException(detail=_MISSING_ANY_ROLE_DETAIL)

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

    Raises:
        NotAuthorizedException: Raised when no authenticated user is attached to the connection.
        PermissionDeniedException: Raised when the user does not expose guard account state, or is
            inactive.
    """
    user = connection.user
    if user is None:
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)

    guarded = _require_guarded_user(user)
    if guarded.is_active:
        return

    msg = "The authenticated user is inactive."
    raise PermissionDeniedException(detail=msg)


def is_verified(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Ensure the authenticated user has a verified account.

    Args:
        connection: Incoming ASGI connection (Litestar request scope).
        _handler: Route handler being guarded; unused but required by Litestar guard signature.

    Raises:
        NotAuthorizedException: Raised when no authenticated user is attached to the connection.
        PermissionDeniedException: Raised when the user is missing account state, or is unverified.
    """
    is_active(connection, _handler)
    user = connection.user
    if user is None:
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)
    guarded = _require_guarded_user(user)
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
        NotAuthorizedException: Raised when no authenticated user is attached to the connection.
        PermissionDeniedException: Raised when the user is missing account state, or lacks superuser
            privileges.
    """
    is_active(connection, _handler)
    user = connection.user
    if user is None:
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)
    guarded = _require_guarded_user(user)
    if guarded.is_superuser:
        return

    msg = "The authenticated user does not have sufficient privileges."
    raise PermissionDeniedException(detail=msg)


def has_any_role(*roles: str) -> Guard:
    """Return a guard that requires any configured normalized role.

    The returned guard first enforces the same authenticated-active user contract as
    :func:`is_active`, then compares normalized flat role membership using the same
    trim/lowercase/deduplicate/sort semantics as the model and manager layers.

    Args:
        *roles: Required role names. Values must be non-empty strings after normalization.

    Returns:
        Litestar-compatible guard callable for route ``guards=[...]`` lists.
    """
    return _build_role_guard(required_roles=_normalize_required_roles(roles), require_all=False)


def has_all_roles(*roles: str) -> Guard:
    """Return a guard that requires all configured normalized roles.

    The returned guard first enforces the same authenticated-active user contract as
    :func:`is_active`, then compares normalized flat role membership using the same
    trim/lowercase/deduplicate/sort semantics as the model and manager layers.

    Args:
        *roles: Required role names. Values must be non-empty strings after normalization.

    Returns:
        Litestar-compatible guard callable for route ``guards=[...]`` lists.
    """
    return _build_role_guard(required_roles=_normalize_required_roles(roles), require_all=True)
