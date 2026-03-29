"""Authorization guards for Litestar route handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from litestar_auth.types import GuardedUserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler

_ACCOUNT_STATE_DETAIL = "The authenticated user does not expose account state required by this guard."


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
