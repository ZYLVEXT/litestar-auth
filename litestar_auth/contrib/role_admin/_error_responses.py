"""Error-response helpers for the contrib role-administration controller."""

from __future__ import annotations

from litestar.exceptions import ClientException

from litestar_auth._plugin.role_admin import SQLAlchemyRoleAdmin
from litestar_auth.exceptions import ErrorCode


def _invalid_role_name(detail: str) -> ClientException:
    """Return the invalid-role-name response."""
    return ClientException(status_code=422, detail=detail, extra={"code": ErrorCode.ROLE_NAME_INVALID})


def _role_not_found(detail: str) -> ClientException:
    """Return the missing-role response."""
    return ClientException(status_code=404, detail=detail, extra={"code": ErrorCode.ROLE_NOT_FOUND})


def _role_already_exists(detail: str) -> ClientException:
    """Return the duplicate-role response."""
    return ClientException(status_code=409, detail=detail, extra={"code": ErrorCode.ROLE_ALREADY_EXISTS})


def _role_still_assigned(detail: str) -> ClientException:
    """Return the assigned-role delete refusal response."""
    return ClientException(status_code=409, detail=detail, extra={"code": ErrorCode.ROLE_STILL_ASSIGNED})


def _role_assignment_user_not_found(detail: str) -> ClientException:
    """Return the missing-user response for role-assignment routes."""
    return ClientException(
        status_code=404,
        detail=detail,
        extra={"code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND},
    )


def _normalize_input_role_name(role_name: str) -> str:
    """Normalize one untrusted role name.

    Returns:
        The normalized role name.

    Raises:
        _invalid_role_name: If the normalized role name would be invalid.
    """
    try:
        return SQLAlchemyRoleAdmin.normalized_role_name(role_name)
    except ValueError as exc:
        raise _invalid_role_name(str(exc)) from exc
