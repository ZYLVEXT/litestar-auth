"""Error-response helpers for the contrib organization-admin controller."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.exceptions import ClientException

from litestar_auth.exceptions import (
    ErrorCode,
    ExpiredOrganizationInvitationTokenError,
    InvalidOrganizationInvitationTokenError,
    OrganizationAlreadyExistsError,
    OrganizationInvitationEmailMismatchError,
    OrganizationLastPrivilegedMemberError,
    OrganizationMembershipAlreadyExistsError,
    OrganizationMembershipNotFoundError,
    OrganizationNotFoundError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_ORGANIZATION_NOT_FOUND_DETAIL = "Organization not found."
_ORGANIZATION_MEMBERSHIP_NOT_FOUND_DETAIL = "Organization membership not found."
_ORGANIZATION_INVITATION_DENIED_DETAIL = "Organization invitation cannot be used."


def _organization_not_found() -> ClientException:
    return ClientException(
        status_code=404,
        detail=_ORGANIZATION_NOT_FOUND_DETAIL,
        extra={"code": ErrorCode.ORGANIZATION_NOT_FOUND},
    )


def _organization_already_exists() -> ClientException:
    return ClientException(
        status_code=409,
        detail="Organization already exists.",
        extra={"code": ErrorCode.ORGANIZATION_ALREADY_EXISTS},
    )


def _organization_membership_not_found() -> ClientException:
    return ClientException(
        status_code=404,
        detail=_ORGANIZATION_MEMBERSHIP_NOT_FOUND_DETAIL,
        extra={"code": ErrorCode.ORGANIZATION_MEMBERSHIP_NOT_FOUND},
    )


def _organization_membership_already_exists() -> ClientException:
    return ClientException(
        status_code=409,
        detail="Organization membership already exists.",
        extra={"code": ErrorCode.ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS},
    )


def _organization_last_privileged_member() -> ClientException:
    return ClientException(
        status_code=409,
        detail="Organization must retain at least one privileged member.",
        extra={"code": ErrorCode.ORGANIZATION_LAST_PRIVILEGED_MEMBER},
    )


def _organization_invitation_invalid() -> ClientException:
    return ClientException(
        status_code=400,
        detail=_ORGANIZATION_INVITATION_DENIED_DETAIL,
        extra={"code": ErrorCode.ORGANIZATION_INVITATION_INVALID},
    )


def _organization_invitation_expired() -> ClientException:
    return ClientException(
        status_code=400,
        detail=_ORGANIZATION_INVITATION_DENIED_DETAIL,
        extra={"code": ErrorCode.ORGANIZATION_INVITATION_EXPIRED},
    )


def _organization_invitation_email_mismatch() -> ClientException:
    return ClientException(
        status_code=400,
        detail=_ORGANIZATION_INVITATION_DENIED_DETAIL,
        extra={"code": ErrorCode.ORGANIZATION_INVITATION_EMAIL_MISMATCH},
    )


_ERROR_RESPONSE_FACTORIES: dict[type[Exception], Callable[[], ClientException]] = {
    OrganizationAlreadyExistsError: _organization_already_exists,
    OrganizationNotFoundError: _organization_not_found,
    OrganizationMembershipAlreadyExistsError: _organization_membership_already_exists,
    OrganizationMembershipNotFoundError: _organization_membership_not_found,
    OrganizationLastPrivilegedMemberError: _organization_last_privileged_member,
    ExpiredOrganizationInvitationTokenError: _organization_invitation_expired,
    OrganizationInvitationEmailMismatchError: _organization_invitation_email_mismatch,
    InvalidOrganizationInvitationTokenError: _organization_invitation_invalid,
}


def _map_organization_admin_error(exc: Exception) -> ClientException:
    """Return the stable non-enumerating HTTP response for an organization-admin error."""
    for error_type, response_factory in _ERROR_RESPONSE_FACTORIES.items():
        if isinstance(exc, error_type):
            return response_factory()
    raise exc


__all__ = ("_map_organization_admin_error",)
