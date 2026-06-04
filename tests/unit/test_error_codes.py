"""Tests for machine-readable error-code registry consistency."""

from __future__ import annotations

import pytest

from litestar_auth._error_codes import ERROR_CODE_REGISTRY, ErrorCode, RoleErrorCode

pytestmark = pytest.mark.unit


def test_insufficient_permissions_error_code_is_registered_with_role_codes() -> None:
    """Permission-denial code is exposed through the group enum, aggregate enum, and registry."""
    assert RoleErrorCode.INSUFFICIENT_PERMISSIONS.value == "INSUFFICIENT_PERMISSIONS"
    assert ErrorCode.INSUFFICIENT_PERMISSIONS.value == "INSUFFICIENT_PERMISSIONS"
    assert ERROR_CODE_REGISTRY[ErrorCode.INSUFFICIENT_PERMISSIONS] is RoleErrorCode.INSUFFICIENT_PERMISSIONS
    assert "InsufficientPermissionsError" in (RoleErrorCode.INSUFFICIENT_PERMISSIONS.__doc__ or "")


def test_organization_guard_error_codes_are_registered_with_role_codes() -> None:
    """Organization denial codes are exposed through the group enum, aggregate enum, and registry."""
    assert RoleErrorCode.INSUFFICIENT_ORGANIZATION_ROLES.value == "INSUFFICIENT_ORGANIZATION_ROLES"
    assert ErrorCode.INSUFFICIENT_ORGANIZATION_ROLES.value == "INSUFFICIENT_ORGANIZATION_ROLES"
    assert (
        ERROR_CODE_REGISTRY[ErrorCode.INSUFFICIENT_ORGANIZATION_ROLES] is RoleErrorCode.INSUFFICIENT_ORGANIZATION_ROLES
    )
    assert (
        ERROR_CODE_REGISTRY[ErrorCode.INSUFFICIENT_ORGANIZATION_PERMISSIONS]
        is RoleErrorCode.INSUFFICIENT_ORGANIZATION_PERMISSIONS
    )
    assert "InsufficientOrganizationRolesError" in (RoleErrorCode.INSUFFICIENT_ORGANIZATION_ROLES.__doc__ or "")
    assert "InsufficientOrganizationPermissionsError" in (
        RoleErrorCode.INSUFFICIENT_ORGANIZATION_PERMISSIONS.__doc__ or ""
    )


@pytest.mark.parametrize(
    ("code_name", "emitter"),
    [
        ("ORGANIZATION_ALREADY_EXISTS", "organization-admin create conflicts"),
        ("ORGANIZATION_NOT_FOUND", "organization-admin lookup failures"),
        ("ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS", "organization-admin duplicate membership failures"),
        ("ORGANIZATION_MEMBERSHIP_NOT_FOUND", "organization-admin membership lookup failures"),
        ("ORGANIZATION_LAST_PRIVILEGED_MEMBER", "organization-admin last privileged member protection"),
        ("ORGANIZATION_INVITATION_INVALID", "InvalidOrganizationInvitationTokenError"),
        ("ORGANIZATION_INVITATION_EXPIRED", "ExpiredOrganizationInvitationTokenError"),
    ],
)
def test_organization_admin_error_codes_are_registered_with_role_codes(code_name: str, emitter: str) -> None:
    """Organization-admin codes are exposed through the group enum, aggregate enum, and registry."""
    role_code = RoleErrorCode[code_name]
    aggregate_code = ErrorCode[code_name]

    assert role_code.value == code_name
    assert aggregate_code.value == code_name
    assert ERROR_CODE_REGISTRY[aggregate_code] is role_code
    assert emitter in (role_code.__doc__ or "")


def test_error_code_registry_contains_every_aggregate_member() -> None:
    """The registry remains complete for all aggregate error codes."""
    assert set(ERROR_CODE_REGISTRY) == set(ErrorCode)
