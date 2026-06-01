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


def test_error_code_registry_contains_every_aggregate_member() -> None:
    """The registry remains complete for all aggregate error codes."""
    assert set(ERROR_CODE_REGISTRY) == set(ErrorCode)
