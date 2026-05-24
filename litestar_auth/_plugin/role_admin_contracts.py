"""Shared role-admin value and error contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UserRoleMembership:
    """Normalized role membership for one CLI-targeted user."""

    email: str
    roles: list[str]


class RoleAdminRoleNotFoundError(LookupError):
    """Raised when the configured role catalog does not contain the requested role."""


class RoleAdminUserNotFoundError(LookupError):
    """Raised when the configured user lookup target does not exist."""


class RoleProtectedError(ValueError):
    """Raised when a role-admin operation targets a protected role."""


class SystemManagedRoleError(RoleProtectedError):
    """Raised when an operation would weaken a plugin-managed role invariant."""
