"""Public authorization guard exports.

Guards enforce authentication and coarse account state (active, verified,
superuser) on Litestar routes. Role and permission guard factories build direct
``guards=[...]`` callables for normalized authorization checks. All guards are
intended for route ``guards=`` lists and compose with application-specific
authorization policies.
"""

from litestar_auth.guards._api_key_guards import has_any_scope, has_scope, requires_api_key, requires_password_session
from litestar_auth.guards._guards import (
    has_all_roles,
    has_any_role,
    is_active,
    is_authenticated,
    is_superuser,
    is_verified,
)
from litestar_auth.guards._permission_guards import has_all_permissions, has_any_permission, has_permission

__all__ = (
    "has_all_permissions",
    "has_all_roles",
    "has_any_permission",
    "has_any_role",
    "has_any_scope",
    "has_permission",
    "has_scope",
    "is_active",
    "is_authenticated",
    "is_superuser",
    "is_verified",
    "requires_api_key",
    "requires_password_session",
)
