# Guards

Use Litestar guards directly in `guards=[...]` route declarations. For the runtime
contract and API reference, see [Guards API](api/guards.md).

## Superuser guard

`is_superuser` requires an authenticated active user and then checks normalized
role membership. By default, the user must expose the `"superuser"` role in
`roles`; set `LitestarAuthConfig.superuser_role_name` when your deployment uses
another normalized role name such as `"admin"`.

## Organization membership guard

`requires_organization_membership` requires an authenticated active user and a verified
current-organization context for the request. It fails closed with
`ErrorCode.AUTHORIZATION_DENIED` when the request is anonymous, the user is inactive, the request
does not carry a tenant hint, the tenant hint does not resolve to an organization, or the
authenticated user has no membership in that organization.

```python
from litestar import get

from litestar_auth.guards import requires_organization_membership


@get("/organization/projects", guards=[requires_organization_membership])
async def list_organization_projects() -> dict[str, bool]:
    return {"ok": True}
```

Tenant hints from headers or subdomains are untrusted. The guard allows the request only after the
authentication middleware has resolved the organization and verified the authenticated user's
membership through the configured organization store.

Use the `litestar_auth_current_organization` dependency when a handler needs the verified
organization and membership objects:

```python
from typing import Any

from litestar import get

from litestar_auth.guards import requires_organization_membership


@get("/organization/me", guards=[requires_organization_membership])
async def read_current_organization(
    litestar_auth_current_organization: Any,
) -> dict[str, str]:
    return {
        "organization_id": str(litestar_auth_current_organization.organization.id),
        "membership_id": str(litestar_auth_current_organization.membership.id),
    }
```

This guard only verifies membership in the resolved current organization. Use the organization role
and permission guards below when a route also requires membership roles or role-derived permissions.
Application-owned tables still need explicit tenant foreign keys, query filters, and database
isolation.

## Organization role guards

`has_organization_role()` requires an authenticated active user, a verified current-organization
context, and all listed roles on that membership row. It does not read the user's global `roles`.
Without verified organization context it fails closed with
`ErrorCode.INSUFFICIENT_ORGANIZATION_ROLES`.

```python
from litestar import get

from litestar_auth.guards import has_organization_role


@get("/organization/billing", guards=[has_organization_role("billing-admin")])
async def organization_billing() -> dict[str, bool]:
    return {"ok": True}
```

Role names use the same trim, lowercase, deduplicate, and sort normalization as global role guards.
At least one role is required, and empty role names are rejected when the guard is created.

## Organization permission guards

`has_organization_permission()` requires an authenticated active role-capable user, a verified
current-organization context, and all listed effective permissions after organization-aware role
resolution. Without verified organization context it fails closed with
`ErrorCode.INSUFFICIENT_ORGANIZATION_PERMISSIONS`.

```python
from litestar import get

from litestar_auth.guards import has_organization_permission


@get("/organization/posts", guards=[has_organization_permission("posts:write")])
async def write_organization_posts() -> dict[str, bool]:
    return {"ok": True}
```

When the request is authenticated with an API key, organization permission guards keep the same
least-privilege ceiling as general permission guards: the owning user's organization-scoped
effective permissions must grant the route requirement, and the key scopes must delegate it.

## Typed role guards

`has_any_role()` and `has_all_roles()` accept plain strings, but their Python 3.12
generic signatures also preserve narrower string subtypes. That means you can keep
role names IDE-discoverable and type-checkable instead of scattering ad-hoc string
literals through your codebase.

### Plain strings

Plain strings remain valid and keep the existing runtime behavior:

```python
from litestar import get

from litestar_auth.guards import has_any_role


@get("/reports", guards=[has_any_role("admin", "billing")])
async def reports_dashboard() -> dict[str, bool]:
    return {"ok": True}
```

### `Literal` role aliases

Use `Literal[...]` when your project has a small fixed role vocabulary and you want
type checkers to catch misspellings at call sites:

```python
from typing import Literal

from litestar_auth.guards import has_any_role

type AppRole = Literal["admin", "billing", "support"]

ADMIN: AppRole = "admin"
BILLING: AppRole = "billing"

reports_guard = has_any_role(ADMIN, BILLING)
```

### `StrEnum` role registries

Use `StrEnum` when you want a central registry that still behaves like strings at
runtime:

```python
from enum import StrEnum

from litestar_auth.guards import has_all_roles


class AppRole(StrEnum):
    ADMIN = "admin"
    BILLING = "billing"
    SUPPORT = "support"


finance_guard = has_all_roles(AppRole.ADMIN, AppRole.BILLING)
```

## Normalization and rejection rules

Role guards normalize configured role names with trim, lowercase, deduplicate, and
sort semantics before matching against the authenticated user's normalized flat role
membership.

Internally, `has_any_role()` and `has_all_roles()` compare normalized role strings
with fixed-work loops rather than set-intersection or subset short-circuit
predicates. This preserves the same flat-role behavior while documenting the
library's defense-in-depth posture; it is not a cryptographic constant-time
guarantee for the full Python runtime or request path.

Invalid guard definitions fail fast during application setup instead of waiting for
the first request:

- At least one role is required.
- Empty or whitespace-only role names are rejected with `ValueError`.

That means `has_any_role(" Admin ", "admin")` collapses to one normalized
requirement, while `has_any_role("   ")` is rejected immediately.

## Permission guards

`has_permission()`, `has_all_permissions()`, and `has_any_permission()` authorize
against the authenticated user's resolved effective permissions. They require the
same account shape as role guards: the request must have an authenticated active
user whose model exposes flat `roles` membership. Permission resolution then comes
from the plugin's request-scope `PermissionResolver`.

When the request is authenticated with an **API key**, permission guards apply the
key's scopes as a least-privilege ceiling: a requirement is satisfied only when the
owning user grants it **and** the key's own scopes delegate it. A scoped key can
therefore never exceed its delegation on a permission-guarded route, mirroring the
`scope_subset_check` ceiling used by scope guards — even for a superuser owner. Keys
whose scopes are legacy simple names (no `resource:action` grammar) or are empty
carry no permission-shaped authority and fail closed on permission guards; use
`has_scope()` for those keys, or `requires_password_session` to exclude API keys
from a route entirely.

```python
from litestar import get

from litestar_auth.guards import has_any_permission, has_permission


@get("/posts", guards=[has_permission("posts:read")])
async def list_posts() -> dict[str, bool]:
    return {"ok": True}


@get("/moderation", guards=[has_any_permission("posts:moderate", "comments:moderate")])
async def moderation_queue() -> dict[str, bool]:
    return {"ok": True}
```

Use `has_permission()` or `has_all_permissions()` when every listed permission is
required. Use `has_any_permission()` when any one listed permission is enough.

When a verified current-organization context is present, the same permission guards become
organization-aware automatically. With the default `OrganizationConfig.role_precedence="replace"`,
membership roles from the current organization replace the user's global roles for permission
resolution, so broad global roles do not leak into tenant-scoped requests. The configured
`superuser_role_name` remains a global grant: a user holding that global role resolves to `"*"` even
inside an organization. Set `OrganizationConfig.role_precedence="merge"` only when your application
intentionally wants global roles and organization membership roles to combine inside org context.
Set `OrganizationConfig.require_authorization_context=True` when permission guards should fail
closed unless the request has verified organization context.

The `replace` default is the safer tenant-isolation posture for most deployments: an organization
permission guard is satisfied only by roles on the verified membership row, except for the explicit
global superuser grant. With `role_precedence="merge"`, every global role on the user is unioned with
the membership roles for each organization the user belongs to. That means a global permission such
as `posts:write` can satisfy `has_organization_permission("posts:write")` in every verified
organization context for that user, not just one tenant. Choose `merge` only when that cross-tenant
global-role behavior is intentional and understood by operators.

Permission strings normalize with the same trim, lowercase, deduplicate, and sort
rules as role names, then must match one of these forms:

- `resource:action` for ordinary route requirements and grants.
- `resource:*` for a grant that covers every action on one resource.
- `*` for the global grant.

Route requirements cannot be wildcards: `has_permission("posts:*")` and
`has_permission("*")` fail closed because a route should name the concrete action it
requires. Wildcards belong on the granted side through `role_permissions` or a
custom resolver. For example, `posts:*` grants `posts:read` and `posts:write`; `*`
grants every concrete permission requirement.

### Configure static role permissions

For simple role-derived authorization, configure `LitestarAuthConfig.role_permissions`.
The field defaults to an empty mapping, so permission guards deny non-superuser
users until you configure grants or provide a custom resolver.

```python
from uuid import UUID

from litestar_auth import LitestarAuthConfig
from litestar_auth.models import User


config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    backends=[jwt_backend],
    role_permissions={
        "editor": ("posts:read", "posts:write"),
        "auditor": ("reports:read",),
        "content-admin": ("posts:*", "comments:*"),
    },
)
```

The configured `superuser_role_name` still acts as a global bypass. A user with that
normalized role resolves to the `"*"` grant, so permission guards allow every
concrete permission requirement without listing each permission in `role_permissions`.

### Use resolved permissions as dependency data

The plugin also registers a `litestar_auth_permissions` dependency. It returns a
`frozenset[str]` from the same request-scope resolver that guards use, or an empty
set for anonymous requests.

```python
from litestar import get


@get("/me/permissions")
async def read_my_permissions(litestar_auth_permissions: frozenset[str]) -> dict[str, list[str]]:
    return {"permissions": sorted(litestar_auth_permissions)}
```

Use this dependency for response shaping or UI hints, not as a replacement for
route guards on protected operations.

### API-key scopes share the permission vocabulary

API-key scope guards still read scopes from `request.auth`, but permission-shaped
scopes now use the same `resource:action`, `resource:*`, and `*` semantics. With
`scope_subset_check=True`, a delegated API key must be covered by the owning user's
currently resolved permissions, so revoking the user's underlying permission also
removes the key's effective route access.

Legacy simple scopes without `:` keep the previous exact scopes-as-role-names
downscoping rule for migration. New deployments should prefer permission-shaped
API-key scopes and matching route requirements.
