# Guards

Use Litestar guards directly in `guards=[...]` route declarations. For the runtime
contract and API reference, see [Guards API](api/guards.md).

## Superuser guard

`is_superuser` requires an authenticated active user and then checks normalized
role membership. By default, the user must expose the `"superuser"` role in
`roles`; set `LitestarAuthConfig.superuser_role_name` when your deployment uses
another normalized role name such as `"admin"`.

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
