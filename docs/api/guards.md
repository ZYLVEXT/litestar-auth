# Guards

Custom user models must expose the typing protocols that match the guards you use—see
[Types and protocols — Which protocol should my user model implement?](types.md#which-protocol-should-my-user-model-implement)
for a feature-to-protocol decision table (`UserProtocol`, `GuardedUserProtocol`,
`RoleCapableUserProtocol`, `TotpUserProtocol`).

Use these callables directly in Litestar `guards=[...]` lists. The role-guard
factories `has_any_role(*roles)` and `has_all_roles(*roles)` require an
authenticated active user, fail closed when `request.user` does not satisfy the
role-capable contract, and compare both configured roles and user roles with the
same normalization rules used by the model and manager layers (trimmed,
lowercased, deduplicated flat strings).

Permission guard factories use the same Litestar guard shape:

- `has_permission(*permissions)` requires every listed permission.
- `has_all_permissions(*permissions)` is the explicit all-of alias.
- `has_any_permission(*permissions)` requires at least one listed permission.

They require an authenticated active role-capable user, resolve effective
permissions through the request-scope permission resolver, and raise
`InsufficientPermissionsError` / `INSUFFICIENT_PERMISSIONS` when access is denied.
Configured requirements must be concrete `resource:action` tokens. Granted
permissions may use `resource:*` or `*`; the configured superuser role resolves to
the global `*` grant.

API-key guards operate on `ApiKeyContext` from `request.auth`:

- `requires_api_key` accepts only API-key-authenticated requests.
- `has_scope(*scopes)` requires every listed key scope and, when the key context was issued with
  `scope_subset_check=True`, still downscopes by the current user's authority.
- `has_any_scope(*scopes)` requires at least one listed key scope and, when the key context was
  issued with `scope_subset_check=True`, still downscopes by current user authority.
- `requires_password_session` rejects API-key callers and is used on self-service API-key
  create/update/revoke routes plus other credential-rotation boundaries.

Permission-shaped API-key scopes share the permission grammar and wildcard matcher:
`reports:*` grants `reports:read`, and `*` grants every concrete permission-shaped
scope. With `scope_subset_check=True`, the default scope authority requires those
delegated grants to be covered by the owning user's resolved permissions. Legacy
simple scopes without `:` keep the exact scopes-as-role-names check for migration.

```python
from litestar import get

from litestar_auth.guards import (
    has_all_permissions,
    has_all_roles,
    has_any_permission,
    has_any_role,
    has_scope,
    is_verified,
    requires_api_key,
)


@get("/billing", guards=[is_verified, has_any_role("admin", "billing")])
async def billing_dashboard() -> dict[str, bool]:
    return {"ok": True}


@get("/finance", guards=[has_all_roles("admin", "billing")])
async def finance_dashboard() -> dict[str, bool]:
    return {"ok": True}


@get("/posts", guards=[has_all_permissions("posts:read", "posts:write")])
async def posts_dashboard() -> dict[str, bool]:
    return {"ok": True}


@get("/moderation", guards=[has_any_permission("posts:moderate", "comments:moderate")])
async def moderation_dashboard() -> dict[str, bool]:
    return {"ok": True}


@get("/reports", guards=[requires_api_key, has_scope("reports:read")])
async def reports() -> dict[str, bool]:
    return {"ok": True}
```

::: litestar_auth.guards
