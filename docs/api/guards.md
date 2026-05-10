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

API-key guards operate on `ApiKeyContext` from `request.auth`:

- `requires_api_key` accepts only API-key-authenticated requests.
- `has_scope(*scopes)` requires every listed key scope and, when the key context was issued with
  `scope_subset_check=True`, still downscopes by the current user's roles.
- `has_any_scope(*scopes)` requires at least one listed key scope and, when the key context was
  issued with `scope_subset_check=True`, still downscopes by current user roles.
- `requires_password_session` rejects API-key callers and is used on self-service API-key
  create/update/revoke routes plus other credential-rotation boundaries.

```python
from litestar import get

from litestar_auth.guards import has_all_roles, has_any_role, has_scope, is_verified, requires_api_key


@get("/billing", guards=[is_verified, has_any_role("admin", "billing")])
async def billing_dashboard() -> dict[str, bool]:
    return {"ok": True}


@get("/finance", guards=[has_all_roles("admin", "billing")])
async def finance_dashboard() -> dict[str, bool]:
    return {"ok": True}


@get("/reports", guards=[requires_api_key, has_scope("reports:read")])
async def reports() -> dict[str, bool]:
    return {"ok": True}
```

::: litestar_auth.guards
