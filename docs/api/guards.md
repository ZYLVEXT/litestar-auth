# Guards

Use these callables directly in Litestar `guards=[...]` lists. The role-guard
factories `has_any_role(*roles)` and `has_all_roles(*roles)` require an
authenticated active user, fail closed when `request.user` does not satisfy the
role-capable contract, and compare both configured roles and user roles with the
same normalization rules used by the model and manager layers (trimmed,
lowercased, deduplicated flat strings).

```python
from litestar import get

from litestar_auth.guards import has_all_roles, has_any_role, is_verified


@get("/billing", guards=[is_verified, has_any_role("admin", "billing")])
async def billing_dashboard() -> dict[str, bool]:
    return {"ok": True}


@get("/finance", guards=[has_all_roles("admin", "billing")])
async def finance_dashboard() -> dict[str, bool]:
    return {"ok": True}
```

::: litestar_auth.guards
