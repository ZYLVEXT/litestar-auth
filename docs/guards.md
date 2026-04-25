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
