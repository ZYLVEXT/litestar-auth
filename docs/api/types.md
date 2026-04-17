# Types and protocols

Runtime-checkable **`Protocol`** definitions and type aliases used across transports, strategies, and user models.

`DbSessionDependencyKey` is the public type alias for `LitestarAuthConfig.db_session_dependency_key`.
It is an `Annotated[str, ...]` contract: values must be valid non-keyword Python identifiers because
Litestar matches dependency keys to callable parameter names. The default is `"db_session"`.

`RoleCapableUserProtocol` is the dedicated public typing surface for user objects that expose normalized flat `roles` membership. Use that protocol directly instead of treating an arbitrary `roles` attribute as sufficient.

That protocol describes the library boundary rather than a storage implementation detail. Bundled
SQLAlchemy models now persist roles through relational `role` / `user_role` tables, but managers,
schemas, and guards still exchange one normalized flat `roles` collection. This remains flat role
membership, not a full RBAC permission model.

## Which protocol should my user model implement?

Pick the **narrowest** protocol that covers the features you enable. If a guard or TOTP flow needs
attributes your model does not expose, authentication may succeed while authorization fails with a
generic permission error—so align the model with [Guards](guards.md) and TOTP usage up front.

| If you use… | Implement |
|-------------|-----------|
| Basic authentication only (strategies resolve `request.user` by `id`) | **`UserProtocol`** or **`UserProtocolStrict`** — `id` |
| `is_active`, `is_verified`, `is_superuser` [guards](guards.md) | **`GuardedUserProtocol`** — `is_active`, `is_verified`, `is_superuser` |
| `has_any_role` / `has_all_roles` [guards](guards.md) | **`RoleCapableUserProtocol`** — `roles` |
| TOTP enrollment, verification, or 2FA flows | **`TotpUserProtocol`** — `email`, `totp_secret` |

Use `UserProtocol` when code needs `isinstance(user, UserProtocol)` at runtime. Use
`UserProtocolStrict` for static-only annotations and type-variable bounds. The strict variant avoids
the `@runtime_checkable` tradeoff: runtime protocol checks are convenient but only validate the
runtime-visible shape of the protocol and carry extra overhead.

## Config inference and dependency-key typing

Prefer `LitestarAuthConfig.create()` when you want type checkers to infer the concrete user and ID
types from `user_model` and `user_manager_class`. Direct dataclass construction still works, but it
usually requires spelling both generic parameters as `LitestarAuthConfig[User, UUID](...)`.

The `db_session_dependency_key` parameter is typed as `DbSessionDependencyKey`, so the annotation
documents the same identifier rule enforced at runtime. This complete example type-checks as
`LitestarAuthConfig[User, UUID]`:

```python
from dataclasses import dataclass
from typing import assert_type
from uuid import UUID

from litestar_auth import DbSessionDependencyKey, LitestarAuthConfig
from litestar_auth.manager import BaseUserManager
from litestar_auth.types import UserProtocolStrict


@dataclass(slots=True)
class User:
    id: UUID
    email: str


class UserManager(BaseUserManager[User, UUID]):
    pass


def needs_static_user_contract(user: UserProtocolStrict[UUID]) -> UUID:
    return user.id


dependency_key: DbSessionDependencyKey = "db_session"

config = LitestarAuthConfig.create(
    user_model=User,
    user_manager_class=UserManager,
    db_session_dependency_key=dependency_key,
)

assert_type(config, LitestarAuthConfig[User, UUID])
```

### Example: account state and roles together

A single model often needs **`GuardedUserProtocol`** and **`RoleCapableUserProtocol`** so both
account-state and role [guards](guards.md) can run:

```python
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(slots=True)
class StaffUser:
    """Satisfies GuardedUserProtocol and RoleCapableUserProtocol."""

    id: int
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: Sequence[str]
```

Add TOTP fields when you enable 2FA; see **`TotpUserProtocol`** in the generated API below.

::: litestar_auth.types
