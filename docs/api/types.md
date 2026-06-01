# Types and protocols

Runtime-checkable **`Protocol`** definitions and type aliases used across transports, strategies, and user models.

`DbSessionDependencyKey` is the public type alias for `LitestarAuthConfig.db_session_dependency_key`.
It is an `Annotated[str, ...]` contract: values must be valid non-keyword Python identifiers because
Litestar matches dependency keys to callable parameter names. The default is `"db_session"`.

`RoleCapableUserProtocol` is the dedicated public typing surface for user objects
that expose normalized flat `roles` membership. Role and permission guards use
this shape before checking authorization grants. Use that protocol directly instead
of treating an arbitrary `roles` attribute as sufficient.

That protocol describes the library boundary rather than a storage implementation detail. Bundled
SQLAlchemy models store role membership in relational `role` / `user_role` tables; managers,
schemas, and guards still exchange one normalized flat `roles` collection.

## Which protocol should my user model implement?

Pick the **narrowest** protocol that covers the features you enable. If a guard or TOTP flow needs
attributes your model does not expose, authentication may succeed while authorization fails with a
generic permission error—so align the model with [Guards](guards.md) and TOTP usage up front.

| If you use… | Implement |
|-------------|-----------|
| Basic authentication only (strategies resolve `request.user` by `id`) | **`UserProtocol`** or **`UserProtocolStrict`** — `id` |
| `is_active`, `is_verified` [guards](guards.md) | **`GuardedUserProtocol`** — `is_active`, `is_verified` |
| `is_superuser`, role guards, and permission guards [guards](guards.md) | **`RoleCapableUserProtocol`** — `roles` |
| TOTP enrollment, verification, or 2FA flows | **`TotpUserProtocol`** — `email`, `totp_secret` |

Use `UserProtocol` when code needs `isinstance(user, UserProtocol)` at runtime. Use
`UserProtocolStrict` for static-only annotations and type-variable bounds. The strict variant avoids
the `@runtime_checkable` tradeoff: runtime protocol checks are convenient but only validate the
runtime-visible shape of the protocol and carry extra overhead.

## Config inference and dependency-key typing

Construct `LitestarAuthConfig` directly. For strict typing, spell both generic parameters as
`LitestarAuthConfig[User, UUID](...)` so the configured user and ID types stay explicit.

The `db_session_dependency_key` parameter is typed as `DbSessionDependencyKey`, so the annotation
documents the same identifier rule enforced at runtime. This complete example type-checks as
`LitestarAuthConfig[User, UUID]`:

```python
from dataclasses import dataclass
from typing import assert_type
from uuid import UUID

from litestar_auth import LitestarAuthConfig
from litestar_auth.types import DbSessionDependencyKey
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

config = LitestarAuthConfig[User, UUID](
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
    roles: Sequence[str]
```

Add TOTP fields when you enable 2FA; see **`TotpUserProtocol`** in the generated API below.

## Permission resolver protocol

Permission authorization is resolved through a structural protocol on
`LitestarAuthConfig.permission_resolver`:

```python
from typing import Protocol


class PermissionResolver(Protocol):
    def resolve(self, user: object, *, context: object | None = None) -> frozenset[str]:
        ...
```

The protocol is exported for explicit typing and structural conformance as
`from litestar_auth import PermissionResolver`; the bundled default implementation
is available as `from litestar_auth import StaticRolePermissionResolver`. Because
`PermissionResolver` is a structural protocol you do not have to subclass it — any
object with a compatible `resolve()` method satisfies `permission_resolver`.

You normally do not need to instantiate this protocol directly. Configure
`LitestarAuthConfig.role_permissions` for static role-derived permissions, or pass
any object with a compatible `resolve()` method as `permission_resolver` when
permissions come from another source.

```python
from dataclasses import dataclass
from uuid import UUID

from litestar_auth import LitestarAuthConfig
from litestar_auth.models import User


@dataclass(slots=True)
class StaticAuditResolver:
    def resolve(self, user: object, *, context: object | None = None) -> frozenset[str]:
        roles = set(getattr(user, "roles", ()))
        if "auditor" in roles:
            return frozenset({"reports:read"})
        return frozenset()


config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    backends=[jwt_backend],
    permission_resolver=StaticAuditResolver(),
)
```

Resolver output is normalized and validated before guards or the
`litestar_auth_permissions` dependency consume it. Invalid output fails closed with
a permission-denied response. When `permission_resolver` is set, it takes precedence
over `role_permissions`; otherwise the plugin builds the static role-permission
resolver from `role_permissions`.

The `context` keyword is reserved for request-aware resolution. The plugin passes
the current Litestar connection today, and the static resolver intentionally ignores
it. Treat `context=None` as a supported call shape for app-owned tests and helper
code. Multi-tenant and DB-backed permission lookup can use this argument in custom
resolvers, but built-in durable multi-tenant authorization semantics remain future
work rather than a promised release date.

::: litestar_auth.types
