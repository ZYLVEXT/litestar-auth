# Migration Guide

## Superuser boolean to role membership

Superuser status is now derived from role membership. The public
`is_superuser` guard still exists, but it checks whether `user.roles` contains
the configured `superuser_role_name` (default `"superuser"`) instead of reading
`user.is_superuser`.

Before upgrading a database that still has an `is_superuser` column, preserve
the data by backfilling role membership for every true row:

1. Ensure the role catalog contains the configured superuser role.
2. Insert missing `user_role` association rows for users where
   `user.is_superuser = true`.
3. Deploy code that no longer reads, writes, or serializes `user.is_superuser`.
4. Drop the old `is_superuser` column after verifying those users authenticate
   with the expected role membership.

Example SQL shape for the default role name:

```sql
INSERT INTO role (name, description)
VALUES ('superuser', 'Superuser access')
ON CONFLICT (name) DO NOTHING;

INSERT INTO user_role (user_id, role_name)
SELECT id, 'superuser'
FROM "user"
WHERE is_superuser = true
ON CONFLICT DO NOTHING;
```

Adjust table names, quoting, and conflict handling for your database dialect
and custom model family. Applications using a custom
`LitestarAuthConfig.superuser_role_name` should backfill that normalized role
name instead of `"superuser"`.

Code changes to make at the same time:

- Remove `is_superuser` from custom SQLAlchemy user models and DTOs.
- Stop passing `is_superuser` to `BaseUserManager.create(...)`,
  `BaseUserManager.update(...)`, `/auth/register`, and `/users/*` payloads.
  The generated register and users request schemas now reject undeclared keys
  during request decoding with `ErrorCode.REQUEST_BODY_INVALID`, so stale
  clients surface immediately instead of being silently accepted.
- Grant or revoke superuser access by mutating the normalized `roles`
  collection through an admin path, seed script, migration, or the role-admin
  CLI/controller.

## Typing: UP bound narrowing and direct config construction

The typing-only API was tightened so downstream annotations describe the same
runtime contracts the library already expects. Runtime behavior is unchanged,
but type checkers may now surface code that relied on broad `Any`-based bounds,
helper-based config construction, manual generic parameters, or plain `str`
dependency keys.

### `LitestarAuthConfig.create()` to direct construction

Construct `LitestarAuthConfig` directly. The dataclass now owns the full public
configuration surface without separate wrapper helpers.

Before:

```python
from uuid import UUID

from litestar_auth import LitestarAuthConfig

config = LitestarAuthConfig.create(
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
)
```

After:

```python
from uuid import UUID

from litestar_auth import LitestarAuthConfig

config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
)
```

### `UP bound=UserProtocol[Any]` consumer code

The library's public `UP` type variable is now bounded to `UserProtocol` instead
of `UserProtocol[Any]`. Code that mirrors the old broad bound can usually drop
the `Any` parameter, or can bind the user and ID together with Python 3.12
generic parameter syntax when the ID type matters.

Before:

```python
from typing import Any, TypeVar

from litestar_auth.types import UserProtocol

UP = TypeVar("UP", bound=UserProtocol[Any])


def user_id(user: UP) -> object:
    return user.id
```

After:

```python
from typing import TypeVar

from litestar_auth.types import UserProtocol

UP = TypeVar("UP", bound=UserProtocol)


def user_id[ID](user: UserProtocol[ID]) -> ID:
    return user.id
```

Use `UserProtocol` as the broad runtime-checkable user bound. Use
`UserProtocol[ID]` when the function or class needs to preserve the concrete ID
type through its return values or collaborators.

### TOTP user-model validation moves to startup

Apps with `totp_config` enabled must use a `user_model` that exposes the
`TotpUserProtocol` fields: `email` and `totp_secret`. The plugin now checks that
contract during startup, so a misconfigured app fails before routes are mounted.
Previously, the same misconfiguration could surface only after a login reached
the pending-2FA branch.

### `DbSessionDependencyKey` adoption

Annotate custom DB-session dependency keys with `DbSessionDependencyKey` instead
of plain `str`. This keeps application code aligned with
`LitestarAuthConfig.db_session_dependency_key` and documents the Python
identifier constraint at the call site.

Before:

```python
from litestar_auth import LitestarAuthConfig

db_session_dependency_key: str = "db_session"

config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    db_session_dependency_key=db_session_dependency_key,
)
```

After:

```python
from litestar_auth import LitestarAuthConfig
from litestar_auth.types import DbSessionDependencyKey

db_session_dependency_key: DbSessionDependencyKey = "db_session"

config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    db_session_dependency_key=db_session_dependency_key,
)
```

### `AuthRateLimitEndpointSlot` string constants to `AuthRateLimitSlot`

Before:

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter

config = AuthRateLimitConfig.from_shared_backend(
    backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
    endpoint_overrides={
        "totp_verify": EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
            scope="ip",
            namespace="totp-verify",
        ),
    },
)
```

After:

```python
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    AuthRateLimitSlot,
    EndpointRateLimit,
    InMemoryRateLimiter,
)

config = AuthRateLimitConfig.from_shared_backend(
    backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
    endpoint_overrides={
        AuthRateLimitSlot.TOTP_VERIFY: EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
            scope="ip",
            namespace="totp-verify",
        ),
    },
)
```

`AuthRateLimitSlot` keeps override mappings typed, IDE-friendly, and aligned
with the preferred public surface.
