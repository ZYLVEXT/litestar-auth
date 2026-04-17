# Migration Guide

## Typing: UP bound narrowing and create() helper

The typing-only API was tightened so downstream annotations describe the same
runtime contracts the library already expects. Runtime behavior is unchanged,
but type checkers may now surface code that relied on broad `Any`-based bounds,
manual generic parameters, or plain `str` dependency keys.

### Manual `LitestarAuthConfig[...]` parameters to `LitestarAuthConfig.create()`

Prefer `LitestarAuthConfig.create()` when constructing a config from a concrete
user model and manager class. The helper keeps the same dataclass fields while
letting type checkers infer the user and ID types from those arguments.

Before:

```python
from uuid import UUID

from litestar_auth import LitestarAuthConfig

config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
)
```

After:

```python
from litestar_auth import LitestarAuthConfig

config = LitestarAuthConfig.create(
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
)
```

Keep explicit `LitestarAuthConfig[User, UUID](...)` only when you intentionally
want to pin a type checker to a wider or narrower static type than the concrete
constructor arguments provide.

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

### `DbSessionDependencyKey` adoption

Annotate custom DB-session dependency keys with `DbSessionDependencyKey` instead
of plain `str`. This keeps application code aligned with
`LitestarAuthConfig.db_session_dependency_key` and documents the Python
identifier constraint at the call site.

Before:

```python
from litestar_auth import LitestarAuthConfig

db_session_dependency_key: str = "db_session"

config = LitestarAuthConfig.create(
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    db_session_dependency_key=db_session_dependency_key,
)
```

After:

```python
from litestar_auth import DbSessionDependencyKey, LitestarAuthConfig

db_session_dependency_key: DbSessionDependencyKey = "db_session"

config = LitestarAuthConfig.create(
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
