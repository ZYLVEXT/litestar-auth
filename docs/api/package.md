# Package overview

The `litestar_auth` package re-exports stable symbols for application code. ORM models (`User`, `OAuthAccount`) and the SQLAlchemy adapter (`SQLAlchemyUserDatabase`) are **not** re-exported from the root — import them from their own modules to keep imports explicit and avoid accidental mapper registration:

```python
from litestar_auth.models import User, OAuthAccount
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
```

For the detailed ORM integration contract, use [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models) and the [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md). This page only names the stable import boundaries.

For the bundled `AccessToken` / `RefreshToken` ORM tables, keep explicit mapper registration under the models package:

```python
from litestar_auth.models import import_token_orm_models

AccessToken, RefreshToken = import_token_orm_models()
```

Call that helper explicitly during metadata bootstrap or Alembic-style autogenerate when your app uses the bundled token tables. For plugin-managed runtime, `LitestarAuth.on_app_init()` bootstraps the same bundled token mappers lazily when bundled DB-token models are active. The strategy-layer `import_token_orm_models()` re-export remains compatibility-only for existing imports, and the helper is intentionally not re-exported from `litestar_auth`.

The canonical opaque DB-token entrypoint is exported from both the root package and `litestar_auth.plugin` as `DatabaseTokenAuthConfig`.

For OAuth, treat root-package re-exports as compatibility aliases. Plugin-managed apps should configure `OAuthConfig` on `LitestarAuthConfig`; `litestar_auth.oauth.create_provider_oauth_controller` plus `litestar_auth.controllers.create_oauth_controller` / `create_oauth_associate_controller` remain the manual escape hatch for custom route tables.

Canonical opaque DB-token wiring:

```python
from uuid import UUID

from litestar import Litestar

from litestar_auth import (
    DatabaseTokenAuthConfig,
    LitestarAuth,
    LitestarAuthConfig,
)
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User

config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret="replace-with-32+-char-db-token-secret",
    ),
    user_model=User,
    user_manager_class=YourUserManager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
)
app = Litestar(plugins=[LitestarAuth(config)])
```

In that example, `session_maker` is any compatible request-session factory callable (`session_maker() -> AsyncSession`). `async_sessionmaker(...)` is a common implementation, but not a requirement.

If you previously built the DB bearer backend by hand with `AuthenticationBackend(..., BearerTransport(), DatabaseTokenStrategy(...))`, migrate to the direct `database_token_auth=DatabaseTokenAuthConfig(...)` form above. Keep manual backends for multi-backend or custom-transport cases.

`backends` remains the explicit manual-backend field. For the canonical `database_token_auth=...` path, call `config.startup_backends()` when you need the setup-time backend templates used during plugin assembly, and `config.bind_request_backends(session)` when you need request-scoped runtime backend instances.

## Public surface (high level)

| Area | Types / functions |
| ---- | ----------------- |
| Plugin | `LitestarAuth`, `LitestarAuthConfig`, `DatabaseTokenAuthConfig`, `OAuthConfig`, `TotpConfig` |
| Backends | `AuthenticationBackend`, `BearerTransport`, `CookieTransport`, `JWTStrategy`, `DatabaseTokenStrategy`, `RedisTokenStrategy`, … |
| Manager | `BaseUserManager`, `require_password_length`, `PasswordHelper` |
| Persistence | `User`, `OAuthAccount` (from `litestar_auth.models`), `AccessToken`, `RefreshToken`, `SQLAlchemyUserDatabase` (from `litestar_auth.db.sqlalchemy`) |
| Guards | `is_authenticated`, `is_active`, `is_verified`, `is_superuser` |
| Errors | `ErrorCode`, `LitestarAuthError`, typed subclasses |
| Protocols | `UserProtocol`, `GuardedUserProtocol`, `TotpUserProtocol` — [Types](types.md) |
| Controllers (advanced) | `create_*_controller` factories for custom route tables — [Controllers API](controllers.md) |
| OAuth helpers | Plugin-managed route table via `OAuthConfig`; manual login helper: `litestar_auth.oauth.create_provider_oauth_controller`; lazy client loader: `load_httpx_oauth_client` |
| TOTP | `generate_totp_secret`, `generate_totp_uri`, `verify_totp`, stores, … |
| Rate limit | `AuthRateLimitConfig`, `EndpointRateLimit`, `InMemoryRateLimiter`, `RedisRateLimiter` |

The authoritative `__all__` list is in `litestar_auth/__init__.py` on your installed version.

## Submodules

Detailed API pages are split by module — use the navigation **Python API** section.
