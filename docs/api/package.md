# Package overview

The `litestar_auth` package re-exports the core plugin surface for application code: `LitestarAuth`,
`LitestarAuthConfig`, plugin config dataclasses, `BaseUserManager`, `UserManagerSecurity`,
authentication backends/transports, guards, user protocols, `ErrorCode`, and `LitestarAuthError`.
Controllers, strategies, token stores, rate limiters, payloads, schemas, ORM models, OAuth helpers,
and TOTP helpers are imported from their dedicated submodules. ORM models (`User`, `Role`,
`UserRole`, `OAuthAccount`) and the SQLAlchemy adapter (`SQLAlchemyUserDatabase`) are **not**
re-exported from the root. Import them from the models package or submodules to keep imports
explicit and avoid accidental mapper registration:

```python
from litestar_auth.models import User
from litestar_auth.models.oauth import OAuthAccount
from litestar_auth.models.role import Role, UserRole
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
```

For the detailed ORM integration contract, use [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models) and the [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md). This page only names the stable import boundaries.
Import `Role` / `UserRole` from `litestar_auth.models.role` when you need the bundled relational
role tables without registering the reference `User` mapper.

For the bundled `AccessToken` / `RefreshToken` ORM tables, keep explicit mapper registration under the models package:

```python
from litestar_auth.models import import_token_orm_models

AccessToken, RefreshToken = import_token_orm_models()
```

Call that helper explicitly during metadata bootstrap or Alembic-style autogenerate when your app uses the bundled token tables. For plugin-managed runtime, `LitestarAuth.on_app_init()` bootstraps the same bundled token mappers lazily when bundled DB-token models are active. The strategy-layer `import_token_orm_models()` re-export remains compatibility-only for existing imports, and the helper is intentionally not re-exported from `litestar_auth`.

The DB-token preset entrypoint is exported from both the root package and `litestar_auth.plugin` as `DatabaseTokenAuthConfig`.

For OAuth, plugin-managed apps should configure `OAuthConfig` on `LitestarAuthConfig` with `oauth_providers` as a sequence of `OAuthProviderConfig(name=..., client=...)`. `litestar_auth.oauth.create_provider_oauth_controller` plus `litestar_auth.controllers.create_oauth_controller` / `create_oauth_associate_controller` remain the manual route-table path for custom layouts.

Opaque DB-token wiring:

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

`backends` remains the explicit manual-backend field, and `config.resolve_backends(session)` is the runtime accessor for every supported backend configuration. For the `database_token_auth=...` path, `config.resolve_startup_backends()` returns startup-only `StartupBackendTemplate` values used during plugin assembly, while `config.resolve_backends(session)` returns the request-scoped runtime `AuthenticationBackend` instances.

For app-owned protected routes, reuse `config.resolve_openapi_security_requirements()` with Litestar `guards=[is_authenticated]` instead of hard-coding backend names in route-level OpenAPI metadata.

Treat the startup templates as plugin-assembly inventory only: they preserve backend names plus transport/strategy metadata for validation and controller wiring, but DB-token runtime work still has to go through `resolve_backends(session)` so the realized backend carries the active `AsyncSession`. Controller selection follows the startup inventory order: the primary backend mounts at `/auth`, later backends mount at `/auth/{backend.name}`, plugin-owned OAuth login routes use the primary backend, and TOTP uses the primary backend unless `totp_backend_name` selects another named startup backend.

The relational-role redesign changes storage only. Public HTTP payloads, managers, and guard
factories still work with one normalized flat `roles` collection. The core plugin-owned auth/users
route table still does not auto-mount role catalog or user-assignment endpoints; use the opt-in
`litestar_auth.contrib.role_admin` controller or the `litestar roles` CLI when you need admin
operations. The library still does not ship permission matrices.

## Public surface (high level)

| Area | Types / functions |
| ---- | ----------------- |
| Plugin | `LitestarAuth`, `LitestarAuthConfig`, `DatabaseTokenAuthConfig`, `OAuthConfig`, `OAuthProviderConfig`, `TotpConfig` |
| Backends | `AuthenticationBackend`, `Authenticator`, `BearerTransport`, `CookieTransport`; strategies from `litestar_auth.authentication.strategy` |
| Manager | `BaseUserManager`, `UserManagerSecurity`; `PasswordHelper` and password policy helpers from their submodules |
| Payloads / schemas | Auth lifecycle DTOs from `litestar_auth.payloads`; user CRUD schemas from `litestar_auth.schemas` |
| Persistence | `User`, `Role`, `UserRole`, `OAuthAccount` (from `litestar_auth.models` / submodules), `AccessToken`, `RefreshToken`, `SQLAlchemyUserDatabase` (from `litestar_auth.db.sqlalchemy`) |
| Guards | `is_authenticated`, `is_active`, `is_verified`, `is_superuser`, `has_any_role`, `has_all_roles` |
| Errors | `ErrorCode`, `LitestarAuthError`; typed subclasses from `litestar_auth.exceptions` |
| Protocols | `UserProtocol`, `GuardedUserProtocol`, `RoleCapableUserProtocol`, `TotpUserProtocol` — [Types](types.md) |
| Controllers (advanced) | `create_*_controller` factories from `litestar_auth.controllers` — [Controllers API](controllers.md) |
| Contrib role admin | `create_role_admin_controller` from `litestar_auth.contrib.role_admin` — [HTTP role administration](../guides/role_admin_http.md) |
| OAuth helpers | Plugin-managed route table via `OAuthConfig`; manual login helper and lazy client loader from `litestar_auth.oauth` |
| TOTP | `generate_totp_secret`, `generate_totp_uri`, `verify_totp`, stores from `litestar_auth.totp` |
| Rate limit | `AuthRateLimitConfig`, `EndpointRateLimit`, `InMemoryRateLimiter`, `RedisRateLimiter` from `litestar_auth.ratelimit` |

The authoritative `__all__` list is in `litestar_auth/__init__.py` on your installed version.

## Submodules

Detailed API pages are split by module — use the navigation **Python API** section.
