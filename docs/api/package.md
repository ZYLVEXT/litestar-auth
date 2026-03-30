# Package overview

The `litestar_auth` package re-exports stable symbols for application code. ORM models (`User`, `OAuthAccount`) and the SQLAlchemy adapter (`SQLAlchemyUserDatabase`) are **not** re-exported from the root — import them from their own modules to keep imports explicit and avoid accidental mapper registration:

```python
from litestar_auth.models import User, OAuthAccount
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
```

Typical plugin wiring:

```python
from litestar_auth import (
    LitestarAuth,
    LitestarAuthConfig,
    AuthenticationBackend,
    JWTStrategy,
    BearerTransport,
    BaseUserManager,
)
from litestar_auth.models import User
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
```

## Public surface (high level)

| Area | Types / functions |
| ---- | ----------------- |
| Plugin | `LitestarAuth`, `LitestarAuthConfig`, `OAuthConfig`, `TotpConfig` |
| Backends | `AuthenticationBackend`, `BearerTransport`, `CookieTransport`, `JWTStrategy`, `DatabaseTokenStrategy`, `RedisTokenStrategy`, … |
| Manager | `BaseUserManager`, `require_password_length`, `PasswordHelper` |
| Persistence | `User`, `OAuthAccount` (from `litestar_auth.models`), `AccessToken`, `RefreshToken`, `SQLAlchemyUserDatabase` (from `litestar_auth.db.sqlalchemy`) |
| Guards | `is_authenticated`, `is_active`, `is_verified`, `is_superuser` |
| Errors | `ErrorCode`, `LitestarAuthError`, typed subclasses |
| Protocols | `UserProtocol`, `GuardedUserProtocol`, `TotpUserProtocol` — [Types](types.md) |
| Controllers (advanced) | `create_*_controller` factories — [Controllers API](controllers.md) |
| OAuth helpers | `create_provider_oauth_controller`, `load_httpx_oauth_client` |
| TOTP | `generate_totp_secret`, `generate_totp_uri`, `verify_totp`, stores, … |
| Rate limit | `AuthRateLimitConfig`, `EndpointRateLimit`, `InMemoryRateLimiter`, `RedisRateLimiter` |

The authoritative `__all__` list is in `litestar_auth/__init__.py` on your installed version.

## Submodules

Detailed API pages are split by module — use the navigation **Python API** section.
