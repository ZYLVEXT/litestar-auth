# Configuration

The plugin is driven by **`LitestarAuthConfig`** (import from `litestar_auth` or `litestar_auth.plugin`). The configuration reference is split by concern so each page stays focused.

Generated detail lives in the [Plugin API](api/plugin.md) (mkdocstrings).

ORM models and the SQLAlchemy adapter are imported from their own modules; the root package does not re-export them:

```python
from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import User  # or your own model
```

## Configuration Pages

| Topic | Page |
| ----- | ---- |
| Database-token preset, backend lifecycle, auth paths, and built-in payloads | [Backends](configuration/backends.md) |
| User model contracts, bundled ORM mixins, token tables, roles, and `SQLAlchemyUserDatabase` | [User and manager](configuration/user_and_manager.md) |
| Role CLI, manager construction, plugin hooks, password helper, schemas, and secret contracts | [Manager customization](configuration/manager.md) |
| Redis auth preset, shared rate limiting, replay stores, and Redis import boundaries | [Redis](configuration/redis.md) |
| `TotpConfig` fields and TOTP route behavior | [TOTP](configuration/totp.md) |
| `OAuthConfig`, provider inventory, redirect policy, and token encryption | [OAuth](configuration/oauth.md) |
| CSRF, legacy-token policy, dependency keys, and shared helpers | [Security and DI](configuration/security.md) |

## Moved Sections

These headings remain for old links and search results. Follow the target page for the maintained content.

## Opaque DB-token preset

Moved to: [Backends](configuration/backends.md#opaque-db-token-preset).

### Backend lifecycle contract

Moved to: [Backends](configuration/backends.md#backend-lifecycle-contract).

## Custom SQLAlchemy `User` and token models

Moved to: [User and manager](configuration/user_and_manager.md#custom-sqlalchemy-user-and-token-models).

### Plugin role CLI

Moved to: [Manager customization](configuration/manager.md#plugin-role-cli).

### Bundled `AccessToken` / `RefreshToken` lifecycle

Moved to: [User and manager](configuration/user_and_manager.md#bundled-accesstoken--refreshtoken-lifecycle).

### Optional relational role contract

Moved to: [User and manager](configuration/user_and_manager.md#optional-relational-role-contract).

### `SQLAlchemyUserDatabase` contract

Moved to: [User and manager](configuration/user_and_manager.md#sqlalchemyuserdatabase-contract).

### Custom password column names

Moved to: [User and manager](configuration/user_and_manager.md#custom-password-column-names).

## Required (at runtime)

Moved to: [Manager customization](configuration/manager.md#required-at-runtime).

## Core wiring

Moved to: [Manager customization](configuration/manager.md#core-wiring).

### User manager customization

Moved to: [Manager customization](configuration/manager.md#user-manager-customization).

## Plugin customization hooks

Moved to: [Manager customization](configuration/manager.md#plugin-customization-hooks).

## Manager password surface

Moved to: [Manager customization](configuration/manager.md#manager-password-surface).

## Paths and HTTP feature flags

Moved to: [Backends](configuration/backends.md#paths-and-http-feature-flags).

## Built-in auth payload boundary

Moved to: [Backends](configuration/backends.md#built-in-auth-payload-boundary).

## Redis-backed auth surface

Moved to: [Redis](configuration/redis.md#redis-backed-auth-surface).

### Shared-backend rate limiting

Moved to: [Redis](configuration/redis.md#shared-backend-rate-limiting).

### Low-level Redis builder path

Moved to: [Redis](configuration/redis.md#low-level-redis-builder-path).

### Redis TOTP replay protection and pending-token deduplication

Moved to: [Redis](configuration/redis.md#redis-totp-replay-protection-and-pending-token-deduplication).

### Redis contrib import boundary

Moved to: [Redis](configuration/redis.md#redis-contrib-import-boundary).

## TOTP — `totp_config: TotpConfig | None`

Moved to: [TOTP](configuration/totp.md#totp--totp_config-totpconfig--none).

## OAuth — `oauth_config: OAuthConfig | None`

Moved to: [OAuth](configuration/oauth.md#oauth--oauth_config-oauthconfig--none).

## Security and token policy

Moved to: [Security and DI](configuration/security.md#security-and-token-policy).

## Schemas and DI

Moved to: [Security and DI](configuration/security.md#schemas-and-di).

## Dependency keys (constants)

Moved to: [Security and DI](configuration/security.md#dependency-keys-constants).

## Shared helpers — `litestar_auth.config`

Moved to: [Security and DI](configuration/security.md#shared-helpers--litestar_authconfig).

## Related

- [HTTP API](http_api.md) — routes controlled by the flags above.
- [Security](security.md) — production interpretation of sensitive flags.
- [Plugin API](api/plugin.md) — mkdocstrings for `LitestarAuth`, configs, and `litestar_auth.config`.
