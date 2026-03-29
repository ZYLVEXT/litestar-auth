# Moving from fastapi-users

Optional reference: how ideas from [**fastapi-users**](https://fastapi-users.github.io/fastapi-users/) map to litestar-auth. This library targets **Litestar** with a **plugin** entry point, **msgspec**-oriented schemas, and **`Transport + Strategy`** backends — the APIs are different, so use this page as a mental map, not a translation table.

## Concept mapping

| fastapi-users | litestar-auth |
| ------------- | ------------- |
| `FastAPIUsers` / router registration | `LitestarAuth` plugin + `LitestarAuthConfig` |
| `UserManager` subclass | `BaseUserManager` subclass |
| Authentication backends (JWT, cookie, …) | `AuthenticationBackend(transport=…, strategy=…)` |
| Transport / strategy split (where exposed) | First-class `BearerTransport`, `CookieTransport`, `JWTStrategy`, `DatabaseTokenStrategy`, `RedisTokenStrategy` |
| Dependency `current_user` | `request.user` after middleware; **guards** (`is_authenticated`, …) for enforcement |
| Users router | `include_users=True` → generated controllers under `users_path` |
| OAuth routers | `oauth_config` + provider controllers (see [OAuth](oauth.md)) |

## API shape differences

- **Framework** — Litestar `InitPlugin`, DI keys, and guards instead of FastAPI dependencies on routers.
- **Validation** — Prefer **msgspec** structs (`user_read_schema`, `user_create_schema`, …), not Pydantic models inside the library (your app may still use either elsewhere).
- **Email** — litestar-auth does not send mail; implement **`BaseUserManager` hooks** (see [Hooks](hooks.md)) to enqueue or send messages.
- **SQLAlchemy** — Default user store is **`SQLAlchemyUserDatabase`** with Advanced Alchemy–friendly patterns; you still own migrations (Alembic / `create_all`).

## Mental model

Where you may be used to choosing **routers** and **backends** separately, litestar-auth centers on:

1. Build one or more **`AuthenticationBackend`** instances (name, transport, strategy).
2. Pass them in **`LitestarAuthConfig.backends`** (order matters: first match wins).
3. Enable HTTP surfaces with flags such as **`include_register`**, **`totp_config`**, **`oauth_config`**.

## Where to read next

- [Architecture](../concepts/architecture.md) — plugin layers.
- [Backends](../concepts/backends.md) — multiple backends and path prefixes.
- [Configuration](../configuration.md) — full configuration reference.
