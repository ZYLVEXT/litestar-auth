# Installation

## Requirements

- **Python** 3.12 up to &lt; 3.15 (see `requires-python` in the package metadata).
- **Litestar** 2.x (declared as a core dependency).
- **Advanced Alchemy** and **SQLAlchemy** — used by the default user model and `SQLAlchemyUserDatabase`.
- **msgspec** — auth payloads and schemas are `msgspec.Struct` types (installed with Litestar; the library does not use Pydantic).

Install the package from PyPI or your index:

```bash
uv add litestar-auth
# or
pip install litestar-auth
```

## Optional extras

| Extra | Purpose |
| ----- | ------- |
| `redis` | Redis-backed token strategy and Redis JWT denylist / rate limiting helpers. |
| `oauth` | OAuth flows via `httpx-oauth` and token encryption (`cryptography`). |
| `totp` | TOTP helpers that need `cryptography` (if not already installed via `oauth`). |
| `all` | `redis` + `oauth` + `totp`. |

```bash
uv add "litestar-auth[all]"
```

### Typical stacks

=== "JWT / Bearer API"

The base install at the top of this page is enough. Configure `BearerTransport` + `JWTStrategy` (see [Quickstart](quickstart.md)).

=== "Browser sessions (cookies)"

Same core package. Use `CookieTransport` and set `csrf_secret` in production. See [Cookie + CSRF cookbook](cookbook/cookie_csrf.md).

=== "OAuth, Redis, or TOTP"

```bash
uv add "litestar-auth[oauth]"   # OAuth
uv add "litestar-auth[redis]"   # Redis strategy, denylist, rate limits
uv add "litestar-auth[totp]"    # TOTP helpers if not already via oauth
# or
uv add "litestar-auth[all]"
```

=== "API keys"

No extra is required. Enable `ApiKeyConfig` on `LitestarAuthConfig` (see [API keys](guides/api_keys.md)).

## What is not included

The library does **not** ship:

- Email delivery (use `BaseUserManager` hooks to call your mailer or queue).
- Admin UI or end-user account dashboards.
- Built-in RBAC, WebAuthn/passkeys, or audit log storage.

High-level **scope and boundaries** are on [Roadmap](roadmap.md).

## Building this documentation

From the repository root:

```bash
just docs-serve   # preview
just docs-build   # static site in site/
```

Uses [Zensical](https://github.com/zensical/zensical) with configuration in `zensical.toml`.
