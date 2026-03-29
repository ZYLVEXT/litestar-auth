# litestar-auth

Authentication and authorization for [Litestar](https://litestar.dev/) applications: registration, login, email verification, password reset, OAuth2, TOTP (2FA), guards, and optional rate limiting. Everything is wired as a native **plugin** with **transport + strategy** composition.

## Who it is for

Teams building on [Litestar](https://litestar.dev/) who need registration, login, verification, password reset, OAuth, optional 2FA, and route guards without re-implementing security-sensitive flows from scratch.

## Features

- **Plugin entry point** — `LitestarAuth` registers middleware, DI, controllers, and exception handling from one config object.
- **Backends** — `AuthenticationBackend` combines a **transport** (Bearer or Cookie) with a **strategy** (JWT, database, or Redis tokens).
- **User manager** — `BaseUserManager` centralizes password hashing, tokens, hooks, and session invalidation.
- **Guards** — `is_authenticated`, `is_active`, `is_verified`, `is_superuser` for route-level authorization.
- **Optional** — TOTP, OAuth login and account linking, auth endpoint rate limits.

## Documentation map

| Section | Start here |
| ------- | ---------- |
| Install & extras | [Installation](install.md) |
| First working app | [Quickstart](quickstart.md) |
| Mental model | [Architecture](concepts/architecture.md), [Backends](concepts/backends.md), [Request lifecycle](concepts/request_lifecycle.md) |
| How-to guides | [Security](guides/security.md), [Registration](guides/registration.md), [OAuth](guides/oauth.md), [TOTP](guides/totp.md), [Rate limiting](guides/rate_limiting.md), [Hooks](guides/hooks.md), [Extending](guides/extending.md) |
| Moving from fastapi-users | [Concept mapping](guides/from_fastapi_users.md) (optional) |
| HTTP reference | [HTTP API](http_api.md), [Errors](errors.md) |
| Config & ops | [Configuration](configuration.md), [Security overview](security.md), [Deployment](deployment.md) |
| Python API | [Package](api/package.md) and subpages under **Python API** in the nav |
| Project | [Roadmap](roadmap.md), [Contributing](contributing.md) |

!!! note "Tooling and AI agents"
    Stable entry points for navigation and API surface: this page (documentation map), [HTTP API](http_api.md), [Package overview](api/package.md), and the authoritative `__all__` in `litestar_auth/__init__.py` on your installed version. Maintainer workflows and verification commands are in [Contributing](contributing.md).

!!! note "Email and UI"
    The library does not send email or ship a UI. Use hooks on `BaseUserManager` to trigger your mailer or jobs.

## Quick peek

```python
--8<-- "docs/snippets/home_quick_peek.py"
```

See [Quickstart](quickstart.md) for a runnable pattern with the default `User` model and secrets.
