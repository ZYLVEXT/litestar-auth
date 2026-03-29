## Unreleased

First **stable public API** as **1.0.0** — authentication and authorization for [Litestar](https://litestar.dev/) as a native plugin, without shipping email delivery or UI (use `BaseUserManager` hooks).

### Added

- **`LitestarAuth` plugin** — single config registers middleware, DI, HTTP controllers, and typed error handling.
- **Transport + strategy model** — `AuthenticationBackend` composes Bearer or cookie transports with JWT, database-backed, or Redis-backed token strategies; optional JWT denylist stores (in-memory, Redis).
- **User lifecycle** — `BaseUserManager` with password hashing via **pwdlib** (Argon2/Bcrypt), verification and reset tokens, refresh flows, session invalidation hooks, and SQLAlchemy user/OAuth persistence helpers (`User`, `OAuthAccount`, `SQLAlchemyUserDatabase`).
- **HTTP surface** — factory-built controllers for register, login, refresh, verify email, forgot/reset password, user CRUD, OAuth login and account linking (`httpx-oauth` extra), and TOTP enable/verify/disable (`totp` / `cryptography` extra).
- **Guards** — `is_authenticated`, `is_active`, `is_verified`, `is_superuser` for route-level authorization.
- **Optional hardening** — configurable rate limiting for auth endpoints; OAuth token encryption helper; TOTP helpers and warnings for production settings.
- **Documentation** — hosted docs (Zensical/MkDocs material), quickstart, architecture and backend guides, security/deployment notes, HTTP API and error reference, and a FastAPI Users concept mapping.

### Packaging

- Published as **`litestar-auth`** on PyPI with optional extras: `redis`, `oauth`, `totp`, and `all`.
- **Python 3.12+**; core runtime deps: Litestar 2.x, Advanced Alchemy, pwdlib, PyJWT.
