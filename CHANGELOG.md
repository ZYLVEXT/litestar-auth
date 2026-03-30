## 1.0.1 (2026-03-30)

### Changed

- **No ORM re-exports from root** — `User`, `OAuthAccount`, and `SQLAlchemyUserDatabase` are no longer re-exported from `litestar_auth` or `litestar_auth.db`. Import them from `litestar_auth.models` and `litestar_auth.db.sqlalchemy` respectively.
- **`SQLAlchemyUserDatabase` requires `user_model`** — The `user_model` parameter is now mandatory. No implicit default model is loaded.
- **`oauth_account_model` is explicit** — OAuth methods (`get_by_oauth_account`, `upsert_oauth_account`) raise `TypeError` unless `oauth_account_model` was passed to the constructor.
- **Default `user_db_factory` built from config** — When `user_db_factory` is not provided, `LitestarAuthConfig.__post_init__` builds a default using `config.user_model`. The SQLAlchemy adapter import is deferred to first call.
- **`litestar_auth.db` is minimal** — Only `BaseUserStore` and `BaseOAuthAccountStore` are exported. No SQLAlchemy adapter.

### Removed

- `_lazy_exports.py` and PEP 562 `__getattr__`/`__dir__` from root and `db` packages — replaced by explicit imports from submodules.
- `_default_user_model()` / `_default_oauth_account_model()` cached helpers in `db/sqlalchemy.py`.
- `DEFAULT_USER_DB_FACTORY` / `_default_user_db_factory` from `_plugin/config.py`.

### Migration

- Replace `from litestar_auth import User` with `from litestar_auth.models import User`.
- Replace `from litestar_auth import SQLAlchemyUserDatabase` with `from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase`.
- Replace `from litestar_auth.db import SQLAlchemyUserDatabase` with `from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase`.
- All `SQLAlchemyUserDatabase(session)` calls must now pass `user_model=YourModel` explicitly.
- For OAuth, pass `oauth_account_model=YourOAuthModel` to `SQLAlchemyUserDatabase`.
- `user_db_factory` can be omitted from `LitestarAuthConfig` — the default is built from `user_model`.

## 1.0.0 (2026-03-29)

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
