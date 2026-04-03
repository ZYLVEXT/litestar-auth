## Unreleased

### Added

- **`litestar_auth.payloads`** — authoritative public module for the built-in auth lifecycle DTOs (`LoginCredentials`, `RefreshTokenRequest`, `ForgotPassword`, `ResetPassword`, `RequestVerifyToken`, `VerifyToken`, and the TOTP payloads). Existing imports from `litestar_auth`, `litestar_auth.controllers`, and individual controller modules remain supported via compatibility re-exports.

### Changed

- **Plugin helper internals are split by lifecycle responsibility** — constructor-time validation remains in `litestar_auth._plugin.validation`, startup-only warnings and fail-closed guards live in `litestar_auth._plugin.startup`, cookie / CSRF middleware helpers live in `litestar_auth._plugin.middleware`, and shared rate-limit endpoint iteration now lives in `litestar_auth._plugin.rate_limit`, without changing intended plugin behavior.
- **`LitestarAuth` façade is slimmer** — private pass-through wrapper methods used only by tests were removed, and plugin wiring now delegates directly to the owning helper modules.
- **Plugin test ownership is realigned** — validation, config, and orchestrator coverage are separated by responsibility, with validation precedence checks focused on observable failure ordering instead of locking the full internal validator call order.
- **Auth payload field metadata is centralized** — shared msgspec field aliases now live in `litestar_auth._schema_fields`, and password-length metadata derives from `litestar_auth.config.MAX_PASSWORD_LENGTH` instead of duplicated literals.
- **Auth docs and API reference are more explicit about request contracts** — `LoginCredentials.identifier` is documented as login-only, while the built-in register, verify, reset-password, refresh, and TOTP routes keep their current email/token-based request shapes; the Python API page now documents both `litestar_auth.payloads` and `litestar_auth.schemas`.

### Fixed

- **Generated OpenAPI contracts are locked more tightly** — direct and plugin-mounted auth routes now have regression coverage for published request-body component names, required fields, validation limits, and the conditional `POST /auth/2fa/enable` no-body vs `TotpEnableRequest` contract.
- **Identifier-vs-email contract drift is less likely** — regression coverage now makes the current boundary explicit: username mode changes how login resolves `identifier`, but built-in verification, password reset, and TOTP flows remain email/token-oriented unless you replace those controllers.

## 1.0.4 (2026-04-02)

### Changed

- **Plugin helper internals are split by lifecycle responsibility** — constructor-time validation remains in `litestar_auth._plugin.validation`, startup-only warnings and fail-closed guards live in `litestar_auth._plugin.startup`, cookie / CSRF middleware helpers live in `litestar_auth._plugin.middleware`, and shared rate-limit endpoint iteration now lives in `litestar_auth._plugin.rate_limit`, without changing intended plugin behavior.
- **`LitestarAuth` façade is slimmer** — private pass-through wrapper methods used only by tests were removed, and plugin wiring now relies directly on the owning helper modules.
- **Plugin test ownership is realigned** — validation, config, and orchestrator tests are separated by responsibility, with validation precedence checks focused on observable failure ordering instead of locking the full internal validator call order.

## 1.0.3 (2026-04-02)

### Added

- **`import_token_orm_models()`** — explicit public helper in `litestar_auth.authentication.strategy` for consumers that need to register `AccessToken` / `RefreshToken` ORM models for Alembic autogenerate or mapper setup, without relying on import side effects.

### Changed

- **`litestar_auth.ratelimit` is now a package** — the former monolithic module is split into focused submodules (`_config`, `_helpers`, `_memory`, `_orchestrator`, `_protocol`, `_redis`) while preserving the existing public import surface.
- **Password-length validation is centralized** — `MAX_PASSWORD_LENGTH` and `require_password_length()` now live in `litestar_auth.config`; legacy imports from `litestar_auth.manager` and `litestar_auth` continue to work.
- **Token audience constants are centralized** — `VERIFY_TOKEN_AUDIENCE`, `RESET_PASSWORD_TOKEN_AUDIENCE`, `JWT_ACCESS_TOKEN_AUDIENCE`, `TOTP_PENDING_AUDIENCE`, and `TOTP_ENROLL_AUDIENCE` now come from `litestar_auth.config`, with legacy import paths preserved.
- **Plugin DI provider no longer relies on `exec()`** — user-manager dependency wiring now uses a closure with an explicit `__signature__`, preserving Litestar DI behavior while improving static analysis and debuggability.
- **Controller OpenAPI request bodies are aligned with runtime behavior** — `POST /auth/register`, `POST /auth/reset-password`, `PATCH /users/me`, and `PATCH /users/{user_id}` now publish `requestBody` consistently without changing the existing 400/422 error payload contract.
- **`POST /auth/2fa/enable` now has conditional OpenAPI parity** — when password step-up is enabled, the route publishes `TotpEnableRequest`; when password step-up is disabled, the route remains documented as a no-body endpoint.

### Fixed

- **Plugin-mounted `/auth/jwt/*` Swagger/OpenAPI coverage is stabilized** — request-body contracts are now locked for `/auth/jwt/login`, `/auth/jwt/register`, `/auth/jwt/reset-password`, and `/auth/jwt/refresh`, reducing the chance of downstream documentation regressions.
- **Misleading backend naming now warns early** — plugin validation emits an advisory `UserWarning` when a backend name contains `jwt` but uses a non-`JWTStrategy`, helping catch confusing configurations without breaking startup.

## 1.0.2 (2026-03-30)

### Changed

- **`litestar_auth.models` is a package** — ORM definitions live under `litestar_auth.models.user`, `litestar_auth.models.oauth`, and shared `litestar_auth.models._oauth_encrypted_types`. Import **`from litestar_auth.models.oauth import OAuthAccount`** to use the OAuth table contract **without** registering the reference `User` mapper. `from litestar_auth.models import User` / `OAuthAccount` remains supported via lazy exports (PEP 562).
- **`OAuthEncryptionKeyCallable`** — public alias for `Callable[[], str | bytes | None]` aligned with `get_oauth_encryption_key_callable()`; `EncryptedString` still requires a cast at the integration layer (documented on the getter).

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
