## Unreleased

### Changed

- **OAuth-scoped user database proxy is no longer typed via `__getattr__` magic** — `_ScopedUserDatabaseProxy` now explicitly delegates to a `BaseUserStore` for non-OAuth methods and casts the wrapped store to `BaseOAuthAccountStore` for `get_by_oauth_account` / `upsert_oauth_account`, instead of forwarding arbitrary attributes through a runtime `__getattr__` that masked the dual `BaseUserStore` + `BaseOAuthAccountStore` contract from type checkers and silently `await`-wrapped synchronous attributes.
- **Failed JWT authentication no longer logs the JWT subject** — INFO-level log lines for "subject could not be decoded", "non-existent user", and "fingerprint mismatch" no longer include the user identifier. This closes a user-enumeration channel via authentication-failure log analysis (OWASP / NIST SP 800-63B §5.2.2). Log levels are unchanged.
- **`LitestarAuthConfig.build_password_helper()` no longer mutates `user_manager_kwargs`** — the memoized default `PasswordHelper` is now stored in a private slot on the config and injected into a request-local copy of `user_manager_kwargs` at manager construction time. The user-supplied `user_manager_kwargs` mapping is left untouched, so callers no longer find an unexpected `password_helper` key after the first `build_password_helper()` call. Use `config.memoized_default_password_helper()` (or another call to `config.build_password_helper()`) to retrieve the same instance.
- **`LitestarAuthConfig.user_db_factory` is no longer rewritten by `__post_init__`** — the dataclass field stays at whatever the caller passed (including `None`). The plugin and any external consumer should call the new `LitestarAuthConfig.resolve_user_db_factory()` method, which returns either the user-supplied factory or a deferred default that imports `litestar_auth.db.sqlalchemy` only on first call. This keeps the public dataclass honest about what the caller actually provided and removes the `Optional`/`__post_init__` round-trip that consumers had to defensively guard against.
- **DB-token strategy detection no longer matches on `__name__` / `__module__` strings** — `_uses_bundled_database_token_models` now uses lazy `isinstance` against the real `DatabaseTokenStrategy` and identity comparisons against the real bundled `AccessToken` / `RefreshToken` classes via `sys.modules.get()`. The check still respects the lazy-import contract: when the DB-token strategy or model modules have not been imported yet, no instance can exist in the configured backends, so the check returns `False` without forcing the SQLAlchemy adapter to load. Renaming `DatabaseTokenStrategy` no longer silently breaks the bundled-bootstrap detection, and IDE rename / static analysis now find the real references.
- **`# noqa: S105` annotations on stable error-code, audience, column, and detail-message constants are now expressed as targeted per-file ignores** — `litestar_auth/exceptions.py`, `litestar_auth/config.py`, `litestar_auth/_auth_model_mixins.py`, and `litestar_auth/controllers/totp.py` now opt out of S105 via `[tool.ruff.lint.per-file-ignores]` with comments explaining why each file's strings are not credentials (machine-readable error codes, JWT audiences, ORM column/class identifiers, user-facing error messages). Inline `# noqa: S105` is preserved on the small set of single-occurrence sites that remain (`manager.py` Fernet prefix, `controllers/auth.py` and `_plugin/config.py` standalone constants), so a real S105 hit on a future code change still surfaces as a review signal.
- **Plugin DI signature adaptation is now centralized and explicitly documented** — the request-backends provider now lives in `litestar_auth._plugin.dependencies` next to the user-manager provider, and both share one `_bind_session_keyed_signature()` helper instead of keeping a second hand-built `__signature__` implementation in `plugin.py`. The helper docstring now spells out the Litestar DI constraint being worked around: the session dependency key is configurable at runtime, but Litestar inspects the runtime callable signature and expects dependency kwargs to match that key. Signature-contract tests now lock the advertised metadata for the backends provider as well.
- **Dummy password timing equalization is now lazy and helper-aware** — `litestar_auth.manager` no longer computes an Argon2 dummy hash at import time. `_get_dummy_hash()` now caches per `PasswordHelper` instance on first use, so unknown-user authentication and forgot-password flows keep using a dummy hash produced by the same helper pipeline that will verify it. This removes import-time password hashing overhead and avoids fast-fail unknown-hash behavior for custom password helpers.

### Migration

- If your code reads `password_helper` out of `user_manager_kwargs` after calling `LitestarAuthConfig.build_password_helper()`, switch to `config.memoized_default_password_helper()` or simply call `config.build_password_helper()` again — both return the same instance.
- If your code reads `LitestarAuthConfig.user_db_factory` directly to obtain the effective factory, switch to `config.resolve_user_db_factory()`. Reading the dataclass field still works for callers that explicitly supplied a factory; it will now return `None` for callers that did not.

## 1.2.0 (2026-04-07)

### Added

- **Canonical high-level Redis auth preset surface** — `litestar_auth.contrib.redis.RedisAuthPreset` and `RedisAuthRateLimitTier` now provide the preferred one-client path for auth rate limiting plus TOTP replay protection, while keeping the lower-level Redis builders available for bespoke wiring.
- **Public Redis helper and typing surface for auth throttling** — `namespace_style`, the `AUTH_RATE_LIMIT_*` slot-set helpers, and a shared Redis protocol vocabulary now formalize the supported Redis-backed auth contract instead of leaving consumers on copied literals and `Any`-based wiring.
- **Typed manager/password reuse surfaces** — `UserManagerSecurity` is the canonical plugin-managed secret contract, `litestar_auth.schemas.UserEmailField` complements `UserPasswordField` for app-owned `msgspec.Struct` schemas, and `PasswordHelper.from_defaults()` plus `LitestarAuthConfig.build_password_helper()` provide a named shared password-helper path outside `BaseUserManager`.
- **Plugin-owned bundled token ORM bootstrap** — plugin-managed DB-token integrations can now register bundled `AccessToken` / `RefreshToken` mappers during app startup instead of relying on import-time side effects for runtime correctness.
- **Official password-hash column customization hook** — app-owned user models can now keep the `hashed_password` attribute contract while mapping it to a legacy column name such as `password_hash` through `auth_hashed_password_column_name`.
- **Repository-enforced 100% branch-aware coverage gate** — the repo configuration now fails verification when `pytest-cov` drops below 100.0% coverage for `litestar_auth`.

### Changed

- **Redis-backed auth is now organized around two clear layers** — `litestar_auth.contrib.redis` is the higher-level convenience boundary, `litestar_auth.ratelimit` remains the lower-level builder layer, and both are documented against one canonical Redis integration story.
- **Preferred Redis preset typing now matches the low-level builders it wraps** — the `RedisAuthPreset(redis=...)` client contract is typed against the combined `RedisRateLimiter` + `RedisUsedTotpCodeStore` operations instead of `object` plus internal `Any` casts, so strict consumers no longer need to weaken typing around the documented one-client path.
- **User-manager construction is typed end-to-end** — the default plugin builder now forwards `security=UserManagerSecurity(...)` when supported, preserves legacy explicit-secret kwargs for compatibility, and keeps deterministic precedence between typed security, legacy kwargs, `id_parser`, `login_identifier`, and password-validator injection.
- **Capability flags on custom manager families are now treated as real inheritable compatibility metadata** — plugin-side detection honors inherited `accepts_security`, `accepts_id_parser`, `accepts_login_identifier`, and `accepts_password_validator` declarations before falling back to constructor introspection.
- **Secret-role warning ownership is aligned across plugin-managed and manual manager construction** — plugin validation owns the config-managed warning baseline, direct `BaseUserManager(...)` construction still warns on manager-owned roles, and custom `user_manager_factory` integrations only surface an extra warning when they diverge from the validated secret surface.
- **Schema metadata and password-policy reuse are consolidated** — built-in and app-owned schemas share one canonical email/password metadata source, and plugin-managed password flows plus app-owned domain or CLI code can now share the same default helper construction path intentionally instead of by convention.
- **ORM integration is less override-heavy and less side-effect driven** — bundled token bootstrap, custom password-hash column mapping, and `SQLAlchemyUserDatabase` custom-model validation are all more explicit while preserving lazy import boundaries.
- **Documentation now converges on canonical Redis, manager/password, and ORM integration guides** — configuration, deployment, API, and cookbook pages now describe one maintained contract per surface instead of duplicating drifting setup recipes.

### Migration

- Prefer `litestar_auth.contrib.redis.RedisAuthPreset` for one-client Redis deployments, and use `namespace_style` plus the `AUTH_RATE_LIMIT_*` helper exports instead of repeating literal slot sets or per-slot namespace overrides when the built-in helper surface fits.
- Move plugin-managed secret wiring to `LitestarAuthConfig.user_manager_security`; keep `user_manager_kwargs` for non-security dependencies and legacy compatibility-only secret keys.
- For custom kwargs-only manager wrappers that forward `security` or deliberately opt out of injected kwargs, declare capability flags such as `accepts_security` or `accepts_id_parser` on your custom manager family base so the inheritance-aware builder logic stays explicit.
- Replace copied email/password `msgspec` metadata with `litestar_auth.schemas.UserEmailField` and `litestar_auth.schemas.UserPasswordField`, and use `config.build_password_helper()` or `PasswordHelper.from_defaults()` when app-owned code should share the library's default hashing policy.
- For bundled DB-token models, rely on plugin startup bootstrap for normal runtime initialization and keep `litestar_auth.models.import_token_orm_models()` for explicit metadata/Alembic flows; for legacy user tables, prefer `auth_hashed_password_column_name` over re-declaring `hashed_password = mapped_column(...)` by hand.

## 1.1.1 (2026-04-06)

### Added

- **Public password-policy reuse alias for custom msgspec schemas** — `litestar_auth.schemas.UserPasswordField` is now the canonical public field alias for app-owned `msgspec.Struct` registration and update payloads that should share the built-in password-length contract.
- **Typed public identifiers for the shared rate-limit builder** — `AuthRateLimitEndpointSlot` and `AuthRateLimitEndpointGroup` are exported from `litestar_auth.ratelimit` so `AuthRateLimitConfig.from_shared_backend(...)` overrides can target a documented, typed contract instead of private string sets.
- **Testing guide for plugin-backed applications** — the docs now include a dedicated guide for `LITESTAR_AUTH_TESTING=1`, request-scoped DB-session sharing, process-local auth state isolation, and the boundary between single-process test conveniences and Redis-backed production stores.

### Changed

- **Database-token preset session factories now use a structural contract** — the DB-token preset and plugin session-sharing path accept Advanced Alchemy-compatible async session factories via a structural callable contract, reducing integration friction around `SQLAlchemyAsyncConfig.session_maker`.
- **`UserAuthRelationshipMixin` is configurable instead of override-heavy** — custom user models can now set class variables for token relationship `lazy` loading and OAuth `lazy` / `foreign_keys` wiring instead of re-implementing the inverse `declared_attr` methods for common custom-user-table setups.
- **Shared-backend rate-limit defaults are now treated as a documented public contract** — the supported slot names, group names, default scopes, default namespace tokens, and override precedence for `AuthRateLimitConfig.from_shared_backend(...)` are now documented and regression-covered, including the migration pattern for legacy underscore namespaces and disabled verification endpoints.
- **Password-policy reuse is consolidated around `litestar_auth.schemas`** — built-in user schemas and app-owned custom registration/update DTOs now align on one canonical password-field surface derived from `DEFAULT_MINIMUM_PASSWORD_LENGTH` and `MAX_PASSWORD_LENGTH`.
- **Testing and deployment docs now describe the real plugin session and isolation model** — request-local DB session reuse, pytest-only testing mode, and the split between in-memory test helpers and Redis-backed production stores are now spelled out across the testing, deployment, configuration, and related guides.
- **Token ORM bootstrap guidance is stricter and more explicit** — docs, import coverage, and compatibility wording now consistently point consumers to `litestar_auth.models.import_token_orm_models()` as the canonical explicit mapper-registration helper, while the strategy-layer import is documented only as a compatibility path.
- **Regression coverage is broader across the new public surfaces** — import-isolation, plugin wiring, scoped-session sharing, schema metadata, SQLAlchemy relationship hooks, rate-limit builder contracts, and documentation-facing examples are now more tightly locked to the intended behavior.

### Migration

- Replace duplicated password metadata such as `msgspec.Meta(min_length=12, max_length=128)` with `litestar_auth.schemas.UserPasswordField` when custom app schemas should track the built-in password policy.
- For custom user models, configure `UserAuthRelationshipMixin` through its class-variable hooks before re-implementing `declared_attr` relationships for token or OAuth wiring.
- Treat `AuthRateLimitConfig.from_shared_backend(...)` string keys as the documented stable slot/group contract and preserve older key-space shapes with `disabled`, `group_backends`, `scope_overrides`, and `namespace_overrides`.
- Keep `litestar_auth.models.import_token_orm_models()` as the canonical explicit token-model bootstrap helper; use the strategy-layer helper only as a compatibility shim while migrating imports.
- Follow the new testing guide for plugin-backed apps: enable `LITESTAR_AUTH_TESTING=1` only under pytest, keep one shared DB session per request, and isolate in-memory auth state per test when counters or denylist state must not leak.

## 1.1.0 (2026-04-03)

### Changed

- **Canonical DB bearer setup is now documented around the preset builder** — `DatabaseTokenAuthConfig` is exported from `litestar_auth`, and the docs now point opaque DB-token users to `LitestarAuthConfig.with_database_token_auth(...)` instead of hand-assembling `AuthenticationBackend(..., BearerTransport(), DatabaseTokenStrategy(...))` for the common case.
- **Token ORM registration is now model-owned** — `litestar_auth.models.import_token_orm_models()` is the canonical helper for explicit `AccessToken` / `RefreshToken` mapper registration, while `litestar_auth.authentication.strategy.import_token_orm_models()` remains available as a compatibility path for existing call sites.
- **Database token persistence can now target custom token ORM classes explicitly** — `DatabaseTokenStrategy` still defaults to the bundled `AccessToken` / `RefreshToken` models, but advanced integrations can pass `DatabaseTokenModels(...)` to bind login/logout, refresh rotation, and expired-token cleanup to mixin-composed custom token tables without patching library internals.
- **Plugin OAuth route ownership is now explicit** — `oauth_providers` remains declarative metadata for manual login-controller registration and encryption checks, while `include_oauth_associate=True` plus non-empty `oauth_associate_providers` is the only plugin-owned OAuth auto-mount path; ambiguous associate-route no-op configs now fail during plugin construction instead of silently mounting nothing.
- **OAuth docs and import coverage now point at one canonical login-helper path** — `litestar_auth.oauth.create_provider_oauth_controller(...)` is the documented login entrypoint, plugin-owned OAuth auto-mounting is documented only for `/auth/associate/{provider}/...`, and the lower-level controller factories are clearly marked as the advanced custom-route escape hatch.

### Migration

- Replace manual DB bearer assembly like `AuthenticationBackend(name="database", transport=BearerTransport(), strategy=DatabaseTokenStrategy(...))` with `DatabaseTokenAuthConfig(...)` plus `LitestarAuthConfig.with_database_token_auth(...)`.
- Keep manual `backends=` assembly only for advanced cases such as multiple backends or a custom transport/strategy mix.
- Replace `from litestar_auth.authentication.strategy import import_token_orm_models` with `from litestar_auth.models import import_token_orm_models`; keep the strategy import only as a compatibility shim while migrating existing code.
- For custom DB token tables, compose `AccessTokenMixin` / `RefreshTokenMixin` / `UserAuthRelationshipMixin` on your own models and pass `DatabaseTokenModels(...)` to `DatabaseTokenStrategy` instead of copying the reference ORM classes.
- If you declare `oauth_providers`, keep mounting login routes explicitly with `litestar_auth.oauth.create_provider_oauth_controller(...)`; only associate routes are plugin-owned, under `/auth/associate/{provider}/...` when `include_oauth_associate=True`.

## 1.0.5 (2026-04-03)

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
