## Unreleased

### Added

- **Explicit OAuth client protocols** — `OAuthClientProtocol`, `OAuthDirectIdentityClientProtocol`, `OAuthProfileClientProtocol`, and `OAuthEmailVerificationClientProtocol` are now exported from `litestar_auth.oauth.client_adapter`, giving manual OAuth controller consumers a statically checkable contract instead of raw `object`-typed inputs. Provisioning via `oauth_client`, `oauth_client_factory`, or `oauth_client_class` + `oauth_client_kwargs` is preserved; invalid import paths, missing methods, or malformed payloads fail closed with `ConfigurationError`.
- **Startup-only DB-token strategy wrapper** — `StartupBackendTemplate` values produced by the canonical `database_token_auth=...` path now carry a startup-only strategy wrapper that preserves DB-token metadata for plugin assembly and validation, but fails closed for runtime token operations until `bind_request_backends(session)` materializes a real request-scoped `DatabaseTokenStrategy`.
- **Backend lifecycle contract documentation** — `docs/configuration.md` now documents the three-surface backend lifecycle (`resolve_backends()`, `startup_backends()`, `bind_request_backends(session)`) and the controller selection order (primary at `/auth`, named backends at `/auth/{name}`, OAuth login via primary, TOTP via primary or `totp_backend_name`).
- **OAuth API contract documentation** — `docs/api/oauth.md` now documents the full manual OAuth client behavioral contract: typed protocols, provisioning modes, identity fallback (`get_id_email` vs `get_profile`), optional `get_email_verified` hooks, and fail-closed error behavior.

### Changed

- **Plugin DI providers no longer use `exec()`-based code generation** — `_make_user_manager_dependency_provider()` and `_make_backends_dependency_provider()` now produce signature-adapted callables that bind the configured `db_session_dependency_key` through `inspect.Parameter` manipulation instead of synthesizing source with `exec()`. The Litestar-visible parameter names, async-generator lifecycle, and fail-closed duplicate-input behavior are preserved.
- **OAuth associate callback no longer uses `exec()`** — `create_oauth_associate_controller()` callback generation now builds a signature-adapted callable instead of generating and executing source. The configured dependency parameter name, direct-manager callback path, guard wiring, route behavior, and state-cookie handling are preserved.
- **OAuth client resolution is centralized** — `create_provider_oauth_controller()`, manual controller assembly, and controller-level helper shims now route through a shared `_resolve_oauth_client()` / `_build_oauth_client_adapter()` boundary in `litestar_auth.oauth.client_adapter` instead of each performing their own client validation and adapter construction.
- **Startup backend inventory resolution is centralized** — controller assembly, plugin-owned OAuth login selection, TOTP backend selection, CSRF transport discovery, and exposed startup backends now use one shared `resolve_backend_inventory()` call on the plugin config instead of rescanning `startup_backends()` or reconstructing backend slots in scattered paths.
- **Default user-manager builder contract is centralized** — runtime kwargs materialization and startup constructor validation now share one `_DefaultUserManagerBuilderContract` boundary. Custom `user_manager_factory` remains the explicit escape hatch for non-canonical constructors.
- **Account-state validator resolution is centralized** — `LitestarAuth._resolve_account_state_validator()` now delegates to a shared plugin validation helper instead of owning a standalone raw `getattr(...)` path. The stable callable surface remains `require_account_state(user, *, require_verified=False)`.
- **JWT revocation-posture resolution is extracted** — the direct/manual revocation-posture resolution now lives in a dedicated helper in the JWT strategy module. The compatibility-versus-shared-store posture constructors are centralized alongside it.
- **TOTP secret-storage posture resolution is centralized** — `BaseUserManager` now delegates to `TotpSecretsService` for persisted TOTP secret handling, sharing one explicit posture resolution path (compatibility-plaintext vs Fernet-encrypted) instead of inlining posture logic in the manager.
- **Exception-bearing helpers use conventional imports** — `litestar_auth.controllers._utils` and `litestar_auth.oauth.service` no longer use runtime globals-preserving import guards for exception classes; they now use conventional top-level imports from `litestar_auth.exceptions`.
- **Unused `importlib` alias removed from Redis strategy** — `litestar_auth.authentication.strategy.redis` no longer carries a module-level `importlib` alias that was a leftover from the reload-era shim layer.

### Fixed

- **Flaky parallel test failures under `pytest -n auto`** — ten `isinstance` checks across `test_plugin_controllers.py`, `test_plugin_config.py`, and `test_imports.py` now resolve `StartupBackendTemplate` and `DatabaseTokenStrategy` types at assertion time via `importlib.import_module()` instead of comparing against stale module-level references that could diverge after cross-test module reloads.
- **Redis strategy test no longer patches through removed module alias** — `test_contrib_redis_preserves_lazy_dependency_error` now monkeypatches `_load_redis_asyncio` directly instead of reaching through the (now removed) `importlib` alias on the Redis strategy module.

### Internal

- **Test coverage reframed around behavioral contracts** — bounded-area tests for plugin dependency wiring, OAuth controller helpers, backend lifecycle, user-manager extension, manual OAuth client, security posture, and exception mapping now assert supported observable behavior (DI-key exposure, injection success, fail-closed semantics, stable error codes) instead of implementation details (`__signature__`, `__qualname__`, exec-specific artifacts).
- **Reload coverage harness isolated** — reload-only coverage for exception-bearing helper tests now uses a shared `load_reloaded_test_alias()` helper instead of mutating imported globals or restoring `litestar_auth.exceptions` state by hand.

## 1.5.0 (2026-04-10)

### Added

- **`RedisAuthClientProtocol` public typing contract** — new runtime-checkable protocol exported from `litestar_auth.contrib.redis` for annotating the shared async Redis client passed to `RedisAuthPreset` and the Redis-backed rate-limit, TOTP replay, and JWT denylist stores.
- **`RedisAuthPreset.build_totp_pending_jti_store()`** — builds `RedisJWTDenylistStore` from the preset's shared Redis client with optional per-call `key_prefix` override and fallback to `totp_pending_jti_key_prefix`.
- **`RedisAuthPreset.totp_pending_jti_key_prefix` field** — optional default Redis key prefix for the pending-login-token JTI denylist built by the preset.
- **`fakeredis[lua]` dev dependency** — test suite now uses `fakeredis` for Redis integration testing instead of hand-built async doubles.

### Changed

- **`RedisJWTDenylistStore` now uses the shared `RedisExpiringValueStoreClient` protocol** — the private `_RedisClientProtocol` is removed; the store's `redis` parameter accepts any client satisfying the shared internal `get()` + `setex()` protocol, which aligns with the composite `RedisAuthClientProtocol` contract.
- **`RedisAuthPreset.redis` field type is now `RedisAuthClientProtocol`** instead of the internal `RedisSharedAuthClient`, giving callers a stable public typing contract for the shared async Redis client.
- **Internal `RedisSharedAuthClient` composite now covers `get()` + `setex()`** — the protocol composition includes `RedisExpiringValueStoreClient` alongside the existing rate-limiter and conditional-set protocols, so the shared client backs the pending-token denylist without a separate client annotation.
- **Rate-limiter `RedisClientProtocol` no longer inherits from `RedisRateLimiterClient`** — `litestar_auth.ratelimit.RedisClientProtocol` now composes `RedisDeleteClient` + `RedisScriptEvalClient` directly, decoupling the public rate-limiter protocol from the internal auth client hierarchy.
- **Docs consolidate the canonical Redis/TOTP recipe into Configuration** — the rate-limiting guide and TOTP guide now reference `Configuration > Canonical Redis-backed auth surface` instead of duplicating the `RedisAuthPreset` snippet, and the canonical recipe itself now includes `build_totp_pending_jti_store()` alongside `build_rate_limit_config()` and `build_totp_used_tokens_store()`.
- **Test suite uses `fakeredis` instead of manual async Redis doubles** — all Redis-touching tests now run against `fakeredis[lua]` backends with shared test fixtures and typed factory protocols, replacing hand-written `AsyncMock`-based doubles that did not enforce the real Redis command contract.

## 1.4.0 (2026-04-09)

### Added

- **Explicit security-posture contracts for JWT revocation and TOTP secret storage** — `JWTStrategy.revocation_posture` now reports whether a strategy uses the compatibility-grade in-memory denylist or a durable shared-store posture, and manager-owned TOTP secret handling now exposes an explicit `totp_secret_storage_posture` contract instead of leaving plaintext-vs-encrypted storage as an implicit side effect of `totp_secret_key` being present or absent.
- **New high-level OAuth and TOTP config fields for production-safe defaults** — `OAuthConfig.oauth_provider_scopes` now pins per-provider OAuth scopes on plugin-owned routes, and `TotpConfig.totp_pending_jti_store` lets the plugin-managed TOTP flow use a shared JWT denylist for pending-login replay protection.
- **Startup-only backend templates for canonical plugin wiring** — `LitestarAuthConfig.startup_backends()` now returns `StartupBackendTemplate` values that describe the setup-time auth surface, while `config.bind_request_backends(session)` remains the runtime path that materializes request-scoped `AuthenticationBackend` instances.

### Changed

- **Auth `ClientException` shaping is now scoped to litestar-auth routes** — the plugin no longer installs a global app-wide `ClientException` handler. Auth routes still return the stable `{detail, code}` payload shape, but unrelated application routes keep Litestar’s default `ClientException` behavior.
- **OAuth scope selection is now server-owned end-to-end** — plugin-owned routes use `OAuthConfig.oauth_provider_scopes`, manual controller factories accept `oauth_scopes=...`, and runtime `GET /authorize?scopes=...` overrides now fail with **400** instead of allowing the caller to change provider permissions from the browser.
- **OAuth associate callbacks now enforce the same account-state gate as login** — inactive or otherwise blocked users can no longer link new OAuth identities through an already-authenticated associate flow.
- **OAuth redirect-origin policy is now fail-closed across both plugin-owned and manual routes** — plugin startup rejects non-HTTPS, loopback, or malformed `oauth_redirect_base_url` values outside explicit `AppConfig(debug=True)` / `unsafe_testing=True` escape hatches, and manual/custom OAuth controller factories reject insecure `redirect_base_url` values immediately with no localhost/plain-HTTP override. Callback bases must now remain clean `https://...` origins without embedded userinfo, query strings, or fragments.
- **Plugin DI now uses native generated callables instead of public `__signature__` rewriting** — configurable dependency keys still work, but the contract is now explicit: `db_session_dependency_key` and OAuth associate `user_manager_dependency_key` must be valid non-keyword Python identifiers because Litestar resolves them by real callable parameter names.
- **OAuth mapper bootstrap is less side-effect driven** — OAuth token-encryption hooks now register when concrete `OAuthAccountMixin` subclasses are declared, and the bundled `User` mapper references the bundled `OAuthAccount` class directly instead of depending on a string-based `importlib` side effect.

### Fixed

- **Pending TOTP login-token replay protection no longer silently degrades to process-local storage** — missing `pending_jti_store` now fails closed unless `unsafe_testing=True`, including the plugin-managed path that forwards `TotpConfig.totp_pending_jti_store` into the generated TOTP controller.
- **JWT and TOTP downgrade messaging is now aligned across runtime validation, startup warnings, and docs** — the plugin-managed single-process JWT denylist tradeoff and plaintext TOTP-secret compatibility posture now share one wording/contract source instead of drifting independently across startup, validation, and documentation.
- **Legacy bcrypt verification now fails closed for overlong passwords** — `PasswordHelper.verify()` and `verify_and_update()` now treat the bcrypt `>72`-byte `ValueError` path as an ordinary authentication failure instead of bubbling an exception through login or password-upgrade flows. This removes a legacy-hash-specific error path while preserving bcrypt compatibility for migration windows.

### Migration

- Configure a public **`https://...`** callback base for all OAuth routes. Plugin-owned OAuth can still use localhost/plain HTTP only behind `AppConfig(debug=True)` or `unsafe_testing=True`; manual/custom OAuth controller factories no longer expose that escape hatch.
- Replace browser-driven OAuth scope requests with server configuration: use `OAuthConfig.oauth_provider_scopes={"provider": ["openid", "email"]}` on the plugin-owned path or `oauth_scopes=[...]` when mounting manual controllers.
- Set `TotpConfig.totp_pending_jti_store` for plugin-managed TOTP or `pending_jti_store=...` when calling `create_totp_controller(...)` directly in any non-testing deployment.
- If your code inspects `config.startup_backends()`, update it to consume `StartupBackendTemplate` values; use `config.bind_request_backends(session)` or `template.bind_runtime_backend(session)` when you need runtime `AuthenticationBackend` instances.

## 1.3.0 (2026-04-09)

### Changed

- **OAuth-scoped user database proxy is no longer typed via `__getattr__` magic** — `_ScopedUserDatabaseProxy` now explicitly delegates to a `BaseUserStore` for non-OAuth methods and casts the wrapped store to `BaseOAuthAccountStore` for `get_by_oauth_account` / `upsert_oauth_account`, instead of forwarding arbitrary attributes through a runtime `__getattr__` that masked the dual `BaseUserStore` + `BaseOAuthAccountStore` contract from type checkers and silently `await`-wrapped synchronous attributes.
- **Failed JWT authentication no longer logs the JWT subject** — INFO-level log lines for "subject could not be decoded", "non-existent user", and "fingerprint mismatch" no longer include the user identifier. This closes a user-enumeration channel via authentication-failure log analysis (OWASP / NIST SP 800-63B §5.2.2). Log levels are unchanged.
- **`LitestarAuthConfig.build_password_helper()` no longer mutates `user_manager_kwargs`** — the memoized default `PasswordHelper` is now stored in a private slot on the config and injected into a request-local copy of `user_manager_kwargs` at manager construction time. The user-supplied `user_manager_kwargs` mapping is left untouched, so callers no longer find an unexpected `password_helper` key after the first `build_password_helper()` call. The default builder also materializes that shared helper on demand even when app code never called `config.build_password_helper()`, while startup validation now checks only the constructor shape and no longer executes `password_validator_factory` side effects. Use `config.memoized_default_password_helper()` (or another call to `config.build_password_helper()`) to retrieve the same instance.
- **`LitestarAuthConfig.user_db_factory` is no longer rewritten by `__post_init__`** — the dataclass field stays at whatever the caller passed (including `None`). The plugin and any external consumer should call the new `LitestarAuthConfig.resolve_user_db_factory()` method, which returns either the user-supplied factory or a deferred default that imports `litestar_auth.db.sqlalchemy` only on first call. This keeps the public dataclass honest about what the caller actually provided and removes the `Optional`/`__post_init__` round-trip that consumers had to defensively guard against.
- **DB-token strategy detection no longer matches on `__name__` / `__module__` strings** — `_uses_bundled_database_token_models` now uses lazy `isinstance` against the real `DatabaseTokenStrategy` and identity comparisons against the real bundled `AccessToken` / `RefreshToken` classes via `sys.modules.get()`. The check still respects the lazy-import contract: when the DB-token strategy or model modules have not been imported yet, no instance can exist in the configured backends, so the check returns `False` without forcing the SQLAlchemy adapter to load. Renaming `DatabaseTokenStrategy` no longer silently breaks the bundled-bootstrap detection, and IDE rename / static analysis now find the real references.
- **`# noqa: S105` annotations on stable error-code, audience, column, and detail-message constants are now expressed as targeted per-file ignores** — `litestar_auth/exceptions.py`, `litestar_auth/config.py`, `litestar_auth/_auth_model_mixins.py`, and `litestar_auth/controllers/totp.py` now opt out of S105 via `[tool.ruff.lint.per-file-ignores]` with comments explaining why each file's strings are not credentials (machine-readable error codes, JWT audiences, ORM column/class identifiers, user-facing error messages). Inline `# noqa: S105` is preserved on the small set of single-occurrence sites that remain (`manager.py` Fernet prefix, `controllers/auth.py` and `_plugin/config.py` standalone constants), so a real S105 hit on a future code change still surfaces as a review signal.
- **Plugin DI signature adaptation is now centralized and explicitly documented** — the request-backends provider now lives in `litestar_auth._plugin.dependencies` next to the user-manager provider, and both share one `_bind_session_keyed_signature()` helper instead of keeping a second hand-built `__signature__` implementation in `plugin.py`. The helper docstring now spells out the Litestar DI constraint being worked around: the session dependency key is configurable at runtime, but Litestar inspects the runtime callable signature and expects dependency kwargs to match that key. Signature-contract tests now lock the advertised metadata for the backends provider as well.
- **Dummy password timing equalization is now lazy and helper-aware** — `litestar_auth.manager` no longer computes an Argon2 dummy hash at import time. `_get_dummy_hash()` now caches per `PasswordHelper` instance on first use, so unknown-user authentication and forgot-password flows keep using a dummy hash produced by the same helper pipeline that will verify it. This removes import-time password hashing overhead and avoids fast-fail unknown-hash behavior for custom password helpers.
- **User-store persistence contracts are now consistently structural** — `BaseUserStore` is now a runtime-checkable `Protocol`, matching `BaseOAuthAccountStore` instead of remaining a separate abstract base class. Custom persistence backends can satisfy the public contract by implementing the documented async CRUD methods without inheriting from a nominal base type, while existing `isinstance(..., BaseUserStore)` checks continue to work through runtime protocol matching.
- **Manager security wiring now has one canonical concrete bundle** — internal construction helpers now synthesize and pass through `UserManagerSecurity` directly instead of juggling parallel “raw”, “resolved”, and protocol-shaped secret bundle dataclasses. Verification/reset secrets still resolve into `AccountTokenSecrets` for token services, but plugin and manager construction now share one concrete raw security shape end-to-end.
- **Default plugin user-manager construction now has one fixed constructor contract** — when `user_manager_factory` is unset, both startup validation and the runtime default builder target the canonical `BaseUserManager`-style call surface: `user_manager_class(user_db, *, password_helper=..., security=..., password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)`, with `id_parser=...` passed directly only when `user_manager_security` is unset. The plugin no longer probes capability flags or adapts injected kwargs per manager family; non-canonical constructors must opt into `user_manager_factory`, and incompatible `user_manager_class` values now fail during `LitestarAuth(config)` instead of on first request.
- **Testing-only security relaxations are now explicit and instance-scoped** — the process-wide `LITESTAR_AUTH_TESTING` switch is gone. Generated fallback secrets, validation relaxations, and plaintext OAuth token test storage now require `unsafe_testing=True` on the specific `LitestarAuthConfig`, `BaseUserManager`, controller factory, or `OAuthTokenEncryption` instance that owns that behavior.
- **OAuth route ownership is now fully plugin-managed when `oauth_providers` is configured** — `oauth_providers` plus `oauth_redirect_base_url` is now the single plugin-owned provider inventory for login routes under `{auth}/oauth/{provider}/...`, and `include_oauth_associate=True` extends that same inventory with authenticated linking routes under `{auth}/associate/{provider}/...`. Ambiguous partial configs now fail during plugin construction, and the implicit localhost redirect fallback is removed.
- **OAuth token persistence now requires an explicit encryption policy** — SQLAlchemy-backed OAuth writes must now carry `OAuthTokenEncryption(...)` explicitly, either by passing `oauth_token_encryption=...` to `SQLAlchemyUserDatabase(...)` or by binding the session path with `bind_oauth_token_encryption(...)`. OAuth token writes fail closed when no policy is configured, and `OAuthTokenEncryption(key=None, unsafe_testing=True)` is the explicit plaintext-only test escape hatch.
- **Public re-export boundaries are tighter** — `DatabaseTokenAuthConfig` now re-exports through `litestar_auth.plugin` instead of the root package importing it from the private `_plugin` package, `litestar_auth.ratelimit.__all__` no longer advertises underscore-prefixed helpers or module-level `importlib` / `logger` objects as public API, and `litestar_auth.models.mixins` no longer re-exports `_TokenModelMixin` solely for coverage tests.
- **Plugin first-party lazy imports no longer use string-based `importlib.import_module(...)` lookups** — `_build_default_user_db()` and `_build_database_token_backend()` still defer importing the SQLAlchemy adapter and DB-token backend pieces until runtime, but now do so with ordinary local imports. The lazy-import contract stays intact while static references remain visible to rename tooling and source navigation.
- **Canonical DB-token plugin wiring now lives on `LitestarAuthConfig` itself** — `LitestarAuthConfig.with_database_token_auth(...)` has been removed in favor of the direct `LitestarAuthConfig(..., database_token_auth=DatabaseTokenAuthConfig(...))` form. `backends` is now the explicit manual-backend path only, preset and manual backends are mutually exclusive, and callers that need setup-time backend templates should use `config.startup_backends()` (or `config.bind_request_backends(session)` for request-scoped runtime binding) instead of assuming the preset materializes into `config.backends`.
- **`RedisAuthPreset.group_rate_limit_tiers` is now a real read-only mapping contract** — the field still accepts any `Mapping[...]` input, but construction now snapshots it into `MappingProxyType(dict(...))` instead of leaving a mutable `dict` behind a `Mapping` annotation. Mutating the caller's source mapping after preset construction no longer changes the preset's effective group-tier budget layout, and the runtime object now matches the public read-only contract.
- **The Redis optional-dependency loader no longer lives behind a fake compatibility shim** — the shared `redis.asyncio` import guard moved from `_compat.py` to `_optional_deps.py` as `_require_redis_asyncio(...)`, and the Redis-backed JWT, opaque-token, rate-limit, and TOTP paths now depend on that explicitly named optional-dependency loader. The old test-only importer injection hook is gone; tests now monkeypatch `importlib.import_module` on the new module instead of pretending this is a cross-version compatibility layer.
- **Residual reload-safe type checks no longer fall back to string identity** — plugin startup now recognizes reloaded `JWTStrategy` classes by comparing against live class objects instead of `__name__` / `__module__` strings, so development reloads no longer depend on textual type identity for the JWT denylist warning path.

### Migration

- If your code reads `password_helper` out of `user_manager_kwargs` after calling `LitestarAuthConfig.build_password_helper()`, switch to `config.memoized_default_password_helper()` or simply call `config.build_password_helper()` again — both return the same instance.
- If your code reads `LitestarAuthConfig.user_db_factory` directly to obtain the effective factory, switch to `config.resolve_user_db_factory()`. Reading the dataclass field still works for callers that explicitly supplied a factory; it will now return `None` for callers that did not.
- Replace `LitestarAuthConfig.with_database_token_auth(...)` with `LitestarAuthConfig(..., database_token_auth=DatabaseTokenAuthConfig(...))`. If your code previously inspected `config.backends` for that canonical preset path, switch to `config.startup_backends()` for setup-time access or `config.bind_request_backends(session)` for request-scoped runtime binding.
- Replace process-wide `LITESTAR_AUTH_TESTING` usage with explicit `unsafe_testing=True` on the specific `LitestarAuthConfig`, `BaseUserManager`, controller factory, or `OAuthTokenEncryption` instance that owns the test-only relaxation.
- For plugin-owned OAuth routes, treat `oauth_providers` as the single provider inventory. Set `oauth_redirect_base_url` whenever `oauth_providers` is non-empty; the plugin now auto-mounts login routes under `{auth}/oauth/{provider}/...`, and `include_oauth_associate=True` reuses that same inventory for `{auth}/associate/{provider}/...`.
- Replace ambient OAuth token-encryption setup with explicit `OAuthTokenEncryption(...)` binding: pass `oauth_token_encryption=...` to `SQLAlchemyUserDatabase(...)` or call `bind_oauth_token_encryption(session, ...)` before OAuth token writes. For plaintext-only tests, use `OAuthTokenEncryption(key=None, unsafe_testing=True)` explicitly.
- If your custom `user_manager_class` does not accept `user_manager_class(user_db, *, password_helper=..., security=..., password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)`, with direct `id_parser=...` when `user_manager_security` is unset, configure `user_manager_factory` instead of relying on plugin-side compatibility adaptation.

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
