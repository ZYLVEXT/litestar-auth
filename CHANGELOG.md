## 5.2.0 (2026-07-13)

### Security

- **Direct `create_auth_controller(...)` now emits the low-timing-floor `SecurityWarning`.** When account
  lockout is enabled with `login_minimum_response_seconds` below the safe floor (`0.2s`), the locked-account
  short-circuit can become timing-distinguishable; previously only plugin-managed startup warned about it.
  The check is shared (`warn_account_lockout_response_floor_too_low`) and respects `unsafe_testing=True`.
- **Dev-dependency audit**: bumped transitive `msgpack` 1.2.0 → 1.2.1 in `uv.lock`
  (GHSA-6v7p-g79w-8964 — Unpacker OOB-read on reuse after error; dev-only via `pip-audit` → `cachecontrol`).

## 5.1.0 (2026-06-17)

### Added

- **Opt-in per-account login lockout.** New `AccountLockoutConfig` on `LitestarAuthConfig`
  (`account_lockout_config`, disabled by default) locks an account key after `failure_threshold`
  failed password logins (default **5**) for a `window_seconds` TTL (default **900s**). Lockout state lives behind the new
  `AccountLockoutStore` protocol with bundled `InMemoryAccountLockoutStore` and `RedisAccountLockoutStore`
  backends (or a custom `store_factory`), all exported from `litestar_auth.ratelimit`. Account keys are
  non-reversible keyed digests of the login identifier (`account_lockout_key`), so the store never holds a
  plaintext email/username; enabling lockout requires an `account_lockout_key_secret` (startup fails closed
  with `ConfigurationError` otherwise). This complements — it does not replace — the existing IP/identifier
  rate limiting, covering distributed brute force against a single account that per-IP limits miss.

### Security

- **Account lockout is non-enumerating and timing-safe.** A locked account, a wrong password, and an
  unknown identifier all return the same generic bad-credentials response, and the lockout check runs inside
  the existing minimum-response-time padding so the short-circuited locked path is not a timing oracle. The
  failure counter resets on successful authentication; the Redis backend increments and checks atomically via
  Lua so multi-worker deployments share one consistent count (the in-memory backend is process-local and
  warns when used across workers).

## 5.0.3 (2026-06-13)

### Added

- **`litestar_auth.totp.abuild_recovery_code_index()` is now public.** Async extension and controller
  code can build TOTP recovery-code lookup indexes through the worker-thread-offloaded helper instead
  of calling the synchronous `build_recovery_code_index()` on the event loop. The existing synchronous
  export is unchanged for CLI and script contexts.

- **`LITESTAR_AUTH_PASSWORD_WORKER_THREAD_LIMIT` environment variable.** The shared Argon2
  worker-thread cap (default **8** concurrent password operations per event loop — per process for
  the typical one-loop server) is now configurable.
  The value is read once, at import of `litestar_auth`, and must be a positive integer; invalid
  values fail fast with `ConfigurationError`. Size it with the memory formula
  `limit * Argon2 memory cost` (roughly `limit * 64 MiB` with the bundled default policy) — see
  the security configuration guide. This is the library's first environment-variable setting; it is
  environment-based rather than config-object-based because the limiter cap is resolved at import,
  before any `LitestarAuthConfig` exists, and applies to every loop in the process.

### Changed

- **Litestar 2.24 explicit dependency annotations; minimum Litestar is now `>=2.24.0,<3.0`.**
  Litestar 2.24 deprecates inferred dependencies (removal in 3.0), so every bundled controller
  handler and dynamically built dependency provider now marks injected parameters with
  `NamedDependency[...]`. **Breaking:** Litestar 2.23 is no longer supported. Applications and
  extensions that define their own handlers consuming litestar-auth dependencies should annotate
  those parameters with the new typed aliases exported from `litestar_auth.extensions`
  (`UserManagerDependency`, `AuthBackendsDependency`, `OrganizationStoreDependency`,
  `ResolvedPermissionsDependency`) — see the Migration guide.

- **Argon2 work no longer blocks the event loop.** All password hashing, verification, and dummy-hash
  construction in async flows — registration, login (including eager unknown-user timing
  equalization), password change, password reset, forgot-password token construction, API-key
  current-password confirmation — and the TOTP recovery-code paths (recovery-code verification and
  recovery-code index construction, previously up to N sequential Argon2 hashes per request) now run
  in an AnyIO worker thread. The public synchronous `PasswordHelper` API and the
  one-Argon2-verify-per-call timing-equalization properties are unchanged. Custom `password_helper`
  implementations supplied to managers now execute in a worker thread and must not rely on
  event-loop thread affinity. Password and TOTP recovery-code Argon2 offloads now share one dedicated
  AnyIO `CapacityLimiter` per event loop capped at 8 concurrent operations, bounding default pwdlib
  Argon2 memory pressure to roughly 8 x 64 MiB per loop instead of AnyIO's broader default
  worker-thread pool.

- **Unknown-user dummy hashes are cached per `PasswordHelper` identity.** The timing-equalization
  dummy hash for unknown-user login and forgot-password paths is now cached process-globally for the
  `PasswordHelper` instance that produced it instead of per manager instance. Because the plugin builds
  a manager per request and memoizes the default `PasswordHelper` per config, the default dummy Argon2
  hash is now computed once per process rather than once per request on unknown-user paths.

- **`anyio` is now a direct dependency** (`anyio>=4.13.0,<5.0`). It was already required
  transitively via Litestar, so dependency trees do not change.

- **`cryptography` minimum for the OAuth and TOTP extras is now `>=48.0.1`.** The upstream 48.0.1
  release updates official wheels to OpenSSL 4.0.1; its release notes do not list a CVE-specific fix.

### Internal

- Removed the accidentally committed `demo_litestar_auth.db` SQLite artifact from the repository and
  added a `*.db` ignore rule; runnable demos create their databases at startup as before.
- Removed the inert setuptools-era `zip-safe` key from `[tool.hatch.build.targets.wheel]`; it is not
  a hatchling option and had no effect on built wheels.
- Raised the development `pip-audit` minimum to `>=2.10.1`.

## 5.0.2 (2026-06-11)

### Fix

- **security**: persist refresh-rotation revocations across autocommit rollback

## 5.0.1 (2026-06-10)

### Added

- **Rate-limit posture warnings for public auth endpoints.** Assembling the login/refresh controllers
  (via `create_auth_controller()` or the plugin) or the registration controller without an
  `AuthRateLimitConfig` covering those endpoints now emits a `SecurityWarning` naming the unthrottled
  routes (`POST /login`, `POST /refresh`, `POST /register`) and the `AuthRateLimitConfig` fields to set.
  Pass `unsafe_testing=True` to silence it for tests and local development. Deployments that already
  configure rate limiting are unaffected.

- **`DatabaseTokenModels.consumed_refresh_token_digest_model`.** The explicit DB-token model contract
  now also carries the consumed-digest lookup model (default: bundled `RefreshTokenConsumedDigest`),
  validated eagerly like the other two models: a custom class must expose mapped `token_digest`,
  `session_id`, and `consumed_at` attributes. Existing configurations need no changes.

### Security

- **Refresh-token replay detection now uses an indexed lookup table.** Consumed refresh-token digests are
  stored in a new `refresh_token_consumed_digest` table (digest primary key, indexed `session_id`) and
  matched with an indexed equality lookup, replacing the previous full scan of the
  `refresh_token.consumed_token_digests` JSON column performed on every unauthenticated `POST /refresh`.
  The legacy JSON dual-write is removed, the expired-session and periodic cleanup paths also reclaim
  consumed-digest rows so the table cannot grow unbounded, and replayed-token session-chain revocation is
  unchanged. **Breaking:** the bundled schema gains the `refresh_token_consumed_digest` table, and
  `RefreshTokenMixin` / custom refresh-token model validation no longer require a `consumed_token_digests`
  attribute — see Migration.

- **JWT session-fingerprint keys are now derived with HKDF-SHA256 domain separation.** The fingerprint
  HMAC key is derived from the JWT signing secret via HKDF (dedicated salt/info) instead of using the raw
  secret bytes directly, keeping the fingerprint key cryptographically separated from the signing key.
  **Breaking:** access tokens carrying a session fingerprint that were issued before this release no
  longer validate, so affected sessions must re-authenticate.

### Changed

- **`import_token_orm_models()` now returns three models.** Both the public
  `litestar_auth.models.import_token_orm_models()` and the low-level strategy helper return
  `(AccessToken, RefreshToken, RefreshTokenConsumedDigest)` so metadata bootstrap and Alembic
  autogenerate flows see the full bundled token-model set rather than relying on an import side effect.
  **Breaking:** call sites that unpack the previous two-tuple must be updated.

- **`SecurityWarning` moved to `litestar_auth.exceptions`.** The warning category emitted for insecure
  defaults (rate-limit posture, TOTP, plugin startup) now lives alongside the other public error types;
  `litestar_auth.totp.SecurityWarning` keeps working as a public re-export. The private
  `litestar_auth._totp_verify` definition site is gone.

### Removed

- **`litestar_auth.totp` no longer leaks private internals.** Underscored helpers
  (`_current_counter`, `_generate_totp_code`, `_consume_matching_recovery_code`, and friends), the
  `hmac` / `time` / `logger` module attributes, and `USED_TOTP_CODE_TTL_SECONDS` are no longer
  importable from the facade; the public `__all__` surface is unchanged. **Breaking for test code:**
  the facade-override hook was removed with them, so monkeypatching
  `litestar_auth.totp._current_counter` no longer affects verification — patch
  `litestar_auth._totp_primitive` directly instead.

### Internal

- Merged `controllers/_session_devices_handlers.py` back into `controllers.session_devices`
  (drops a mid-file `noqa: E402` import cycle workaround), switched the OAuth client adapter to direct
  function imports, and normalized several private modules to `import package.module as alias` form to
  reduce circular-import fragility. No behavior change.

### Packaging

- `pyproject.toml` now uses the PEP 639 SPDX license expression (`license = "MIT"` plus
  `license-files`) instead of the deprecated table form; LICENSE copyright year refreshed.

### Migration

- **Add the `refresh_token_consumed_digest` lookup table, backfill it, then drop the legacy JSON column.**
  Create the table (DDL and Alembic variants in `docs/migration.md`), copy existing
  `refresh_token.consumed_token_digests` digests into it keyed by `session_id` *before* serving this code,
  then `DROP COLUMN refresh_token.consumed_token_digests`. Skipping the backfill leaves a transition
  window in which refresh tokens consumed before the upgrade are not recognized as replays (no
  session-chain revocation) until those legacy sessions expire or are revoked. Custom refresh-token models
  passed to `DatabaseTokenModels` no longer need a `consumed_token_digests` attribute.

## 5.0.0 (2026-06-09)

### Added

- **Public extension SDK (`litestar_auth.extensions`).** The internal extension kernel is now a stable,
  publicly documented authoring surface. `litestar_auth.extensions` is the only import path an external
  extension needs — it re-exports the `AuthExtension` contract together with its
  `AuthExtensionValidationContext` / `AuthExtensionRegistrationContext` typed contexts (all three are now
  also exported from the root `litestar_auth` package), `EXTENSION_API_VERSION`,
  `EXTENSION_ENTRY_POINT_GROUP`, and the public controller factories authors need (reaching into
  `litestar_auth._plugin.*` is unsupported and guarded by an import-isolation regression test). Register
  extensions explicitly via `LitestarAuthConfig.extensions=(...)`; an extension contributes controllers,
  dependencies, middleware, OpenAPI security schemes, startup/shutdown hooks, and exception handlers
  through the typed contexts. An optional `enabled` flag toggles an extension off without removing it from
  configuration (omitting it is treated as enabled).

- **Versioned extension boundary.** `EXTENSION_API_VERSION` (currently `(1, 0)`) versions the authoring
  contract independently of the rest of the library. An extension may declare a `requires_api` minimum;
  an incompatible requirement fails closed with `ConfigurationError` before any application wiring runs.

- **Opt-in entry-point discovery.** New `LitestarAuthConfig.auto_discover_extensions` (default `False`)
  loads external extensions published under the `litestar_auth.extensions` entry-point group, following
  the `litestar_auth_ext_*` distribution-naming convention. Discovery is fail-closed: an entry point that
  cannot load, cannot instantiate, or does not produce a valid `AuthExtension` raises `ConfigurationError`.

- **CLI and manager-event contribution surfaces.** New optional `AuthCliExtension` lets an extension
  contribute CLI commands; `on_cli_init` now routes through it (the built-in organization administration
  CLI is its first internal consumer). New optional `AuthEventSubscriberExtension` lets an extension
  observe manager lifecycle events through **redacted** payloads — token-bearing values and credential
  fields (passwords, hashed passwords, invitation tokens, and similar) are stripped before delivery.

- **`RoleAdminExtension` first-party extension.** The contrib role-administration controller is now also
  available as a public `RoleAdminExtension` (import from `litestar_auth.contrib.role_admin`) for explicit
  `extensions=(...)` registration — the canonical example of the user-facing authoring API. A runnable
  reference is bundled at `examples/demo_external_extension/`.

### Changed

- **Built-in optional features now wire through the extension pipeline.** OAuth, TOTP, user-owned API
  keys, and organization administration/invitations are auto-materialized into the same extension pipeline
  from their existing configuration flags. Behavior for existing configurations is unchanged. As part of
  this, `LitestarAuthConfig.resolve_extensions()` is memoized, so extension-relevant configuration must be
  set before the plugin first resolves extensions during application init.

- **Extension OpenAPI security scheme names must be globally unique and fail closed on collision.**
  Extension-contributed OpenAPI security scheme names may not collide with each other or with core auth
  scheme names (bearer/cookie backend names, `apiKeyAuth`, and `apiKeyHmacAuth` for signed API keys). A
  collision raises `ConfigurationError` during application initialization, before the app is usable.

## 4.2.0 (2026-06-05)

### Added

- **Permission-based authorization.** New `has_permission()`, `has_all_permissions()`, and
  `has_any_permission()` route guards authorize against an authenticated user's effective permissions
  using `resource:action` tokens, with `resource:*` and `*` grants (route requirements themselves may not
  be wildcards and fail closed). Configure grants declaratively via `LitestarAuthConfig.role_permissions`
  (role → permission iterable) or supply a custom `permission_resolver` implementing the new
  `PermissionResolver` protocol; the bundled `StaticRolePermissionResolver` maps flat roles to permissions
  and treats the configured `superuser_role_name` as a global `*` grant. Denials raise
  `InsufficientPermissionsError` (`ErrorCode.INSUFFICIENT_PERMISSIONS`) with structured context but without
  echoing permission names in the response message. A `litestar_auth_permissions` dependency
  (`DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY`) exposes the request's resolved permissions for response
  shaping and UI hints — not a substitute for route guards.

- **Multi-tenant organizations (opt-in).** New global-`User` + `OrganizationMembership` identity model with
  bundled lazy ORM models `Organization`, `OrganizationMembership`, and `OrganizationInvitation` (import from
  `litestar_auth.models`; composable mixins `OrganizationMixin` / `OrganizationMembershipMixin` /
  `OrganizationInvitationMixin`, kept out of the root package and `litestar_auth.db` to preserve lazy ORM
  import isolation). Persistence goes through `BaseOrganizationStore` (with `OrganizationData`,
  `MembershipData`, `OrganizationInvitationData` payloads) and the bundled `SQLAlchemyOrganizationStore`
  (`litestar_auth.db.sqlalchemy`). Everything is gated by `LitestarAuthConfig.organization_config`
  (`OrganizationConfig`, disabled by default). A request's verified organization is resolved by a pluggable
  `TenantResolver` — built-ins `HeaderTenantResolver`, `SubdomainTenantResolver`, and the signed
  `ClaimTenantResolver` — exposed to handlers via the `litestar_auth_current_organization` dependency, with
  the `requires_organization_membership` guard for member-only routes.

- **Organization-scoped authorization.** `has_organization_role()` and `has_organization_permission()`
  authorize against the caller's roles in the *current* organization. Within an organization the membership
  roles replace the user's global flat roles for permission resolution (the configured `superuser_role_name`
  still grants a global `*`), so the existing `has_permission()` guards become organization-scoped when an
  organization context is present. Denials use `INSUFFICIENT_ORGANIZATION_ROLES` /
  `INSUFFICIENT_ORGANIZATION_PERMISSIONS`; precedence and fail-closed behavior are configurable via
  `OrganizationConfig.role_precedence` and `OrganizationConfig.require_authorization_context`.

- **Signed active organization and switch-organization flow.** The JWT strategy can carry a verified
  organization claim and issue an org-bound token; `ClaimTenantResolver` reads that signed claim (trusted,
  unlike the header/subdomain hints). An opt-in `POST /switch-organization` endpoint
  (`include_switch_organization`) verifies the caller's membership in the target organization before
  reissuing an org-bound token (`ORGANIZATION_SWITCH_DENIED` on failure). Signed active organization is
  JWT-strategy-specific; other strategies fall back to the header/subdomain resolvers. The endpoint exposes an
  `AuthRateLimitConfig.organization_switch` rate-limit slot (off by default), mirroring the invitation
  accept/decline slots.

- **Organization administration and email invitations (opt-in).** Bundled
  `create_organization_admin_controller` (organization CRUD + membership management) and an `organizations`
  CLI group manage organizations and memberships behind `include_organization_admin`, with
  last-privileged-member protection (`ORGANIZATION_LAST_PRIVILEGED_MEMBER`).
  `create_organization_invitation_controller` (`include_organization_invitations`) adds email-scoped
  invitations: an admin issues a signed single-use invitation token delivered via the new
  `on_after_organization_invitation(invitation, token)` manager hook (the library never sends email), and the
  invitee accepts at `POST /organization-invitations/accept`. Accepting or declining an invitation requires an
  active, verified account (`is_active` + `is_verified`): an inactive or unverified caller is denied with the
  standard permission-denied response even when holding a valid invitation token.

- **Optional server-side single-use for verify and reset-password tokens.** New
  `account_token_denylist_store` on `LitestarAuthConfig` and `BaseUserManager` accepts any shared
  `JWTDenylistStore` (for example `RedisJWTDenylistStore`). When configured, a verify or reset token's
  `jti` is checked on entry and consumed on success, so a captured token cannot be replayed even before the
  password fingerprint / verification state rotates. Unset (default) preserves the existing
  fingerprint / verification-state single-use and is fully backward compatible.

### Changed

- **Redis optional extra requires redis-py 8.x with no deprecated command surface.** `litestar-auth[redis]`
  now pins `redis>=8.0.0,<9.0.0`. Built-in stores use `SET ... EX=` and `SET ... NX PX=` only (not
  `SETEX` / `PSETEX`). `RedisAuthClientProtocol` and `RedisExpiringValueStoreClient` expect
  `set(..., ex=...)` instead of `setex`. The rate-limit retry-after Lua script accepts flat and nested
  `ZRANGE ... WITHSCORES` shapes under redis-py 8 + fakeredis. See `docs/migration.md` (redis-py 8).
- **Minimum runtime dependencies:** Litestar ≥ 2.23 and Advanced Alchemy ≥ 1.11.
- **Litestar 2.23 dependency markers:** generated plugin routes and contrib handlers now use
  ``di.NamedDependency[T]`` instead of the deprecated ``params.Dependency()`` marker so import-time
  deprecations stay compatible with strict ``filterwarnings = ["error"]`` test suites.
- **Advanced Alchemy filter vocabulary:** role-catalog pagination and role-name existence checks use
  ``ChoicesFilter`` and ``LimitOffset`` via ``get_many_and_count`` instead of loading full catalogs into
  Python and slicing. ``ChoicesFilter`` (new in Advanced Alchemy 1.11) is the clearer membership-filter
  vocabulary in place of ``CollectionFilter`` / ``.in_()`` — neither of which is deprecated. Contrib
  role-admin list endpoints now paginate at the database layer.

- **API-key scope guards share the permission vocabulary.** `has_scope()` / `has_any_scope()` now accept
  permission-shaped `resource:action`, `resource:*`, and `*` scopes and match them with the same engine as
  permission guards. With `scope_subset_check=True` (default) a delegated key must remain within the owning
  user's currently resolved permissions, so revoking the underlying permission also removes the key's route
  access. Legacy simple scopes without `:` keep the previous scopes-as-role-names subset behavior for
  migration.

- **Concurrent organization/membership creation returns a clean conflict.** A create-organization or
  add-member request that loses a unique-constraint race (duplicate slug, or duplicate
  `(user_id, organization_id)` membership) now surfaces the existing conflict domain error instead of an
  unhandled 500. The store maps the constraint violation within a savepoint, so the outer transaction stays
  usable and the conflict re-classification query runs without discarding earlier work.

### Security

- **Tenant hints are untrusted; organization access requires verified membership.** A header- or
  subdomain-resolved organization slug is only a lookup key: the current-organization context is published
  only after the authenticated user's membership is verified, and every organization guard fails closed
  without it. Switching organizations and accepting invitations both verify membership/identity
  server-side — invitation accept requires the authenticated user's email to match the invitation
  (`ORGANIZATION_INVITATION_EMAIL_MISMATCH`), so a leaked or forwarded invitation token cannot be used to
  join an organization. Invitation tokens are signed, single-use, and persisted only as a hash; switch and
  accept denials are non-enumerating.

- **API-key scopes bound permission guards (least privilege).** When a request is authenticated with an
  API key, `has_permission()`, `has_all_permissions()`, and `has_any_permission()` now require the key's
  own scopes to delegate each permission in addition to the owning user granting it, so a scoped key can
  never exceed its delegation on a permission-guarded route — even for a superuser owner. This mirrors the
  `scope_subset_check` ceiling already enforced for `has_scope()` guards. Keys with legacy simple scopes
  (no `resource:action` grammar) or empty scopes carry no permission-shaped authority and fail closed on
  permission guards; use `has_scope()` or `requires_password_session` for those routes.

- **OAuth account association verifies provider-email ownership (CWE-345).** `associate_account` now
  rejects linking a provider identity whose email already belongs to a *different* local user — using the
  same email resolution as login — and responds with `OAUTH_USER_ALREADY_EXISTS`. This prevents an
  authenticated user from attaching a provider account that carries someone else's email to their own
  account. Linking a provider whose email is your own, or owned by nobody, is unaffected.

- **Password login no longer reveals disabled/unverified account state (CWE-203).** On the password-login
  route, inactive/unverified account-state failures now return the generic `LOGIN_BAD_CREDENTIALS` response
  instead of `LOGIN_ACCOUNT_UNAVAILABLE`, so a caller holding a valid password can no longer distinguish
  "account exists but disabled/unverified" from "wrong credentials". The login rate-limit counter is still
  incremented on the failure. Other account-state-gated flows where identity is already proven (refresh,
  OAuth local session) keep emitting `LOGIN_ACCOUNT_UNAVAILABLE`. Integrators keying on the login error
  code should treat both states as `LOGIN_BAD_CREDENTIALS`.

### Documentation

- **Multi-tenant organizations documented.** `docs/configuration/organizations.md`, `docs/http_api.md`, and
  `docs/errors.md` cover the organization models, `OrganizationConfig`, tenant resolution, org-scoped guards,
  the switch-organization endpoint, administration controllers/CLI, and invitations. The roadmap marks
  multi-tenancy delivered and states that row-level isolation of *application* tables remains the
  application's responsibility — the library provides the `litestar_auth_current_organization` dependency and
  authorization primitives, not automatic query filtering.

- **Guards guide documents permission-based authorization.** `docs/guards.md` covers the permission
  guards, `resource:action` / `resource:*` / `*` grammar, `role_permissions` configuration, the superuser
  global grant, the `litestar_auth_permissions` dependency, and the API-key delegation ceiling. The roadmap
  clarifies that flat `role` / `user_role` tables remain the persistence layer and that `role_permissions`
  and custom `permission_resolver` objects are the current extension points for effective permissions.

- **Account-token and login-enumeration hardening documented.** `docs/security.md` and
  `docs/configuration/security.md` cover the optional `account_token_denylist_store` single-use posture,
  `docs/errors.md` documents that the password-login route folds inactive/unverified state into
  `LOGIN_BAD_CREDENTIALS`, and `docs/cookbook/oauth_associate.md` documents the provider-email ownership
  check on association.

## 4.1.0 (2026-05-29)

### Added

- **Configurable trusted-proxy hop count for rate limiting.** `EndpointRateLimit.trusted_proxy_hops`
  (plus `SharedRateLimitConfigOptions.trusted_proxy_hops` and
  `RedisAuthRateLimitConfigOptions.trusted_proxy_hops`) selects which `X-Forwarded-For` entry, counted
  from the right, is trusted as the client IP behind a multi-proxy chain (CDN → LB → app). The default
  `1` preserves the previous rightmost-entry behavior byte-for-byte; when the header carries fewer
  entries than the configured hop count, rate-limit identity fails closed to the direct client host.
- **Fail-closed DNS validation for OAuth redirect hosts (default).** `OAuthConfig.oauth_redirect_dns_strict`
  (plugin-owned routes) and `oauth_redirect_dns_strict` on the manual/provider OAuth controller configs
  (`OAuthControllerConfig`, `OAuthAssociateControllerConfig`, `ProviderOAuthControllerConfig`) now default
  to `True`: the redirect-host SSRF gate rejects DNS resolver failures, empty answers, and answers without
  any usable public address with `ConfigurationError` at validation/startup time. Set
  `oauth_redirect_dns_strict=False` to restore fail-open resolver handling for offline or sandboxed startup
  environments. The check still resolves DNS only at validation time and does not defend against DNS
  rebinding, so pair it with runtime network egress controls. **Potentially breaking:** deployments whose
  OAuth `redirect_base_url` host cannot be resolved at startup (offline, sandboxed, or transient DNS
  failure) now fail closed unless they opt out with `oauth_redirect_dns_strict=False`.

### Changed

- **Demo example apps share one secret-resolution helper.** All seven `examples/demo_*/app.py` resolve
  secrets through `examples._demo_secrets.resolve_demo_secrets`, centralizing the insecure-default
  warning and the env-var-read-or-raise behavior while preserving each app's `*_INSECURE` flag,
  default tuple, error wording, and tuple/dataclass return shape. Examples only; no library API change.

### Security

- **Stronger production secret entropy validation.** `validate_secret_strength` now estimates entropy
  with a pattern-aware heuristic that caps exactly-periodic secrets built from a short repeated unit
  (e.g. `"abc123" * 22`) at the entropy of that unit, and additionally rejects a single uninterrupted run
  of near-consecutive codepoints (e.g. `"abcdefghijklmnopqrstuvwxyz123456"`) that clears the 128-bit
  frequency floor yet is trivially guessable. Structured-but-long secrets that previously cleared the floor
  are rejected at startup. Cryptographically random secrets (`secrets.token_hex(32)`,
  `secrets.token_urlsafe(32)`) still pass, the single-span sequential check does not touch repeated-unit
  secrets, and the `unsafe_testing=True` and `minimum_entropy_bits=0` bypasses are unchanged.
  **Potentially breaking:** weak production secrets that previously validated may now be rejected —
  generate strong secrets and redeploy.
- **Trusted-proxy hop count applied to the TOTP pending-token client binding.**
  `build_pending_totp_client_binding` honors `trusted_proxy_hops`, sourced from the configured
  `totp_verify_rate_limit`, so the anti-theft client-IP fingerprint resolves the same `X-Forwarded-For`
  hop the verify-endpoint rate limiter keys on. Previously this path always trusted the rightmost
  entry, which in multi-proxy deployments bound to the shared inner-proxy address. The default of 1 hop
  is unchanged.

### Documentation

- **Deployment hardening guidance.** The deployment security contract documents the role-admin
  controller authorization footgun (an explicit empty `guards=[]` disables the default `is_superuser`
  guard) and the limits of the OAuth `redirect_base_url` SSRF gate (validation-time DNS check that fails
  closed on resolver errors by default and does not defend against DNS rebinding — opt out with
  `oauth_redirect_dns_strict=False` for offline or sandboxed startup, and pair the gate with runtime
  egress controls).

## 4.0.1 (2026-05-29)

### Fix

- **docs**: align auth documentation with code and remove migration-style wording

## 4.0.0 (2026-05-28)

### Added

- **Advanced Alchemy coexistence regression with native ``async_sessionmaker``.** Integration coverage now exercises ``SQLAlchemyPlugin`` + ``LitestarAuth`` when both plugins share a real ``aiosqlite``-backed ``async_sessionmaker``, in addition to the existing sync-adapter ``E2ESessionMaker`` probe.
- **Per-domain error-code enums.** `ErrorCode` is now an aggregate registry composed of
  `AuthErrorCode`, `TokenErrorCode`, `RoleErrorCode`, `TotpErrorCode`, `OAuthErrorCode`, and
  `ApiKeyErrorCode`, each documenting the emission site of every member. Wire-format values
  are byte-identical to the previous flat StrEnum; `ErrorCode.LOGIN_BAD_CREDENTIALS` and all
  other existing names keep resolving. `ApiKeyNotFoundError` now carries an API-key-specific
  code instead of falling back to `AUTHORIZATION_DENIED`.
- **`consumed_token_digests` field on the refresh-token contract.** `RefreshTokenMixin` and
  the bundled SQLAlchemy `RefreshToken` model expose a nullable JSON column that records
  keyed digests of refresh tokens already consumed by a prior rotation. Custom refresh-token
  models passed to `DatabaseTokenModels` must expose the same mapped attribute. See Security.
- **Per-user invalidation epoch on the Redis token strategy.** `RedisStrategy.write_token` now
  pairs every persisted token with the current per-user epoch and `read_token` rejects tokens
  whose stored epoch is behind the live counter. `invalidate_all_tokens()` bumps the epoch
  atomically (Lua) and sweeps the per-user index in one round trip.
- **`BaseUserManagerConfig.creatable_fields` and `updatable_fields`.** Explicit per-manager
  allowlists make `BaseUserManager.create(..., safe=False)` and `update(...)` deny-by-default
  for any non-privileged field that is not declared. Public registration and OAuth bootstrap
  paths continue to call `safe=True` and only persist `email`/`password`.
- **`SystemManagedRoleError`** and **`RoleProtectedError`** exposed from
  `litestar_auth._plugin.role_admin` for callers that want to differentiate destructive
  RBAC invariant violations from generic `ValueError`s.
- **`UnencryptedOAuthTokenBackend`.** Explicit plaintext OAuth-token storage backend wired
  in only when `OAuthTokenEncryption(unsafe_testing=True)` is constructed without a Fernet
  keyring. Replaces the implicit plaintext fall-through that lived on `_RawFernetBackend`.
- **`STATE_COOKIE_MAX_AGE` constant** is now importable from `litestar_auth.oauth._flow_cookie`
  and reused by both the cookie `max-age` and Fernet server-side `ttl`.
- **Refresh-token reuse-detection regression tests, JWT denylist float-`exp` boundary tests,
  Redis orphan-token invalidation tests, and OAuth flow-cookie TTL tests.** New regression
  coverage for every security fix below.

### Changed

- **Minimum runtime dependencies:** Litestar ≥ 2.22 and Advanced Alchemy ≥ 1.10.
- **SQLAlchemy user pagination** uses Advanced Alchemy ``get_many_and_count`` instead of the deprecated ``list_and_count``.
- **Generated plugin routes** declare Litestar 2.22 query and path parameters with explicit ``Annotated[..., QueryParameter/PathParameter(...)]`` metadata (including dynamic paginated user listing).
- **`LitestarAuthConfig.session_scope_key`:** optional Advanced Alchemy scope key for request sessions. Defaults to Advanced Alchemy's ``SESSION_SCOPE_KEY``. When using ``SQLAlchemyPlugin``, pass ``SQLAlchemyAsyncConfig.session_scope_key`` (for example via ``bind_auth_session_to_alchemy``) so middleware, DI, and ``before_send`` handlers share the same scoped session as Advanced Alchemy.
- **`bind_auth_session_to_alchemy`` / ``AlchemyAuthSessionBinding``:** helper for wiring ``session_maker`` and ``session_scope_key`` from a constructed ``SQLAlchemyAsyncConfig`` into ``LitestarAuthConfig``.

### Removed

- **`litestar_auth._plugin.feature_configs`, `litestar_auth._plugin.backend_inventory`,
  and `litestar_auth._plugin._totp_controller` module paths.** All three were thin
  backward-compatibility shims re-exporting from the canonical `litestar_auth._plugin.features`
  and `litestar_auth._plugin.totp_controller` packages. The `_plugin/` namespace is
  private, BC is not a product requirement (AGENTS.md), and the canonical seams are
  `litestar_auth._plugin.features` and `litestar_auth._plugin.totp_controller`. Any
  importer of the old `_totp_controller` path must switch to
  `litestar_auth._plugin.totp_controller`; tests that previously monkey-patched the
  shim should target `litestar_auth._plugin.totp_controller._core` to retain
  `_core`-scoped behavior overrides.

### Security

- **DB refresh-token reuse detection.** `rotate_refresh_token` now records the consumed
  digest atomically alongside the rotation and detects replays of an already-consumed
  refresh token. A replayed token revokes every refresh-token row sharing the compromised
  `session_id` (the entire refresh-session chain) instead of silently failing as an
  ordinary missing token. Closes the stolen-then-rotated theft window within
  `refresh_max_age`. RFC 6749 §10.4 / OAuth 2.1 §6.1 compliance.
- **JWT denylist TTL now honors float `exp` claims.** `JWTStrategy.destroy_token` previously
  used `isinstance(exp, int)`, collapsing the denylist TTL to 1s for any JWT whose `exp` was
  encoded as a float (legal per RFC 7519 §2 NumericDate) and effectively voiding revocation
  for externally-minted tokens. The guard now accepts any finite numeric `exp` and falls back
  safely for missing or non-numeric values.
- **Redis `invalidate_all_tokens()` is now fail-closed.** A per-user epoch bumped atomically
  via Lua, plus epoch validation on every `read_token`, means orphan tokens missing from the
  per-user index are rejected immediately on use instead of surviving until their TTL.
  "Logout from all devices" is now a hard guarantee under Redis eviction.
- **Configured superuser role is system-managed.** `delete_role` rejects deletion of the
  role named by `AuthConfig.superuser_role_name` with `SystemManagedRoleError`, regardless
  of `force=True`. `unassign_user_roles` and the matching CLI/HTTP paths refuse to remove
  the last assignment of the superuser role. Closes a destructive admin-lockout vector
  reachable from the bundled `roles delete --force` and `roles unassign` commands.
- **OAuth flow cookie enforces server-side TTL.** `_OAuthFlowCookieCipher.decrypt` now
  passes `ttl=STATE_COOKIE_MAX_AGE` (300s) to `Fernet.decrypt`, so a leaked or replayed
  state cookie cannot stay cryptographically valid beyond the browser `max-age`.
- **OAuth callback clears the state cookie on every exit path.** Both login
  (`/auth/oauth/{provider}/callback`) and associate
  (`/auth/associate/{provider}/callback`) wrap the callback body in
  `_clear_state_cookie_on_callback_exit`, so a callback that raises (invalid state,
  provider error, account-state rejection) still expires the encrypted state+verifier
  cookie. Previously the cookie was only cleared on the happy path.
- **OAuth token encryption fails closed at the backend.** `_RawFernetBackend` raises
  `ConfigurationError` if it is invoked without a configured keyring; production code paths
  cannot reach a silent plaintext fall-through. Explicit plaintext storage is reachable only
  through the new `UnencryptedOAuthTokenBackend`, which `OAuthTokenEncryption` selects only
  when `unsafe_testing=True` is set without a key.
- **Rate-limit identifier inputs are length-capped before PBKDF2.** `_extract_email` and the
  HMAC API-key identifier extractor now bound the string fed into the rate-limit key
  derivation, removing a CPU-amplification vector on every unauthenticated login,
  forgot-password, and signed-API-key request. The attacker-supplied `Credential=` value in
  the `LSA1-HMAC-SHA256` Authorization header is no longer used as a rate-limit bucket
  partition, closing a per-key bucket-pollution / denial-of-service vector against
  legitimate API-key holders.
- **API-key authentication failure classification runs before rate-limit increment.** The
  authentication middleware now classifies the failure code before incrementing the
  `api_key_use` budget, so unauthenticated requests carrying random or malformed key ids no
  longer burn the legitimate owner's bucket.
- **Admin user mutations require admin step-up proof.** Superuser `PATCH /users/{user_id}`
  requests must include the authenticated admin's `current_password`, and may include
  `totp_code` when the admin has TOTP enabled. Superuser `DELETE /users/{user_id}` accepts
  a JSON body with the same admin step-up fields. The target user's password never
  satisfies this check.
- **`BaseUserManager.create(..., safe=False)` and `update(...)` reject undeclared custom
  fields by default.** Single explicit field policy with `creatable_fields` /
  `updatable_fields` allowlists. Public registration and OAuth bootstrap (`safe=True`) keep
  accepting only `email`/`password`. Direct `safe=False` create calls and update calls now
  raise `AuthorizationError` naming any field that is neither in the allowlist nor covered
  by the privileged-field override. Existing privileged-field behavior is unchanged.
- **Login response timing parity.** `/auth/login` now wraps failure, pending-2FA, and
  fully-authenticated branches in `await_minimum_response_seconds` (configurable via
  `AuthSettings`, default unchanged), restoring branch-timing parity that previously leaked
  whether the target user had TOTP enrolled.

### Changed

- **Subsystem decomposition (no external behavior change).** Internal modules were split
  into focused submodules across `_plugin/`, `_manager/`, `controllers/`, `oauth/`,
  `authentication/strategy/`, `ratelimit/`, `db/`, and the top-level crypto helpers.
  Public import surfaces are preserved through each package's `__init__.py`. Notable
  boundaries: `authentication/strategy/db.py` → `db.py` + `_db_refresh.py` +
  `_db_rotation.py` + `_db_client_metadata.py`; `_plugin/role_admin.py` →
  `role_admin/{_core,_queries,_mutations,_invariants}.py`; `_plugin/startup.py` →
  `startup/{_core,_warnings,_requirements}.py`; `_plugin/config.py` →
  `config/{_core,_protocols,_defaults,_resolvers,_validation}.py`; `_plugin/validation.py`
  → nine concern-named submodules under `validation/`; `_plugin/features/registry.py` →
  five submodules; `_plugin/dependencies.py` → `dependencies.py` + `exception_handlers.py`;
  `oauth/service.py` → authorization issuer + callback resolver + linking policy + account
  upserter; `_manager/api_keys.py` → `api_key_config.py` + `api_key_secrets.py` +
  `api_key_service.py` + `api_key_row.py`; `totp.py` →
  `_totp_primitive.py` + `_totp_recovery.py` + `_totp_verify.py` (lazy Argon2 dummy hash).
- **Type tightening.** ~50 `cast("Any", ...)` sites removed across `authentication/`,
  `controllers/`, `db/`, and `_plugin/` via typed Protocols and narrower seams. Zero
  `# type: ignore` directives in `litestar_auth/`.
- **Plugin feature wiring is table-driven.** A `FeatureWiring` descriptor list replaces
  per-feature procedural branches in `_plugin/_hooks.py` and `_plugin/startup/`; adding a
  feature is a single descriptor row.
- **Validation kernel.** `_plugin/validation/` now shares an `IssueCollector` /
  `ValidationIssue` kernel across `general`, `api_key`, `oauth`, `totp`, `roles`,
  `credentials`, `request_security`, `session`, and `login_identifier` validators.
- **API-key failure classification.** The contextvar-based nonce-failure shuttle is gone;
  `ApiKeyStrategy` returns a typed `ApiKeyFailureReason` enum alongside the `None` result
  and the middleware maps that single value to the public ErrorCode.
- **Account-state helpers** collapsed into a single `AccountStatePolicy` with domain-error
  and client-error tiers (`require` / `require_for_client`). The
  `LOGIN_ACCOUNT_UNAVAILABLE` wire mapping is unchanged.
- **Schema field aliases** consolidated in `litestar_auth/_schema_fields.py`; the public
  `UserEmailField` and `UserPasswordField` remain importable from `litestar_auth.schemas`.
- **OAuth associate-callback factory** is now one shared primitive that drives both the
  direct-manager and dependency-key handler variants.
- **Fernet keyring** is a single shared abstraction; OAuth token encryption and TOTP
  enrollment secrets use the same nullable-keyring policy.

### Internal

- **Controller partition flattening.** Four single-consumer private partition files were
  inlined back into their parent controllers: `controllers/_auth_login.py` +
  `_auth_refresh.py` + `_auth_routes.py` → `controllers/auth.py`;
  `controllers/_users_handlers.py` + `_users_routes.py` → `controllers/users.py`;
  `controllers/_oauth_associate_routes.py` + `_oauth_authorize_routes.py` +
  `_oauth_login_handlers.py` → `controllers/oauth.py`;
  `controllers/_totp_confirm_handlers.py` → `controllers/totp_handlers.py`.
  Public route registration, request-body wiring, and OpenAPI metadata are unchanged.
- **Dead manager hook `Protocol` layer removed.** `_manager/_protocols.py` no longer
  declares the hook surface that mirrored `ManagerHookBus` method-for-method; nothing
  typed against the Protocol and the parallel definition was unreachable.
- **`UserLifecycleService` policy delegates inlined.** Six private pass-through wrappers
  (`_normalize_email`, `_normalize_username_lookup`, `_normalize_roles`,
  `_validate_password`, `_hash_password`, `_verify_and_update_password`) deleted from
  `_manager/user_lifecycle.py`; all call sites go through `self._policy.<method>` or
  `self._policy.password_helper.<method>` directly.
- **`_finalize_route_handler` helper.** A single typed helper in
  `controllers/_request_body.py` (re-exported via `controllers/_utils.py`) replaces 15
  repeated `cast("RequestBodyRouteHandler", ...)` call sites across
  `controllers/users.py` (7) and `contrib/role_admin/_controller_handlers.py` (8),
  bridging the Litestar decorator return type to the local request-body Protocol behind
  one named seam.
- **Private `ApiKeyMixin` re-export module removed.** `litestar_auth/_api_key_model_mixin.py`
  was a one-line re-export of `ApiKeyMixin` from `_auth_model_mixins`; the only in-repo
  consumer now imports the symbol directly from its canonical module.
  `litestar_auth.models.ApiKeyMixin` (the public path) is unchanged.
- **Lint hygiene pass.** `del`-no-op argument bodies replaced by underscore-prefixed
  names or a single targeted `# noqa: ARG002` where the public signature is a contract;
  redundant `RUF100` suffixes stripped from 32 noqa directives across the library and
  e2e tests, with whole directives removed where the underlying rule was already
  silenced by per-file ignores; the lone `except Exception` + `isinstance(exc,
  IntegrityError)` filter in `contrib/role_admin/_controller_handlers.py` rewritten to
  `except IntegrityError`; an `F401`-suppressed re-export removed from
  `controllers/_users_helpers.py`.
- **Coverage configuration consolidated.** `[tool.coverage.report] exclude_lines` now
  covers `@overload` signatures, ellipsis placeholder bodies, `Protocol` and `TypedDict`
  class bodies, and PEP 695 `type` aliases via structural regex patterns; 78 per-line
  templated `# pragma: no cover - ...` comments were removed from `litestar_auth/`
  (91 → 13 pragmas, with the 13 remaining all carrying singular, non-templated reasons).
  The `--cov-fail-under=100` gate remains green.
- **Code-quality finding sweep (CodeQL standard + AI).** Three actionable findings
  triaged against the codebase and fixed; remaining findings audited and dismissed as
  false positives (CodeQL not modelling `pytest.raises`, `Never`/`NoReturn`, cross-module
  private imports, or constant-time security intent).
- **Dead duplicate `_INVALID_CREDENTIALS_DETAIL` removed.** The unused private constant
  in `controllers/_step_up.py` duplicated the canonical `INVALID_CREDENTIALS_DETAIL`
  exported from `controllers/auth.py` and `controllers/_error_responses.py`; deleted to
  prevent future divergence. No import-path or wire-format change.
- **API-key `last_used_write_strategy` validator derives its allowed set from the type.**
  `_plugin/validation/api_key.py` now reads the allowed strategy values via
  `typing.get_args(ApiKeyLastUsedWriteStrategy)` instead of a hard-coded literal set,
  and the configuration error message lists them dynamically. The duplicated
  `ApiKeyLastUsedWriteStrategy` redeclaration in `_manager/api_key_config.py` was
  reconciled to import the canonical alias from `_plugin/features/_defaults.py`, which
  is now a plain `Literal` assignment (no longer a PEP 695 `type` statement) so
  `get_args` returns the literal values at runtime; the static-typing surface for
  consumers is unchanged.
- **Constant-time API-key failure classification documented.** The trailing
  `api_key_secret_matches` / `_signed_request_signature_matches` comparisons inside
  `_classify_bearer_failure_reason` and `_classify_signed_failure_reason` in
  `authentication/strategy/api_key.py` carry single-line comments noting that the
  reason intentionally maps to the wrong-secret / wrong-signature failure to prevent
  timing-based discrimination between valid and invalid secrets on already-failed
  authentication. The conditional and return values are unchanged.

### Migration

- **Add the `consumed_token_digests` column.** Deployments using the bundled
  `refresh_token` table must add a nullable JSON column. SQLite/PostgreSQL recipes are in
  `docs/migration.md`. Custom refresh-token models passed to `DatabaseTokenModels` must
  expose a mapped `consumed_token_digests` attribute; composing `RefreshTokenMixin` is the
  recommended path.
- **Declare custom manager fields explicitly.** If you call
  `BaseUserManager.create(..., safe=False)` or `update(...)` with non-standard fields,
  pass `creatable_fields=...` / `updatable_fields=...` to `BaseUserManager(...)` or
  `BaseUserManagerConfig(...)`. The deny-by-default policy raises `AuthorizationError`
  naming the rejected field.
- **Admin user mutation requests must include admin step-up proof.** Clients calling
  `PATCH /users/{user_id}` must add the authenticated admin's `current_password` to the
  update body. Clients calling `DELETE /users/{user_id}` must send a JSON body such as
  `{ "current_password": "admin-password" }`. Enrolled admins can send `totp_code` inline
  or satisfy the recent-TOTP marker policy.
- **Internal `_plugin/` import paths reorganized.** Anything that imported from the
  removed `_plugin.feature_configs` or `_plugin.backend_inventory` must switch to
  `litestar_auth._plugin.features`. Code that reached into `_plugin/{role_admin, startup,
  config, totp_controller, controllers}.py` privates must switch to the new submodule
  paths or — preferably — go through the package's public surface.
- **Per-domain error-code enums are optional.** Wire-format values and `ErrorCode.<NAME>`
  imports are byte-identical. Callers that want clearer intent can now also import
  `AuthErrorCode`, `TokenErrorCode`, `RoleErrorCode`, `TotpErrorCode`, `OAuthErrorCode`,
  or `ApiKeyErrorCode`.

## 3.3.0 (2026-05-17)

### Added

- **Unified login account-state error code.** Added `ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE` for
  account-state failures that are intentionally opaque to clients.
- **`LitestarAuthConfig.verify_minimum_response_seconds`** and
  **`LitestarAuthConfig.request_verify_minimum_response_seconds`** (default `0.4`) — minimum
  wall-clock duration for plugin-owned `POST /auth/verify` and
  `POST /auth/request-verify-token` responses, padding success and failure paths alike as
  defense-in-depth against timing-based enumeration on the verification flow.
- **`ErrorCode.TOTP_STEPUP_REQUIRED`** and the matching `ClientException` factory for the new
  step-up gate (see Security).

### Removed

- **Deprecated differentiated login account-state codes.** Removed `ErrorCode.LOGIN_USER_INACTIVE`
  and `ErrorCode.LOGIN_USER_NOT_VERIFIED`; downstream consumers should match
  `LOGIN_ACCOUNT_UNAVAILABLE` instead.

### Security

- **Self-service email changes now require current-password proof.** `PATCH /users/me` still
  accepts non-credential self-service updates, but changing `email` now requires
  `current_password` on `UserUpdate`. Missing or wrong current passwords fail with the existing
  `LOGIN_BAD_CREDENTIALS` error and share the same rate-limit slot as
  `POST /users/me/change-password`. Successful email changes still flow through the manager
  update lifecycle, preserving verification and session-binding invalidation behavior.
- **Hard delete now removes user-owned auth state.** `BaseUserManager.delete()` now invalidates
  configured token strategies and deletes SQL-backed API keys before deleting the user row, and the
  bundled user-owned SQL tables now declare `ON DELETE CASCADE` on their user foreign keys. Deleting a
  user with access tokens, refresh tokens, API keys, OAuth accounts, TOTP secrets, or recovery codes
  now removes those dependent secrets instead of leaving orphaned state or relying on backend-specific
  FK failures. Redis opaque tokens and Redis TOTP step-up markers are deleted through their per-user
  indexes; legacy Redis token keys that were written without an index still expire naturally by TTL.
- **Sensitive controller operations now enforce TOTP step-up.** Enrolled users must present a recent
  TOTP marker or a valid inline `totp_code` before self-service email changes, API-key create/update/revoke,
  OAuth account association, TOTP disable, or recovery-code regeneration. Missing proof returns 403 with
  `TOTP_STEPUP_REQUIRED`; TOTP disable still accepts a recovery code as the lockout-recovery path.
- **Account-state responses no longer reveal inactive vs. unverified state.** Login and related
  account-state gated flows now return the same 400 / `LOGIN_ACCOUNT_UNAVAILABLE` client payload to
  prevent account-state enumeration (audit VULN #1, CWE-204). Operators can still observe the
  internal reason through the `account_state_failure` structured log event on the
  `litestar_auth.security` logger.

### Migration

- **Email change requests must include `current_password`.** Clients that change the
  authenticated user's email must send `{ "email": "new@example.com", "current_password":
  "current-password" }`. Non-email self-service updates from custom `user_update_schema`
  contracts do not require `current_password`. Password rotation remains on
  `POST /users/me/change-password` with `ChangePasswordRequest`.
- **Recreate user-owned auth FKs with `ON DELETE CASCADE`.** Deployments using the bundled SQLAlchemy
  auth tables should drop and recreate the foreign keys from `access_token.user_id`,
  `refresh_token.user_id`, `api_key.user_id`, `oauth_account.user_id`, and `user_role.user_id` to the
  user table with `ON DELETE CASCADE`. See `docs/migration.md` for an Alembic shape. PostgreSQL
  deployments that previously saw FK violations on hard delete will now delete dependents; SQLite
  deployments must keep `PRAGMA foreign_keys=ON` enabled to observe the same database-level cascade.
- **Update assertions and client handling for account-state failures.** Replace any downstream
  assertions on `LOGIN_USER_INACTIVE` or `LOGIN_USER_NOT_VERIFIED` with
  `LOGIN_ACCOUNT_UNAVAILABLE`; use server logs, not client payloads, when the internal
  inactive/unverified reason is needed.

## 3.2.0 (2026-05-10)

### Fixed

- **Refresh routes now coexist with API-key backends.** `enable_refresh=True` startup validation
  skips `ApiKeyTransport` backends because API keys do not participate in refresh-token flows, while
  non-API-key backends still must use a `RefreshableStrategy`.

## 3.1.0 (2026-05-10)

### Added

- **User-owned API keys.** New opt-in `ApiKeyConfig(enabled=True, ...)` wiring adds API-key
  authentication, self-service `/api-keys` routes, superuser `/users/{user_id}/api-keys` routes,
  scope guards, `ApiKeyContext`, HMAC-digest persistence, one-time raw credential responses, active
  key limits, expiry, soft revocation, `last_used_at` tracking, and `apiKeyAuth` OpenAPI security.
- **Signed API-key requests.** Optional `LSA1-HMAC-SHA256` request signing adds canonical request
  verification (mandatory `Host`, `X-Auth-Date`, `X-Auth-Nonce` in `SignedHeaders`; strict ISO-8601
  timestamp), `X-Auth-Nonce` replay protection, `apiKeyHmacAuth` OpenAPI security, in-memory and
  Redis nonce stores, and encrypted signing-secret storage through `api_keys.secret_encryption_keyring`.
- **API-key authorization guards.** New `requires_api_key`, `has_scope`, `has_any_scope`, and
  `requires_password_session` guards exported from `litestar_auth.guards`, with a pluggable
  `ApiKeyConfig.scope_authority` (default: scopes-as-role-names via
  `default_api_key_scope_authority`).
- **API-key rate-limit slots.** `AuthRateLimitConfig.api_key_create`, `api_key_update`, and
  `api_key_use` slots throttle credential-check failures and failed signed-auth attempts (the latter
  keyed by `api_key_id`).
- **API-key error codes.** `API_KEY_INVALID`, `API_KEY_REVOKED`, `API_KEY_EXPIRED`,
  `API_KEY_SCOPE_DENIED`, `API_KEY_LIMIT_REACHED`, `API_KEY_SIGNATURE_INVALID`,
  `API_KEY_SIGNATURE_TIMESTAMP_SKEW`, `API_KEY_SIGNATURE_NONCE_REPLAY`.
- **API-key lifecycle hooks.** `on_after_api_key_created`, `on_after_api_key_revoked`, and
  `on_after_api_key_used` (throttled) on `BaseUserManager` for audit-trail integration.
- **Signing-secret rotation helpers.** `BaseUserManager.api_key_signing_secret_requires_reencrypt`
  and `reencrypt_api_key_signing_secret` perform row-level Fernet re-encryption when the active
  keyring key changes.

- **Refresh-session / device management.** New opt-in
  ``include_session_devices`` flag on ``LitestarAuthConfig`` mounts a
  plugin-owned controller exposing authenticated routes for inspecting and
  revoking active refresh sessions:
  - ``GET /auth/sessions`` and ``POST /auth/sessions`` list active refresh
    sessions for the authenticated user; the ``POST`` variant accepts a
    ``RefreshTokenRequest`` body so non-cookie clients can mark the current
    session via ``is_current``.
  - ``DELETE /auth/sessions/{session_id}`` revokes one session by its
    public id (404 with ``REFRESH_SESSION_NOT_FOUND`` when the id is
    absent or foreign to the user).
  - ``POST /auth/sessions/revoke-others`` revokes every active refresh
    session for the user except the current one (resolved from the request
    body or refresh-token cookie when available).
- **Public session metadata payloads.** New
  ``litestar_auth.payloads.RefreshSessionRead`` and
  ``RefreshSessionListResponse`` msgspec structs, plus bounded
  ``SessionClientMetadataKey`` / ``SessionClientMetadataValue`` aliases,
  describe the safe response shape (``session_id``, ``created_at``,
  ``last_used_at``, ``is_current``, optional ``client_metadata``). Raw
  refresh tokens and stored token digests are never returned.
- **Strategy protocols for session management.** New
  ``RefreshSessionManagementStrategy`` and
  ``RefreshSessionIdentifierStrategy`` runtime-checkable protocols and a
  frozen ``RefreshSession`` dataclass in
  ``litestar_auth.authentication.strategy.base`` describe the contract a
  strategy must implement for the new controller. ``DatabaseTokenStrategy``
  implements both protocols (``list_refresh_sessions``,
  ``revoke_refresh_session``, ``revoke_other_refresh_sessions``,
  ``identify_refresh_session``) and prunes expired refresh-token rows
  before listing or revoking.
- **Bounded client metadata on refresh tokens.** ``RefreshTokenMixin`` (and
  the bundled ``RefreshToken`` model) now persists a public
  ``session_id`` (UUID4, unique, indexed), a ``last_used_at`` timestamp,
  and a JSON ``client_metadata`` column. Login and refresh handlers call
  the new ``RefreshTokenRequestContextRecorder`` hook so the DB strategy
  can capture a normalized, length-capped ``user_agent`` hint from the
  current request without ever storing arbitrary header content.
- **Cookie transport refresh-token reader.**
  ``CookieTransport.read_refresh_token`` returns the refresh token from
  the dedicated refresh cookie, used by the new session controller (and a
  shared ``_resolve_refresh_token_value`` helper) to identify the
  request's current session in cookie flows.
- **New error codes / exceptions.** ``ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED``
  and ``ErrorCode.REFRESH_SESSION_NOT_FOUND``, plus
  ``SessionManagementUnsupportedError`` and ``RefreshSessionNotFoundError``
  (both subclassing ``TokenError``), accompany the new controller.

### Changed

- **API-key admin routes require password-session authentication.** Superuser routes that mint,
  list, or revoke another user's API keys now reject API-key-authenticated callers with
  `AUTHORIZATION_DENIED`, matching the password-session boundary used for self-service key
  mutations.
- **API-key self-service read routes require password-session authentication.** User-owned
  `/api-keys` and `/api-keys/{key_id}` read routes now reject API-key-authenticated callers with
  `AUTHORIZATION_DENIED`, matching the existing password-session boundary for key mutations.
- **Signed API-key body buffering now caps ASGI frame count.** Signed-request pre-auth buffering is
  bounded by both `api_keys.signed_body_max_bytes` and `api_keys.signed_body_max_messages`; requests
  exceeding either limit fail closed with `REQUEST_BODY_INVALID`.
- **API-key update routes can now be rate limited.** `AuthRateLimitConfig.api_key_update` adds an opt-in
  `api-key-update` endpoint slot for self-service `PATCH /api-keys/{key_id}` password
  re-verification and scope-denial failures. Successful updates reset the slot counter, matching the
  create-route posture without changing the default unthrottled PATCH behavior.
- **API-key update rate-limit configuration was renamed.** Migrate
  `AuthRateLimitConfig(update=...)` to `AuthRateLimitConfig(api_key_update=...)`; the
  `AuthRateLimitSlot.API_KEY_UPDATE` string value also changed from `"update"` to
  `"api_key_update"`.
- **API-key bearer failure-code taxonomy is documented.** The security model now records the
  deliberate `API_KEY_INVALID` / `API_KEY_REVOKED` / `API_KEY_EXPIRED` trade-off for high-entropy
  bearer `key_id` values and the API-key guide links to that operator-facing explanation.
- **Direct middleware integrations no longer buffer signed API-key bodies by default.**
  `LitestarAuthMiddlewareConfig.api_key_backend_present` now defaults to `False`; plugin-managed
  applications are unchanged because the plugin still passes the computed backend inventory
  explicitly. Direct integrators that construct `LitestarAuthMiddleware` outside the plugin and use
  an `ApiKeyTransport` must pass `api_key_backend_present=True` to enable LSA1 signed-body buffering.
- **``DatabaseTokenModels`` contract widened for refresh tokens.**
  Refresh-token models supplied through ``DatabaseTokenModels`` must now
  expose mapped ``session_id``, ``last_used_at``, and ``client_metadata``
  attributes in addition to the previously required
  ``token``/``created_at``/``user_id``/``user``. Validation now uses
  separate required-attribute tuples per model. The bundled
  ``RefreshToken`` satisfies the new contract automatically; custom
  refresh-token classes must add the three new mapped columns.
- **Refresh-token rotation preserves session identity.** Rotating a
  refresh token now reuses the previous row's ``session_id`` and
  ``created_at`` and stamps ``last_used_at``, so a single device's session
  retains a stable public id across rotations and surfaces realistic
  "last used" timestamps in the new listing endpoint.

### Migration

- **API-key table.** Enabling `ApiKeyConfig(enabled=True)` requires a new `api_key` table with
  unique-indexed `key_id`, FK-indexed `user_id`, bytes `hashed_secret`, nullable bytes
  `encrypted_secret` (signing keys only), `name`, JSON `scopes`, `prefix_env`, `signing_required`,
  `expires_at`, `last_used_at`, `created_at`, `revoked_at`, `created_via`, and JSON-bounded
  `client_metadata`. See `docs/migration.md` for the schema snippet.
- **API-key secrets.** `UserManagerSecurity.api_key_hash_secret` is required whenever
  `ApiKeyConfig.enabled=True`; `ApiKeyConfig.secret_encryption_keyring` (Fernet) is additionally
  required when `signing_enabled=True`. Both are validated for distinctness against every other
  configured secret at startup.
- **Database schema.** Existing deployments using ``DatabaseTokenStrategy``
  must add three columns to their refresh-token table: a unique, indexed
  ``session_id VARCHAR(36)`` (backfill with UUID4s for existing rows),
  a nullable ``last_used_at`` timestamp, and a nullable JSON
  ``client_metadata`` column. The mixin defaults handle new rows; backfill
  is required only for previously persisted refresh tokens you intend to
  keep.
- **Custom refresh-token models.** Any subclass that bypassed
  ``RefreshTokenMixin`` must declare matching ``session_id``,
  ``last_used_at``, and ``client_metadata`` mapped attributes or
  ``DatabaseTokenModels`` will raise ``ConfigurationError`` at startup.
- **Enabling the new controller is opt-in.** Set
  ``LitestarAuthConfig(include_session_devices=True)`` (alongside
  ``enable_refresh=True``) to mount the routes; existing apps that do not
  set the flag are unaffected.

## 3.0.0 (2026-05-09)

### Added

- **`litestar_auth.config.validate_secret_strength()` — opt-in production
  gate for token / cookie / Fernet secrets.** Combines the existing length
  floor with an approximate Shannon-entropy floor (default
  `MINIMUM_SECRET_ENTROPY_BITS = 128.0`) so that degenerate misconfig like
  `"a" * 32` is rejected before reaching JWT signing or Fernet key
  derivation. The internal callsites still apply the chars-count floor only,
  to keep test fixtures interchangeable with production config; operators
  should wire `validate_secret_strength` into the application's startup hook
  (or a custom `LitestarAuthConfig` bootstrap) to enforce the entropy floor
  on user-supplied secrets. Pass `minimum_entropy_bits=0` to disable the
  entropy gate while keeping length validation.

### Changed

- **PKCE code-verifier generation no longer truncates `secrets.token_urlsafe`
  output or runs a runtime alphabet check.** Verifier length (64 characters)
  and entropy (≥384 bits) are unchanged; the implementation now relies on
  `secrets.token_urlsafe(48)` returning exactly 64 unpadded base64url
  characters by construction. No behavioral change for callers.

### Security (breaking)

- **Production secrets now require an entropy floor, not only a length
  floor.** JWT HMAC signing secrets, database/Redis token hash secrets,
  manager reset/verify secrets, CSRF secrets, OAuth flow-cookie secrets,
  TOTP pending secrets, and recovery/telemetry HMAC keys now use
  `validate_production_secret(...)` outside explicit `unsafe_testing=True`
  paths. Repeated or low-alphabet strings such as `"a" * 32` previously
  satisfied the 32-character minimum while providing little real key
  strength; they now fail closed with a `ConfigurationError`.

  **Migration.** Generate each production secret with a CSPRNG, for example
  `python -c "import secrets; print(secrets.token_hex(32))"` or
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Test-only
  repeated strings must either move behind `unsafe_testing=True` or be
  replaced with realistic fixture secrets.
- **Self-service ``UserUpdate`` is now email-only.** ``is_active``,
  ``is_verified``, and ``roles`` were previously accepted as ``Optional``
  fields on the self-service profile-update schema and rejected at runtime
  by ``_build_safe_self_update`` plus a request-body preflight. The
  OpenAPI surface still advertised them as mutable on ``/users/me``, and
  any regression in the runtime deny-list (a misnamed comparison, a
  custom controller bypassing the helper, an extra middleware reordering
  payload validation) silently re-opened privilege escalation. Privileged
  fields now live exclusively on ``AdminUserUpdate``, and ``UserUpdate``
  rejects them at msgspec decode via ``forbid_unknown_fields=True`` before
  the controller layer ever runs. The bundled soft-delete path on
  ``DELETE /users/{user_id}`` was migrated from
  ``UserUpdate(is_active=False)`` to ``AdminUserUpdate(is_active=False)``
  in the same change.
  **Migration.** Self-service ``PATCH /users/me`` now accepts only
  ``{ "email": "new@example.com" }``; send privileged updates through
  admin ``PATCH /users/{user_id}`` with ``AdminUserUpdate``. Programmatic
  callers that constructed ``UserUpdate(is_active=...)`` or
  ``UserUpdate(roles=...)`` must switch to ``AdminUserUpdate(...)`` plus
  ``manager.update(..., allow_privileged=True)``. Apps that previously
  customised ``user_update_schema=...`` to add app-specific safe fields
  keep working — the runtime ``_build_safe_self_update`` deny-list still
  rejects the privileged field names as defense-in-depth for custom
  schemas. See [docs/migration.md](docs/migration.md) for the full
  upgrade recipe.
- **OAuth associate authorize is now `POST` and protected by Litestar's CSRF
  middleware.** Previously the authenticated associate flow lived behind a
  `GET` endpoint, which could be triggered by a cross-site top-level
  navigation while a victim held a `SameSite=Lax` session cookie. An
  attacker who induced the victim to follow `https://target/auth/associate/{provider}/authorize`
  while signed into an attacker-controlled provider account could force the
  callback to link that attacker account onto the victim's local user, then
  log in as the victim via the linked provider identity. The route is now
  POST, so cookie-transport deployments fail closed at Litestar's CSRF
  middleware before the body runs (cross-site requests cannot mirror the
  Strict/Lax CSRF cookie into the configured `csrf_header_name`), and
  bearer-only deployments rely on the cross-origin attachment of
  `Authorization` being impossible. The login authorize route stays GET
  because anonymous OAuth login has no victim session to abuse.

  **Migration.** Plain `<a href="/auth/associate/{provider}/authorize">`
  links no longer trigger the associate flow. Cookie-transport deployments
  must POST and forward the plugin-managed CSRF token in the configured
  header (default `X-CSRF-Token`); see
  [Cookbook: OAuth associate](docs/cookbook/oauth_associate.md) for a
  ready-to-use JavaScript fetch recipe. Bearer-only deployments must POST
  with the existing `Authorization` header but do not need a CSRF token.
  Server-rendered apps can still drive associate from a button: render a
  `<form method="post">` and post via JavaScript that adds the CSRF
  header. Manual `create_oauth_associate_controller` and plugin-managed
  associate controllers share the same POST contract; no factory
  parameters changed.
- **OAuth `redirect_base_url` hostname validation now resolves DNS at
  validation time and rejects hostnames whose A/AAAA records point at
  non-routable addresses.** Previously the predicate only inspected IP
  literals, so a misconfigured callback hostname (e.g. an internal CNAME
  resolving to ``169.254.169.254`` or RFC 1918) silently passed
  startup-time validation and forwarded OAuth ``code`` to internal
  infrastructure. Resolution failures (offline CI, sandboxed startup,
  transient DNS outages) fall through to the historical accept-hostname
  behaviour so structurally valid configurations still validate; DNS
  rebinding remains the operator's responsibility to mitigate via egress
  firewall rules at runtime.
- **`SQLAlchemyUserDatabase.update` now rejects fields that are not mapped
  attributes (columns or relationships) or settable Python properties on the
  configured user model.** Previously the persistence layer trusted callers
  to filter privileged or unknown fields, relying on the manager's
  ``SAFE_FIELDS`` / ``PRIVILEGED_FIELDS`` allow-lists upstream. Any
  application code wired straight to the persistence adapter could smuggle
  arbitrary attribute writes through ``setattr`` and either silently no-op
  or quietly mutate state. The new defense-in-depth check is derived from
  the user model itself, so custom models with extra columns, custom
  relationships, or computed setter properties (e.g. ``roles`` delegating
  into ``role_assignments``) keep working out of the box; only truly
  unmapped names are rejected with ``ValueError``.
- **TOTP recovery-code verification now performs exactly one Argon2 verify
  per call.** The hit-and-mismatch branch previously ran a second dummy
  Argon2 verify on top of the candidate-hash verify, leaking the underlying
  lookup-digest collision via a 2x timing skew and doubling the per-request
  Argon2 work an attacker could amortise. All three paths (no-hit,
  hit-and-mismatch, hit-and-match) now execute a single verify against
  either the indexed candidate or the dummy hash, so timing is constant
  and Argon2 cost is bounded.
- **`JWTStrategy` now fails closed when an asymmetric algorithm
  (`RS256`/`RS384`/`RS512`/`ES256`/`ES384`/`ES512`) is configured without an
  explicit `verify_key`.** The previous fallback silently reused the private
  signing secret as the verify key, leaking private material into any
  consumer that reads the verify side. Asymmetric strategies must now pass
  the public-key PEM as `verify_key`. As a side effect, the chars-count
  `validate_secret_length` check is no longer applied to asymmetric
  signing material — multi-line PEMs are validated structurally by PyJWT at
  sign/verify time. HMAC algorithms (`HS256`/`HS384`/`HS512`) keep the
  existing chars-count secret-length floor unchanged.
- **OAuth `redirect_base_url` now rejects non-routable hosts at plugin startup
  and across the manual/custom controller factories.** The validator already
  blocked HTTP and loopback origins; it now additionally rejects RFC 1918
  private ranges, RFC 3927 link-local addresses (including the
  `169.254.169.254` cloud IMDS endpoint), multicast, reserved, and unspecified
  literals. A misconfigured callback URL can no longer point OAuth provider
  redirects at internal infrastructure. The plugin-managed and manual paths
  now share a single predicate, and error messages describe the policy as
  "routable public HTTPS origin".
- **Auth rate-limit counters for `POST /auth/forgot-password` and
  `POST /auth/request-verify-token` now increment in a `finally` block.**
  Transient manager errors (broken email transport, database hiccups) no
  longer bypass the limiter and yield a free unrate-limited path. Both flows
  remain enumeration-resistant by construction, so counting failures does not
  open an account-existence side channel.
- **Plugin startup now emits a `SecurityWarning` when `JWTStrategy` would
  silently disable session-fingerprint binding for the configured user
  model.** The default `session_fingerprint_getter` needs `hashed_password`
  on the user model to bind JWTs to credential state; passkey-only or
  OAuth-only models that omit this attribute previously degraded silently.
  Callers that supply a custom `session_fingerprint_getter` are unaffected.

## 2.4.0 (2026-05-03)

### Security

- **TOTP pending-login and enrollment JWTs now require an explicit `typ:JWT`
  JOSE header.** Tokens minted by older library versions are rejected by the new
  decoders. Both token types have a 5-minute TTL, so in-flight tokens expire
  within the rollout window. `JwtDecodeConfig.leeway` now defaults to the
  package's 30-second clock-skew tolerance; consumers that require strict
  zero-leeway decoding must pass `leeway=0` explicitly.
- **TOTP recovery-code verification now uses a keyed lookup index before one
  Argon2 verify.** **Breaking schema/config change:** recovery-code persistence
  moves from `recovery_codes_hashes: list[str]` to
  `recovery_codes: dict[str, str]`, where keys are HMAC-SHA-256 lookup digests
  and values are Argon2 hashes. Existing recovery codes are invalidated during
  deployment; users must authenticate with their TOTP app and regenerate codes
  via `POST /auth/2fa/recovery-codes/regenerate`. Production `totp_config`
  deployments must now set a distinct 32+ character
  `UserManagerSecurity.totp_recovery_code_lookup_secret`. This closes V1, the
  recovery-code Argon2 amplification CPU-DoS vector.

### Fixed

- Misconfigured plugins with `enable_refresh=True` and a non-`RefreshableStrategy`
  backend now fail at app boot via `ConfigurationError` instead of at the first
  refresh-capable request. The lazy per-request check is preserved as
  defense-in-depth for callers that bypass plugin startup.

## 2.3.0 (2026-05-02)

### Added
- **`CookieTransportConfig`** — typed cookie transport settings object for
  callers that prefer passing the whole cookie configuration as one value.
- **`BaseUserManagerConfig`** — typed user-manager settings object for direct
  manager construction; existing `BaseUserManager(user_db, ..., security=...)`
  calls remain supported.
- **`AuthControllerConfig`** — typed settings object for direct
  `create_auth_controller(...)` assembly; existing keyword options remain
  supported.
- **`OAuthControllerConfig`** — typed settings object for direct
  `create_oauth_controller(...)` assembly; existing keyword options remain
  supported.
- **`OAuthAssociateControllerConfig`** — typed settings object for direct
  `create_oauth_associate_controller(...)` assembly; existing keyword options
  remain supported.
- **`ProviderOAuthControllerConfig`** — typed settings object for direct
  `create_provider_oauth_controller(...)` assembly; existing keyword options
  remain supported.
- **`RoleAdminControllerConfig`** — typed settings object for direct
  `create_role_admin_controller(controller_config=...)` assembly; existing
  keyword options, including the plugin `config=...`, remain supported.
- **`RegisterControllerConfig`** — typed settings object for direct
  `create_register_controller(...)` assembly; existing keyword options remain
  supported.
- **`UsersControllerConfig`** — typed settings object for direct
  `create_users_controller(...)` assembly; existing keyword options remain
  supported.
- **`DatabaseTokenStrategyConfig` and `JWTStrategyConfig`** — typed strategy
  settings objects for callers that prefer grouping strategy configuration
  explicitly; existing constructor keyword options remain supported.
- **`RedisTokenStrategyConfig`** — typed Redis token strategy settings object;
  existing constructor keyword options remain supported.

### Changed

- **`LitestarAuthMiddleware` now takes `LitestarAuthMiddlewareConfig(...)`** —
  Breaking only for direct manual middleware instantiation; the plugin wiring
  constructs the config internally.

## 2.2.0 (2026-04-25)

### Added

- **New rate-limit slots `AuthRateLimitSlot.CHANGE_PASSWORD` and
  `AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES`** — exported from
  `litestar_auth.ratelimit`, registered with login-shaped (`scope=ip_email`,
  `namespace=change-password`, `group=login`) and TOTP-shaped defaults
  respectively, and accepted by `enabled`, `disabled`, `endpoint_overrides`,
  `scope_overrides`, and `namespace_overrides` exactly like the existing slots.
- **`AdminUserUpdate` and `ChangePasswordRequest` schemas** are exported from
  `litestar_auth.schemas` for the privileged admin update path and the new
  self-service password-rotation flow respectively.
- **`POST /users/me/change-password`** — authenticated credential-rotation
  endpoint on the users controller; returns `204 No Content` on success and
  delegates the new password to `user_manager.update(...)` so existing
  token/session invalidation hooks fire.
- **`POST /auth/2fa/recovery-codes/regenerate`** — authenticated TOTP
  recovery-code regeneration endpoint that atomically replaces all hashed
  codes through the manager lifecycle and returns the new codes exactly once.
- **`LitestarAuthConfig.register_minimum_response_seconds`** (default `0.4`)
  — minimum wall-clock duration for plugin-owned `POST /auth/register`
  responses, padding success and mapped domain-failure paths alike as
  defense-in-depth against lower-tail timing-based account enumeration.
- **`LitestarAuthConfig.deployment_worker_count`** — explicit
  deployment-posture declaration; when set greater than `1`, plugin startup
  fails closed if any auth rate-limit endpoint backend reports
  `is_shared_across_workers=False`.
- **`FernetKeyringConfig(active_key_id=..., keys=...)`** on `OAuthConfig`
  and `UserManagerSecurity` — versioned-Fernet keyring inputs for
  encrypted-at-rest OAuth tokens and TOTP secrets, plus
  `OAuthTokenEncryption.requires_reencrypt(...)` /
  `OAuthTokenEncryption.reencrypt(...)` and
  `BaseUserManager.totp_secret_requires_reencrypt(...)` /
  `BaseUserManager.reencrypt_totp_secret_for_storage(...)` row-level helpers
  for explicit at-rest rotation jobs.
- **`TotpConfig.totp_pending_require_client_binding`** (default `True`) —
  toggles TOTP pending-login JWT client binding; set to `False` only when the
  deployment explicitly accepts cross-client pending-token replay.

### Changed

- **Privileged admin updates use the dedicated `AdminUserUpdate` schema** —
  `PATCH /users/{user_id}` now decodes against `AdminUserUpdate`, while
  self-service `PATCH /users/me` decodes against the (now non-credential)
  `UserUpdate` and rejects privileged fields fail-closed. The default
  `AdminUserUpdate` accepts optional `roles` so superuser `PATCH /users/{id}`
  can manage them.
- **Controller OpenAPI request bodies are aligned with runtime behavior** —
  `POST /auth/register`, `POST /auth/reset-password`, `PATCH /users/me`,
  `POST /users/me/change-password`, and `PATCH /users/{user_id}` now publish
  `requestBody` consistently without changing the existing 400/422 error
  payload contract.

### Security

- **Self-service password rotation now requires current-password re-verification** — **Breaking for
  clients that sent `password` through `UserUpdate` / self-service profile updates.** VULN #1 is
  remediated by removing `password` from `UserUpdate` and moving authenticated credential rotation
  to `POST /users/me/change-password` with `ChangePasswordRequest` (`current_password`,
  `new_password`). Wrong current-password submissions use the existing `LOGIN_BAD_CREDENTIALS`
  response contract, invalid replacement passwords use `UPDATE_USER_INVALID_PASSWORD`, and successful
  rotation continues through the manager update lifecycle so existing token/session invalidation
  hooks run. Self-service `PATCH /users/me` also fails closed (`400 REQUEST_BODY_INVALID`) when
  callers submit any of `password`, `hashed_password`, `is_active`, `is_verified`, or `roles`
  instead of silently stripping them. Admin-initiated password rotation remains available through
  `AdminUserUpdate` on the privileged users update path.
- **Public registration failures now use one enumeration-resistant response** — **Breaking for
  clients that parsed register-specific duplicate or password-policy error codes.** VULN #2 is
  remediated by collapsing duplicate identifiers, password-policy failures, and manager
  authorization rejections to the same 400 / `REGISTER_FAILED` response with the generic detail
  `Registration could not be completed.` The old register-specific `ErrorCode` members
  (`REGISTER_USER_ALREADY_EXISTS`, `REGISTER_INVALID_PASSWORD`) are removed, plugin-owned
  registration applies the configured minimum response-time envelope, and duplicate attempts invoke
  `on_after_register_duplicate(user)` with the existing account so applications can enqueue
  out-of-band owner notifications without changing the public response.
- **OAuth authorization-code flow now enforces PKCE S256 end-to-end** — **Breaking for manual
  `OAuthClientAdapter` integrations whose underlying client does not accept `code_challenge` /
  `code_challenge_method` on authorize and `code_verifier` on token exchange.** VULN #3 is
  remediated per RFC 9700 by generating a fresh 64-character verifier and unpadded
  base64url-SHA256 `code_challenge` for every authorize call, persisting the verifier in the
  existing httpOnly state cookie next to `state`, and forwarding the matching verifier on callback
  token exchange. Tampered or verifier-less flow cookies map to the existing
  `400 OAUTH_STATE_INVALID` failure response. Adapters whose underlying client cannot accept the
  PKCE kwargs raise `ConfigurationError` at construction time rather than silently downgrading.
- **TOTP enrollment now issues one-time recovery codes** — **Breaking for clients that assume
  `TotpConfirmEnableResponse` contains only `enabled`.** VULN #4 is remediated by returning
  `recovery_codes` exactly once from `POST /auth/2fa/enable/confirm`, accepting unused recovery
  codes in `TotpVerifyRequest.code` on `POST /auth/2fa/verify`, and adding authenticated
  `POST /auth/2fa/recovery-codes/regenerate` for rotation. The bundled user model now stores only
  hashed recovery-code values in `recovery_codes_hashes`; custom models and migrations must add an
  equivalent hashed-only field before enabling this flow.
- **OAuth tokens and TOTP secrets at rest now use a versioned Fernet keyring** — **Breaking for
  operators that supplied a single unversioned Fernet key and have no rotation plan.** VULN #5 is
  remediated by introducing the storage format `fernet:v1:<key_id>:<ciphertext>` for new writes,
  surfacing `FernetKeyringConfig(active_key_id=..., keys=...)` on `OAuthConfig` and
  `UserManagerSecurity`, and exposing `OAuthTokenEncryption.requires_reencrypt(...)` /
  `OAuthTokenEncryption.reencrypt(...)` plus
  `BaseUserManager.totp_secret_requires_reencrypt(...)` /
  `BaseUserManager.reencrypt_totp_secret_for_storage(...)` row-level helpers for explicit
  at-rest rotation jobs. Single-key `oauth_token_encryption_key` and `totp_secret_key` shortcuts
  remain supported and are persisted under the `default` key id; legacy unversioned Fernet values
  are accepted only as explicit migration input.
- **Library-issued JWTs now declare and validate `typ=JWT`** — VULN #6 is remediated as
  defense-in-depth: access tokens, manager-issued verify and reset tokens, and the destroy-token
  revocation decode all emit an explicit `typ=JWT` JOSE header on issuance and reject missing or
  unexpected `typ` headers before the normal signed decode. This is not a substitute for
  signature, audience, issuer, algorithm, or required-claim validation, all of which continue to
  apply.
- **Role-membership guards use fixed-work matching** — VULN #7 is remediated by replacing the
  previous `user_roles & required_role_set` short-circuit predicate in `has_any_role` and the
  subset check in `has_all_roles` with fixed-work iteration over normalized role strings using
  `hmac.compare_digest`. This is a defense-in-depth posture, not a claim of cryptographic
  constant-time behavior across Python or the network.
- **Plugin startup fails closed on declared multi-worker auth rate limiting** — **Breaking for
  declared multi-worker deployments that paired process-local rate-limit backends with the previous
  warning-only posture.** VULN #8 is remediated by adding
  `LitestarAuthConfig.deployment_worker_count` and raising `ConfigurationError` at startup when any
  auth rate-limit endpoint backend reports `is_shared_across_workers=False` while
  `deployment_worker_count > 1`. Use `RedisRateLimiter` (or
  `RedisAuthPreset.build_rate_limit_config(...)`) for multi-worker production; in-memory rate
  limiting remains supported for explicit single-process deployments and tests.
- **TOTP pending-login tokens are client-bound by default** — VULN #10 is remediated by adding
  `cip` and `uaf` SHA-256 fingerprint claims to pending-login JWTs and rejecting `/auth/2fa/verify`
  requests whose trusted-proxy-aware client IP or User-Agent no longer matches the issuing login.
  Mismatches reuse the existing 400 `TOTP_PENDING_BAD_TOKEN` response. Set
  `TotpConfig.totp_pending_require_client_binding=False` only when the deployment explicitly
  accepts cross-client pending-token replay.

## 2.1.0 (2026-04-23)

### Security

- **Superuser status is now role-based end to end** — **Breaking for applications that read or
  wrote `user.is_superuser` or exposed it in custom DTOs.** The bundled ORM model, user schemas,
  manager create/update paths, user controllers, and contrib role-admin responses no longer carry
  an `is_superuser` attribute or field. The public `is_superuser` guard remains importable, but it
  authorizes by membership in the configured superuser role (`superuser_role_name`, default
  `"superuser"`). Before dropping an existing database column, backfill equivalent role membership
  for every row where `is_superuser` is true; see `docs/migration.md`.
- **Verification is now required by default for login and built-in TOTP completion** — **Breaking
  for applications that relied on immediate login after registration.**
  `LitestarAuthConfig.requires_verification`, `create_auth_controller(..., requires_verification=...)`,
  and `create_totp_controller(..., requires_verification=...)` now default to `True`, closing the
  account-squatting / pre-account-takeover gap where an attacker could register someone else's email
  and authenticate before proving mailbox ownership.
- **`request_verify_token` now uses an enumeration-resistant hook contract** — **Breaking for
  custom `BaseUserManager` subclasses overriding `on_after_request_verify_token`.**
  The hook signature is now `on_after_request_verify_token(user: UP | None, token: str | None)`, and
  the manager always executes the same JWT-signing path before invoking it. Unknown and already-
  verified emails therefore no longer return measurably faster from the library path, and hook
  implementations must equalize downstream I/O when `user` is `None`.
- **Secret-bearing config objects no longer expose live values through autogenerated `repr()` output** —
  `TotpConfig.totp_pending_secret`, `OAuthConfig.oauth_token_encryption_key`,
  `DatabaseTokenAuthConfig.token_hash_secret`, `LitestarAuthConfig.csrf_secret`, and
  `OAuthTokenEncryption.key` are now excluded from dataclass `repr`/`str` surfaces so routine debug
  logging does not leak active signing or encryption material.
- **OAuth token encryption policy binding is now nominal** — **Breaking for development reload
  harnesses or tests that reused stale `OAuthTokenEncryption` instances across module reloads.**
  Session-bound policies, cached ORM-instance policies, and direct OAuth persistence checks now
  accept only concrete `OAuthTokenEncryption` instances from the current `litestar_auth.oauth_encryption`
  module. Structurally similar objects and policies retained from old module identities are ignored
  or rejected instead of being normalized into fresh policies.
- **JWT revocation posture binding is now nominal** — **Breaking for development reload harnesses
  or tests that reused stale `JWTRevocationPosture` instances across module reloads.**
  Plugin-managed JWT revocation notices now accept only concrete posture objects returned by
  `JWTStrategy.revocation_posture` from the current `litestar_auth.authentication.strategy.jwt`
  module. Structurally similar posture-shaped objects are ignored instead of being treated as the
  strategy contract.
- **Default insufficient-role errors are now sanitized** — **Breaking for clients that parsed
  `required_roles`, `user_roles`, or `require_all` from the bundled HTTP `403` response or default
  exception message.** `InsufficientRolesError` still stores structured role context on the
  exception instance, but the generated message and bundled plugin exception wiring now expose only
  generic prose plus the stable `code`, keeping role names out of ordinary logs and wire payloads.
- **Database-backed opaque tokens no longer accept legacy plaintext compatibility flags** —
  **Breaking for callers that passed `accept_legacy_plaintext_tokens` to
  `DatabaseTokenStrategy` / `DatabaseTokenAuthConfig` or
  `allow_legacy_plaintext_tokens` to `LitestarAuthConfig`.** The DB-token strategy now reads and
  deletes opaque tokens by keyed digest only. Rotate or invalidate any lingering plaintext DB-token
  rows before upgrading.
- **`InMemoryRateLimiter` always fails closed at key capacity** — **Breaking for callers that
  explicitly enabled the removed legacy LRU mode.** New keys are rejected and logged with
  `event=rate_limit_memory_capacity` when `max_keys` is reached and no expired counters can be
  pruned, and the compatibility-only `fail_closed_on_capacity` constructor parameter has been
  removed.
- **Redis-backed opaque-token invalidation is now index-only** — **Breaking for callers that passed
  `max_scan_keys` to `RedisTokenStrategy` or relied on scan-based invalidation of pre-index token
  keys.** `RedisTokenStrategy.invalidate_all_tokens(...)` now deletes only tokens recorded in the
  per-user Redis index written by current `write_token(...)` calls. Token keys created by older
  deployments without that index are not discovered by a keyspace scan and expire naturally by their
  Redis TTL; rotate or flush them before upgrading if immediate revocation is required.
- **Secret-role reuse now fails closed in production** — **Breaking for deployments that reused one
  configured value across `verification_token_secret`, `reset_password_token_secret`,
  `totp_pending_secret`, or `totp_secret_key`.** `LitestarAuth(config)` validation and direct
  `BaseUserManager(..., security=UserManagerSecurity(...))` construction now raise
  `ConfigurationError` outside explicit `unsafe_testing=True` instead of emitting
  `SecurityWarning`. Configure one distinct high-entropy value per role; error messages identify
  the reused roles and audiences without exposing the secret value.
- **Default password hashing is now Argon2-only** — **Breaking for deployments that still store
  bcrypt password hashes and relied on the library default helper to verify them.**
  `PasswordHelper.from_defaults()`, bare `PasswordHelper()`,
  `BaseUserManager(..., password_helper=None)`, and `LitestarAuthConfig.resolve_password_helper()`
  no longer verify bcrypt hashes. Keep any bcrypt migration window application-owned by passing an
  explicit `PasswordHelper(password_hash=PasswordHash((Argon2Hasher(), BcryptHasher())))` through
  `UserManagerSecurity.password_helper` or direct manager construction; see `docs/migration.md`.
- **TOTP no longer supports SHA1 algorithms** — **Breaking for deployments with SHA1-enrolled
  authenticator clients.** `TotpAlgorithm`, `TotpConfig.totp_algorithm`,
  `create_totp_controller(..., totp_algorithm=...)`, and the low-level TOTP helpers now accept
  only `SHA256` or `SHA512`. The compatibility `SECRET_BYTES` constant was removed, and generated
  secrets are sized directly from the selected supported algorithm. Re-enroll existing SHA1 users
  before upgrading.
- **Persisted TOTP secrets now require encrypted storage** — **Breaking for direct/custom manager
  integrations that omitted `UserManagerSecurity.totp_secret_key` and stored plaintext TOTP
  secrets.** `BaseUserManager.totp_secret_storage_posture` now reports only the
  `fernet_encrypted` contract, non-null TOTP secret writes require `totp_secret_key`, and unprefixed
  legacy plaintext persisted values fail closed on read. Configure a Fernet key and encrypt, rotate,
  or disable existing plaintext TOTP secrets before upgrading.
- **JWT revocation storage must be explicit** — **Breaking for callers using
  `JWTStrategy(secret=...)` without a denylist store.** The strategy no longer constructs
  `InMemoryJWTDenylistStore` implicitly. Pass `denylist_store=RedisJWTDenylistStore(...)` or another
  shared `JWTDenylistStore` for production, or set `allow_inmemory_denylist=True` for deliberate
  single-process development, test, or consciously single-process app wiring. The plugin-level
  `allow_nondurable_jwt_revocation` flag was removed because the strategy constructor now owns that
  opt-in.
- **Manual cookie auth controllers must declare their CSRF posture** — **Breaking for callers using
  `create_auth_controller(...)` directly with `CookieTransport`.** Pass
  `csrf_protection_managed_externally=True` only when the mounted routes are protected by app-owned
  CSRF middleware or an equivalent framework-level CSRF mechanism. For controlled non-browser cookie
  flows, set `CookieTransport(allow_insecure_cookie_auth=True)` explicitly. Plugin-owned route tables
  continue to validate cookie CSRF through `LitestarAuthConfig.csrf_secret`.
- **OAuth provider names are now route-safe slugs** — **Breaking for provider inventories or manual
  OAuth factories using names outside `[A-Za-z0-9_-]`.** `OAuthProviderConfig(name=...)` and manual
  `create_provider_oauth_controller(provider_name=...)` now require 1-64 ASCII letters, digits,
  underscores, or hyphens, with an alphanumeric first and last character, so provider names remain
  safe for route paths, cookie names, and callback URL construction.

### Internal

- **`pytest -n auto` is now capped at 8 workers** — `pyproject.toml` adds `--maxprocesses=8` to the
  default pytest options because the async/ASGI-heavy suite reproducibly triggers macOS
  socket/event-loop teardown warnings when xdist fans out to all logical CPUs.

### Changed

- **Compatibility import re-exports were removed** — **Breaking for callers importing
  `UserAuthRelationshipMixin` / `UserRoleRelationshipMixin` from
  `litestar_auth.models.user_relationships`, `import_token_orm_models` from
  `litestar_auth.authentication.strategy`, `create_provider_oauth_controller` from
  `litestar_auth.contrib.oauth`, or `_ScopedUserDatabaseProxy` / `_UserManagerFactory` from
  `litestar_auth._plugin`.** Import relationship mixins from `litestar_auth.models.mixins`, the
  bundled token bootstrap helper from `litestar_auth.models`, the manual OAuth helper from
  `litestar_auth.oauth`, and session-binding internals from `litestar_auth._plugin.session_binding`.
- **Rate-limit slot compatibility aliases were removed** — **Breaking for callers importing
  `AuthRateLimitEndpointSlot` or `AUTH_RATE_LIMIT_*_SLOTS` from `litestar_auth.ratelimit`.**
  Iterate `AuthRateLimitSlot` for the full public slot inventory, pass enum members to
  `enabled`, `disabled`, and `endpoint_overrides`, and use
  `{AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}` for the common
  verification-route disablement case.

## 2.0.0 (2026-04-22)

### Security

- **TOTP enrollment JWTs no longer carry the generated TOTP secret** — the short-lived JWT returned
  by `/2fa/enable` now carries only lookup claims. The pending secret is stored server-side in
  `TotpEnrollmentStore`, encrypted first with `user_manager_security.totp_secret_key`, and
  `/2fa/enable/confirm` atomically consumes the matching `jti`. Each new `/2fa/enable` replaces the
  user's previous pending enrollment, so stale, reused, and invalid-code-consumed enrollment tokens
  cannot be confirmed later.
- **`create_totp_controller(..., totp_secret_key=..., enrollment_store=...)` is required in production** —
  **Breaking for callers of the manual controller factory.** `totp_secret_key` protects the
  server-side pending enrollment secret and persisted user TOTP secret; `enrollment_store` enforces
  latest-only, single-use enrollment confirmation. Omitting either now fails closed with
  `ConfigurationError`; opt out only with `unsafe_testing=True`. The plugin-owned path forwards
  `UserManagerSecurity.totp_secret_key` automatically, but production `TotpConfig` must now provide
  `totp_enrollment_store`.
- **Failed-login logs now include a keyed identifier digest** — `BaseUserManager.authenticate()`
  still avoids plaintext emails/usernames in logs, but failed attempts now carry
  `identifier_digest` and `login_identifier_type` fields so operators can correlate brute-force
  activity during incident response.
- **`unsafe_testing=True` pending-JTI bypass now emits structured critical telemetry** — the existing
  `SecurityWarning` remains, and the first bypass per process also logs
  `event=totp_pending_jti_dedup_disabled`.
- **`InMemoryRateLimiter` now fails closed at key capacity by default** — new keys are rejected and
  logged with `event=rate_limit_memory_capacity` when `max_keys` is reached and no expired counters
  can be pruned. Legacy LRU eviction is still available with `fail_closed_on_capacity=False`.
- **OAuth associate flow no longer treats two `None` IDs as a match** — `OAuthService.associate_account`
  now explicitly rejects any candidate where either the existing owner or the current user lacks a
  resolved `id`. This is a defense-in-depth change against downstream stores that return
  partially-constructed users; the stable `OAUTH_ACCOUNT_ALREADY_LINKED` client error is reused.

### Migration

- Set `user_manager_security.totp_secret_key` (Fernet key) when you enable `TotpConfig`. The plugin
  already required this for at-rest encryption of persisted secrets; it is now also required for
  pending-enrollment secret storage.
- Configure `TotpConfig.totp_enrollment_store`, typically via
  `RedisAuthPreset.build_totp_enrollment_store()` for Redis-backed deployments.
- For manual controller wiring, pass both `totp_secret_key=settings.totp_secret_key` and
  `enrollment_store=...` to `create_totp_controller(...)` alongside the existing
  `totp_pending_secret=...`. Tests that intentionally use plaintext, process-local enrollment
  state must opt in with `unsafe_testing=True`.

## 1.11.0 (2026-04-20)

### Added

- **`litestar_auth.contrib.role_admin.create_role_admin_controller(...)`** — an
  opt-in contrib HTTP role-administration surface for relational role-capable
  SQLAlchemy apps. The controller is not auto-mounted by `LitestarAuth`; mount
  it explicitly alongside the plugin when you want admin-only `/roles` catalog
  and assignment routes backed by `RoleCreate`, `RoleUpdate`, `RoleRead`, and
  `UserBrief`.

### Fixed

- **`create_role_admin_controller(config=config)` no longer raises `KeyError`
  when `config.db_session_dependency_key` differs from the default** — the
  internal dependency-parameter renamer is now a no-op for handlers that do
  not declare the request-scoped session dependency, so the config+session_maker
  branch (which opens its own sessions) is safe for any valid
  `db_session_dependency_key` value.

### Documentation

- **New HTTP role-admin guide and migration notes** — the supported HTTP role
  management path now points at `litestar_auth.contrib.role_admin`, while the
  cookbook pages are explicitly scoped to fully custom controllers. The docs
  now call out the behavior-parity fix versus the old cookbook pattern:
  contrib assign/unassign flows preserve `BaseUserManager.update(...)`
  lifecycle hooks instead of mutating association rows behind the manager.
- **If you copied the old role-admin cookbook into your app, migrate to
  `litestar_auth.contrib.role_admin` for the supported HTTP admin path.** The
  contrib controller keeps catalog and assignment behavior aligned with
  `litestar roles`, defaults to `guards=[is_superuser]`, and preserves manager
  lifecycle hooks on assign/unassign. Keep the cookbook only when you
  intentionally need a fully custom controller or custom schemas.

## 1.10.0 (2026-04-20)

### Changed

- **`LitestarAuthConfig.resolve_backends(session)` is the single runtime accessor** — **Breaking
  for callers of the previous no-arg `resolve_backends()` or `resolve_request_backends()`.** The
  accessor now always takes an `AsyncSession` and uniformly returns the effective backend tuple
  for every supported configuration (manual `backends=` or the `database_token_auth=` preset).
  The previous no-arg `resolve_backends()` that raised `ValueError` to redirect callers to
  `resolve_startup_backends()` / `resolve_request_backends(session)` is gone;
  `resolve_startup_backends()` remains for startup-only inventory. Mutual exclusion between
  `backends=` and `database_token_auth=` is still enforced with a clear error at config build
  time.
- **`user_manager_class` is now `type[BaseUserManager[UP, ID]] | None`** — the field is honestly
  `Optional` in the dataclass, which removes the `cast(..., None)` that was previously needed to
  express the factory path. Consumers reading `config.user_manager_class` directly must handle
  `None` explicitly; `__post_init__` continues to enforce mutual exclusion with
  `user_manager_factory`.
- **`BaseUserManager.__init__` accepts a `skip_reuse_warning: bool = False` keyword** — the
  plugin-managed builder passes `skip_reuse_warning=True` after config validation has already
  emitted the reused-secret `SecurityWarning`, replacing the previous `ContextVar`-based owner
  signalling. Manager-only construction (including the `litestar roles` CLI manager) continues
  to emit the warning exactly once, unchanged from 1.9.
- **`BaseUserManager` exposes `manager.users`, `manager.tokens`, `manager.totp` service façades**
  — the four internal services (`_user_lifecycle`, `_account_tokens`, `_account_token_security`,
  `_totp_secrets`) are now reachable as public attributes, with low-level JWT helpers available
  through `manager.tokens.security`. The default lifecycle hooks (`on_after_register`,
  `on_after_login`, `on_after_verify`, `on_after_request_verify_token`, `on_after_forgot_password`,
  `on_after_reset_password`, `on_after_update`, `on_before_delete`, `on_after_delete`) moved to a
  new `UserManagerHooks[UP]` mixin that `BaseUserManager` inherits; override points remain
  identical.
- **Controller DI parameters use concrete protocols instead of `Any`** — the
  `litestar_auth_user_manager` parameter in every generated controller (`auth`, `users`,
  `register`, `verify`, `reset`, `totp`, `oauth`) is now typed with the controller-specific
  runtime-checkable protocol (`AuthControllerUserManagerProtocol[UP, ID]`,
  `UsersControllerUserManagerProtocol[UP, ID]`, `TotpUserManagerProtocol[UP]`, and the per-module
  equivalents). No generated controller still carries `user_manager: Any, # noqa: ANN401`.
- **TOTP user-model compatibility is validated at plugin startup** — **Breaking for deployments
  that relied on the first-login 500 to surface the misconfiguration.** When `totp_config` is set,
  plugin init now calls `validate_totp_user_model_protocol()` and raises `ConfigurationError` if
  the configured `user_model` does not implement `TotpUserProtocol` (`email: str` and
  `totp_secret: str | None`). The `isinstance(user, TotpUserProtocol)` / `ConfigurationError`
  branch that ran on every login request is gone.
- **`UserAlreadyExistsError` accepts a keyword-only `identifier=UserIdentifier(...)`** — the
  small keyword-only `UserIdentifier(identifier_type=..., identifier_value=...)` dataclass is the
  single structured-context entry point; `identifier_type` and `identifier_value` are still
  mirrored onto the exception instance for read access. `InvalidPasswordError` is fully
  keyword-only. Both exceptions no longer run partial-context validation in `__init__`; the
  declared types describe the contract.

### Removed

- **`LitestarAuthConfig.create()`, `.with_default_manager()`, and `.with_custom_manager_factory()`
  classmethod factories removed** — **Breaking, notable reversal of the 1.9.0 addition.**
  The three factories each carried ~35 identical keyword parameters, forcing every new config
  field to be declared in four places. Construct `LitestarAuthConfig[UP, ID](...)` directly;
  mutual exclusion between `user_manager_class=` and `user_manager_factory=` is enforced by
  `__post_init__`, `user_manager_factory` must be callable when provided, and the clearer error
  messages now point at the direct-construction path. The migration is mechanical — the dataclass
  already accepts every factory keyword unchanged.
- **Root package payload re-exports removed** — **Breaking for callers importing payload structs
  from `litestar_auth`.** Import `LoginCredentials`, `RefreshTokenRequest`, `ForgotPassword`,
  `ResetPassword`, `VerifyToken`, `RequestVerifyToken`, `TotpEnableResponse`,
  `TotpVerifyRequest`, `TotpConfirmEnableRequest`, `TotpConfirmEnableResponse`,
  `TotpDisableRequest` from `litestar_auth.payloads`. Import `UserCreate`, `UserRead`,
  `UserUpdate` from `litestar_auth.schemas`.
- **`litestar_auth.controllers.__init__` no longer re-exports payload structs** — **Breaking for
  callers importing payloads via `litestar_auth.controllers`.** The controllers package exposes
  only the controller factories (`create_auth_controller`, `create_users_controller`,
  `create_register_controller`, `create_verify_controller`, `create_reset_password_controller`,
  `create_totp_controller`, `create_oauth_controller`, `create_oauth_associate_controller`) and
  `TotpUserManagerProtocol`. Import payloads from `litestar_auth.payloads`.
- **`litestar_auth.payloads` no longer re-exports `UserCreate`, `UserRead`, `UserUpdate`** —
  **Breaking for callers importing user CRUD schemas from `litestar_auth.payloads`.** Import
  user schemas from `litestar_auth.schemas` instead; `litestar_auth.payloads` now contains only
  the structs that originate there.
- **Manager-module compatibility re-exports removed** — **Breaking for callers importing
  `SAFE_FIELDS`, `_PRIVILEGED_FIELDS`, `MAX_PASSWORD_LENGTH`, or `require_password_length` from
  `litestar_auth.manager`.** Import `SAFE_FIELDS` / `_PRIVILEGED_FIELDS` from their canonical
  module (`litestar_auth._manager.user_lifecycle`) and `MAX_PASSWORD_LENGTH` /
  `require_password_length` from `litestar_auth.config`.
- **Root `__all__` shrunk from 85 symbols to 26** — **Breaking for callers importing controller
  factories, strategies, token stores, rate limiters, TOTP helpers, or individual exception
  subclasses from the root package.** `litestar_auth.__all__` now contains only the primary
  entry points: `LitestarAuth`, `LitestarAuthConfig`, `DatabaseTokenAuthConfig`, `TotpConfig`,
  `OAuthConfig`, `OAuthProviderConfig`, `BaseUserManager`, `UserManagerSecurity`,
  `AuthenticationBackend`, `Authenticator`, `BearerTransport`, `CookieTransport`, the six core
  guards, `ErrorCode`, `LitestarAuthError`, the five user protocols, and `__version__`. Import
  everything else from its submodule (`litestar_auth.controllers`,
  `litestar_auth.authentication.strategy`, `litestar_auth.ratelimit`, `litestar_auth.totp`,
  `litestar_auth.exceptions`, etc.).
- **`OAuthProviderConfig.coerce()` no longer accepts legacy `(name, client)` tuples or
  duck-typed duplicates** — **Breaking for callers passing tuples through
  `OAuthConfig.oauth_providers`.** `oauth_providers` is now typed
  `Sequence[OAuthProviderConfig] | None`; construct providers explicitly via
  `OAuthProviderConfig(name=..., client=...)`. The duck-typed
  `type(value).__name__ == cls.__name__` fallback that silently accepted hot-reloaded
  class duplicates is gone.
- **`_UseDefaultCode` sentinel and exception `@overload` stacks removed** — every exception
  constructor now takes `code: str | None = None` (where `None` resolves to the class
  `default_code`), with no `_UseDefaultCode` / `_USE_DEFAULT_CODE` singletons and no
  `TYPE_CHECKING` overload stacks on `LitestarAuthError`, `InsufficientRolesError`,
  `UserAlreadyExistsError`, `InvalidPasswordError`, or `OAuthAccountAlreadyLinkedError`.
  **Minor breaking change:** passing `code=None` explicitly no longer raises `TypeError`; it
  resolves to `default_code` like an omitted argument.
- **`_require_non_empty_string`, `_require_present_context`, `_require_non_empty_role_names`
  removed from `litestar_auth.exceptions`** — structured context fields are stored verbatim;
  any invariant checks belong at the raise sites, not in `__init__`.

### Internal

- **`_SecretValue` simplified to a masked-repr dataclass** — the wrapper no longer implements
  `__eq__` via `hmac.compare_digest` or `__hash__` via `hmac.digest(...)`; Python's default
  identity equality applies. Secrets are still masked in `repr()` / `str()` and
  `get_secret_value()` still returns the raw string. The `import hmac` that served only the
  removed equality / hash paths is gone.
- **Module-level dummy-hash cache replaced with per-instance caching** — the
  `_DUMMY_PASSWORD_HASHES: WeakKeyDictionary` + `_DUMMY_PASSWORD_HASH_LOCK` globals are gone;
  each `BaseUserManager` lazily computes one dummy hash via its active `PasswordHelper` and
  caches it on the instance. Enumeration-resistance behavior on unknown-user login / forgot-password
  paths is unchanged.
- **Redundant `UserManagerSecurity.__str__ = __repr__` assignment removed** — Python's default
  `object.__str__` already returns `__repr__()`; the explicit alias was dead code.
- **`BaseUserManager` no longer needs `# noqa: PLR0904`** — after the service-façade + hooks-mixin
  decomposition the public surface fits within the lint threshold.
- **Startup backend inventory flattened from four classes to two** — `_BackendSlot`,
  `_StartupBackendInventoryEntry`, and the private `_StartupBackendInventory` are collapsed into
  a single public `StartupBackendInventory` dataclass holding a
  `tuple[StartupBackendTemplate, ...]`. Index / name lookups are direct tuple indexing;
  multi-backend drift detection (missing index, backend-name mismatch) keeps the same error
  semantics.
- **Defensive `request.user is None` branches removed from authenticated handlers** —
  `_users_handle_get_me`, `_users_handle_update_me`, and `_handle_auth_logout` rely on the
  `is_authenticated` guard invariant and narrow `request.user` via a local `cast` instead of a
  dead raise branch. The live identity check in `_users_handle_delete_user` ("superusers cannot
  delete themselves") is unchanged.

### Documentation

- **`docs/configuration.md` split into seven focused sub-pages under `docs/configuration/`** —
  `backends.md`, `user_and_manager.md`, `manager.md`, `redis.md`, `totp.md`, `oauth.md`, and
  `security.md`, each under 300 lines. `docs/configuration.md` is now a 139-line index that keeps
  the old section headings with `Moved to:` links so existing anchors still lead readers to the
  right page. Navigation in `zensical.toml` is updated accordingly.
- **`docs/quickstart.md` rewritten as a 148-line end-to-end example** — five fenced code blocks
  (install, SQLite `create_tables.py`, inline `app.py`, run commands, register / verify / login /
  protected-route requests) produce a working login without opening any other docs page. The
  inline app is kept byte-for-byte in sync with `docs/snippets/quickstart_plugin.py` by a
  regression test; a new `tests/integration/test_docs_quickstart.py` exercises the full flow
  against isolated SQLite.
- **`README.md` rewritten as a 145-line landing page** with an elevator pitch, a runnable
  quick-peek block that mirrors the quickstart snippet, a feature list, install guidance with
  extras, and absolute `https://zylvext.github.io/litestar-auth/…` docs links suitable for the
  PyPI surface.
- **`docs/snippets/home_quick_peek.py` is now a self-contained importable module** — the previous
  `YourIdType` / `YourUser` / `YourUserManager` / `async_session_factory` placeholders are
  replaced with concrete types wired through `DatabaseTokenAuthConfig` + `LitestarAuthConfig` +
  `LitestarAuth`. A smoke test in `tests/unit/test_docs_snippets.py` imports the module and
  asserts `module.app` is a `Litestar` instance so future doc rot fails CI.
- **Canonical / compatibility shim vocabulary removed from docs and public docstrings** — after
  the 1.9 + Unreleased refactors removed the shims the vocabulary described, all 87+ occurrences
  of "canonical", "compatibility shim", "preferred one-client", and "escape hatch" across 24 docs
  pages and the affected public Python modules are rewritten into neutral, declarative "Use X
  for Y" guidance. A docs-wide banned-vocabulary regression in
  `tests/unit/test_docs_redis_totp_guidance.py` keeps the sweep enforced.
- **`litestar_auth/__init__.py` module docstring reframed around the primary use case** — the
  preamble now describes the plugin/config/manager/guards entry points and points at the
  submodules for everything else; the previous OAuth "advanced escape hatch" headline is gone
  and a runnable `DatabaseTokenAuthConfig` + `LitestarAuth` example is embedded directly.

### Migration

- **Switch from `LitestarAuthConfig.create(...)` / `.with_default_manager(...)` /
  `.with_custom_manager_factory(...)` to direct construction.** The dataclass accepts every
  factory keyword, so the migration is mechanical:
  Before: `LitestarAuthConfig.with_default_manager(user_model=User, user_manager_class=UserManager,
  session_maker=session_maker, user_manager_security=UserManagerSecurity(...))`
  After: `LitestarAuthConfig[User, UUID](user_model=User, user_manager_class=UserManager,
  session_maker=session_maker, user_manager_security=UserManagerSecurity(...))`.
  For the custom-factory path, pass `user_manager_factory=my_factory` directly;
  `__post_init__` still rejects configs that set both `user_manager_class=` and
  `user_manager_factory=`.
- **Replace `resolve_backends()` calls with `resolve_backends(session)`.** Call sites that used
  to call the no-arg method and catch `ValueError` should drop the try/except and pass the
  active `AsyncSession`. Use `resolve_startup_backends()` only for startup-only inventory.
- **Construct OAuth providers as real `OAuthProviderConfig` instances.**
  Before: `OAuthConfig(oauth_providers=[("google", google_client)])`
  After: `OAuthConfig(oauth_providers=[OAuthProviderConfig(name="google", client=google_client)])`.
- **Import payloads from `litestar_auth.payloads` and user schemas from `litestar_auth.schemas`.**
  No payload struct is re-exported from `litestar_auth`, `litestar_auth.controllers`, or
  (for user schemas) `litestar_auth.payloads` any more.
- **Retarget compat imports from `litestar_auth.manager`.** `SAFE_FIELDS` / `_PRIVILEGED_FIELDS`
  now live in `litestar_auth._manager.user_lifecycle`; `MAX_PASSWORD_LENGTH` /
  `require_password_length` live in `litestar_auth.config`.
- **Migrate non-core imports off the root package.** Controller factories → `litestar_auth.controllers`.
  Strategies → `litestar_auth.authentication.strategy`. Token stores → their strategy module.
  Rate limiters → `litestar_auth.ratelimit`. TOTP helpers → `litestar_auth.totp`. Individual
  exception subclasses → `litestar_auth.exceptions`. Typed aliases (`DbSessionDependencyKey`,
  `UserManagerExtraKwargs`) → `litestar_auth.types`.
- **Raise `UserAlreadyExistsError` with keyword-only `identifier=UserIdentifier(...)`.**
  Before: `raise UserAlreadyExistsError("already exists", identifier_type="email",
  identifier_value=email)`
  After: `raise UserAlreadyExistsError("already exists",
  identifier=UserIdentifier(identifier_type="email", identifier_value=email))`.
  The mirrored `identifier_type` / `identifier_value` attributes remain readable on the
  exception instance.
- **If you configure `totp_config`, ensure `user_model` implements `TotpUserProtocol`.**
  Plugin init now fails fast with `ConfigurationError` when `email: str` or
  `totp_secret: str | None` is missing from the user model, instead of raising on first login.

## 1.9.0 (2026-04-18)

### Added

- **`LitestarAuthConfig.with_default_manager()` / `with_custom_manager_factory()` factory
  classmethods** — two named construction paths replace the previous "set one of several fields
  and hope the right branch fires" layout on `LitestarAuthConfig`. `with_default_manager(...)` is
  the canonical entrypoint for apps that use the bundled `BaseUserManager`-style constructor and
  wires `user_manager_class`, `user_manager_security`, and `session_maker` through one typed
  signature that guarantees `user_manager_factory=None` on the returned config.
  `with_custom_manager_factory(...)` is the explicit escape hatch for non-canonical constructors;
  it validates the factory is callable at build time, guarantees `user_manager_class=None` on the
  returned config, and raises `ConfigurationError` when the factory is `None` or not callable.
  Both factories delegate to `__post_init__` so all existing validation (login identifier,
  dependency key, backend inventory) still runs; see `docs/migration.md` for before/after examples.
- **`UserManagerSecurity.password_helper` and `UserManagerSecurity.password_validator` fields** —
  the canonical security bundle now carries the shared password helper and validator directly
  instead of requiring callers to thread them through `user_manager_kwargs`.
  `LitestarAuthConfig.resolve_password_helper()` prefers the typed bundle before falling back to
  the legacy kwargs, and direct helper overrides on the config continue to take precedence.
- **`ErrorCode.INSUFFICIENT_ROLES` and `InsufficientRolesError`** — role-membership failures now
  raise a dedicated `InsufficientRolesError(required_roles=..., user_roles=..., require_all=...)`
  with the `INSUFFICIENT_ROLES` machine-readable code, instead of reusing the generic
  authorization-error shape with a static detail string. The plugin's HTTP 403 handler serializes
  the three context fields into the JSON body so API clients and operators can reconstruct which
  roles were required and which the principal actually had without parsing prose.
- **Operational context on `OAuthAccountAlreadyLinkedError`, `UserAlreadyExistsError`, and
  `InvalidPasswordError`** — `OAuthAccountAlreadyLinkedError` now carries
  `provider`, `account_id`, and `existing_user_id`; `UserAlreadyExistsError` carries
  `identifier_type` (`"email"` / `"username"`) and `identifier_value`; `InvalidPasswordError`
  carries optional `user_id`. Raise sites in `SQLAlchemyUserDatabase.upsert_oauth_account()`,
  `BaseUserManager` create/update paths, and password-policy enforcement are updated to pass the
  new context. Empty-string and whitespace context values are rejected at construction time via
  shared validators, so the invariants are checked once rather than at every raise site.
- **Split OAuth email-verification client protocols and `make_async_email_verification_client()`
  helper** — `OAuthEmailVerificationAsyncClientProtocol` (async-only, runtime-checkable) and
  `OAuthEmailVerificationSyncClientProtocol` (sync-only) replace the previous
  `bool | Awaitable[bool]` union as the preferred typing contract.
  `make_async_email_verification_client(sync_client)` wraps a sync implementation onto the async
  protocol via `asyncio.to_thread()`, giving callers one documented migration path instead of
  relying on the adapter's legacy `inspect.isawaitable()` dispatch. Both protocols and the helper
  are re-exported from `litestar_auth.oauth`.
- **`LitestarAuthConfig.create()` classmethod with type inference** — a method-local generic
  signature `create[ConfigUP: UserProtocol[Any], ConfigID](user_model=..., user_manager_class=...)
  -> LitestarAuthConfig[ConfigUP, ConfigID]` lets callers construct a fully typed config without
  repeating the `LitestarAuthConfig[User, UUID](...)` explicit parameterization. Existing direct
  construction continues to work.
- **`UserProtocolStrict`, `UserManagerExtraKwargs`, and `DbSessionDependencyKey` typing surfaces**
  — `UserProtocolStrict[ID]` is the static-only variant of `UserProtocol[ID]` for consumers who
  want nominal-style checking without `@runtime_checkable` overhead; `UserManagerExtraKwargs` is a
  `TypedDict(total=False)` describing the legacy `user_manager_kwargs` contents;
  `DbSessionDependencyKey = Annotated[str, _valid_python_identifier_validator]` promotes the
  "must be a valid non-keyword Python identifier" rule from `__post_init__` prose into the type
  system. `LoginIdentifier` is now the single source of truth for the accepted values via
  `get_args(LoginIdentifier.__value__)`.
- **`litestar_auth/py.typed` marker** — the package now ships a PEP 561 marker and
  `pyproject.toml` declares `artifacts = ["litestar_auth/py.typed"]` with `zip-safe = false`, so
  downstream type checkers pick up the library's inline annotations from installed wheels.
- **`AuthRateLimitSlot` StrEnum** — `LOGIN`, `REFRESH`, `REGISTER`, `FORGOT_PASSWORD`,
  `RESET_PASSWORD`, `TOTP_ENABLE`, `TOTP_CONFIRM_ENABLE`, `TOTP_VERIFY`, `TOTP_DISABLE`,
  `VERIFY_TOKEN`, and `REQUEST_VERIFY_TOKEN` are now an IDE-autocompletable StrEnum exported from
  `litestar_auth.ratelimit`. `endpoint_overrides`, `scope_overrides`, and `namespace_overrides`
  now type their keys as `Mapping[AuthRateLimitSlot, ...]`; the legacy
  `AuthRateLimitEndpointSlot` Literal alias remains for backward compatibility because the
  StrEnum values are str-equivalent at runtime.
- **`AuthRateLimitConfig.strict()` / `.lenient()` / `.disabled()` preset factories** — three
  named classmethods replace the "copy a working config from the docs" pattern. `strict(backend)`
  wires the `LOGIN`, `REGISTER`, and `TOTP_VERIFY` slots at tightened budgets; `lenient(backend)`
  keeps `LOGIN` / `REFRESH` / `REGISTER` at the shared-backend default while cloning the
  sensitive slots with a 5-attempt cap; `disabled()` returns an `AuthRateLimitConfig()` with all
  slots `None` for local development and integration tests.
- **Generic `has_any_role[RoleNameT: str](...)` and `has_all_roles[RoleNameT: str](...)` role
  guards** — the two role-guard factories now use Python 3.12 generic syntax, so `Literal` and
  `StrEnum` role registries flow through to the returned guard's type without erasure. Empty
  role collections, whitespace-only role names, and no-argument calls are rejected with
  `ValueError` at construction time instead of failing opaquely at first request.

### Changed

- **Role-guard denial now raises `InsufficientRolesError` instead of a generic
  `AuthorizationError`** — **Breaking for clients that matched on the previous detail string.**
  Both the `has_any_role` and `has_all_roles` branches raise `InsufficientRolesError` with
  `required_roles`, `user_roles`, and `require_all` populated, and the plugin HTTP 403 handler
  emits the three context fields as top-level JSON keys alongside `detail` and `code`. Clients
  that previously matched on `detail == "..."` should migrate to the stable
  `code == "INSUFFICIENT_ROLES"` field (or the structured context fields) — see
  `docs/exceptions.md`.
- **`LitestarAuthError.code` is now a required attribute** — **Breaking for custom subclasses
  that omitted `default_code`.** `LitestarAuthError.__init__` now rejects `code=None` and all
  bundled subclasses declare `default_code`; custom exceptions that inherited from
  `LitestarAuthError` without setting `default_code` must add one, or pass `code=` explicitly at
  every raise site.
- **`UP` TypeVar bound narrowed from `UserProtocol[Any]` to `UserProtocol`** — **Typing-only
  breaking change.** Consumer code that annotated generic helpers with
  `TypeVar("T", bound=UserProtocol[Any])` should switch to `bound=UserProtocol` to match the
  library's new bound; runtime behavior is unchanged. The narrowed bound preserves the `ID`
  parameter so generic inference across `LitestarAuthConfig[UP, ID]` now flows correctly without
  collapsing to `Any`.
- **Rate-limit precedence chain simplified to `backend → group_backends → endpoint_overrides`** —
  **Breaking for callers that relied on the previous five-level chain.** `scope_overrides` and
  `namespace_overrides` still accept values, but now emit `DeprecationWarning`s and are applied
  as shims before `endpoint_overrides`. Consolidate any custom per-slot limits into
  `endpoint_overrides` keyed by `AuthRateLimitSlot` values — see `docs/migration.md`.
- **`LitestarAuthConfig.__post_init__` rejects conflicting manager configuration** — **Breaking
  for configs that set both `user_manager_factory` and `user_manager_class` simultaneously.**
  The construction paths are now mutually exclusive and the error message points at
  `with_default_manager()` / `with_custom_manager_factory()` as the two supported entrypoints.
- **OAuth email-verification dispatch is a clean single-path async call** — the adapter's hot
  path now uses `inspect.iscoroutinefunction()` on the client's `get_email_verified` attribute
  and awaits the result directly, instead of routing every call through the
  `bool | Awaitable[bool]` union handler. Legacy clients implementing the deprecated union
  protocol continue to work via a scoped fallback that emits a `DeprecationWarning` on first use.

### Removed

- **Legacy manager kwargs surface removed** — Migration: `LitestarAuthConfig.user_manager_kwargs`
  and the `user_manager_kwargs=` parameter on `LitestarAuthConfig.create()`,
  `LitestarAuthConfig.with_default_manager()`, and
  `LitestarAuthConfig.with_custom_manager_factory()` are gone. Use
  `UserManagerSecurity.password_helper` and `UserManagerSecurity.password_validator` directly.
- **Legacy OAuth email-verification union protocol removed** —
  `OAuthEmailVerificationClientProtocol` and its supporting adapter helpers for
  `bool | Awaitable[bool]` dispatch are gone. Use
  `OAuthEmailVerificationAsyncClientProtocol` directly, or wrap sync implementations with
  `make_async_email_verification_client()`.
- **Legacy rate-limit compatibility parameters removed** —
  `AuthRateLimitConfig.from_shared_backend()` no longer accepts `namespace_style`,
  `scope_overrides`, or `namespace_overrides`; `AuthRateLimitNamespaceStyle` is removed; and
  `RedisAuthPreset.build_rate_limit_config()` no longer accepts those same three parameters.
  Use `endpoint_overrides` keyed by `AuthRateLimitSlot`.

### Internal

- **Shared context validators on `LitestarAuthError`** — `_require_non_empty_string()`,
  `_require_present_context()`, and `_require_non_empty_role_names()` now enforce non-empty /
  non-whitespace invariants for the new exception context fields at construction time, so
  violations fail loudly at the raise site rather than surfacing as blank JSON values downstream.
- **`UserManagerSecurity` now carries `password_helper` / `password_validator` directly** — the
  plugin's manager construction path reads those fields from the security bundle when the legacy
  `user_manager_kwargs` entries are absent, so the "canonical bundle" remains the single
  authoritative source for security-adjacent wiring.

### Migration

- **Switch to the named `LitestarAuthConfig` factory classmethods.** Replace
  `LitestarAuthConfig(user_manager_class=..., user_manager_kwargs={"password_helper": ...})`
  with `LitestarAuthConfig.with_default_manager(user_manager_class=...,
  user_manager_security=UserManagerSecurity(password_helper=..., password_validator=...))`.
  For non-canonical constructors, use
  `LitestarAuthConfig.with_custom_manager_factory(user_manager_factory=my_factory, ...)`.
- **Move `password_helper` / `password_validator` out of `user_manager_kwargs`.** Pass them on
  `UserManagerSecurity(...)` instead; `user_manager_kwargs` usage emits a `DeprecationWarning`
  that points at the replacement fields.
- **Manager security migration snippet.**
  Before: `LitestarAuthConfig.create(..., user_manager_kwargs={"password_helper": helper,
  "password_validator": validator})`
  After: `LitestarAuthConfig.create(...,
  user_manager_security=UserManagerSecurity(password_helper=helper, password_validator=validator))`
- **Match on `code == "INSUFFICIENT_ROLES"` (or on the structured context fields) instead of
  previous role-guard detail strings.** The JSON 403 response now carries `required_roles`,
  `user_roles`, and `require_all` alongside `detail` and `code`.
- **Add `default_code` to any custom `LitestarAuthError` subclass** that previously inherited
  the attribute-less default. `LitestarAuthError.__init__(code=None, ...)` now raises.
- **Narrow `bound=UserProtocol[Any]` annotations in consumer code to `bound=UserProtocol`.**
  The `ID` parameter is preserved by the narrower bound, so generic inference now flows without
  `Any`-collapsing.
- **Migrate OAuth email-verification clients to `OAuthEmailVerificationAsyncClientProtocol`.**
  For pure-sync implementations, wrap with
  `make_async_email_verification_client(sync_client)`; for mixed sync/async clients, implement
  the async protocol directly. The legacy union protocol continues to work for one minor
  release with a `DeprecationWarning`.
- **OAuth email-verification migration snippet.**
  Before: `client: OAuthEmailVerificationClientProtocol = LegacyClient()`
  After: `client: OAuthEmailVerificationAsyncClientProtocol =
  make_async_email_verification_client(LegacyClient())`
- **Replace `AuthRateLimitConfig` ad hoc wiring with presets.** Use
  `AuthRateLimitConfig.strict(backend)`, `.lenient(backend)`, or `.disabled()` for the common
  cases; use `AuthRateLimitConfig.from_shared_backend(backend, endpoint_overrides={
  AuthRateLimitSlot.LOGIN: ..., ...})` for custom per-slot limits. Move any `scope_overrides` /
  `namespace_overrides` / `namespace_style` configuration into `endpoint_overrides` keyed by
  `AuthRateLimitSlot` values before the deprecated fields are removed.
- **Rate-limit override migration snippet.**
  Before: `AuthRateLimitConfig.from_shared_backend(backend, namespace_style="route",
  scope_overrides={"login": "strict"}, namespace_overrides={"login": "auth/login"})`
  After: `AuthRateLimitConfig.from_shared_backend(backend, endpoint_overrides={
  AuthRateLimitSlot.LOGIN: EndpointRateLimit(backend=backend, scope="strict",
  namespace="auth/login")})`
- **Use `LitestarAuthConfig.create(...)` to get automatic generic inference** — the classmethod
  returns `LitestarAuthConfig[ConfigUP, ConfigID]` without needing
  `LitestarAuthConfig[MyUser, UUID](...)` explicit parameterization.
- **Annotate `db_session_dependency_key` with the exported `DbSessionDependencyKey` alias** when
  propagating the value through app-owned code; the `Annotated` validator documents the
  "valid non-keyword Python identifier" rule at the type level.

## 1.8.0 (2026-04-14)

### Added

- **`litestar roles` CLI for role catalog and user-role management** — A `roles` command group is
  now registered by `LitestarAuth` through Litestar's `CLIPlugin` surface. Operators can list
  normalized roles (`roles list`), create roles idempotently (`roles create <role>`), delete roles
  with an explicit `--force` guard when assignments exist (`roles delete <role>`), assign and
  unassign roles for a target user (`roles assign --email … <role>…` /
  `roles unassign --email … <role>…`), and display current membership
  (`roles show-user --email …`). Role mutations route through `BaseUserManager.update()` so
  `on_after_update()` lifecycle hooks, audit logging, and downstream entitlement side effects fire
  consistently for both single-user and multi-user forced-delete paths. Requires `LitestarAuth`
  with a configured `session_maker` and a relational role-capable user model
  (`UserRoleRelationshipMixin` or a custom equivalent); see the new role-management CLI guide in
  `docs/guides/roles_cli.md`.
- **Plugin-level customization hooks** — `LitestarAuthConfig` now accepts three optional typed
  hook callbacks for applications that need to adjust plugin-owned behavior without subclassing or
  forking. `exception_response_hook` replaces the built-in `LitestarAuthError` response handler
  with a caller-supplied `Response` factory; `middleware_hook` receives the constructed
  `DefineMiddleware` and returns the (possibly wrapped) middleware instance to insert into the app;
  `controller_hook` receives the built controller list and returns the filtered or decorated list to
  register. All hooks default to `None` and existing plugin behavior is fully preserved when they
  are not set.
- **`OAuthProviderConfig` is now a named dataclass** — **Breaking:** `OAuthProviderConfig` is now
  a frozen dataclass with explicit `name: str` and `client: object` fields, replacing the opaque
  `tuple[str, object]` type alias. Existing tuple entries continue to work at runtime via the new
  `OAuthProviderConfig.coerce()` classmethod, but static type checkers will flag bare tuples passed
  to `oauth_providers`. The named type is exported from `litestar_auth.config`.

### Security

- **In-memory JWT denylist is now fail-closed under capacity** — `InMemoryJWTDenylistStore` no
  longer evicts already-denied JTI entries when `max_entries` is reached. `deny()` now returns
  `False`, and the bundled logout and pending-token burn routes raise `TokenError` and return
  **HTTP 503** rather than silently opening a capacity gap where a freshly revoked access or
  pending-login token remains usable for the rest of its lifetime. This matches the fail-closed
  behavior already applied to `InMemoryUsedTotpCodeStore`. Switch to `RedisJWTDenylistStore` for
  an unbounded, durable denylist in production.
- **TOTP replay protection TTL aligned with drift window** — `USED_TOTP_CODE_TTL_SECONDS` is now
  `TIME_STEP_SECONDS * (2 * TOTP_DRIFT_STEPS + 1)` (90 s with `TOTP_DRIFT_STEPS=1`, up from
  60 s). The previous value could let a replay-store entry expire up to ~29 s before the
  corresponding TOTP code became invalid, leaving a narrow window for a replayed code to pass
  verification a second time.

### Changed

- **OAuth token ORM columns are wider** — `oauth_access_token_type` and `oauth_refresh_token_type`
  in `litestar_auth.models._oauth_encrypted_types` now use `String(length=4096)` instead of
  `2048`, so Fernet-encrypted access and refresh tokens from providers that issue large JWTs fit
  reliably.
- **`OAuthTokenEncryption` builds its Fernet backend once at construction** —
  `OAuthTokenEncryption.__post_init__()` now caches the `_RawFernetBackend` instance on the frozen
  dataclass instead of allocating a new backend on every `encrypt()` / `decrypt()` call. As a side
  effect, invalid Fernet keys now raise at `OAuthTokenEncryption(key=…)` construction time rather
  than on first use.
- **`SQLAlchemyUserDatabase.update()` no longer issues a redundant SELECT** — the repository
  `update()` call already hydrates relationships via `load=self._user_load`; the follow-up
  `_reload_with_relationships()` query has been removed from the `update()` path. Each user update
  now executes one fewer database round-trip.
- **Guard denial messages include the guard name and required protocol** — account-state and
  role-membership guard failures now report the specific guard name and the `GuardedUserProtocol`
  or `RoleCapableUserProtocol` attributes the user model must expose, replacing the previous
  generic static strings with actionable operator-facing guidance.
- **Protocol hierarchy decision table added to type reference** — `docs/api/types.md` and the
  `litestar_auth.types` module docstring now include a feature-to-protocol mapping table
  (`UserProtocol`, `GuardedUserProtocol`, `RoleCapableUserProtocol`, `TotpUserProtocol`) so users
  can identify which protocol their model must satisfy for account-state guards, role guards, and
  TOTP flows without reading guard implementation details.
- **Role CLI user lookups use async-safe eager loading** — `roles assign`, `roles unassign`,
  `roles show-user`, and forced `roles delete --force` now preload role membership via
  `selectinload` before accessing `user.roles`, so supported custom models with `lazy='select'`
  role-assignment relationships work correctly under native `AsyncSession` execution.

### Internal

- **`RedisAuthPreset.build_rate_limit_config()` consolidated** — the four copy-paste branches for
  the `identity_fields` × `trusted_headers` kwarg combinations are replaced with a single call
  site using a conditionally-built kwargs dict. Observable rate-limiter behavior is unchanged.

### Migration

- **`OAuthProviderConfig` named type** — Replace any `(name, client)` tuple entries in
  `oauth_providers` with `OAuthProviderConfig(name=name, client=client)` to satisfy type checkers.
  Existing tuples continue to work at runtime through `OAuthProviderConfig.coerce()`.
- **JWT denylist capacity now surfaces HTTP 503** — If client or middleware code assumes logout
  always returns a success response, add handling for 503 when using the default in-memory denylist
  under load. Consider `RedisJWTDenylistStore` for durable, unbounded revocation in production.
- **Fernet key validated at `OAuthTokenEncryption` construction** — `OAuthTokenEncryption(key=…)`
  now validates the key immediately. Replace placeholder keys such as `"a" * 44` with a proper
  32-byte url-safe base64-encoded key:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
- **OAuth token DDL** — Existing deployments must widen `oauth_account.access_token` and
  `oauth_account.refresh_token` (or equivalent custom column names) with database-specific DDL, for
  example `ALTER TABLE oauth_account ALTER COLUMN access_token TYPE VARCHAR(4096)` and the same for
  `refresh_token` on PostgreSQL. Adjust identifiers and types for your dialect (MySQL may rebuild
  the table depending on row format).

## 1.7.0 (2026-04-11)

### Added

- **Bundled relational role models and mixins are now part of the public ORM surface** — `Role`,
  `UserRole`, `RoleMixin`, `UserRoleAssociationMixin`, and `UserRoleRelationshipMixin` are now
  exported from `litestar_auth.models` so bundled and custom SQLAlchemy model families can use
  first-class role tables without copying mapper wiring.
- **Built-in role guard factories are now exported** — `has_any_role(*roles)` and `has_all_roles(*roles)` return Litestar-compatible guard callables for flat normalized role membership on app-owned routes and custom controller/router surfaces.

### Changed

- **`LitestarAuthConfig` method names follow a consistent verb convention** — canonical entry points are `resolve_password_helper()`, `get_default_password_helper()`, `resolve_startup_backends()`, and `resolve_request_backends(session)`. **Breaking:** the older aliases (`build_password_helper()`, `memoized_default_password_helper()`, `startup_backends()`, `bind_request_backends(session)`) are removed with no compatibility shims; migrate call sites to the `resolve_*` / `get_*` names.
- **`BaseUserManager` secrets contract is `security=` only** — **Breaking:** per-field `verification_token_secret`, `reset_password_token_secret`, `totp_secret_key`, and `id_parser` constructor kwargs are removed. Pass everything through `security=UserManagerSecurity(...)` (the default plugin builder already does). Custom `user_manager_factory` implementations must supply the same `security=` bundle when they construct managers.
- **Bundled role persistence now uses relational tables instead of a JSON column** — the bundled
  `User` and the supported custom-model path now persist global role membership through `role` and
  `user_role` rows, while `user.roles` remains the normalized flat `list[str]` contract consumed by
  managers, schemas, and guards.
- **Manager create/update flows now share one role-normalization path** — when role membership is persisted through `BaseUserManager`, the library normalizes it to trimmed, lowercased, deduplicated, sorted strings, and create-time safe/default registration semantics keep `roles` privileged unless callers explicitly opt into privileged input.
- **Built-in auth and users DTOs are now role-aware** — default `UserRead` responses from register, verify, reset-password, and `/users/*` routes now include normalized `roles`, and default `UserUpdate` accepts optional `roles` so superuser `PATCH /users/{id}` can manage them while `/users/me` continues stripping privileged fields.
- **Route-level role authorization now has a canonical guard surface** — `has_any_role(...)` / `has_all_roles(...)` require authenticated active users, fail closed for role-incapable user objects, and compare runtime/user-configured role names with the same normalization semantics as persistence and manager writes.

### Migration

- Existing deployments that previously stored roles in the bundled `user.roles` JSON column (or an
  app-owned copy of that column) should create `role` and `user_role` tables, normalize and
  deduplicate current role arrays, backfill association rows, and then remove or ignore the legacy
  column once the application points at the relational model family.
- Custom user models that want the same role-capable typing and built-in role-aware surfaces should
  compose `UserRoleRelationshipMixin` plus sibling `RoleMixin` / `UserRoleAssociationMixin`
  classes, or provide an equivalent normalized flat `roles` contract.
- Import the bundled relational role tables from `litestar_auth.models.role` when you need them
  without registering the reference `User` mapper, or compose the mixins on your own declarative
  base for app-owned table names and registries.
- Clients using the built-in register/verify/reset/users responses should expect a new `roles` array in the default payload shape. Apps that keep the built-in controllers with role-less user models should provide custom `user_read_schema` / `user_update_schema` types that intentionally omit `roles`.
- Applications that want to use the built-in role guard factories on app-owned routes should ensure their authenticated user type satisfies `RoleCapableUserProtocol`; otherwise the guards now fail closed with **403** instead of relying on ad hoc `user.roles` access.
- Replace removed `LitestarAuthConfig` aliases with `resolve_password_helper()`, `get_default_password_helper()`, `resolve_startup_backends()`, and `resolve_request_backends(session)`.
- Construct `BaseUserManager` with `security=UserManagerSecurity(...)` only; move any former per-field secret or `id_parser` arguments into that bundle.

## 1.6.1 (2026-04-11)

### Added

- **Public OpenAPI auth helpers for app-owned routes** — `LitestarAuthConfig.resolve_openapi_security_requirements()` and `resolve_openapi_security_schemes()` now expose the same auth-scheme derivation used by the plugin-owned route table, so application-defined Litestar handlers, routers, and controllers can advertise auth requirements in OpenAPI without hard-coding backend names.

### Changed

- **Protected-route OpenAPI metadata is now reusable outside the plugin route table** — docs now show the canonical pattern for app-owned routes: pair runtime guards such as `is_authenticated` with `security=config.resolve_openapi_security_requirements()` so runtime enforcement and OpenAPI documentation stay aligned.
- **Manual protected controller factories now accept OpenAPI auth metadata consistently** — the manual OAuth associate and TOTP controller surfaces accept `security=...`, matching the existing plugin-owned route behavior and letting custom route tables publish standard OpenAPI auth requirements.
- **Plugin-owned OpenAPI auth metadata is now more explicit** — `LitestarAuthConfig.include_openapi_security` controls whether plugin-managed protected routes register OpenAPI auth schemes and per-operation security requirements.

### Fixed

- **OpenAPI security requirements now use the correct alternative-backend semantics** — when multiple auth backends are configured, protected operations now publish OR-style security requirements instead of incorrectly requiring all schemes at once, so Swagger and other OpenAPI clients can authorize with any configured backend.
- **OAuth associate callback routes no longer appear public in OpenAPI** — plugin-owned and manually mounted `/auth/associate/{provider}/callback` endpoints now publish the same auth requirement metadata as the corresponding protected authorize route.

## 1.6.0 (2026-04-11)

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
