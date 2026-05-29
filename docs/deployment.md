# Deployment checklist

Use this when moving from local development to production, especially for **secrets**, **multi-worker** deployments, and **shared stores** (Redis) where in-memory defaults are insufficient.

## Process topology

- **Single worker / dev** — in-memory JWT denylist, in-memory rate limiting, and in-memory TOTP stores are acceptable for local testing only.
- **Multiple workers or restarts that matter** — use **Redis** (or equivalent shared stores) for: JWT `jti` denylist, the auth rate-limit config, `totp_enrollment_store`, `totp_pending_jti_store`, and `totp_used_tokens_store`. When one async Redis client should back auth rate limiting plus the TOTP stores, use `litestar_auth.contrib.redis.RedisAuthPreset` as the shared-client path and keep the three TOTP stores conceptually separate: pending-enrollment secrets, pending-token JTI deduplication, and used-code replay protection.

Declare known process topology with `LitestarAuthConfig.deployment_worker_count`. `None` means the
plugin cannot reliably infer the ASGI host's worker count and preserves warning-only startup
diagnostics. `1` means a known single-worker deployment. Values greater than `1` mean known
multi-worker: startup fails with `ConfigurationError` when any enabled auth rate-limit endpoint uses
a process-local backend such as `InMemoryRateLimiter`. Use `RedisRateLimiter` or
`RedisAuthPreset` before declaring a multi-worker production deployment.

## Secrets and keys

- Store production secrets in a secrets manager or KMS-backed runtime secret
  source. Do not commit them, bake them into images, or share one value across
  auth roles for convenience.
- Rotate secrets independently by role. Plan rotation for JWT signing keys,
  verify/reset-token secrets, CSRF secrets, TOTP Fernet keys, OAuth token
  encryption keys, API-key signing-secret Fernet keys, OAuth flow-cookie
  secrets, and opaque-token hash secrets before the first production incident.
- For the full manager/password contract, including `PasswordHelper` sharing,
  `password_validator_factory`, and the `UserEmailField` / `UserPasswordField`
  schema helpers, see
  [Configuration](configuration/manager.md#manager-password-surface). The checklist below only
  calls out production consequences.
- For plugin-managed apps, configure manager-scoped secrets via
  `LitestarAuthConfig.user_manager_security`.
- **JWT signing secret** (or private key) — high entropy; rotation plan.
- **`verification_token_secret`** and **`reset_password_token_secret`** — configure both through
  `user_manager_security`; each must satisfy the production strength gate enforced by
  `validate_production_secret` (32+ characters plus the default entropy floor).
- **`login_identifier_telemetry_secret`** — optional dedicated key for failed-login
  `identifier_digest` log correlation. Configure it through `user_manager_security` only when you
  want stable cross-request digests; otherwise the digest field is omitted.
- **`totp_secret_keyring`** — configure through `user_manager_security` when TOTP is enabled; required in
  production because stored TOTP secrets and pending-enrollment secrets must be encrypted at rest.
  Use `FernetKeyringConfig(active_key_id=..., keys=...)` so old key ids remain readable during rotation.
  The one-key `totp_secret_key` field remains available when a single active Fernet key is enough.
  Existing plaintext persisted TOTP secrets must be encrypted, rotated, or cleared before upgrading
  to versions that enforce encrypted-only TOTP secret storage.
- **`csrf_secret`** — required for meaningful CSRF protection when using cookie-based auth with the plugin’s CSRF wiring.
- **`totp_pending_secret`** — required when TOTP is enabled; protects pending login payloads.
- **`oauth_token_encryption_keyring`** — required when OAuth providers are configured (encrypts tokens at rest in the DB). The one-key `oauth_token_encryption_key` field remains available for single-key deployments.
- **`oauth_flow_cookie_secret`** — required when OAuth providers are configured (HKDF-derived into the Fernet key that encrypts and authenticates transient OAuth `state` plus PKCE verifier material in the browser-held flow cookie).
- **`token_hash_secret`** (database opaque token strategy) — protects digest-at-rest storage for DB tokens.
- **`api_keys.secret_encryption_keyring`** — required when API-key request signing is enabled and
  signing-required API keys can be created. This keyring encrypts the recoverable signing secret
  copy stored in `api_key.encrypted_secret`; bearer keys do not use it and remain digest-only.
- Keep **`verification_token_secret`**, **`reset_password_token_secret`**,
  **`login_identifier_telemetry_secret`** when configured, **`totp_pending_secret`**, every
  configured TOTP Fernet key, and **`oauth_flow_cookie_secret`** distinct. Production configuration
  rejects reuse with `ConfigurationError`; only explicit `unsafe_testing=True` test setups bypass
  this validation. For plugin-managed apps the error is raised during `LitestarAuth(config)`
  validation; direct `BaseUserManager(...)` construction enforces the same rule for its
  manager-owned secret roles. Distinct values are the supported posture:
  `litestar-auth:verify`, `litestar-auth:reset-password`, and
  `litestar-auth:2fa-pending` / `litestar-auth:2fa-enroll` already separate JWT audiences, while
  failed-login telemetry, TOTP Fernet keys, and `oauth_flow_cookie_secret` should remain dedicated
  keys with no JWT audience.

For non-keyring secrets (`verification_token_secret`, `reset_password_token_secret`,
`login_identifier_telemetry_secret`, `csrf_secret`, `totp_pending_secret`,
`oauth_flow_cookie_secret`, and opaque-token hash secrets), write an application runbook before
production. Rotation is role-specific: verification/reset/TOTP pending JWT secret
rotation invalidates outstanding tokens for that flow, OAuth flow-cookie rotation invalidates
in-progress OAuth handshakes, CSRF secret rotation affects active browser sessions, and login
telemetry rotation starts a new digest correlation window. Keep token lifetimes short enough that
planned rotation can happen without a long dual-secret compatibility period.

## Deployment security contract

These requirements are deployment preconditions, not library toggles that make unsafe infrastructure
safe. Configure them before exposing browser auth, rate-limited auth endpoints, OAuth token storage,
TOTP, or API-key request signing to production traffic.

### Reverse-proxy and trust boundaries

Set `trusted_proxy=True` only on rate-limit endpoints whose traffic reaches the application through a
trusted reverse proxy or load balancer that overwrites the configured `trusted_headers`. This applies
to `EndpointRateLimit.trusted_proxy`, `EndpointRateLimit.trusted_headers`,
`EndpointRateLimit.trusted_proxy_hops`, and the shared builders that
copy those settings into endpoint limiters, including `SharedRateLimitConfigOptions.trusted_proxy` and
`RedisAuthRateLimitConfigOptions.trusted_proxy`.

The default trusted header is `X-Forwarded-For`. When `trusted_proxy=True`, the rate-limit key builder
uses `trusted_proxy_hops=1` by default, selecting the **rightmost** `X-Forwarded-For` value because
that is the value appended by the immediately upstream trusted proxy in common
`proxy_add_x_forwarded_for` deployments. Leftmost entries may be client-controlled and spoofed. For
multi-proxy chains such as CDN -> load balancer -> app, set `trusted_proxy_hops` to the number of
trusted proxy hops between the real client IP and the application, counted from the right. If the
header carries fewer entries than `trusted_proxy_hops`, rate-limit identity fails closed to the direct
client host. Leave `trusted_proxy=False` when those conditions are not true; the direct client host is
the fail-closed rate-limit identity source.

### Cookie transport security requirements

Browser cookie authentication requires HTTPS in production. Keep `CookieTransportConfig.secure=True`
and `CookieTransport.secure=True`, terminate TLS before the app, and set HSTS at the edge. The
transport rejects `samesite="none"` with `secure=False`; cross-site browser flows that need
`CookieTransportConfig.samesite="none"` must therefore run over HTTPS and need explicit CSRF
protection because browsers automatically attach those cookies to cross-origin requests.

For plugin-owned cookie auth, configure `LitestarAuthConfig.csrf_secret`; production validation fails
closed when `CookieTransport` is used without it unless you explicitly opt into a non-browser or
externally managed CSRF posture. The escape valves are narrow by design:
`CookieTransportConfig.allow_insecure_cookie_auth=True` / `CookieTransport.allow_insecure_cookie_auth`
for controlled non-browser cookie use, or manual route setups that set
`csrf_protection_managed_externally=True` only when app-owned CSRF middleware protects unsafe methods.
Use `LitestarAuthConfig.csrf_header_name` to align clients with the expected CSRF header.

### Secrets at rest and key rotation

Persisted OAuth tokens, persisted TOTP secrets, pending TOTP enrollment secrets, and API-key
signing-required raw secrets are secrets at rest. Configure their encryption fields before production:
`OAuthConfig.oauth_token_encryption_keyring` or the one-key `oauth_token_encryption_key`;
`UserManagerSecurity.totp_secret_keyring` or the one-key `totp_secret_key`; and
`ApiKeyConfig.secret_encryption_keyring`, surfaced in plugin config as
`api_keys.secret_encryption_keyring`. API-key signing stores the reversible ciphertext in
`api_key.encrypted_secret`; bearer API keys remain digest-only and are not signing-secret rotation
candidates.

Use `FernetKeyringConfig(active_key_id=..., keys=...)` for deployments that need no-downtime
rotation. The caller-owned migration pattern is dual-key: deploy old and new keys together, switch
`active_key_id` to the new key for fresh writes, re-encrypt stored rows one at a time, verify that no
stored values still require re-encryption, and only then remove the old key id. The library provides
row-level helpers such as `OAuthTokenEncryption.requires_reencrypt(...)` /
`OAuthTokenEncryption.reencrypt(...)`, `BaseUserManager.totp_secret_requires_reencrypt(...)` /
`BaseUserManager.reencrypt_totp_secret_for_storage(...)`, and
`BaseUserManager.api_key_signing_secret_requires_reencrypt(...)` /
`BaseUserManager.reencrypt_api_key_signing_secret(...)`; it does not provide a global database sweep,
locking strategy, batching job, audit-log table, or full Fernet key-rotation service. Those migration
concerns remain application-owned until the library ships a built-in helper.

### Privileged controllers and role administration

The contrib role-admin controller (`create_role_admin_controller(...)`) defaults to a single
`is_superuser` guard when `guards=None`. An explicit guard sequence replaces that default verbatim —
including an **empty list**, which leaves the role-administration endpoints with **no authorization
guard**. The empty-override is intentional (it lets you compose a fully custom guard stack), but it is
a footgun: never pass `guards=[]` to a privileged controller meaning "use the defaults". In
production, either leave `guards=None` to keep the `is_superuser` default, or supply an explicit
non-empty guard sequence that enforces at least equivalent privilege. The role-catalog invariants
still fail closed regardless of guards — they refuse to modify the system-managed superuser role or
remove the final superuser assignment — but those are integrity guards, not an authorization
substitute.

## DB refresh-session metadata

Session/device management is a DB-backed refresh-token feature. Before enabling
`include_session_devices=True` in production, verify the active refresh-token table has the required
metadata columns:

- `session_id` — unique non-sensitive public id for the refresh session;
- `created_at` — original row creation timestamp;
- `last_used_at` — nullable timestamp updated on successful refresh rotation;
- `client_metadata` — nullable bounded JSON for safe hints such as normalized User-Agent;
- `consumed_token_digests` — nullable JSON list of already-rotated keyed refresh-token digests used
  to detect replay.

For bundled models, these fields come from `RefreshTokenMixin`. Existing installations must run an
application-owned migration before rollout: add missing columns, backfill each existing row with a
unique UUID-style `session_id`, leave `last_used_at` null for historical sessions, and only store
bounded non-secret metadata. Leave `consumed_token_digests` null for historical rows; new rotations
populate it automatically. Custom refresh-token models must expose the same mapped attributes or
`DatabaseTokenModels` validation fails at startup.

Do not migrate by copying raw token values into public metadata. The API exposes only `session_id`
and safe metadata; raw access tokens, raw refresh tokens, stored token digests, and keyed token
digests must remain server-side storage details. Stored consumed digests are not public metadata and
must not be logged or returned by application APIs.

## Versioned Fernet key rotation

Persisted OAuth provider tokens and TOTP secrets use the same versioned Fernet-at-rest envelope:
`fernet:v1:<key_id>:<ciphertext>`. The `key_id` is not secret; it tells the library which configured
Fernet key decrypts the value. Do not log or publish the ciphertext portion.

Generate a Fernet key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Configure production keyrings with named ids instead of treating one unversioned key as the
long-term shape:

```python
from litestar_auth import FernetKeyringConfig, OAuthConfig, UserManagerSecurity

oauth_token_keyring = FernetKeyringConfig(
    active_key_id="oauth_2026_04",
    keys={
        "oauth_2026_04": settings.oauth_fernet_key_2026_04,
    },
)
totp_secret_keyring = FernetKeyringConfig(
    active_key_id="totp_2026_04",
    keys={
        "totp_2026_04": settings.totp_fernet_key_2026_04,
    },
)

oauth_config = OAuthConfig(
    oauth_token_encryption_keyring=oauth_token_keyring,
    # other OAuth fields...
)
user_manager_security = UserManagerSecurity(
    totp_secret_keyring=totp_secret_keyring,
    # verification/reset/password fields...
)
```

No-downtime rotation is a staged data migration:

1. Generate a new Fernet key and add it to the relevant keyring while keeping the current key id
   active. This proves every running instance can read both old and new key ids.
2. Deploy the same key map with `active_key_id` changed to the new key id. New OAuth and TOTP writes
   store `fernet:v1:<new_key_id>:...`; old rows remain readable because the old key id is still
   configured.
3. Run an application-owned migration job over stored OAuth `access_token` / `refresh_token`
   columns, stored TOTP secret columns, and API-key signing rows with non-null `encrypted_secret`.
   The library exposes row-level helpers, not an automatic database sweep: call
   `OAuthTokenEncryption.requires_reencrypt(value)` / `OAuthTokenEncryption.reencrypt(value)` for
   OAuth token values, `BaseUserManager.totp_secret_requires_reencrypt(value)` /
   `BaseUserManager.reencrypt_totp_secret_for_storage(value)` for TOTP values, and
   `BaseUserManager.api_key_signing_secret_requires_reencrypt(row)` /
   `BaseUserManager.reencrypt_api_key_signing_secret(row_or_key_id)` for one API-key signing row.
4. Verify that a fresh scan finds no stored values requiring re-encryption. Treat unknown key ids,
   malformed values, or decryption failures as migration errors; do not skip them silently.
5. Remove retired key ids only after all app instances run the new config and the verification scan
   is clean. Keeping retired keys indefinitely is not a rotation strategy.

Legacy unversioned Fernet rows such as `fernet:<ciphertext>` do not carry a key id and are not the
normal runtime compatibility path. If you have them from an older release, migrate them with known
knowledge of the old key material and rewrite them to `fernet:v1:<key_id>:<ciphertext>` before relying
on the versioned keyring. Plaintext persisted TOTP secrets are still unsupported; clear those rows or
encrypt them before production rollout.

### API-key signing-secret rotation runbook

API-key request signing is the exception to the bearer-key digest-only model. Signing-required keys
need the raw secret for HMAC verification, so the server stores an encrypted copy in
`api_key.encrypted_secret` using `api_keys.secret_encryption_keyring`. That storage is reversible by
design. Bearer API keys have only `hashed_secret`, cannot be converted to signing mode, and should be
replaced with newly issued signing-required keys if a client needs request signing.

For no-downtime rotation:

1. Deploy a keyring that includes both the retired id and the new id, while the old id is still
   active. Confirm every application instance can read existing signing rows.
2. Deploy the same key map with `active_key_id` set to the new id. New signing-required API keys
   write `fernet:v1:<new_key_id>:...` envelopes.
3. Run an operator-owned job that scans signing-required rows with non-null `encrypted_secret`,
   checks each row with `BaseUserManager.api_key_signing_secret_requires_reencrypt(row)`, and calls
   `await BaseUserManager.reencrypt_api_key_signing_secret(row_or_key_id)` for rows that still use a
   non-active key id.
4. Run the scan again and require a zero-candidate result before removing the retired key id from
   `api_keys.secret_encryption_keyring`.

The SQLAlchemy store exposes `list_signing_keys_requiring_reencrypt(...)` for candidate discovery,
and custom stores should provide the same row-level behavior. Keep batching, locking, retries, and
operator audit logs in application-owned migration tooling; the library does not own a
global sweep or built-in audit-log table.

```python
async def rotate_api_key_signing_secrets(manager: BaseUserManager, api_key_store: BaseApiKeyStore) -> int:
    rows = await api_key_store.list_signing_keys_requiring_reencrypt(
        manager.api_key_signing_secret_requires_reencrypt,
    )
    for row in rows:
        await manager.reencrypt_api_key_signing_secret(row)
    return len(rows)
```

Do not log raw API keys, `encrypted_secret` ciphertexts, decrypted signing secrets, or exception
payloads from failed rotation. Unknown key ids, malformed envelopes, rows missing `encrypted_secret`,
or bearer rows passed to the helper are fail-closed conditions that need data cleanup before
old Fernet key ids are removed.

## Redis (recommended for scaled deployments)

Use Redis-backed components when you run multiple workers or need durability:

- **JWT denylist** — `RedisJWTDenylistStore` instead of in-memory.
- **Shared auth surface** — use `litestar_auth.contrib.redis.RedisAuthPreset` when one async Redis
  client should back auth rate limiting plus the TOTP stores. The maintained production recipe lives
  in [Configuration](configuration/redis.md#redis-backed-auth-surface); it wires
  `build_rate_limit_config()`, `build_totp_enrollment_store()`, `build_totp_pending_jti_store()`, and
  `build_totp_used_tokens_store()` from the public Redis contrib surface.
- **Distinct TOTP stores** — keep `totp_enrollment_store` for pending enrollment secrets,
  `totp_pending_jti_store` for pending-login JWT replay prevention, and `totp_used_tokens_store`
  for consumed-code replay prevention, even when all three are derived from the same Redis client.
- **Low-level direct builders** — keep `AuthRateLimitConfig.from_shared_backend(RedisRateLimiter(...))`
  plus direct `RedisTotpEnrollmentStore(...)` / `RedisJWTDenylistStore(...)` /
  `RedisUsedTotpCodeStore(...)` construction when you intentionally need separate backends or
  bespoke key prefixes.

Use [Configuration](configuration/redis.md#redis-backed-auth-surface) as the maintained source
for the `RedisAuthPreset` flow, the `AUTH_RATE_LIMIT_*` helper exports, namespace
families, migration recipe, fallback low-level builder/store APIs, and the
`litestar_auth.ratelimit` versus `litestar_auth.contrib.redis` import split. Deployment adds the
production requirement: those Redis-backed stores are the supported path once multiple workers or
restarts matter.

The in-memory rate limiter, in-memory denylist, and in-memory TOTP stores are **not** sufficient
across processes. With `deployment_worker_count=None`, the plugin may log startup warnings when
in-memory rate limiting or in-memory TOTP state is detected outside tests. With
`deployment_worker_count > 1`, process-local auth rate-limit endpoint backends fail closed at
startup because per-worker counters cannot enforce one shared budget.

## Rate limiting behavior

When `rate_limit_config` is set, throttled endpoints return **429** with **`Retry-After`**. Covered surfaces include login, register, forgot/reset password, change-password, refresh, verify / request-verify-token, and TOTP enable / confirm / verify / disable (see [Rate limiting guide](guides/rate_limiting.md)).

## OAuth

- Set **`oauth_token_encryption_keyring`** for any configured providers, or the one-key
  **`oauth_token_encryption_key`** for a single active key.
- Set **`oauth_flow_cookie_secret`** for any configured providers. This value is HKDF-derived into the Fernet key that protects the short-lived flow cookie containing OAuth state and the PKCE verifier; keep it high-entropy and distinct from every other auth secret.
- Plugin-owned OAuth startup fails closed unless **`oauth_redirect_base_url`** uses a public **`https://...`** origin. Plain HTTP and loopback hosts are only supported behind local/test overrides such as `AppConfig(debug=True)` or `unsafe_testing=True`.
- Manual/custom OAuth controllers require the same public **`https://...`** baseline for `redirect_base_url`, enforced at controller construction time with no localhost or plain-HTTP override.
- The `redirect_base_url` host is additionally validated against non-routable / SSRF-adjacent ranges (loopback, RFC 1918 private, RFC 3927 link-local including the `169.254.169.254` cloud metadata endpoint, multicast, reserved, unspecified); hostnames are DNS-resolved once at validation time and checked the same way. This gate **fails open** when DNS resolution is unavailable and does **not** defend against DNS rebinding (the address resolved at validation time may differ at runtime). Pair it with runtime **egress controls** on the OAuth callback path so a misconfigured or rebinding `redirect_base_url` cannot reach internal infrastructure.
- Set **`oauth_redirect_dns_strict=True`** on plugin or manual OAuth configuration when startup should fail closed for DNS resolver failures or empty/unusable resolver answers. Leave it unset to preserve the default fail-open behavior in offline or sandboxed startup environments.
- **`oauth_associate_by_email`**: keep `False` unless you understand identity linking risk. If `True` on the plugin-owned route table, pair it with **`oauth_trust_provider_email_verified=True`** only for providers that cryptographically assert email ownership. Manual OAuth controllers use the lower-level **`trust_provider_email_verified=True`** flag instead (see [OAuth guide](guides/oauth.md)).

## Cookies

- Keep **`oauth_cookie_secure=True`** (default) behind HTTPS.
- Terminate only HTTPS in production, set HSTS at the edge, and keep
  `CookieTransport.secure=True` for browser sessions.
- Serve TOTP enrollment (`POST /auth/2fa/enable` by default) only over HTTPS; that response includes
  the plaintext secret and otpauth URI needed to render the QR code.
- For local HTTP dev you may relax cookie `secure` flags on transports — never in production.
- Set `trusted_proxy=True` on rate-limit endpoints only when a trusted reverse
  proxy overwrites the configured forwarded headers. Otherwise, leave the
  default `False` so callers cannot spoof rate-limit keys.

## Observability

- Monitor **429** rates on auth endpoints (brute force / abuse).
- Monitor `REFRESH_SESSION_NOT_FOUND` rates on session/device revoke routes. Spikes can indicate
  stale clients, repeated foreign-session guesses, or UI bugs sending the wrong public `session_id`.
- Monitor `SESSION_MANAGEMENT_UNSUPPORTED` after configuration changes. It means session/device
  routes were enabled for a strategy that does not implement the DB refresh-session contract.
- Log authentication failures without storing secrets or raw tokens. Failed-login
  `identifier_digest` is emitted only when `login_identifier_telemetry_secret` is configured; it is
  keyed and non-reversible, but still belongs in your privacy notice if you use it for abuse
  correlation.
- Emails are normalized account identifiers. Built-in rate-limit keys use scoped PBKDF2-HMAC-SHA-256 digests for
  normalized identifiers before writing backend keys, but these digests are not a privacy boundary against
  brute-force guessing of common identifiers. Database encryption at rest and privacy disclosures remain
  application/operator responsibilities.
- Send reset/verify emails through a queue or background worker and perform
  equivalent work for existing and non-existing accounts. Synchronous SMTP/API
  differences in `on_after_forgot_password` or `on_after_request_verify_token`
  can reintroduce account enumeration at the application boundary.

## Testing vs production

- See the [testing guide](guides/testing.md) for the plugin-backed pytest recipe.
- `unsafe_testing=True` is a per-instance test-only override. Keep it out of local manual runs, staging, and production traffic.
- Request-scoped DB-session sharing is still per HTTP request in tests. Separate login, refresh, authenticated, and logout requests each get their own request-local session.
- Single-process testing conveniences such as in-memory JWT revocation, in-memory rate limiting, and relaxed TOTP store requirements do not become production-safe because `unsafe_testing` is enabled.

## Documentation builds

Published docs should match the released package version. Build with `just docs-build` before tagging releases.
