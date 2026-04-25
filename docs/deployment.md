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
  encryption keys, OAuth flow-cookie secrets, and opaque-token hash secrets
  before the first production incident.
- For the full manager/password contract, including `PasswordHelper` sharing,
  `password_validator_factory`, and the `UserEmailField` / `UserPasswordField`
  schema helpers, see
  [Configuration](configuration.md#manager-password-surface). The checklist below only
  calls out production consequences.
- For plugin-managed apps, configure manager-scoped secrets via
  `LitestarAuthConfig.user_manager_security`.
- **JWT signing secret** (or private key) — high entropy; rotation plan.
- **`verification_token_secret`** and **`reset_password_token_secret`** — configure both through
  `user_manager_security`; each must satisfy the production minimum enforced by
  `validate_secret_length` (32+ characters by default).
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
- **`oauth_flow_cookie_secret`** — required when OAuth providers are configured (encrypts and authenticates transient OAuth `state` plus PKCE verifier material in the browser-held flow cookie).
- **`token_hash_secret`** (database opaque token strategy) — protects digest-at-rest storage for DB tokens.
- Keep **`verification_token_secret`**, **`reset_password_token_secret`**,
  **`login_identifier_telemetry_secret`** when configured, **`totp_pending_secret`**, every
  configured TOTP Fernet key, and **`oauth_flow_cookie_secret`** distinct. Production configuration now
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
production. Rotation is intentionally role-specific: verification/reset/TOTP pending JWT secret
rotation invalidates outstanding tokens for that flow, OAuth flow-cookie rotation invalidates
in-progress OAuth handshakes, CSRF secret rotation affects active browser sessions, and login
telemetry rotation starts a new digest correlation window. Keep token lifetimes short enough that
planned rotation can happen without a long dual-secret compatibility period.

## Versioned Fernet key rotation

Persisted OAuth provider tokens and TOTP secrets use the same versioned Fernet-at-rest envelope:
`fernet:v1:<key_id>:<ciphertext>`. The `key_id` is not secret; it tells the library which configured
Fernet key decrypts the value. Do not log or publish the ciphertext portion.

Generate a Fernet key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Configure production keyrings with explicit ids instead of treating one unversioned key as the
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
   now store `fernet:v1:<new_key_id>:...`; old rows remain readable because the old key id is still
   configured.
3. Run an application-owned migration job over stored OAuth `access_token` / `refresh_token` columns
   and stored TOTP secret columns. The library exposes row-level helpers, not an automatic database
   sweep: call `OAuthTokenEncryption.requires_reencrypt(value)` / `OAuthTokenEncryption.reencrypt(value)`
   for OAuth token values, and `BaseUserManager.totp_secret_requires_reencrypt(value)` /
   `BaseUserManager.reencrypt_totp_secret_for_storage(value)` for TOTP values.
4. Verify that a fresh scan finds no stored values requiring re-encryption. Treat unknown key ids,
   malformed values, or decryption failures as migration errors; do not skip them silently.
5. Remove retired key ids only after all app instances run the new config and the verification scan
   is clean. Keeping retired keys indefinitely is not a rotation strategy.

Legacy unversioned Fernet rows such as `fernet:<ciphertext>` do not carry a key id and are not the
normal runtime compatibility path. If you have them from an older release, migrate them with explicit
knowledge of the old key material and rewrite them to `fernet:v1:<key_id>:<ciphertext>` before relying
on the versioned keyring. Plaintext persisted TOTP secrets are still unsupported; clear those rows or
encrypt them before production rollout.

## Redis (recommended for scaled deployments)

Use Redis-backed components when you run multiple workers or need durability:

- **JWT denylist** — `RedisJWTDenylistStore` instead of in-memory.
- **Shared auth surface** — use `litestar_auth.contrib.redis.RedisAuthPreset` when one async Redis
  client should back auth rate limiting plus the TOTP stores. The maintained production recipe lives
  in [Configuration](configuration.md#redis-backed-auth-surface); it wires
  `build_rate_limit_config()`, `build_totp_enrollment_store()`, `build_totp_pending_jti_store()`, and
  `build_totp_used_tokens_store()` from the public Redis contrib surface.
- **Distinct TOTP stores** — keep `totp_enrollment_store` for pending enrollment secrets,
  `totp_pending_jti_store` for pending-login JWT replay prevention, and `totp_used_tokens_store`
  for consumed-code replay prevention, even when all three are derived from the same Redis client.
- **Low-level direct builders** — keep `AuthRateLimitConfig.from_shared_backend(RedisRateLimiter(...))`
  plus direct `RedisTotpEnrollmentStore(...)` / `RedisJWTDenylistStore(...)` /
  `RedisUsedTotpCodeStore(...)` construction when you intentionally need separate backends or
  bespoke key prefixes.

Use [Configuration](configuration.md#redis-backed-auth-surface) as the maintained source
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
- Set **`oauth_flow_cookie_secret`** for any configured providers. This value protects the short-lived flow cookie containing OAuth state and the PKCE verifier; keep it high-entropy and distinct from every other auth secret.
- Plugin-owned OAuth startup now fails closed unless **`oauth_redirect_base_url`** uses a public **`https://...`** origin. Plain HTTP and loopback hosts are only supported behind explicit local/test overrides such as `AppConfig(debug=True)` or `unsafe_testing=True`.
- Manual/custom OAuth controllers now use the same public **`https://...`** baseline for `redirect_base_url`, but they enforce it at controller construction time with no localhost or plain-HTTP override.
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
- Log authentication failures without storing secrets or raw tokens. Failed-login
  `identifier_digest` is emitted only when `login_identifier_telemetry_secret` is configured; it is
  keyed and non-reversible, but still belongs in your privacy notice if you use it for abuse
  correlation.
- Emails are normalized account identifiers. Built-in rate-limit keys hash normalized identifiers
  before writing backend keys, but database encryption at rest and privacy disclosures remain
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
