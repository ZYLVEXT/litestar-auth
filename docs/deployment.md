# Deployment checklist

Use this when moving from local development to production, especially for **secrets**, **multi-worker** deployments, and **shared stores** (Redis) where in-memory defaults are insufficient.

## Process topology

- **Single worker / dev** — in-memory JWT denylist, in-memory rate limiting, and in-memory TOTP stores are acceptable for local testing only.
- **Multiple workers or restarts that matter** — use **Redis** (or equivalent shared stores) for: JWT `jti` denylist, the auth rate-limit config, `totp_enrollment_store`, `totp_pending_jti_store`, and `totp_used_tokens_store`. When one async Redis client should back auth rate limiting plus the TOTP stores, use `litestar_auth.contrib.redis.RedisAuthPreset` as the shared-client path and keep the three TOTP stores conceptually separate: pending-enrollment secrets, pending-token JTI deduplication, and used-code replay protection.

## Secrets and keys

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
- **`totp_secret_key`** — configure through `user_manager_security` when TOTP is enabled; required in
  production because stored TOTP secrets and pending-enrollment secrets must be encrypted at rest.
  Existing plaintext persisted TOTP secrets must be encrypted, rotated, or cleared before upgrading
  to versions that enforce encrypted-only TOTP secret storage.
- **`csrf_secret`** — required for meaningful CSRF protection when using cookie-based auth with the plugin’s CSRF wiring.
- **`totp_pending_secret`** — required when TOTP is enabled; protects pending login payloads.
- **`oauth_token_encryption_key`** — required when OAuth providers are configured (encrypts tokens at rest in the DB).
- **`token_hash_secret`** (database opaque token strategy) — protects digest-at-rest storage for DB tokens.
- Keep **`verification_token_secret`**, **`reset_password_token_secret`**,
  **`totp_pending_secret`**, and **`totp_secret_key`** distinct. Production configuration now
  rejects reuse with `ConfigurationError`; only explicit `unsafe_testing=True` test setups bypass
  this validation. For plugin-managed apps the error is raised during `LitestarAuth(config)`
  validation; direct `BaseUserManager(...)` construction enforces the same rule for its
  manager-owned secret roles. Distinct values are the supported posture:
  `litestar-auth:verify`, `litestar-auth:reset-password`, and
  `litestar-auth:2fa-pending` / `litestar-auth:2fa-enroll` already separate JWT audiences, while
  `totp_secret_key` should remain a dedicated encryption key with no JWT audience.

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

The in-memory rate limiter, in-memory denylist, and in-memory TOTP stores are **not** sufficient across processes. The plugin may log startup warnings when in-memory rate limiting or in-memory TOTP state is detected outside tests.

## Rate limiting behavior

When `rate_limit_config` is set, throttled endpoints return **429** with **`Retry-After`**. Covered surfaces include login, register, forgot/reset password, refresh, verify / request-verify-token, and TOTP enable / confirm / verify / disable (see [Rate limiting guide](guides/rate_limiting.md)).

## OAuth

- Set **`oauth_token_encryption_key`** for any configured providers.
- Plugin-owned OAuth startup now fails closed unless **`oauth_redirect_base_url`** uses a public **`https://...`** origin. Plain HTTP and loopback hosts are only supported behind explicit local/test overrides such as `AppConfig(debug=True)` or `unsafe_testing=True`.
- Manual/custom OAuth controllers now use the same public **`https://...`** baseline for `redirect_base_url`, but they enforce it at controller construction time with no localhost or plain-HTTP override.
- **`oauth_associate_by_email`**: keep `False` unless you understand identity linking risk. If `True` on the plugin-owned route table, pair it with **`oauth_trust_provider_email_verified=True`** only for providers that cryptographically assert email ownership. Manual OAuth controllers use the lower-level **`trust_provider_email_verified=True`** flag instead (see [OAuth guide](guides/oauth.md)).

## Cookies

- Keep **`oauth_cookie_secure=True`** (default) behind HTTPS.
- For local HTTP dev you may relax cookie `secure` flags on transports — never in production.

## Observability

- Monitor **429** rates on auth endpoints (brute force / abuse).
- Log authentication failures without storing secrets or raw tokens.

## Testing vs production

- See the [testing guide](guides/testing.md) for the plugin-backed pytest recipe.
- `unsafe_testing=True` is a per-instance test-only override. Keep it out of local manual runs, staging, and production traffic.
- Request-scoped DB-session sharing is still per HTTP request in tests. Separate login, refresh, authenticated, and logout requests each get their own request-local session.
- Single-process testing conveniences such as in-memory JWT revocation, in-memory rate limiting, and relaxed TOTP store requirements do not become production-safe because `unsafe_testing` is enabled.

## Documentation builds

Published docs should match the released package version. Build with `just docs-build` before tagging releases.
