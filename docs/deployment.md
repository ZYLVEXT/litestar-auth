# Deployment checklist

Use this when moving from local development to production, especially for **secrets**, **multi-worker** deployments, and **shared stores** (Redis) where in-memory defaults are insufficient.

## Process topology

- **Single worker / dev** — in-memory JWT denylist, in-memory rate limiting, and in-memory TOTP replay cache are acceptable for local testing only.
- **Multiple workers or restarts that matter** — use **Redis** (or equivalent shared stores) for: JWT `jti` denylist, the auth rate-limit config, `totp_used_tokens_store`, and TOTP pending-token JTI store if you mount a custom controller with a shared store (see [TOTP guide](guides/totp.md)). `litestar_auth.contrib.redis.RedisAuthPreset` is the preferred one-client path for the rate-limit config plus replay store pair.

## Secrets and keys

- For the full manager/password contract, including `PasswordHelper` sharing,
  `password_validator_factory`, and the `UserEmailField` / `UserPasswordField`
  schema helpers, see
  [Configuration](configuration.md#canonical-manager-password-surface). The checklist below only
  calls out production consequences.
- For plugin-managed apps, configure manager-scoped secrets via
  `LitestarAuthConfig.user_manager_security`.
- **JWT signing secret** (or private key) — high entropy; rotation plan.
- **`verification_token_secret`** and **`reset_password_token_secret`** — configure both through
  `user_manager_security`; each must satisfy the production minimum enforced by
  `validate_secret_length` (32+ characters by default).
- **`totp_secret_key`** — configure through `user_manager_security` when TOTP is enabled; required in
  production because stored TOTP secrets must be encrypted at rest.
- **`csrf_secret`** — required for meaningful CSRF protection when using cookie-based auth with the plugin’s CSRF wiring.
- **`totp_pending_secret`** — required when TOTP is enabled; protects pending login payloads.
- **`oauth_token_encryption_key`** — required when OAuth providers are configured (encrypts tokens at rest in the DB).
- **`token_hash_secret`** (database opaque token strategy) — protects digest-at-rest storage for DB tokens.
- Keep **`verification_token_secret`**, **`reset_password_token_secret`**,
  **`totp_pending_secret`**, and **`totp_secret_key`** distinct. Current releases warn on reuse in
  production to preserve compatibility. For plugin-managed apps the warning is emitted once during
  `LitestarAuth(config)` validation; direct `BaseUserManager(...)` construction keeps its own
  manager-scoped warning path. Distinct values are still the supported posture:
  `litestar-auth:verify`, `litestar-auth:reset-password`, and
  `litestar-auth:2fa-pending` / `litestar-auth:2fa-enroll` already separate JWT audiences, while
  `totp_secret_key` should remain a dedicated encryption key with no JWT audience.

## Redis (recommended for scaled deployments)

Use Redis-backed components when you run multiple workers or need durability:

- **JWT denylist** — `RedisJWTDenylistStore` instead of in-memory.
- **Shared auth surface** — use `litestar_auth.contrib.redis.RedisAuthPreset` when one async Redis
  client should back both auth rate limiting and `totp_config.totp_used_tokens_store`. For strict
  typing, that shared client only needs the combined `RedisRateLimiter` +
  `RedisUsedTotpCodeStore` operations: `eval(...)`, `delete(...)`, and
  `set(name, value, nx=True, px=ttl_ms)`.
- **Low-level escape hatches** — keep `AuthRateLimitConfig.from_shared_backend(RedisRateLimiter(...))`
  and direct `RedisUsedTotpCodeStore(...)` construction when you need separate backends or bespoke
  key prefixes.

Use [Configuration](configuration.md#canonical-redis-backed-auth-surface) as the maintained source
for the preferred `RedisAuthPreset` flow, the `AUTH_RATE_LIMIT_*` helper exports,
`namespace_style`, the migration recipe, the fallback low-level builder/store APIs, and the
`litestar_auth.ratelimit` versus `litestar_auth.contrib.redis` import split.
Deployment adds the production requirement: those Redis-backed stores are the supported path once
multiple workers or restarts matter.

The in-memory rate limiter and in-memory denylist are **not** sufficient across processes. The plugin may log startup warnings when in-memory rate limiting is detected outside tests.

## Rate limiting behavior

When `rate_limit_config` is set, throttled endpoints return **429** with **`Retry-After`**. Covered surfaces include login, register, forgot/reset password, refresh, verify / request-verify-token, and TOTP enable / confirm / verify / disable (see [Rate limiting guide](guides/rate_limiting.md)).

## OAuth

- Set **`oauth_token_encryption_key`** for any configured providers.
- Use **`https`** redirect URIs in production; review startup warnings for insecure redirect bases.
- **`oauth_associate_by_email`**: keep `False` unless you understand identity linking risk. If `True` on the plugin-owned route table, pair it with **`oauth_trust_provider_email_verified=True`** only for providers that cryptographically assert email ownership. Manual OAuth controllers use the lower-level **`trust_provider_email_verified=True`** flag instead (see [OAuth guide](guides/oauth.md)).

## Cookies

- Keep **`oauth_cookie_secure=True`** (default) behind HTTPS.
- For local HTTP dev you may relax cookie `secure` flags on transports — never in production.

## Observability

- Monitor **429** rates on auth endpoints (brute force / abuse).
- Log authentication failures without storing secrets or raw tokens.

## Testing vs production

- See the [testing guide](guides/testing.md) for the canonical plugin-backed pytest recipe.
- `unsafe_testing=True` is a per-instance test-only escape hatch. Keep it out of local manual runs, staging, and production traffic.
- Request-scoped DB-session sharing is still per HTTP request in tests. Separate login, refresh, authenticated, and logout requests each get their own request-local session.
- Single-process testing conveniences such as in-memory JWT revocation, in-memory rate limiting, and relaxed TOTP store requirements do not become production-safe because `unsafe_testing` is enabled.

## Documentation builds

Published docs should match the released package version. Build with `just docs-build` before tagging releases.
