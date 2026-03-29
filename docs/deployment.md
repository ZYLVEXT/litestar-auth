# Deployment checklist

Use this when moving from local development to production, especially for **secrets**, **multi-worker** deployments, and **shared stores** (Redis) where in-memory defaults are insufficient.

## Process topology

- **Single worker / dev** — in-memory JWT denylist, in-memory rate limiting, and in-memory TOTP replay cache are acceptable for local testing only.
- **Multiple workers or restarts that matter** — use **Redis** (or equivalent shared stores) for: JWT `jti` denylist, `AuthRateLimitConfig` backend, `totp_used_tokens_store`, and TOTP pending-token JTI store if you mount a custom controller with a shared store (see [TOTP guide](guides/totp.md)).

## Secrets and keys

- **JWT signing secret** (or private key) — high entropy; rotation plan.
- **`verification_token_secret`** and **`reset_password_token_secret`** — at least the minimum length enforced by `validate_secret_length` (32+ characters by default).
- **`csrf_secret`** — required for meaningful CSRF protection when using cookie-based auth with the plugin’s CSRF wiring.
- **`totp_pending_secret`** — required when TOTP is enabled; protects pending login payloads.
- **`oauth_token_encryption_key`** — required when OAuth providers are configured (encrypts tokens at rest in the DB).
- **`token_hash_secret`** (database opaque token strategy) — protects digest-at-rest storage for DB tokens.

## Redis (recommended for scaled deployments)

Use Redis-backed components when you run multiple workers or need durability:

- **JWT denylist** — `RedisJWTDenylistStore` instead of in-memory.
- **Rate limiting** — `RedisRateLimiter` via `AuthRateLimitConfig` (see [Rate limiting](api/ratelimit.md)).
- **TOTP replay store** — `RedisUsedTotpCodeStore` for `totp_config.totp_used_tokens_store`.

The in-memory rate limiter and in-memory denylist are **not** sufficient across processes. The plugin may log startup warnings when in-memory rate limiting is detected outside tests.

## Rate limiting behavior

When `rate_limit_config` is set, throttled endpoints return **429** with **`Retry-After`**. Covered surfaces include login, register, forgot/reset password, refresh, verify / request-verify-token, and TOTP enable / confirm / verify / disable (see [Rate limiting guide](guides/rate_limiting.md)).

## OAuth

- Set **`oauth_token_encryption_key`** for any configured providers.
- Use **`https`** redirect URIs in production; review startup warnings for insecure redirect bases.
- **`oauth_associate_by_email`**: keep `False` unless you understand identity linking risk. If `True`, you must use **`trust_provider_email_verified=True`** only with providers that cryptographically assert email ownership (see [OAuth guide](guides/oauth.md)).

## Cookies

- Keep **`oauth_cookie_secure=True`** (default) behind HTTPS.
- For local HTTP dev you may relax cookie `secure` flags on transports — never in production.

## Observability

- Monitor **429** rates on auth endpoints (brute force / abuse).
- Log authentication failures without storing secrets or raw tokens.

## Testing vs production

- `LITESTAR_AUTH_TESTING=1` is **only** for automated tests; the library rejects non-pytest use at startup.

## Documentation builds

Published docs should match the released package version. Build with `just docs-build` before tagging releases.
