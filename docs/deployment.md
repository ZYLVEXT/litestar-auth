# Deployment checklist

Use this when moving from local development to production, especially for **secrets**, **multi-worker** deployments, and **shared stores** (Redis) where in-memory defaults are insufficient.

## Process topology

- **Single worker / dev** — in-memory JWT denylist, in-memory rate limiting, and in-memory TOTP replay cache are acceptable for local testing only.
- **Multiple workers or restarts that matter** — use **Redis** (or equivalent shared stores) for: JWT `jti` denylist, the `AuthRateLimitConfig.from_shared_backend()` backend, `totp_used_tokens_store`, and TOTP pending-token JTI store if you mount a custom controller with a shared store (see [TOTP guide](guides/totp.md)).

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
- **Rate limiting** — prefer one `RedisRateLimiter` passed to `AuthRateLimitConfig.from_shared_backend(...)` so all standard auth endpoints share Redis-backed counters with the documented stable slot names, group names, scopes, and namespace tokens (see [Rate limiting](guides/rate_limiting.md)).
- **TOTP replay store** — `RedisUsedTotpCodeStore` for `totp_config.totp_used_tokens_store`.

Canonical shared-backend recipe:

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, RedisRateLimiter

rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60),
)
```

`from_shared_backend()` uses these stable builder identifiers:

- Slots: `login`, `refresh`, `register`, `forgot_password`, `reset_password`, `totp_enable`, `totp_confirm_enable`, `totp_verify`, `totp_disable`, `verify_token`, `request_verify_token`
- `group_backends` groups: `login`, `refresh`, `register`, `password_reset`, `totp`, `verification`
- Default `ip_email` scopes: `login`, `forgot_password`, `request_verify_token`
- Default `ip` scopes: every other supported slot

Default namespace tokens are `login`, `refresh`, `register`, `forgot-password`, `reset-password`, `totp-enable`, `totp-confirm-enable`, `totp-verify`, `totp-disable`, `verify-token`, and `request-verify-token`.

If you are migrating from an older manual recipe, keep existing key-space choices with `namespace_overrides` and `scope_overrides`, and use `disabled` for slots such as `verify_token` or `request_verify_token` when your deployed surface does not expose them.

Example migration pattern for a Redis deployment with separate credential, refresh, and TOTP budgets:

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, RedisRateLimiter

credential_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60)
refresh_backend = RedisRateLimiter(redis=redis_client, max_attempts=10, window_seconds=300)
totp_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=300)

rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    credential_backend,
    group_backends={"refresh": refresh_backend, "totp": totp_backend},
    disabled={"verify_token", "request_verify_token"},
    namespace_overrides={
        "forgot_password": "forgot_password",
        "reset_password": "reset_password",
        "totp_enable": "totp_enable",
        "totp_confirm_enable": "totp_confirm_enable",
        "totp_verify": "totp_verify",
        "totp_disable": "totp_disable",
    },
)
```

This keeps the credential-oriented slots on `credential_backend`, moves `refresh` and `totp_*` to their own backends, preserves the legacy underscore namespaces, and leaves the verification slots unset. Reserve direct `EndpointRateLimit(...)` assembly for advanced per-endpoint exceptions, or `endpoint_overrides` when a single slot needs a custom limiter while staying inside the shared-builder contract.

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

- See the [testing guide](guides/testing.md) for the canonical plugin-backed pytest recipe.
- `LITESTAR_AUTH_TESTING=1` is **only** for automated tests; the library rejects non-pytest use at startup.
- Request-scoped DB-session sharing is still per HTTP request in tests. Separate login, refresh, authenticated, and logout requests each get their own request-local session.
- Single-process testing conveniences such as in-memory JWT revocation, in-memory rate limiting, and relaxed TOTP store requirements do not become production-safe because testing mode is enabled.

## Documentation builds

Published docs should match the released package version. Build with `just docs-build` before tagging releases.
