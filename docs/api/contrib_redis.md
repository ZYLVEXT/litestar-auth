# Redis contrib

Use [Configuration](../configuration.md#canonical-redis-backed-auth-surface) for the canonical
Redis-backed auth story: the preferred one-client preset flow, the `AUTH_RATE_LIMIT_*` helper
exports, namespace families, migration behavior, and TOTP store guidance still live there.

`litestar_auth.contrib.redis` is the higher-level entrypoint when one async Redis client should back
auth rate limiting plus both TOTP Redis stores:

- `RedisAuthClientProtocol` is the stable typing contract for annotating the shared async Redis
  client passed to `RedisAuthPreset`.
- `RedisAuthPreset` builds `AuthRateLimitConfig`, `RedisUsedTotpCodeStore`, and the pending-token
  `RedisJWTDenylistStore` helper from one shared client and per-group rate-limit tiers. Import slot helpers such as
  `AUTH_RATE_LIMIT_VERIFICATION_SLOTS` from `litestar_auth.ratelimit` when calling
  `build_rate_limit_config(...)`. The shared-client contract covers the combined operations used by
  the rate-limiter, used-code replay, and pending-JTI denylist helpers: `eval(...)`, `delete(...)`,
  `set(name, value, nx=True, px=ttl_ms)`, `get(...)`, and `setex(...)`.
- `RedisTokenStrategy` and `RedisUsedTotpCodeStore` remain the direct low-level convenience imports.
- `AuthRateLimitConfig.from_shared_backend()`, direct `RedisRateLimiter(...)` construction, and
  direct `RedisJWTDenylistStore(...)` / `RedisUsedTotpCodeStore(...)` construction remain the
  fallback escape hatches for applications that need separate backends or fully bespoke wiring.

Optional Redis-backed helpers (requires `litestar-auth[redis]`).

::: litestar_auth.contrib.redis
