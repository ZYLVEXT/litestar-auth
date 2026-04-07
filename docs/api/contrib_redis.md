# Redis contrib

Use [Configuration](../configuration.md#canonical-redis-backed-auth-surface) for the canonical
Redis-backed auth story: the preferred one-client preset flow, the `AUTH_RATE_LIMIT_*` helper
exports, namespace families, migration behavior, and TOTP replay-store guidance still live there.

`litestar_auth.contrib.redis` is the higher-level entrypoint when one async Redis client should back
both auth rate limiting and TOTP replay protection:

- `RedisAuthPreset` builds `AuthRateLimitConfig` plus `RedisUsedTotpCodeStore` from one shared
  client and per-group rate-limit tiers. Import slot helpers such as
  `AUTH_RATE_LIMIT_VERIFICATION_SLOTS` from `litestar_auth.ratelimit` when calling
  `build_rate_limit_config(...)`. The shared client only needs the combined
  `RedisRateLimiter` + `RedisUsedTotpCodeStore` operations:
  `eval(...)`, `delete(...)`, and `set(name, value, nx=True, px=ttl_ms)`.
- `RedisTokenStrategy` and `RedisUsedTotpCodeStore` remain the direct low-level convenience imports.
- `AuthRateLimitConfig.from_shared_backend()` and direct `RedisRateLimiter(...)` construction remain
  the fallback escape hatches for applications that need separate backends or fully bespoke wiring.

Optional Redis-backed helpers (requires `litestar-auth[redis]`).

::: litestar_auth.contrib.redis
