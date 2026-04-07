# Rate limiting

Optional **per-endpoint** limits protect login, registration, token flows, and TOTP surfaces from
brute force and abuse. Configure **`AuthRateLimitConfig`** on
**`LitestarAuthConfig.rate_limit_config`**. For the current Redis-backed contract, including the
stable slot and group inventory, migration recipe, and `RedisUsedTotpCodeStore` pairing, use
[Configuration](../configuration.md#canonical-redis-backed-auth-surface) as the maintained source
of truth. This guide focuses on how the rate-limit surface maps onto the HTTP routes you expose.

## Canonical shared-backend setup

```python
from litestar_auth import TotpConfig
from litestar_auth.contrib.redis import RedisAuthPreset, RedisAuthRateLimitTier
from litestar_auth.ratelimit import AUTH_RATE_LIMIT_VERIFICATION_SLOTS

redis_auth = RedisAuthPreset(
    redis=redis_client,
    rate_limit_tier=RedisAuthRateLimitTier(max_attempts=5, window_seconds=60),
    group_rate_limit_tiers={
        "refresh": RedisAuthRateLimitTier(max_attempts=10, window_seconds=300),
        "totp": RedisAuthRateLimitTier(max_attempts=5, window_seconds=300),
    },
)
rate_limit_config = redis_auth.build_rate_limit_config(
    disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    namespace_style="snake_case",
)
totp_config = TotpConfig(
    totp_pending_secret="replace-with-32+-char-secret",
    totp_used_tokens_store=redis_auth.build_totp_used_tokens_store(),
)
```

`RedisAuthPreset` is the preferred one-client Redis path when auth rate limiting and the TOTP
replay store should share the same async Redis client. Keep
`AuthRateLimitConfig.from_shared_backend()` plus direct `RedisRateLimiter(...)` /
`RedisUsedTotpCodeStore(...)` construction as the advanced escape hatch for applications that need
separate backends or deeper per-slot customization. For the exact slot names, groups, default
scopes, namespace families, helper exports, override precedence, and migration recipe, follow
[Configuration](../configuration.md#canonical-redis-backed-auth-surface).

`enabled` and `disabled` remain the underlying builder inputs. When app code needs the supported
slot inventory directly, import `AUTH_RATE_LIMIT_ENDPOINT_SLOTS`,
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP`, or `AUTH_RATE_LIMIT_VERIFICATION_SLOTS` from
`litestar_auth.ratelimit` instead of repeating literal frozensets. Use
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS` for explicit `enabled=...` calls, and use either
`AUTH_RATE_LIMIT_VERIFICATION_SLOTS` or
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"]` for `disabled=...` when the built-in
verification routes stay off.

## Behavior

- When a limit is exceeded, clients receive **429 Too Many Requests** with **`Retry-After`**.
- Backends: **`InMemoryRateLimiter`** (single process / dev) or **`RedisRateLimiter`** (production, multiple workers). See [Deployment](../deployment.md).
- For pytest-driven plugin tests, `InMemoryRateLimiter` is the canonical single-process choice described in the [testing guide](testing.md). Keep limiter state isolated per test when counters must not leak.

## Config fields → HTTP surface

Each field accepts an **`EndpointRateLimit`** (or `None` to disable that bucket). Map them to routes you expose:

`AUTH_RATE_LIMIT_ENDPOINT_SLOTS` exposes this same ordered slot inventory, and
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"]` is the group-level equivalent of
`AUTH_RATE_LIMIT_VERIFICATION_SLOTS`.

| `AuthRateLimitConfig` field / `AuthRateLimitEndpointSlot` value | `AuthRateLimitEndpointGroup` value | Default scope | Default namespace token | Typical route / action |
| -------------------------------------------------------------- | ---------------------------------- | ------------- | ----------------------- | ---------------------- |
| `login` | `login` | `ip_email` | `login` | `POST {auth}/login` |
| `refresh` | `refresh` | `ip` | `refresh` | `POST {auth}/refresh` |
| `register` | `register` | `ip` | `register` | `POST {auth}/register` |
| `forgot_password` | `password_reset` | `ip_email` | `forgot-password` | `POST {auth}/forgot-password` |
| `reset_password` | `password_reset` | `ip` | `reset-password` | `POST {auth}/reset-password` |
| `verify_token` | `verification` | `ip` | `verify-token` | `POST {auth}/verify` |
| `request_verify_token` | `verification` | `ip_email` | `request-verify-token` | `POST {auth}/request-verify-token` |
| `totp_enable` | `totp` | `ip` | `totp-enable` | `POST {auth}/2fa/enable` |
| `totp_confirm_enable` | `totp` | `ip` | `totp-confirm-enable` | `POST {auth}/2fa/enable/confirm` |
| `totp_verify` | `totp` | `ip` | `totp-verify` | `POST {auth}/2fa/verify` |
| `totp_disable` | `totp` | `ip` | `totp-disable` | `POST {auth}/2fa/disable` |

The plugin turns these `totp_*` limiters into an internal orchestrator so **`totp_verify`** can reset counters on success or account-state failures while other TOTP routes keep independent budgets (see `TotpRateLimitOrchestrator` in `litestar_auth.ratelimit`).

!!! note "Reset password counter"
    For **`reset_password`**, failed attempts (invalid token or password) can still consume budget; success may reset the window — see implementation notes in `litestar_auth.ratelimit`.

## Migration from existing Redis key shapes

If an older app already depends on separate credential, refresh, and TOTP budgets or underscore
namespaces, follow the migration recipe in
[Configuration](../configuration.md#canonical-redis-backed-auth-surface). Start with
`namespace_style="snake_case"` when your deployed keys already use slot-aligned underscore names,
keep `namespace_overrides` only for bespoke exceptions, use
`AUTH_RATE_LIMIT_VERIFICATION_SLOTS` when the built-in verification routes stay disabled, and
reserve `scope_overrides`, `group_backends`, or `endpoint_overrides` for cases where the preset or
shared builder still does not match the existing key shape.

## Advanced manual wiring

Keep direct `AuthRateLimitConfig(..., EndpointRateLimit(...))` construction for exceptional cases where specific endpoints need materially different wiring than the shared-backend builder can express.

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit

rate_limit_config = AuthRateLimitConfig(
    login=EndpointRateLimit(backend=login_backend, scope="ip_email", namespace="login"),
    totp_verify=EndpointRateLimit(backend=totp_backend, scope="ip", namespace="totp-verify"),
)
```

## Further reading

- [Python API — Rate limiting](../api/ratelimit.md) — mkdocstrings for the public rate-limit entrypoints and advanced types.
- [Security guide](security.md) — when to prefer Redis.
- [Configuration](../configuration.md#canonical-redis-backed-auth-surface) — canonical Redis-backed
  auth contract, migration recipe, and replay-store guidance.
