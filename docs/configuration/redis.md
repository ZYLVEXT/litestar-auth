# Redis

Use this page for Redis-backed auth helpers, shared rate-limit wiring, TOTP enrollment state, replay stores, pending-token deduplication, and Redis import boundaries.

## Redis-backed auth surface

This section is the Redis integration guide for the currently implemented auth surface.
Use it for the shared-backend rate-limit contract, migration of existing Redis key shapes, TOTP
pending-enrollment state, replay protection, pending-login-token JTI deduplication, and the stable split between
`litestar_auth.ratelimit` and `litestar_auth.contrib.redis`.

### Shared-backend rate limiting

For the usual Redis deployment where one async Redis client should back auth rate limiting, TOTP
pending enrollment, replay protection, and pending-login-token JTI deduplication, start with
`litestar_auth.contrib.redis.RedisAuthPreset` plus explicit verification slots from
`litestar_auth.ratelimit.AuthRateLimitSlot`:

For strict typing, annotate the shared client with
`litestar_auth.contrib.redis.RedisAuthClientProtocol`. The shared-client recipe assumes a
`redis.asyncio.Redis`-compatible runtime client. The shared protocol covers the combined operations
used by the preset's rate-limiter, pending-enrollment, used-code replay, and pending-token denylist helpers:
`eval(...)`, `delete(...)`, `set(name, value, nx=True, px=ttl_ms)`, `get(...)`, and `setex(...)`.

```python
from litestar_auth import TotpConfig
from litestar_auth.contrib.redis import (
    RedisAuthClientProtocol,
    RedisAuthPreset,
    RedisAuthRateLimitTier,
)
from litestar_auth.ratelimit import AuthRateLimitSlot

redis_client: RedisAuthClientProtocol
redis_auth = RedisAuthPreset(
    redis=redis_client,
    rate_limit_tier=RedisAuthRateLimitTier(max_attempts=5, window_seconds=60),
    group_rate_limit_tiers={
        "refresh": RedisAuthRateLimitTier(max_attempts=10, window_seconds=300),
        "totp": RedisAuthRateLimitTier(max_attempts=5, window_seconds=300),
    },
)
rate_limit_config = redis_auth.build_rate_limit_config(
    disabled={AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN},
)
totp_config = TotpConfig(
    totp_pending_secret="replace-with-32+-char-secret",
    totp_enrollment_store=redis_auth.build_totp_enrollment_store(),
    totp_pending_jti_store=redis_auth.build_totp_pending_jti_store(),
    totp_used_tokens_store=redis_auth.build_totp_used_tokens_store(),
)
```

`RedisAuthPreset` is the highest-level shared-client Redis path. Keep the module split explicit:

- `litestar_auth.contrib.redis` owns the higher-level convenience entrypoints such as `RedisAuthPreset`,
  `RedisAuthRateLimitTier`, `RedisAuthClientProtocol`, `RedisTokenStrategy`,
  `RedisTotpEnrollmentStore`, and `RedisUsedTotpCodeStore`.
- `litestar_auth.ratelimit` owns the lower-level shared-builder surface such as
  `AuthRateLimitConfig.from_shared_backend()`, `RedisRateLimiter`, the typed slot enum, and the group alias.

`RedisAuthPreset.build_rate_limit_config()` forwards the live shared-builder inputs:
`enabled`, `disabled`, `group_backends`, and `endpoint_overrides`, plus the shared proxy and
identity settings. Explicit `group_backends` still win over any preset
`group_rate_limit_tiers`. `RedisAuthPreset.group_rate_limit_tiers` is snapshotted into a read-only
mapping at construction time, so later mutations to the caller's source `dict` do not silently
change the preset's runtime budget layout.
`build_totp_enrollment_store()`, `build_totp_used_tokens_store()`, and
`build_totp_pending_jti_store()` follow the same precedence: per-call `key_prefix=` wins over the
preset default, and `None` preserves each low-level store's current built-in prefix.

### Redis opaque-token invalidation

`RedisTokenStrategy` writes each opaque token under a TTL-backed token key and records that key in a
per-user Redis set. `invalidate_all_tokens(user)` uses only that per-user set: indexed tokens and
the index key are deleted together, and the strategy does not scan the broader keyspace.

If you are upgrading from a version that created Redis token keys without the per-user index, those
orphaned keys are not force-invalidated by `invalidate_all_tokens(...)`; they remain valid only
until their existing Redis TTL expires. Rotate or flush pre-index token keys before upgrading if you
need immediate global invalidation of those sessions.

The shared builder itself exposes typed public identifiers from
`litestar_auth.ratelimit`:

```python
from litestar_auth.ratelimit import AuthRateLimitEndpointGroup, AuthRateLimitSlot

all_slots = tuple(AuthRateLimitSlot)
verification_slots = {AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}
```

- `AuthRateLimitSlot` names the per-endpoint enum keys accepted by `enabled`, `disabled`, and
  `endpoint_overrides`.
- `AuthRateLimitEndpointGroup` names the shared-backend keys accepted by `group_backends`.
- Use `tuple(AuthRateLimitSlot)` for explicit `enabled=...` calls that should include every
  supported slot.
- Use `{AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}` for
  `disabled=...` when verification routes stay off.

### Low-level Redis builder path

Keep direct `AuthRateLimitConfig.from_shared_backend()` plus direct `RedisRateLimiter(...)`,
`RedisTotpEnrollmentStore(...)`, `RedisUsedTotpCodeStore(...)`, and
`RedisJWTDenylistStore(...)` construction as the low-level path
when you need separate backends, bespoke key prefixes, or fully manual wiring:

```python
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    AuthRateLimitSlot,
    RedisRateLimiter,
)
from litestar_auth.totp import RedisTotpEnrollmentStore, RedisUsedTotpCodeStore

shared_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60)
rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    shared_backend,
    enabled=tuple(AuthRateLimitSlot),
    disabled={AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN},
)
totp_used_tokens_store = RedisUsedTotpCodeStore(redis=redis_client)
totp_enrollment_store = RedisTotpEnrollmentStore(redis=redis_client)
```

The private catalog that stores these defaults remains internal, but the values below are the supported builder surface:

| `AuthRateLimitSlot` value | `AuthRateLimitEndpointGroup` value | Default scope | Default namespace token |
| ------------------------- | ---------------------------------- | ------------- | ----------------------- |
| `AuthRateLimitSlot.LOGIN` | `login` | `ip_email` | `login` |
| `AuthRateLimitSlot.REFRESH` | `refresh` | `ip` | `refresh` |
| `AuthRateLimitSlot.REGISTER` | `register` | `ip` | `register` |
| `AuthRateLimitSlot.FORGOT_PASSWORD` | `password_reset` | `ip_email` | `forgot-password` |
| `AuthRateLimitSlot.RESET_PASSWORD` | `password_reset` | `ip` | `reset-password` |
| `AuthRateLimitSlot.TOTP_ENABLE` | `totp` | `ip` | `totp-enable` |
| `AuthRateLimitSlot.TOTP_CONFIRM_ENABLE` | `totp` | `ip` | `totp-confirm-enable` |
| `AuthRateLimitSlot.TOTP_VERIFY` | `totp` | `ip` | `totp-verify` |
| `AuthRateLimitSlot.TOTP_DISABLE` | `totp` | `ip` | `totp-disable` |
| `AuthRateLimitSlot.VERIFY_TOKEN` | `verification` | `ip` | `verify-token` |
| `AuthRateLimitSlot.REQUEST_VERIFY_TOKEN` | `verification` | `ip_email` | `request-verify-token` |

Accepted `AuthRateLimitEndpointGroup` values are exactly `login`, `refresh`, `register`, `password_reset`, `totp`, and `verification`.

Builder precedence is:

1. `endpoint_overrides` wins per slot and can replace the limiter or set it to `None`.
2. Otherwise, only slots enabled by `enabled` (defaults to every supported slot) and not listed in `disabled` are materialized.
3. Generated limiters start from `backend`, then `group_backends` can swap the backend for the slot's group before the builder materializes the final per-slot limiter.

Generated limiters keep the package-owned scope and namespace defaults from the private endpoint
catalog. Use `{AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}` to leave
unused verification slots unset, and keep direct `EndpointRateLimit(...)` assembly only for advanced per-endpoint
exceptions.

Migration example for an older Redis recipe: this keeps login, register, and password-reset style
routes on one backend, splits out refresh and TOTP budgets, and leaves verification slots unset.
The preset is just a higher-level wrapper around the current shared-builder surface, so the same
slot and override rules still apply.

```python
from litestar_auth.contrib.redis import RedisAuthPreset, RedisAuthRateLimitTier
from litestar_auth.ratelimit import AuthRateLimitSlot

redis_auth = RedisAuthPreset(
    redis=redis_client,
    rate_limit_tier=RedisAuthRateLimitTier(max_attempts=5, window_seconds=60),
    group_rate_limit_tiers={
        "refresh": RedisAuthRateLimitTier(max_attempts=10, window_seconds=300),
        "totp": RedisAuthRateLimitTier(max_attempts=5, window_seconds=300),
    },
)

rate_limit_config = redis_auth.build_rate_limit_config(
    disabled={AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN},
)
```

Add `endpoint_overrides` only when an existing deployment needs a fully custom per-slot limiter or
an explicit `None` disablement beyond the shared `enabled` / `disabled` selection.

### Redis TOTP enrollment, replay protection, and pending-token deduplication

Use `RedisTotpEnrollmentStore` for `TotpConfig.totp_enrollment_store` when pending enrollment
state must be visible across workers or restarts, use `RedisUsedTotpCodeStore` for
`TotpConfig.totp_used_tokens_store` when TOTP codes must not be reusable across workers or
restarts, and use `RedisJWTDenylistStore` for `TotpConfig.totp_pending_jti_store` when pending
login tokens must not be replayed across workers or restarts.
`RedisAuthPreset.build_totp_enrollment_store()`, `RedisAuthPreset.build_totp_used_tokens_store()`,
and `RedisAuthPreset.build_totp_pending_jti_store()` are the shared-client path when the same
Redis client also backs auth rate limiting. The direct low-level store implementations remain
available when you intentionally want bespoke wiring or separate Redis backends.

```python
from litestar_auth import TotpConfig
from litestar_auth.authentication.strategy.jwt import RedisJWTDenylistStore
from litestar_auth.contrib.redis import RedisTotpEnrollmentStore, RedisUsedTotpCodeStore

totp_config = TotpConfig(
    totp_pending_secret="replace-with-32+-char-secret",
    totp_enrollment_store=RedisTotpEnrollmentStore(redis=redis_client),
    totp_pending_jti_store=RedisJWTDenylistStore(redis=redis_client),
    totp_used_tokens_store=RedisUsedTotpCodeStore(redis=redis_client),
)
```

`totp_pending_secret` still signs pending-2FA JWTs for the controller flow; it does not replace
server-side stores. Configure `TotpConfig.totp_enrollment_store` for pending enrollment secrets,
`TotpConfig.totp_pending_jti_store` for pending login-token JTI deduplication, and
`TotpConfig.totp_used_tokens_store` for TOTP-code replay protection.

### Redis contrib import boundary

`litestar_auth.contrib.redis` is the public Redis convenience boundary. It exposes
`RedisAuthClientProtocol`, `RedisAuthPreset`, `RedisAuthRateLimitTier`,
`RedisTokenStrategy`, `RedisTotpEnrollmentStore`, and `RedisUsedTotpCodeStore`.
The high-level one-client preset lives there, while the typed slot enum, group alias, and low-level
shared-backend builder surface remain on `litestar_auth.ratelimit`.
