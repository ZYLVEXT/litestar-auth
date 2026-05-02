# Rate limiting

Use [Configuration](../configuration.md#redis-backed-auth-surface) as the main guide
for the current Redis-backed auth contract: the `RedisAuthPreset` flow, stable slot and
group names, namespace defaults and override patterns, and the TOTP Redis-store
setup all live there. This page focuses on the public rate-limit types themselves.

The higher-level one-client Redis preset lives in `litestar_auth.contrib.redis.RedisAuthPreset`.
This module owns the lower-level shared builder plus the `AuthRateLimitSlot` enum accepted by
`SharedRateLimitConfigOptions.enabled` and `SharedRateLimitConfigOptions.disabled`.

For a smaller public-entry-point preset, `AuthRateLimitConfig.strict(backend=...)` wires a shared
backend to `login`, `register`, and `totp_verify` using the package default scopes and route-style
namespaces. Pass a backend that already encodes the lower attempt budget you want for those
surfaces.

For internal or lower-risk deployments, `AuthRateLimitConfig.lenient(backend=...)` uses the
supplied built-in backend for `login`, `refresh`, and `register`, then clones that limiter with a
five-attempt cap for token- and secret-bearing routes such as password reset, verification, and
TOTP. That keeps the broader environment budget off the sensitive recovery and step-up surfaces.

For local development, test harnesses, or other trusted environments that want the plugin wiring
without active throttling, `AuthRateLimitConfig.disabled()` returns a config where every auth slot
is left unset.

Import the builder aliases and slot enum from `litestar_auth.ratelimit` when app code annotates
or reuses the shared-backend inventory:

```python
from litestar_auth.ratelimit import (
    AuthRateLimitEndpointGroup,
    AuthRateLimitSlot,
    SharedRateLimitConfigOptions,
)

shared_options = SharedRateLimitConfigOptions(
    enabled=tuple(AuthRateLimitSlot),
    disabled={AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN},
)
```

- `AuthRateLimitSlot` names the per-endpoint enum keys accepted by `SharedRateLimitConfigOptions.enabled`,
  `SharedRateLimitConfigOptions.disabled`, and `SharedRateLimitConfigOptions.endpoint_overrides`.
- `AuthRateLimitEndpointGroup` names the shared-backend keys accepted by
  `SharedRateLimitConfigOptions.group_backends`.
- Iterate `AuthRateLimitSlot` directly when you need every supported slot for an explicit
  `SharedRateLimitConfigOptions.enabled` value.
- Use `{AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}` for
  `SharedRateLimitConfigOptions.disabled` when verification routes stay off.

::: litestar_auth.ratelimit
    options:
      members:
        - AuthRateLimitConfig
        - AuthRateLimitEndpointGroup
        - AuthRateLimitSlot
        - EndpointRateLimit
        - RateLimitScope
        - SharedRateLimitConfigOptions
        - InMemoryRateLimiter
        - RedisRateLimiter
        - RateLimiterBackend
        - TotpRateLimitOrchestrator
        - TotpSensitiveEndpoint
