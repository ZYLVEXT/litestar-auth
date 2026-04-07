# Rate limiting

Use [Configuration](../configuration.md#canonical-redis-backed-auth-surface) as the canonical guide
for the current Redis-backed auth contract: the preferred `RedisAuthPreset` flow, stable slot and
group names, namespace families, helper exports, migration behavior, and the paired TOTP
replay-store setup all live there. This page focuses on the public rate-limit types themselves.

The higher-level one-client Redis preset lives in `litestar_auth.contrib.redis.RedisAuthPreset`.
This module owns the lower-level shared builder plus the slot/group helper exports that feed
`enabled=...` and `disabled=...`.

Import the builder aliases and slot helpers from `litestar_auth.ratelimit` when app code annotates
or reuses the shared-backend inventory:

```python
from litestar_auth.ratelimit import (
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS,
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP,
    AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    AuthRateLimitEndpointGroup,
    AuthRateLimitEndpointSlot,
    AuthRateLimitNamespaceStyle,
)
```

- `AuthRateLimitEndpointSlot` names the per-endpoint keys accepted by `enabled`, `disabled`, `scope_overrides`, `namespace_overrides`, and `endpoint_overrides`.
- `AuthRateLimitEndpointGroup` names the shared-backend keys accepted by `group_backends`.
- `AuthRateLimitNamespaceStyle` names the supported namespace families accepted by `namespace_style`.
- `AUTH_RATE_LIMIT_ENDPOINT_SLOTS` exposes the ordered supported slot inventory derived from the package-owned catalog.
- `AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP` exposes read-only group-to-slot frozensets keyed by `AuthRateLimitEndpointGroup`.
- `AUTH_RATE_LIMIT_VERIFICATION_SLOTS` is the convenience alias for `AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"]`, which is useful for `disabled=...` when verification routes stay off.

::: litestar_auth.ratelimit
    options:
      members:
        - AUTH_RATE_LIMIT_ENDPOINT_SLOTS
        - AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP
        - AUTH_RATE_LIMIT_VERIFICATION_SLOTS
        - AuthRateLimitConfig
        - AuthRateLimitEndpointGroup
        - AuthRateLimitNamespaceStyle
        - AuthRateLimitEndpointSlot
        - EndpointRateLimit
        - RateLimitScope
        - InMemoryRateLimiter
        - RedisRateLimiter
        - RateLimiterBackend
        - TotpRateLimitOrchestrator
        - TotpSensitiveEndpoint
