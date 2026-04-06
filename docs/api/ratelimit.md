# Rate limiting

`AuthRateLimitConfig.from_shared_backend()` is the canonical public entrypoint for the common shared-backend recipe. It materializes endpoint-specific `EndpointRateLimit` values from the private auth slot catalog while keeping manual `AuthRateLimitConfig(..., EndpointRateLimit(...))` assembly available as the advanced escape hatch.

Import the builder aliases from `litestar_auth.ratelimit` when app code annotates shared-backend inputs:

```python
from litestar_auth.ratelimit import AuthRateLimitEndpointGroup, AuthRateLimitEndpointSlot
```

- `AuthRateLimitEndpointSlot` names the per-endpoint keys accepted by `enabled`, `disabled`, `scope_overrides`, `namespace_overrides`, and `endpoint_overrides`.
- `AuthRateLimitEndpointGroup` names the shared-backend keys accepted by `group_backends`.

Those aliases are the stable builder identifiers:

| `AuthRateLimitEndpointSlot` value | `AuthRateLimitEndpointGroup` value | Default scope | Default namespace token |
| --------------------------------- | ---------------------------------- | ------------- | ----------------------- |
| `login` | `login` | `ip_email` | `login` |
| `refresh` | `refresh` | `ip` | `refresh` |
| `register` | `register` | `ip` | `register` |
| `forgot_password` | `password_reset` | `ip_email` | `forgot-password` |
| `reset_password` | `password_reset` | `ip` | `reset-password` |
| `totp_enable` | `totp` | `ip` | `totp-enable` |
| `totp_confirm_enable` | `totp` | `ip` | `totp-confirm-enable` |
| `totp_verify` | `totp` | `ip` | `totp-verify` |
| `totp_disable` | `totp` | `ip` | `totp-disable` |
| `verify_token` | `verification` | `ip` | `verify-token` |
| `request_verify_token` | `verification` | `ip_email` | `request-verify-token` |

There is no extra preset or namespace-family mode behind those aliases. Use `group_backends`, `scope_overrides`,
`namespace_overrides`, `disabled`, and `endpoint_overrides` directly when migrating existing key shapes.

Override precedence is:

1. `endpoint_overrides` wins per slot and can replace the limiter or set it to `None`.
2. Otherwise, only slots enabled by `enabled` (defaults to all supported slots) and not listed in `disabled` are generated.
3. Generated limiters start from `backend`, then `group_backends` can swap the backend for the slot's group.
4. `scope_overrides` and `namespace_overrides` adjust the generated limiter for that slot.

Those identifiers are the public builder contract. The private recipe objects that store them remain internal implementation details.

::: litestar_auth.ratelimit
    options:
      members:
        - AuthRateLimitConfig
        - AuthRateLimitEndpointGroup
        - AuthRateLimitEndpointSlot
        - EndpointRateLimit
        - RateLimitScope
        - InMemoryRateLimiter
        - RedisRateLimiter
        - RateLimiterBackend
        - TotpRateLimitOrchestrator
        - TotpSensitiveEndpoint
