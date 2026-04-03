# Rate limiting

Optional **per-endpoint** limits protect login, registration, token flows, and TOTP surfaces from brute force and abuse. Configure **`AuthRateLimitConfig`** on **`LitestarAuthConfig.rate_limit_config`**. For the common Redis-backed setup, use **`AuthRateLimitConfig.from_shared_backend()`** and let the library materialize the standard auth endpoint slots for you.

## Canonical shared-backend setup

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, RedisRateLimiter

rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    RedisRateLimiter(
        redis=redis_client,
        max_attempts=5,
        window_seconds=60,
    ),
)
```

The shared-backend builder keeps the package defaults for scopes and namespace tokens:

- `login`, `forgot_password`, and `request_verify_token` use `ip_email`.
- The remaining auth slots use `ip`.
- Namespace tokens follow the route-oriented defaults such as `login`, `forgot-password`, and `totp-verify`.

When migrating from an existing manual recipe, preserve established key shapes with `scope_overrides` and `namespace_overrides`. Use `group_backends`, `enabled` / `disabled`, or `endpoint_overrides` only when your app intentionally deviates from the standard package recipe.

## Behavior

- When a limit is exceeded, clients receive **429 Too Many Requests** with **`Retry-After`**.
- Backends: **`InMemoryRateLimiter`** (single process / dev) or **`RedisRateLimiter`** (production, multiple workers). See [Deployment](../deployment.md).

## Config fields → HTTP surface

Each field accepts an **`EndpointRateLimit`** (or `None` to disable that bucket). Map them to routes you expose:

| `AuthRateLimitConfig` field | Typical route / action |
| --------------------------- | ---------------------- |
| `login` | `POST {auth}/login` |
| `refresh` | `POST {auth}/refresh` |
| `register` | `POST {auth}/register` |
| `forgot_password` | `POST {auth}/forgot-password` |
| `reset_password` | `POST {auth}/reset-password` |
| `verify_token` | `POST {auth}/verify` |
| `request_verify_token` | `POST {auth}/request-verify-token` |
| `totp_enable` | `POST {auth}/2fa/enable` |
| `totp_confirm_enable` | `POST {auth}/2fa/enable/confirm` |
| `totp_verify` | `POST {auth}/2fa/verify` |
| `totp_disable` | `POST {auth}/2fa/disable` |

The plugin turns these `totp_*` limiters into an internal orchestrator so **`totp_verify`** can reset counters on success or account-state failures while other TOTP routes keep independent budgets (see `TotpRateLimitOrchestrator` in `litestar_auth.ratelimit`).

!!! note "Reset password counter"
    For **`reset_password`**, failed attempts (invalid token or password) can still consume budget; success may reset the window — see implementation notes in `litestar_auth.ratelimit`.

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
- [Configuration](../configuration.md) — `rate_limit_config` field.
