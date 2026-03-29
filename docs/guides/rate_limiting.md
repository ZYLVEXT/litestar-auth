# Rate limiting

Optional **per-endpoint** limits protect login, registration, token flows, and TOTP surfaces from brute force and abuse. Configure **`AuthRateLimitConfig`** on **`LitestarAuthConfig.rate_limit_config`**.

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

## Further reading

- [Python API — Rate limiting](../api/ratelimit.md) — mkdocstrings for `AuthRateLimitConfig`, backends, and helpers.
- [Security guide](security.md) — when to prefer Redis.
- [Configuration](../configuration.md) — `rate_limit_config` field.
