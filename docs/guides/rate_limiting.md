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

`from_shared_backend()` exposes typed public builder identifiers from `litestar_auth.ratelimit`:

```python
from litestar_auth.ratelimit import AuthRateLimitEndpointGroup, AuthRateLimitEndpointSlot
```

- `AuthRateLimitEndpointSlot` names the per-endpoint keys accepted by `enabled`, `disabled`, `scope_overrides`, `namespace_overrides`, and `endpoint_overrides`.
- `AuthRateLimitEndpointGroup` names the shared-backend keys accepted by `group_backends`.

The private recipe catalog that stores these defaults is still internal, but the supported builder contract is:

- Supported `AuthRateLimitEndpointSlot` values: `login`, `refresh`, `register`, `forgot_password`, `reset_password`, `totp_enable`, `totp_confirm_enable`, `totp_verify`, `totp_disable`, `verify_token`, `request_verify_token`
- Supported `AuthRateLimitEndpointGroup` values: `login`, `refresh`, `register`, `password_reset`, `totp`, `verification`

Override precedence is:

1. `endpoint_overrides` wins per slot and can replace the limiter or set it to `None`.
2. Otherwise, only slots enabled by `enabled` (defaults to all supported slots) and not listed in `disabled` are generated.
3. Generated limiters start from `backend`, then `group_backends` can swap the backend for the slot's group.
4. `scope_overrides` and `namespace_overrides` adjust the generated limiter for that slot.

When migrating from an existing manual recipe, preserve established key shapes with `scope_overrides` and `namespace_overrides`, and use `disabled` for slots you intentionally leave unset. There is no separate migration preset or namespace switch beyond these current builder arguments.

## Behavior

- When a limit is exceeded, clients receive **429 Too Many Requests** with **`Retry-After`**.
- Backends: **`InMemoryRateLimiter`** (single process / dev) or **`RedisRateLimiter`** (production, multiple workers). See [Deployment](../deployment.md).
- For pytest-driven plugin tests, `InMemoryRateLimiter` is the canonical single-process choice described in the [testing guide](testing.md). Keep limiter state isolated per test when counters must not leak.

## Config fields → HTTP surface

Each field accepts an **`EndpointRateLimit`** (or `None` to disable that bucket). Map them to routes you expose:

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

## Migration recipe for existing Redis key shapes

If an older app already depends on separate credential, refresh, and TOTP budgets plus underscore namespaces, preserve that behavior with the current builder surface. This is a migration pattern built from the existing builder knobs, not a separate preset:

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

In that example, `login`, `register`, `forgot_password`, and `reset_password` stay on `credential_backend`, the `refresh` group moves to `refresh_backend`, the `totp_*` slots move to `totp_backend`, and the verification slots stay unset.

Add `scope_overrides` only when an existing key shape depends on a non-default scope for a specific slot. Keep direct `AuthRateLimitConfig(..., EndpointRateLimit(...))` assembly for cases where a slot needs a wholly custom limiter instead of the shared builder.

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
