# Rate limiting

Optional **per-endpoint** limits protect login, registration, token flows, and TOTP surfaces from
brute force and abuse. Configure **`AuthRateLimitConfig`** on
**`LitestarAuthConfig.rate_limit_config`**. For the current Redis-backed contract, including the
stable slot and group inventory, migration recipe, and the paired TOTP Redis-store wiring, use
[Configuration](../configuration.md#redis-backed-auth-surface) as the maintained source
of truth. This guide focuses on how the rate-limit surface maps onto the HTTP routes you expose.

## Start with a preset

Most applications should start with one of the built-in `AuthRateLimitConfig` factories instead of
building every slot manually.

### `AuthRateLimitConfig.strict()`

Use `strict()` when the public sign-in surface should share one intentionally low-budget backend.
This preset wires that backend to `login`, `register`, and `totp_verify` with the package default
scopes and route-style namespaces.

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, InMemoryRateLimiter

rate_limit_config = AuthRateLimitConfig.strict(
    backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
)
```

### `AuthRateLimitConfig.lenient()`

Use `lenient()` when `login`, `refresh`, and `register` can share a broader built-in budget, but
password-reset, verification, and TOTP routes still need stricter protection. The preset preserves
the backend you pass for the lower-risk slots and clones it with a five-attempt cap for the
sensitive routes.

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, InMemoryRateLimiter

rate_limit_config = AuthRateLimitConfig.lenient(
    backend=InMemoryRateLimiter(max_attempts=20, window_seconds=300),
)
```

### `AuthRateLimitConfig.disabled()`

Use `disabled()` for local development, tests, or other trusted environments that want the plugin
surface wired without active throttling. The preset returns an `AuthRateLimitConfig` with every
slot left unset.

```python
from litestar_auth.ratelimit import AuthRateLimitConfig

rate_limit_config = AuthRateLimitConfig.disabled()
```

## Custom shared-backend setup

Use [Configuration](../configuration.md#redis-backed-auth-surface) for the maintained
production Redis/TOTP recipe. That shared-client snippet is the single source of truth for wiring
`RedisAuthPreset`, `AUTH_RATE_LIMIT_VERIFICATION_SLOTS`, `TotpConfig.totp_enrollment_store`,
`TotpConfig.totp_pending_jti_store`, and `TotpConfig.totp_used_tokens_store` from one shared async Redis client.

This guide deliberately does not repeat the full snippet, because the slot inventory, namespace
families, and shared-client TOTP wiring now live in one maintained place. Keep
`AuthRateLimitConfig.from_shared_backend()` plus direct `RedisRateLimiter(...)` /
`RedisTotpEnrollmentStore(...)` / `RedisJWTDenylistStore(...)` /
`RedisUsedTotpCodeStore(...)` construction as the advanced
low-level path when applications intentionally need separate backends or deeper per-slot customization.

Reach for `from_shared_backend()` when the preset is close, but you still need endpoint- or
group-specific changes. Prefer `endpoint_overrides` for per-slot customization.

```python
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    AuthRateLimitSlot,
    EndpointRateLimit,
    InMemoryRateLimiter,
)

shared_backend = InMemoryRateLimiter(max_attempts=10, window_seconds=60)

rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    shared_backend,
    endpoint_overrides={
        AuthRateLimitSlot.TOTP_VERIFY: EndpointRateLimit(
            backend=shared_backend,
            scope="ip",
            namespace="totp-verify",
        ),
    },
)
```

`enabled` and `disabled` remain the underlying builder inputs. When app code needs the supported
slot inventory directly, import `AUTH_RATE_LIMIT_ENDPOINT_SLOTS`,
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP`, or `AUTH_RATE_LIMIT_VERIFICATION_SLOTS` from
`litestar_auth.ratelimit` instead of repeating literal frozensets. Use
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS` for explicit `enabled=...` calls, and use either
`AUTH_RATE_LIMIT_VERIFICATION_SLOTS` or
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"]` for `disabled=...` when the built-in
verification routes stay off.

## `AuthRateLimitSlot`

Prefer the `AuthRateLimitSlot` enum when application code, annotations, or override mappings refer
to supported auth rate-limit slots. The enum is the IDE-friendly public inventory for
`endpoint_overrides` and other slot-keyed inputs.

```python
from litestar_auth.ratelimit import AuthRateLimitSlot

AuthRateLimitSlot.LOGIN
AuthRateLimitSlot.REQUEST_VERIFY_TOKEN
AuthRateLimitSlot.TOTP_VERIFY
```

`AuthRateLimitEndpointSlot` still exists as the legacy literal type alias, but new code should
prefer `AuthRateLimitSlot`.

## Behavior

- When a limit is exceeded, clients receive **429 Too Many Requests** with **`Retry-After`**.
- Backends: **`InMemoryRateLimiter`** (single process / dev) or **`RedisRateLimiter`** (production, multiple workers). See [Deployment](../deployment.md).
- `InMemoryRateLimiter` fails closed for new keys when `max_keys` is reached and no expired counters can be pruned. It logs `event=rate_limit_memory_capacity`; size `max_keys` for local/dev traffic or use Redis for public multi-worker deployments.
- For the production shared-client Redis path, use the configuration recipe so rate
  limiting stays aligned with the TOTP Redis stores instead of hand-maintaining a partial copy in
  this guide.
- For pytest-driven plugin tests, `InMemoryRateLimiter` is the documented single-process choice described in the [testing guide](testing.md). Keep limiter state isolated per test when counters must not leak.

## Config fields → HTTP surface

Each field accepts an **`EndpointRateLimit`** (or `None` to disable that bucket). Map them to routes you expose:

`AUTH_RATE_LIMIT_ENDPOINT_SLOTS` exposes this same ordered slot inventory, and
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"]` is the group-level equivalent of
`AUTH_RATE_LIMIT_VERIFICATION_SLOTS`.

| `AuthRateLimitConfig` field / `AuthRateLimitSlot` value | `AuthRateLimitEndpointGroup` value | Default scope | Default namespace token | Typical route / action |
| -------------------------------------------------------- | ---------------------------------- | ------------- | ----------------------- | ---------------------- |
| `login` / `AuthRateLimitSlot.LOGIN` | `login` | `ip_email` | `login` | `POST {auth}/login` |
| `refresh` / `AuthRateLimitSlot.REFRESH` | `refresh` | `ip` | `refresh` | `POST {auth}/refresh` |
| `register` / `AuthRateLimitSlot.REGISTER` | `register` | `ip` | `register` | `POST {auth}/register` |
| `forgot_password` / `AuthRateLimitSlot.FORGOT_PASSWORD` | `password_reset` | `ip_email` | `forgot-password` | `POST {auth}/forgot-password` |
| `reset_password` / `AuthRateLimitSlot.RESET_PASSWORD` | `password_reset` | `ip` | `reset-password` | `POST {auth}/reset-password` |
| `verify_token` / `AuthRateLimitSlot.VERIFY_TOKEN` | `verification` | `ip` | `verify-token` | `POST {auth}/verify` |
| `request_verify_token` / `AuthRateLimitSlot.REQUEST_VERIFY_TOKEN` | `verification` | `ip_email` | `request-verify-token` | `POST {auth}/request-verify-token` |
| `totp_enable` / `AuthRateLimitSlot.TOTP_ENABLE` | `totp` | `ip` | `totp-enable` | `POST {auth}/2fa/enable` |
| `totp_confirm_enable` / `AuthRateLimitSlot.TOTP_CONFIRM_ENABLE` | `totp` | `ip` | `totp-confirm-enable` | `POST {auth}/2fa/enable/confirm` |
| `totp_verify` / `AuthRateLimitSlot.TOTP_VERIFY` | `totp` | `ip` | `totp-verify` | `POST {auth}/2fa/verify` |
| `totp_disable` / `AuthRateLimitSlot.TOTP_DISABLE` | `totp` | `ip` | `totp-disable` | `POST {auth}/2fa/disable` |

The plugin turns these `totp_*` limiters into an internal orchestrator so **`totp_verify`** can reset counters on success or account-state failures while other TOTP routes keep independent budgets (see `TotpRateLimitOrchestrator` in `litestar_auth.ratelimit`).

!!! note "Reset password counter"
    For **`reset_password`**, failed attempts (invalid token or password) can still consume budget; success may reset the window — see implementation notes in `litestar_auth.ratelimit`.

When existing deployments need underscore namespaces or other slot-specific deviations, express
them directly in `endpoint_overrides` keyed by `AuthRateLimitSlot`:

```python
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    AuthRateLimitSlot,
    EndpointRateLimit,
)

rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    backend,
    endpoint_overrides={
        AuthRateLimitSlot.FORGOT_PASSWORD: EndpointRateLimit(
            backend=backend,
            scope="ip_email",
            namespace="forgot_password",
        ),
        AuthRateLimitSlot.RESET_PASSWORD: EndpointRateLimit(
            backend=backend,
            scope="ip",
            namespace="reset_password",
        ),
    },
)
```

Follow the broader Redis key-shape migration recipe in
[Configuration](../configuration.md#redis-backed-auth-surface) when an existing
deployment also needs group-level backend changes, disabled verification routes, or staged TOTP
adoption.

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
- [Configuration](../configuration.md#redis-backed-auth-surface) — Redis-backed
  auth contract, migration recipe, and replay-store guidance.
