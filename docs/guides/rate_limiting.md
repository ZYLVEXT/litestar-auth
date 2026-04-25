# Rate limiting

Optional **per-endpoint** limits protect login, registration, token flows, and TOTP surfaces from
brute force and abuse. Configure **`AuthRateLimitConfig`** on
**`LitestarAuthConfig.rate_limit_config`**. For the current Redis-backed contract, including the
stable slot and group inventory, override patterns, and the paired TOTP Redis-store wiring, use
[Configuration](../configuration.md#redis-backed-auth-surface) as the maintained source
of truth. This guide focuses on how the rate-limit surface maps onto the HTTP routes you expose.

## Start with a preset

Most applications should start with one of the built-in `AuthRateLimitConfig` factories instead of
building every slot manually.

### `AuthRateLimitConfig.strict()`

Use `strict()` when the public sign-in surface should share one intentionally low-budget backend.
This preset wires that backend to `login`, `register`, and `totp_verify` with the package default
scopes and route-style namespaces. This in-memory example is for single-process development or
pytest-style tests:

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
sensitive routes. This in-memory example is for single-process development or tests:

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
`RedisAuthPreset`, `AuthRateLimitSlot`, `TotpConfig.totp_enrollment_store`,
`TotpConfig.totp_pending_jti_store`, and `TotpConfig.totp_used_tokens_store` from one shared async Redis client.

This guide deliberately does not repeat the full snippet, because the slot inventory, namespace
families, and shared-client TOTP wiring now live in one maintained place. Keep
`AuthRateLimitConfig.from_shared_backend()` plus direct `RedisRateLimiter(...)` /
`RedisTotpEnrollmentStore(...)` / `RedisJWTDenylistStore(...)` /
`RedisUsedTotpCodeStore(...)` construction as the advanced
low-level path when applications intentionally need separate backends or deeper per-slot customization.

Reach for `from_shared_backend()` when the preset is close, but you still need endpoint- or
group-specific changes. Prefer `endpoint_overrides` for per-slot customization. The in-memory
backend shown here is only for single-process development or tests; use `RedisRateLimiter` or
`RedisAuthPreset` for multi-worker production.

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
slot inventory directly, iterate `AuthRateLimitSlot`. Use `tuple(AuthRateLimitSlot)` for explicit
`enabled=...` calls, and use `{AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}`
for `disabled=...` when the built-in verification routes stay off.

## `AuthRateLimitSlot`

Use the `AuthRateLimitSlot` enum when application code, annotations, or override mappings refer
to supported auth rate-limit slots. The enum is the IDE-friendly public inventory for `enabled`,
`disabled`, `endpoint_overrides`, and other slot-keyed inputs.

```python
from litestar_auth.ratelimit import AuthRateLimitSlot

AuthRateLimitSlot.LOGIN
AuthRateLimitSlot.REQUEST_VERIFY_TOKEN
AuthRateLimitSlot.TOTP_VERIFY
```

## Behavior

- When a limit is exceeded, clients receive **429 Too Many Requests** with **`Retry-After`**.
- Backends: **`InMemoryRateLimiter`** (single process / dev) or **`RedisRateLimiter`** (production, multiple workers). See [Deployment](../deployment.md).
- `InMemoryRateLimiter` fails closed for new keys when `max_keys` is reached and no expired counters can be pruned. It logs `event=rate_limit_memory_capacity`; size `max_keys` for local/dev traffic or use Redis for public multi-worker deployments.
- `LitestarAuthConfig.deployment_worker_count` is the explicit topology declaration for startup validation. `None` means unknown worker count and preserves warning-only diagnostics, `1` means known single-worker, and values greater than `1` fail closed if any enabled auth rate-limit slot uses a process-local backend.
- For the production shared-client Redis path, use the configuration recipe so rate
  limiting stays aligned with the TOTP Redis stores instead of hand-maintaining a partial copy in
  this guide.
- For pytest-driven plugin tests, `InMemoryRateLimiter` is the documented single-process choice described in the [testing guide](testing.md). Keep limiter state isolated per test when counters must not leak.

## Config fields → HTTP surface

Each field accepts an **`EndpointRateLimit`** (or `None` to disable that bucket). Map them to routes you expose:

`AuthRateLimitSlot` is the public slot inventory. Iterate it directly for ordered `enabled=...`
inputs, and pass `{AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}` when
verification endpoints should stay disabled.

| `AuthRateLimitConfig` field / `AuthRateLimitSlot` value | `AuthRateLimitEndpointGroup` value | Default scope | Default namespace token | Typical route / action |
| -------------------------------------------------------- | ---------------------------------- | ------------- | ----------------------- | ---------------------- |
| `login` / `AuthRateLimitSlot.LOGIN` | `login` | `ip_email` | `login` | `POST {auth}/login` |
| `refresh` / `AuthRateLimitSlot.REFRESH` | `refresh` | `ip` | `refresh` | `POST {auth}/refresh` |
| `register` / `AuthRateLimitSlot.REGISTER` | `register` | `ip` | `register` | `POST {auth}/register` |
| `forgot_password` / `AuthRateLimitSlot.FORGOT_PASSWORD` | `password_reset` | `ip_email` | `forgot-password` | `POST {auth}/forgot-password` |
| `reset_password` / `AuthRateLimitSlot.RESET_PASSWORD` | `password_reset` | `ip` | `reset-password` | `POST {auth}/reset-password` |
| `change_password` / `AuthRateLimitSlot.CHANGE_PASSWORD` | `login` | `ip_email` | `change-password` | `POST {users}/me/change-password` |
| `verify_token` / `AuthRateLimitSlot.VERIFY_TOKEN` | `verification` | `ip` | `verify-token` | `POST {auth}/verify` |
| `request_verify_token` / `AuthRateLimitSlot.REQUEST_VERIFY_TOKEN` | `verification` | `ip_email` | `request-verify-token` | `POST {auth}/request-verify-token` |
| `totp_enable` / `AuthRateLimitSlot.TOTP_ENABLE` | `totp` | `ip` | `totp-enable` | `POST {auth}/2fa/enable` |
| `totp_confirm_enable` / `AuthRateLimitSlot.TOTP_CONFIRM_ENABLE` | `totp` | `ip` | `totp-confirm-enable` | `POST {auth}/2fa/enable/confirm` |
| `totp_verify` / `AuthRateLimitSlot.TOTP_VERIFY` | `totp` | `ip` | `totp-verify` | `POST {auth}/2fa/verify` |
| `totp_disable` / `AuthRateLimitSlot.TOTP_DISABLE` | `totp` | `ip` | `totp-disable` | `POST {auth}/2fa/disable` |
| `totp_regenerate_recovery_codes` / `AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES` | `totp` | `ip` | `totp-regenerate-recovery-codes` | `POST {auth}/2fa/recovery-codes/regenerate` |

The plugin wires these `totp_*` limiters through `TotpRateLimitOrchestrator` so **`totp_verify`**
can reset counters on success or account-state failures while other TOTP routes keep independent
budgets.

!!! note "Reset password counter"
    For **`reset_password`**, failed attempts (invalid token or password) can still consume budget; success may reset the window — see implementation notes in `litestar_auth.ratelimit`.

!!! note "Change password counter"
    For **`change_password`**, wrong current-password submissions consume budget, and success resets the window. The default `ip_email` scope uses the authenticated user's email because `ChangePasswordRequest` intentionally has no email field.

When an application needs underscore namespaces or other slot-specific deviations, express
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

Follow the broader Redis override guidance in
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
  auth contract, override patterns, and replay-store guidance.
