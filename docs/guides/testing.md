# Testing plugin-backed apps

Use this guide when you test an app that mounts `LitestarAuth` as a plugin. It consolidates the supported contract around explicit `unsafe_testing` overrides, request-scoped database sessions, and isolation of process-local auth state.

!!! note "Current surface only"
    The library does not ship a `litestar_auth.testing` module, a Redis flush helper, or another dedicated test harness API. Use Litestar's `AsyncTestClient`, your app fixtures, and the existing configuration seams documented here.

!!! note "Contributors to this repository"
    This page is the app-level testing guide. If you are changing `litestar-auth` itself, keep the repo-internal test pyramid and marker guidance in the [test suite README](https://github.com/ZYLVEXT/litestar-auth/blob/main/tests/README.md) and run the mandatory verification block from [Contributing](../contributing.md).

## Enable explicit unsafe testing only in test-owned fixtures

Set `unsafe_testing=True` on the `LitestarAuthConfig` instance that your fixture builds:

```python
from litestar import Litestar
import pytest

from litestar_auth import LitestarAuth, LitestarAuthConfig


@pytest.fixture
def app() -> Litestar:
    config = LitestarAuthConfig(
        ...,
        unsafe_testing=True,
    )
    return Litestar(plugins=[LitestarAuth(config)])
```

`unsafe_testing` is an explicit test-only override:

- Some required token secrets can fall back to generated values during tests so you do not have to hard-code production secrets in fixtures.
- Security warnings for the documented single-process recipe are suppressed for that specific config instance.
- Validation relaxations stay scoped to the config, controller, manager, or OAuth-encryption policy where you opted in; other app instances remain strict.

Do not enable `unsafe_testing` for manual local runs, staging, or production traffic.

If you bypass the plugin and use lower-level helpers directly, the same contract is still explicit and instance-scoped:

- `BaseUserManager(..., unsafe_testing=True)`
- `create_totp_controller(..., unsafe_testing=True)`
- `OAuthTokenEncryption(key=None, unsafe_testing=True)`

## Use a real app and Litestar's `AsyncTestClient`

Build the same `Litestar` app shape that production uses and exercise it through HTTP. For plugin-backed apps, that usually means:

- Construct `LitestarAuthConfig` inside the app fixture.
- Install the plugin on a real `Litestar` app.
- Drive requests with `litestar.testing.AsyncTestClient`.
- Prefer per-test app fixtures when your auth state is process-local.

## Request-scoped database session contract

When the plugin owns session creation through `LitestarAuthConfig.session_maker`, one HTTP request reuses one request-local database session across:

- auth middleware
- injected `db_session`
- DI-built auth backends
- the DI-built user manager

That sharing boundary is per request, not per client:

- A login request gets one request-local session.
- A later authenticated request gets its own request-local session.
- Logout and refresh requests each get their own request-local session as well.

If your app provides `db_session` externally with `db_session_dependency_provided_externally=True`, keep the same contract: return one shared session object for the whole request rather than allocating a fresh session per dependency resolution.

## Isolate auth state explicitly

`unsafe_testing=True` does not reset auth state for you. Isolation is still the application's responsibility.

| Surface | Test-friendly seam | Your isolation responsibility |
| ------- | ------------------ | ----------------------------- |
| JWT revocation / logout | process-local in-memory denylist under `unsafe_testing=True` | build a fresh strategy or app per test unless cross-request state sharing is the point of the test |
| DB token strategy | real database tables behind your test session factory | roll back or clear tables between tests |
| Rate limiting | `InMemoryRateLimiter` for single-process tests | create a fresh limiter or app fixture per test when counters must not leak |
| TOTP replay protection | omit `totp_used_tokens_store` under `unsafe_testing=True` or use `InMemoryUsedTotpCodeStore` | isolate the store per test; use Redis-backed stores when validating multi-worker behavior |
| TOTP pending-token JTI dedupe | plugin-built controller allows `pending_jti_store=None` under `unsafe_testing=True` | isolate the app instance per test; use a shared denylist store for production-like flows |
| TOTP pending enrollment | plugin-built controller creates an `InMemoryTotpEnrollmentStore` under `unsafe_testing=True` when `totp_enrollment_store` is omitted | isolate the app/store per test; use `RedisTotpEnrollmentStore` or equivalent for production-like multi-worker flows |
| TOTP enrollment secret encryption | plugin-built controller allows `totp_secret_key=None` under `unsafe_testing=True`, storing pending enrollment secrets in plaintext process-local memory | configure a real Fernet key in production — missing `totp_secret_key` fails closed with `ConfigurationError` when `unsafe_testing=False` |
| In-memory or fake user stores | app-owned fakes and stubs | create new instances per test and avoid module-global auth state |

## Single-process conveniences vs production-safe stores

The following shortcuts are for single-process tests that explicitly opt into `unsafe_testing=True`:

- in-memory JWT denylist behavior
- `InMemoryRateLimiter`
- `InMemoryTotpEnrollmentStore`
- `InMemoryUsedTotpCodeStore`
- plugin-built TOTP controller flows without a shared `pending_jti_store`

For production or multi-worker integration environments, configure shared durable stores instead:

- `RedisJWTDenylistStore` for JWT revocation or TOTP pending-token deduplication
- `RedisRateLimiter` for auth endpoint rate limits
- `RedisTotpEnrollmentStore` for pending TOTP enrollment state
- `RedisUsedTotpCodeStore` for TOTP replay protection

## Feature-specific boundaries

- [Rate limiting](rate_limiting.md): `InMemoryRateLimiter` is appropriate for single-process tests with explicit `unsafe_testing`, not for multi-worker deployments.
- [TOTP](totp.md): `unsafe_testing` can relax replay, pending-token, and enrollment-store requirements for app tests, but production still needs explicit shared stores when durability matters.
- [Deployment](../deployment.md): use the production checklist when leaving the single-process test harness.
