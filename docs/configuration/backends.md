# Backends

Use this page for the database-token preset, backend lifecycle helpers, route path flags, and built-in auth payloads.

## Opaque DB-token preset

Use `DatabaseTokenAuthConfig` plus direct `LitestarAuthConfig(..., database_token_auth=...)`
construction for the common bearer + database-token flow. This is the documented entrypoint for
opaque DB tokens; it builds the `AuthenticationBackend`, `BearerTransport`, and
`DatabaseTokenStrategy` for you.

```python
from uuid import UUID

from litestar import Litestar

from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User

config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret="replace-with-32+-char-db-token-secret",
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
)
app = Litestar(plugins=[LitestarAuth(config)])
```

Here, `session_maker` means a callable session factory the plugin can invoke as `session_maker()` to obtain the request-local `AsyncSession`. `async_sessionmaker(...)` is the most common implementation, but any factory with that runtime contract is supported.

If you previously hand-assembled `AuthenticationBackend(..., transport=BearerTransport(), strategy=DatabaseTokenStrategy(...))`, migrate that setup to the direct `database_token_auth=DatabaseTokenAuthConfig(...)` form above. Keep manual `backends=` assembly only when you need multiple backends, custom token models, or another custom transport/strategy mix.

When you use `database_token_auth=...`, `config.backends` stays empty by design. `config.resolve_startup_backends()` returns startup-only `StartupBackendTemplate` values for plugin assembly and validation, while `config.resolve_backends(session)` returns the request-scoped runtime `AuthenticationBackend` instances bound to the active `AsyncSession` for every supported backend configuration.

### Backend lifecycle contract

Treat the two backend helpers as distinct surfaces:

- `config.resolve_startup_backends()` is the plugin's startup inventory. Manual backends are wrapped as `StartupBackendTemplate` values, and the DB-token preset also contributes a `StartupBackendTemplate` that is valid for plugin assembly, validation, and route selection only.
- `config.resolve_backends(session)` realizes request-scoped `AuthenticationBackend` instances aligned with `config.resolve_startup_backends()` order. Use this surface whenever runtime login, refresh, logout, token validation, or other request-time work needs the active `AsyncSession`.
- Startup-only DB-token templates fail closed if they are used for runtime database-token work before `resolve_backends(session)` supplies a request session.

Controller selection follows that startup inventory:

- The primary backend mounts at `{auth_path}`.
- Additional backends mount at `{auth_path}/{backend.name}` in configured order.
- Plugin-owned OAuth login routes use the primary startup backend.
- TOTP uses the primary startup backend unless `TotpConfig.totp_backend_name` selects another named backend from the same startup inventory.

## Paths and HTTP feature flags

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `auth_path` | `"/auth"` | Base path for generated auth controllers. |
| `users_path` | `"/users"` | Base path for user CRUD when enabled. |
| `include_register` | `True` | `POST .../register` |
| `include_verify` | `True` | Verify + request-verify-token |
| `include_reset_password` | `True` | Forgot + reset password |
| `include_users` | `False` | User management routes |
| `enable_refresh` | `False` | `POST .../refresh` |
| `requires_verification` | `True` | Stricter login / TOTP-verify policy |
| `hard_delete` | `False` | Physical vs soft delete semantics for user delete |
| `login_identifier` | `"email"` | `"email"` or `"username"` for `POST {auth_path}/login` credential lookup |

**Multiple backends:** first backend → `{auth_path}`; others → `{auth_path}/{backend-name}/...`.

When `requires_verification=True`, the shared account-state policy is consistent across login,
refresh, and TOTP verification: inactive users fail first, and unverified users fail next.

## Built-in auth payload boundary

The generated controllers do not use one universal credential field. `login_identifier` only changes how `LoginCredentials.identifier` is interpreted on `POST {auth_path}/login`.

| Route | Built-in request schema | Published fields |
| ----- | ---------------------- | ---------------- |
| `POST {auth_path}/login` | `LoginCredentials` | `identifier`, `password` |
| `POST {auth_path}/register` | `UserCreate` | `email`, `password` |
| `POST {auth_path}/request-verify-token` | `RequestVerifyToken` | `email` |
| `POST {auth_path}/verify` | `VerifyToken` | `token` |
| `POST {auth_path}/forgot-password` | `ForgotPassword` | `email` |
| `POST {auth_path}/reset-password` | `ResetPassword` | `token`, `password` |

Verify and reset token values are signed JWTs issued by the manager security service. Library-issued
tokens include JOSE `typ=JWT`, and decode rejects tokens with a missing or unexpected `typ` header
before the normal signed audience, required-claim, and password-fingerprint validation. Custom test
fixtures or advanced integrations that mint these tokens directly must set the same header; the
header check is not a replacement for the existing signed JWT validation.

By default, built-in TOTP routes publish `TotpEnableRequest`, `TotpConfirmEnableRequest`, `TotpVerifyRequest`, and `TotpDisableRequest`. `TotpVerifyRequest.code` and `TotpDisableRequest.code` accept either a current TOTP code or an unused recovery code where documented. The built-in TOTP flow still uses `user.email` for the otpauth URI and password step-up, even when `login_identifier="username"`.
