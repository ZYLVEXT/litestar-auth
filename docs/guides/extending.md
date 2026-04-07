# Extending litestar-auth

## User model

Subclass the provided [`User`](../api/models.md) (or follow the same column contract) and point `LitestarAuthConfig.user_model` at your class. Keep sensitive fields out of public schemas via `user_read_schema` / msgspec structs.

## User manager

Subclass [`BaseUserManager`](../api/manager.md) to implement **lifecycle hooks** and custom rules. See the dedicated [Hooks](hooks.md) page for when each hook runs and timing considerations (`on_after_forgot_password`).

The plugin injects a request-scoped manager built with your `user_db_factory`, `backends`, and optional `password_validator`.

### Constructor compatibility

If your manager needs **`password_validator`** or **`login_identifier`**, either accept them in `__init__` or set class attributes `accepts_password_validator` / `accepts_login_identifier` so the plugin can detect support.

### Custom factory

Set `user_manager_factory` on `LitestarAuthConfig` for full control over manager construction (must
match the `UserManagerFactory` contract).

Plugin-managed manager construction inherits the plugin-owned secret-role reuse baseline. If your
custom factory instantiates `BaseUserManager` (or a subclass) with the same
verification/reset/TOTP secrets that were already validated during `LitestarAuth(config)`, manager
construction suppresses the duplicate warning. If the custom factory diverges from that
config-owned surface, the manager constructor surfaces the additional warning for the manager-owned
roles it actually wires. Keep custom factories aligned with `user_manager_security` / legacy
config-owned secret kwargs unless you intentionally want the factory-built manager to carry that
additional warning.

## Controllers and DTOs

Factory functions such as `create_auth_controller` live in `litestar_auth.controllers`. The plugin calls them internally based on flags like `include_register`. For advanced scenarios you can:

- Reuse the built-in auth lifecycle DTOs from [`litestar_auth.payloads`](../api/schemas.md#built-in-auth-payloads): `LoginCredentials`, `RefreshTokenRequest`, `ForgotPassword`, `ResetPassword`, `RequestVerifyToken`, `VerifyToken`, and the TOTP request/response structs. These are the names the generated OpenAPI publishes for the default controllers.
- Provide custom **msgspec** schemas via [`litestar_auth.schemas`](../api/schemas.md#user-crud-schemas) or your own structs wired through `user_create_schema`, `user_update_schema`, and `user_read_schema` for registration and user CRUD surfaces.
- Fork behavior inside your manager rather than replacing controllers first.

If an app-owned `user_create_schema` or `user_update_schema` keeps `email` and `password` fields, import
`UserEmailField` and `UserPasswordField` from `litestar_auth.schemas` instead of duplicating the built-in email regex
or `msgspec.Meta(min_length=12, max_length=128)` locally:

```python
import msgspec

from litestar_auth.schemas import UserEmailField, UserPasswordField


class ExtendedUserCreate(msgspec.Struct):
    email: UserEmailField
    password: UserPasswordField
    display_name: str
```

If you already use `UserPasswordField`, keep that import and switch only the `email` annotation from `str` to
`UserEmailField` when you want the built-in email validation contract. Those aliases only keep schema metadata aligned
with the built-in `UserCreate` and `UserUpdate` structs. Runtime password policy still lives on the manager side
through `password_validator_factory` or the default `require_password_length` validator.

If app-owned services, background jobs, or CLI commands also hash or verify passwords directly, call
`config.build_password_helper()` once after constructing `LitestarAuthConfig(...)` and reuse the returned helper
instead of building a separate default `PasswordHelper` instance in each call site. See
[Configuration](../configuration.md#canonical-manager-password-surface) for the combined secret/helper/schema contract.

`user_create_schema`, `user_update_schema`, and `user_read_schema` do not replace the built-in login, verification, reset-password, refresh, or TOTP request payloads. If you need different field names for those routes, mount or wrap the relevant controller factory instead of expecting `login_identifier` or `user_*_schema` to rename `identifier`, `email`, `token`, `refresh_token`, `pending_token`, or `code`.

## Multiple backends

Additional backends after the first are exposed under `/auth/{backend_name}/...`. Use distinct `name` values on each `AuthenticationBackend`.

## Rate limits

Pass `rate_limit_config` to apply throttles to sensitive endpoints without ad hoc middleware. See [Rate limiting](rate_limiting.md).

## Related

- [Configuration](../configuration.md)
- [Plugin API](../api/plugin.md)
- [Hooks](hooks.md)
