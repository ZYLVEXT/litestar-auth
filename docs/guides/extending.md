# Extending litestar-auth

## User model

Subclass the provided [`User`](../api/models.md) (or follow the same column contract) and point `LitestarAuthConfig.user_model` at your class. Keep sensitive fields out of public schemas via `user_read_schema` / msgspec structs.

## User manager

Subclass [`BaseUserManager`](../api/manager.md) to implement **lifecycle hooks** and custom rules. See the dedicated [Hooks](hooks.md) page for when each hook runs and timing considerations (`on_after_forgot_password`).

The plugin injects a request-scoped manager built with your `user_db_factory`, `backends`, and optional `password_validator`.

### Constructor compatibility

If your manager needs **`password_validator`** or **`login_identifier`**, either accept them in `__init__` or set class attributes `accepts_password_validator` / `accepts_login_identifier` so the plugin can detect support.

### Custom factory

Set `user_manager_factory` on `LitestarAuthConfig` for full control over manager construction (must match the `UserManagerFactory` contract).

## Controllers and DTOs

Factory functions such as `create_auth_controller` live in `litestar_auth.controllers`. The plugin calls them internally based on flags like `include_register`. For advanced scenarios you can:

- Provide custom **msgspec** schemas via `user_create_schema`, `user_update_schema`, `user_read_schema`.
- Fork behavior inside your manager rather than replacing controllers first.

## Multiple backends

Additional backends after the first are exposed under `/auth/{backend_name}/...`. Use distinct `name` values on each `AuthenticationBackend`.

## Rate limits

Pass `rate_limit_config` to apply throttles to sensitive endpoints without ad hoc middleware. See [Rate limiting](rate_limiting.md).

## Related

- [Configuration](../configuration.md)
- [Plugin API](../api/plugin.md)
- [Hooks](hooks.md)
