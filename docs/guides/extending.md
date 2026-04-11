# Extending litestar-auth

## User model

Subclass the provided [`User`](../api/models.md) (or follow the same contract) and point
`LitestarAuthConfig.user_model` at your class. Keep sensitive fields out of public schemas via
`user_read_schema` / msgspec structs.

The bundled user contract now includes a non-null flat `roles` collection in addition to the
existing email/password/account-state fields. The bundled `User` gets that surface from
`UserRoleRelationshipMixin`, and the bundled persistence layer now stores membership in sibling
`Role` / `UserRole` tables instead of a JSON column on the user row. `RoleCapableUserProtocol` is
the dedicated typing surface for that capability.

Migration note: if you previously persisted the bundled `user.roles` JSON column, or copied that
column shape onto an app-owned model, create relational role tables, normalize and deduplicate the
stored role names, backfill one association row per `(user, role)` pair, and then switch the app
to the bundled `Role` / `UserRole` models or a custom `UserRoleRelationshipMixin` +
`RoleMixin` / `UserRoleAssociationMixin` family. Keep `user.roles: Sequence[str]` as the boundary
seen by DTOs, managers, and guards even when storage becomes relational.

This redesign preserves the existing flat role guards and payloads. It does not add permission
matrices, role-management endpoints, or a policy DSL.

## User manager

Subclass [`BaseUserManager`](../api/manager.md) to implement **lifecycle hooks** and custom rules. See the dedicated [Hooks](hooks.md) page for when each hook runs and timing considerations (`on_after_forgot_password`).

The plugin injects a request-scoped manager built with your `user_db_factory`, `backends`, and the canonical `BaseUserManager`-style constructor kwargs.

### Default builder contract

Without `user_manager_factory`, the plugin calls `user_manager_class(user_db, *, password_helper=..., security=..., password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)`. When `user_manager_security` is unset, the default builder passes `id_parser=...` directly instead of folding it into `security`.

If your manager narrows or renames that constructor surface, configure `user_manager_factory` instead of relying on plugin-side capability detection. `password_validator_factory` belongs to that default builder contract: the plugin only resolves and injects the validator automatically when it still owns the canonical manager constructor call.

### Custom factory

Set `user_manager_factory` on `LitestarAuthConfig` for full control over manager construction when your manager does not follow the default builder contract (must match the `UserManagerFactory` contract). The factory receives `session`, `user_db`, `config`, and request-bound `backends`; it does not receive side-channel `password_helper`, `password_validator`, or `security` kwargs from the plugin. If your custom builder still wants password-policy enforcement, build and pass that validator explicitly inside the factory.

Plugin-managed manager construction inherits the plugin-owned secret-role reuse baseline. If your
custom factory instantiates `BaseUserManager` (or a subclass) with the same
verification/reset/TOTP secrets that were already validated during `LitestarAuth(config)`, manager
construction suppresses the duplicate warning. If the custom factory diverges from that
config-owned surface, the manager constructor surfaces the additional warning for the manager-owned
roles it actually wires. Keep custom factories aligned with `user_manager_security` unless you
intentionally want the factory-built manager to carry that additional warning.

Generated controllers and plugin-owned flows also resolve one stable account-state callable from
`user_manager_class`: `require_account_state(user, *, require_verified=False)`. Inheriting
`BaseUserManager` keeps the built-in policy, and custom manager classes or adapters should forward
the same user argument and keyword-only `require_verified` flag when they customize account-state
handling.

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

When you want custom DTOs to stay aligned with the built-in role-aware user contract, add `roles` to
your read/update structs and keep registration schemas non-privileged:

```python
import uuid

import msgspec

from litestar_auth.schemas import UserEmailField, UserPasswordField


class ExtendedUserRead(msgspec.Struct):
    id: uuid.UUID
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: list[str]
    display_name: str


class ExtendedUserUpdate(msgspec.Struct, omit_defaults=True):
    email: UserEmailField | None = None
    password: UserPasswordField | None = None
    roles: list[str] | None = None
    display_name: str | None = None
```

With that shape, the built-in controllers stay fail-closed: public registration still strips
`roles`, `PATCH /users/me` removes `roles` and other privileged fields before calling the manager,
and superuser `PATCH /users/{user_id}` can persist validated role membership through the same
`user_update_schema`.

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
