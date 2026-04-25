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

This redesign preserves the existing flat role guards and structured role exception context. It does not add permission
matrices or a policy DSL. The core plugin-owned auth/users controllers still do not auto-mount
role catalog or user-assignment endpoints. Operator-driven role administration lives on the
plugin-owned [`litestar roles`](roles_cli.md) CLI surface, and applications that want an HTTP
admin surface can opt into [HTTP role administration](role_admin_http.md).

### Role CLI compatibility

The `litestar roles` commands work only when the configured app still exposes the relational role
contract through both `LitestarAuthConfig.user_model` and `session_maker`.

Supported shapes:

- The bundled `litestar_auth.models.User`.
- A custom SQLAlchemy family composed from `UserRoleRelationshipMixin`, `RoleMixin`, and
  `UserRoleAssociationMixin`.
- An equivalent mapped contract that keeps `user.roles` as the normalized flat boundary while also
  exposing compatible relational mappings for `user.role_assignments`, assignment-row `role_name`,
  and the mapped role row.

Roleless models, legacy JSON-only role storage, or ad hoc non-relational `roles` properties remain
valid for app surfaces that do not need CLI role administration, but `litestar roles` fails closed
for those apps instead of inferring persistence behavior.

See [Role management CLI](roles_cli.md) for operator examples and destructive-delete semantics, or
[HTTP role administration](role_admin_http.md) for the supported contrib controller.

## User manager

Subclass [`BaseUserManager`](../api/manager.md) to implement **lifecycle hooks** and custom rules. The default no-op hook bodies live on `UserManagerHooks`, which `BaseUserManager` already inherits, so existing subclasses keep the same override surface. See the dedicated [Hooks](hooks.md) page for when each hook runs and timing considerations (`on_after_forgot_password`).

The plugin injects a request-scoped manager built with your `user_db_factory`, `backends`, and the default `BaseUserManager`-style constructor kwargs.

### Default builder contract

Without `user_manager_factory`, the plugin calls `user_manager_class(user_db, *, password_helper=..., security=..., password_validator=..., backends=..., login_identifier=..., superuser_role_name=..., unsafe_testing=...)`. The default builder always passes `security=UserManagerSecurity(...)`; when `user_manager_security` is unset, `LitestarAuthConfig.id_parser` is folded into that bundle (there is no separate `id_parser=` kwarg on the default builder call). `superuser_role_name` is additive, defaults to `"superuser"`, and is normalized with the same role-name rules as `user.roles`.

If your manager narrows or renames that constructor surface, configure `user_manager_factory` instead of relying on plugin-side capability detection. `password_validator_factory` belongs to that default builder contract: the plugin only resolves and injects the validator automatically when it still owns the default manager constructor call.

### Custom factory

Set `user_manager_factory` on `LitestarAuthConfig` for full control over manager construction when your manager does not follow the default builder contract (must match the `UserManagerFactory` contract). The factory receives `session`, `user_db`, `config`, and request-bound `backends`; it does not receive side-channel `password_helper`, `password_validator`, or `security` kwargs from the plugin. If your custom builder still wants password-policy enforcement or a custom superuser role, read those values from `config` and pass them explicitly inside the factory.

Plugin-managed manager construction inherits the plugin-owned secret-role validation baseline. If
your custom factory instantiates `BaseUserManager` (or a subclass), keep its
verification/reset/TOTP secrets aligned with `user_manager_security`. Outside explicit
`unsafe_testing`, both `LitestarAuth(config)` validation and direct manager construction raise
`ConfigurationError` when one configured value is reused across secret roles.

Generated controllers and plugin-owned flows also resolve one stable account-state callable from
`user_manager_class`: `require_account_state(user, *, require_verified=False)`. Inheriting
`BaseUserManager` keeps the built-in policy, and custom manager classes or adapters should forward
the same user argument and keyword-only `require_verified` flag when they customize account-state
handling.

## Plugin hooks

`LitestarAuthConfig` now exposes three opt-in plugin customization hooks for apps that want to
keep the plugin-owned route table but still own response envelopes, middleware wrapping, or
controller registration:

- `exception_response_hook` replaces the plugin's default auth-route `ClientException` formatter.
- `middleware_hook` receives the constructed auth `DefineMiddleware` before insertion.
- `controller_hook` receives the built controller list before registration.

All three default to `None`, so existing apps keep the current behavior unchanged.

### Exception response hook

Use `exception_response_hook` when plugin-owned auth errors should fit an app-specific response
envelope:

```python
from litestar.enums import MediaType
from litestar.response import Response


def auth_error_response(exc, request):
    status_code = getattr(exc, "status_code", 400)
    return Response(
        content={
            "error": {
                "code": exc.code,
                "message": str(exc),
                "path": request.url.path,
            },
        },
        status_code=status_code,
        media_type=MediaType.JSON,
        headers=getattr(exc, "headers", None),
    )


config.exception_response_hook = auth_error_response
```

Compatibility note: this hook replaces the plugin's default auth-error adapter for plugin-owned
routes. Route-local request-body decode / validation handlers keep their existing payload contract;
mount custom controllers when those routes also need a different envelope.

### Middleware hook

Use `middleware_hook` when the app needs to wrap the plugin-owned auth middleware instead of
rebuilding the middleware stack manually:

```python
from litestar.middleware import DefineMiddleware

from litestar_auth.authentication import LitestarAuthMiddleware


class AuthHeaderMiddleware(LitestarAuthMiddleware):
    async def __call__(self, scope, receive, send):
        async def send_with_header(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-auth-hook", b"enabled"))
                message = {**message, "headers": headers}
            await send(message)

        await super().__call__(scope, receive, send_with_header)


def wrap_auth_middleware(middleware: DefineMiddleware) -> DefineMiddleware:
    return DefineMiddleware(AuthHeaderMiddleware, *middleware.args, **middleware.kwargs)


config.middleware_hook = wrap_auth_middleware
```

The hook runs after the plugin has already derived CSRF settings and auth-cookie names, so the
replacement middleware receives the same constructor args the plugin would have inserted.

### Controller hook

Use `controller_hook` when you want to drop or replace parts of the generated route table without
forking the plugin:

```python
def filter_plugin_controllers(controllers):
    return [
        controller
        for controller in controllers
        if getattr(controller, "__name__", "") != "VerifyController"
    ]


config.controller_hook = filter_plugin_controllers
```

The hook receives fully built controller classes. Keep filtering explicit: dropping controllers
also drops the corresponding routes and their exception-handler wiring.

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


class ExtendedUserCreate(msgspec.Struct, forbid_unknown_fields=True):
    email: UserEmailField
    password: UserPasswordField
    display_name: str
```

If you already use `UserPasswordField`, keep that import and switch only the `email` annotation from `str` to
`UserEmailField` when you want the built-in email validation contract. Those aliases only keep schema metadata aligned
with built-in credential-bearing structs such as `UserCreate`, `AdminUserUpdate`, and
`ChangePasswordRequest`. Runtime password policy still lives on the manager side through
`password_validator_factory` or the default `require_password_length` validator; self-service
profile updates should not include `password`.

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
    roles: list[str]
    display_name: str


class ExtendedUserUpdate(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
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
`config.resolve_password_helper()` once after constructing `LitestarAuthConfig(...)` and reuse the returned helper
instead of building a separate default `PasswordHelper` instance in each call site. See
[Configuration](../configuration.md#manager-password-surface) for the combined secret/helper/schema contract.

`user_create_schema`, `user_update_schema`, and `user_read_schema` do not replace the built-in login, verification, reset-password, refresh, or TOTP request payloads. If you need different field names for those routes, mount or wrap the relevant controller factory instead of expecting `login_identifier` or `user_*_schema` to rename `identifier`, `email`, `token`, `refresh_token`, `pending_token`, or `code`.

## Multiple backends

Additional backends after the first are exposed under `/auth/{backend_name}/...`. Use distinct `name` values on each `AuthenticationBackend`.

## Rate limits

Pass `rate_limit_config` to apply throttles to sensitive endpoints without ad hoc middleware. See [Rate limiting](rate_limiting.md).

## Related

- [Configuration](../configuration.md)
- [Plugin API](../api/plugin.md)
- [Hooks](hooks.md)
