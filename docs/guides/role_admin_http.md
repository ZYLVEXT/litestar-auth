# HTTP role administration

Use this guide for the supported HTTP role-management surface:
`litestar_auth.contrib.role_admin.RoleAdminExtension` or
`litestar_auth.contrib.role_admin.create_role_admin_controller(...)`.

!!! warning "Opt-in admin surface"
    `LitestarAuth` does not auto-mount role administration. Opt in with
    `RoleAdminExtension` or register the factory-built controller explicitly,
    keep the default `is_superuser` guard unless you have reviewed a stricter
    replacement, and treat guard overrides as security-sensitive application
    code.

!!! note "Contrib expectations"
    `litestar_auth.contrib.role_admin` is a public contrib module. It is
    supported, but it can evolve faster than the core plugin-owned auth/users
    route table. Read the changelog when upgrading and keep app-owned tests
    around the routes you mount.

## Mount it through the plugin

The plugin-managed path is `RoleAdminExtension`. It validates the role-admin
model prerequisites during plugin startup, contributes the generated controller
through the auth extension registry, and marks the route table as
litestar-auth-owned so route-scoped auth exception handlers apply to role-admin
errors.

```python
from uuid import UUID

from litestar import Litestar

from litestar_auth import LitestarAuth, LitestarAuthConfig
from litestar_auth.contrib.role_admin import RoleAdminExtension
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User


class UserManager(BaseUserManager[User, UUID]):
    pass


config = LitestarAuthConfig[User, UUID](
    session_maker=session_maker,
    user_model=User,
    user_manager_class=UserManager,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
    extensions=(RoleAdminExtension(),),
)

app = Litestar(plugins=[LitestarAuth(config)])
```

By default the extension mounts the same controller as the manual factory path:
`/roles` with `guards=[is_superuser]`.

```python
from litestar_auth.guards import has_any_role

config = LitestarAuthConfig[User, UUID](
    session_maker=session_maker,
    user_model=User,
    user_manager_class=UserManager,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
    extensions=(
        RoleAdminExtension(
            route_prefix="admin/roles",
            guards=[has_any_role("role_admin", "superuser")],
        ),
    ),
)
```

The extension does not add a new OpenAPI security scheme. It relies on the
schemes already registered by `LitestarAuthConfig.include_openapi_security`;
protected operations remain guarded by Litestar guards at runtime. If your
OpenAPI consumers require operation-level security metadata on role-admin
routes, add it through your application-level OpenAPI customization in the same
way you would for other app-owned guarded routes.

## Mount it alongside the plugin

The manual factory path remains public and supported. Build the controller from
the same `LitestarAuthConfig` instance that already wires your plugin:

```python
from uuid import UUID

from litestar import Litestar

from litestar_auth import LitestarAuth, LitestarAuthConfig
from litestar_auth.contrib.role_admin import create_role_admin_controller
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User


class UserManager(BaseUserManager[User, UUID]):
    pass


config = LitestarAuthConfig[User, UUID](
    session_maker=session_maker,
    user_model=User,
    user_manager_class=UserManager,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
)

RoleAdminController = create_role_admin_controller(config=config)

app = Litestar(
    plugins=[LitestarAuth(config)],
    route_handlers=[RoleAdminController],
)
```

That `config=` path keeps the HTTP controller aligned with the plugin-owned
session factory, `db_session_dependency_key`, role-model family resolution, and
manager construction used by the CLI and the rest of the auth stack. When using
this manual path, the factory still marks the generated controller as
litestar-auth-owned so scoped auth exception handling is preserved.

For direct grouped settings, pass `RoleAdminControllerConfig(...)` as
`controller_config=...`. The existing `config=...` keyword remains the
`LitestarAuthConfig` input for plugin-backed model resolution.

## What the factory does

- Resolves the relational role model family from `config.user_model` by
  default. You can still override `user_model`, `role_model`, or
  `user_role_model` explicitly when needed.
- Mounts under `/roles` by default. `RoleAdminExtension(route_prefix="admin/roles")`
  or `create_role_admin_controller(route_prefix="admin/roles")` becomes
  `/admin/roles`.
- Applies `guards=[is_superuser]` by default.
- Publishes the fixed contrib payloads from
  `litestar_auth.contrib.role_admin._schemas`:
  `RoleCreate`, `RoleUpdate`, `RoleRead`, and `UserBrief`.
- Returns paginated list payloads with the shape
  `{"items": [...], "total": int, "limit": int, "offset": int}`.
- Runs assign/unassign through `SQLAlchemyRoleAdmin.assign_user_roles()` and
  `.unassign_user_roles()`, which preserves `BaseUserManager.update(...)`
  lifecycle hooks instead of mutating relationship rows behind the manager.
  Those contrib paths opt into `allow_privileged=True` explicitly because role
  membership is part of the privileged manager surface.
- Preserves the same system-managed role invariants as the CLI: the configured
  `LitestarAuthConfig.superuser_role_name` (default `"superuser"`) catalog row
  cannot be deleted, and the final assignment for that role cannot be removed.

The HTTP reference for every route, status code, and role-admin `ErrorCode`
mapping lives in [HTTP API](../http_api.md#contrib-role-administration-opt-in).

## Override hooks

### Custom guard policy

Keep the default `is_superuser` guard unless you have a narrower
application-specific admin role and have reviewed the downgrade risk.

```python
from litestar_auth.guards import has_any_role

RoleAdminController = create_role_admin_controller(
    config=config,
    guards=[has_any_role("role_admin", "superuser")],
)
```

### Custom route prefix

```python
RoleAdminController = create_role_admin_controller(
    config=config,
    route_prefix="admin/roles",
)
```

### Explicit-model mounting without `config`

If you skip `config=` and pass explicit models, the generated handlers expect a
request-scoped session dependency. Assignment routes also require a
request-scoped `litestar_auth_user_manager` so role mutations still travel
through the manager lifecycle:

```python
RoleAdminController = create_role_admin_controller(
    user_model=User,
    role_model=Role,
    user_role_model=UserRole,
)
```

Use that lower-level path only when you intentionally do not want
config-driven assembly.

### Custom schemas or envelopes

`create_role_admin_controller(...)` does not take schema override parameters.
The supported contrib contract is the fixed `RoleCreate`, `RoleUpdate`,
`RoleRead`, and `UserBrief` payload family.

If you need different fields, response envelopes, or materially different
handler semantics, keep the contrib controller as your reference
implementation and fork to the cookbook path:

- [Cookbook: Custom role catalog administration API](../cookbook/role_admin_controller.md)
- [Cookbook: Testing a custom role administration controller](../cookbook/role_admin_tests.md)

## Production posture

- The module is opt-in. Nothing under `litestar_auth.contrib.role_admin` is
  auto-registered by the plugin.
- The default guard is intentionally strict. A weaker guard is a security
  posture change in your application, not a cosmetic customization.
- The controller stays aligned with the flat public `user.roles` contract. It
  does not expose raw `role` / `user_role` rows, permission matrices, or
  object-level RBAC policy.
- User identifiers on assignment routes are parsed UUID-first and then fall
  back to the configured model's primary-key shape, so the same controller can
  work with bundled UUID ids and integer-key custom models.

## Related

- [HTTP API](../http_api.md)
- [Role management CLI](roles_cli.md)
- [Extending](extending.md)
