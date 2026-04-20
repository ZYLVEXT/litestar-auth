# Role management CLI

`LitestarAuth` registers a plugin-owned `litestar roles` command group for operator-driven role
catalog and user-role administration. The commands use the active plugin configuration, the
configured SQLAlchemy session factory, and the same normalized flat `user.roles` contract already
used by guards, DTOs, and manager updates.

This guide covers the CLI path. If you need an HTTP admin surface, mount the opt-in
[HTTP role administration](role_admin_http.md) contrib controller. The core plugin-generated
auth/users route table still does not auto-mount role catalog or user-assignment endpoints, and
the library still does not expose raw `role` / `user_role` rows over HTTP.

## Prerequisites

`litestar roles ...` is available when all of these are true:

- Your app is wired through `LitestarAuth(config)`, so Litestar's CLI sees the plugin instance.
- `LitestarAuthConfig.session_maker` is configured.
- `LitestarAuthConfig.user_model` is a relational role-capable SQLAlchemy model family:
  - the bundled `litestar_auth.models.User`, or
  - a custom family built from `UserRoleRelationshipMixin`, `RoleMixin`, and
    `UserRoleAssociationMixin`, or an equivalent mapped relationship contract.
- The Litestar CLI can already resolve your application the same way it does for other `litestar`
  commands.

If the app is roleless, keeps roles only in a legacy JSON column, or exposes a non-relational
`roles` property, the command exits non-zero with a clear error instead of guessing how to persist
catalog and assignment changes.

## Normalization and safety rules

- Role names use the same trim/lowercase/deduplicate semantics as the public `user.roles`
  contract.
- `create`, `assign`, and `unassign` are idempotent against already-normalized state.
- `delete` fails closed when users still hold the role. Use `--force` only when you intentionally
  want to remove that role from every affected user as part of the delete.
- User-targeted commands select the target by `--email`. This CLI does not introduce user lookup by
  ID, username, or arbitrary filters.

## Catalog commands

List the deterministic normalized role catalog:

```bash
$ litestar roles list
['admin', 'billing']
```

Create one role. The CLI normalizes the name first, so repeated creates stay idempotent:

```bash
$ litestar roles create " Billing "
['admin', 'billing']
```

Delete one role that is no longer assigned to any user:

```bash
$ litestar roles delete billing
['admin']
```

Deleting an assigned role fails closed until you opt into the destructive path:

```bash
$ litestar roles delete admin
Error: Role admin will not delete role 'admin' while assignments still exist. Re-run with --force to remove dependent user-role assignments.
```

```bash
$ litestar roles delete --force admin
[]
```

## User-role commands

Assign roles to a user selected by email. Inputs are normalized before persistence:

```bash
$ litestar roles assign --email member@example.com " Billing " admin ADMIN
member@example.com: ['admin', 'billing', 'member']
```

Remove selected roles from the same user. Unrelated roles stay unchanged, and repeating the command
is safe:

```bash
$ litestar roles unassign --email member@example.com billing support
member@example.com: ['admin', 'member']
```

Read the current normalized membership for one user:

```bash
$ litestar roles show-user --email member@example.com
member@example.com: ['admin', 'member']
```

Unknown users fail clearly with a non-zero exit:

```bash
$ litestar roles show-user --email missing@example.com
Error: Role admin could not find a user with email 'missing@example.com'.
```

## Custom SQLAlchemy role tables

The CLI does not hard-code the bundled `Role` or `UserRole` table names. It resolves the active
role catalog and assignment model family from `LitestarAuthConfig.user_model`, so custom table
names built from `RoleMixin` and `UserRoleAssociationMixin` are supported.

Custom families must still preserve the documented relational role contract:

- `user.roles` remains the normalized flat public surface.
- `user.role_assignments` maps the assignment rows.
- Each assignment row exposes normalized `role_name` and a mapped `role` relationship.
- The role row exposes `name`.

If your custom model intentionally omits that relational shape, keep the app on the HTTP/user
surfaces only; the CLI is intentionally unavailable for that configuration.

## What does not change

- Guards, schemas, and manager updates still exchange flat normalized `roles: list[str]` values.
- The library still does not add permission matrices or object-level RBAC. HTTP role
  administration is available only through the opt-in contrib controller, not the core
  plugin-generated route table.
- The CLI is an operator workflow, not an end-user API surface.

## Related

- [Configuration](../configuration.md)
- [Extending](extending.md)
- [HTTP role administration](role_admin_http.md)
- [HTTP API](../http_api.md)
