# Models

Package `litestar_auth.models` exposes the reference **`User`**, **`Role`**, **`UserRole`**, and
**`OAuthAccount`** ORM models plus the side-effect-free mixins behind the bundled model family.
Names are loaded lazily (PEP 562) when accessed on the package.

## Import paths

| Goal | Import |
|------|--------|
| Shared auth-model mixins without registering reference mappers | `from litestar_auth.models.mixins import UserModelMixin, UserAuthRelationshipMixin, UserRoleRelationshipMixin, RoleMixin, UserRoleAssociationMixin, OAuthAccountMixin, AccessTokenMixin, RefreshTokenMixin` |
| Bundled `AccessToken` / `RefreshToken` mapper bootstrap | `from litestar_auth.models import import_token_orm_models` |
| Bundled role tables without loading reference `User` | `from litestar_auth.models.role import Role, UserRole` |
| OAuth table contract **without** loading reference `User` | `from litestar_auth.models.oauth import OAuthAccount` |
| Reference `User` (and typical tests / quickstarts) | `from litestar_auth.models import User` or `from litestar_auth.models.user import User` |

Use [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models) as the
main ORM setup guide for token bootstrap lifecycle, relational role composition, custom model
families, `SQLAlchemyUserDatabase`, and password-column customization. Use the [Custom user +
OAuth cookbook](../cookbook/custom_user_oauth.md) when the application owns the `user` table.

Avoid `from litestar_auth.models import User` (or the `user` submodule) in apps that already map table `user` to a custom model. That import registers the bundled reference mapper and conflicts with an app-owned mapping. Likewise, importing `OAuthAccount` from `litestar_auth.models.oauth` only keeps the reference `User` lazy; when the app owns a different user class, table, or registry, prefer an `OAuthAccountMixin` subclass that points back at the custom user contract.

`import_token_orm_models()` remains the explicit helper for bundled token metadata bootstrap and Alembic-style autogenerate. `LitestarAuth.on_app_init()` now calls the same helper lazily for plugin-managed runtime when bundled DB-token models are active, so no extra import side effect is required only to make the plugin work.

For custom SQLAlchemy models, compose the mixins on your own declarative base instead of copying
columns or relationship wiring from the reference classes.
[Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models) covers the full
support matrix and migration notes.

## Lazy imports and IDE support

`litestar_auth.models` exposes names such as `User` and `OAuthAccount` through [PEP
562](https://peps.python.org/pep-0562/) `__getattr__` so that **importing the package does not
register SQLAlchemy mappers** or run other ORM side effects until a symbol is accessed.

Static type checkers still see those symbols with full annotations (the package uses
`TYPE_CHECKING`-friendly patterns for stubs and forward references). Some IDEs cannot resolve
**go to definition** or offer reliable autocomplete through a runtime `__getattr__` hook. For full
IDE support—jump to definition, rename, and completion—import from the concrete modules directly:

- `from litestar_auth.models.user import User`
- `from litestar_auth.models.oauth import OAuthAccount`

The [import paths](#import-paths) table restates the same guidance in task-oriented form.

## `UserModelMixin` hook

`UserModelMixin` keeps the runtime attribute contract on `hashed_password`. When an app-owned user table only needs a different SQL column name, set `auth_hashed_password_column_name` on the custom user class:

```python
class CustomUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "custom_user"
    auth_hashed_password_column_name = "password_hash"
```

`BaseUserManager`, `SQLAlchemyUserDatabase`, and JWT password fingerprinting still read and write `user.hashed_password`; only the SQL column name changes. If an app needs more than a column-name remap, it can still own the mapped attribute directly with `hashed_password = mapped_column(...)` on the app model.

## `UserAuthRelationshipMixin` hooks

`UserAuthRelationshipMixin` keeps the bundled inverse relationship contract by default: `back_populates="user"` on `access_tokens`, `refresh_tokens`, and `oauth_accounts`, with SQLAlchemy's normal loader behavior and inferred foreign-key linkage. Override only the narrow class hooks the mixin documents:

- `auth_access_token_model`, `auth_refresh_token_model`, `auth_oauth_account_model` point those inverse relationships at custom mapped classes, or to `None` when a branch is intentionally omitted.
- `auth_token_relationship_lazy` forwards one optional `lazy=` setting to both token collections.
- `auth_oauth_account_relationship_lazy` forwards one optional `lazy=` setting to `oauth_accounts`.
- `auth_oauth_account_relationship_foreign_keys` forwards one optional `foreign_keys=` hint to `oauth_accounts`.

The mixin does not accept arbitrary `relationship()` kwargs. For behavior outside those hooks, keep an app-owned explicit relationship definition.

## Relational role hooks

`UserRoleRelationshipMixin` is the supported user-side role facade. It keeps
`user.roles -> list[str]` as the normalized public contract while persisting membership through
relationship rows instead of a JSON column on the user table.

- `auth_user_role_model` points `role_assignments` at the association-row mapper.
- `auth_user_role_relationship_lazy` forwards one optional `lazy=` setting to
  `role_assignments`.

`RoleMixin` and `UserRoleAssociationMixin` provide the sibling tables behind that facade:

- `RoleMixin` maps the global role catalog row (`name`) plus inverse `user_assignments`.
- `UserRoleAssociationMixin` maps the `(user_id, role_name)` association row and the `user` /
  `role` relationships.
- The association mixin hooks (`auth_user_model`, `auth_user_table`, `auth_role_model`,
  `auth_role_table`) let apps point the same boilerplate at custom table names and mapped classes.

The bundled `User` model composes `UserRoleRelationshipMixin`, and the bundled `Role` /
`UserRole` models are the reference implementation of the same contract.

## Role shape

The bundled relational role family consists of:

- `role.name` — normalized global role name, primary key
- `user_role.user_id` — foreign key to `user.id`, part of the composite primary key
- `user_role.role_name` — foreign key to `role.name`, part of the composite primary key

At the library boundary, the user contract is still the normalized flat `roles: list[str]`
surface consumed by managers, schemas, and guards. The relational tables are an internal
persistence detail of the bundled/custom SQLAlchemy model family, not a change to the higher-level
role API.

## Migrating from legacy JSON roles

If an existing deployment still stores roles in a JSON column on the user row, migrate in this
order:

1. Create `role` and `user_role`, or the equivalent custom tables built from
   `RoleMixin` / `UserRoleAssociationMixin`.
2. Normalize and deduplicate each stored role array with the same trim/lowercase rules used by the
   library.
3. Backfill one `role` row per normalized name and one `user_role` row per `(user, role)` pair.
4. Switch the app to the bundled `Role` / `UserRole` models or a custom mixin-composed role family.
5. Remove or ignore the legacy JSON column once reads and writes use relational membership.

This ORM redesign does not change the higher-level auth contract: managers, schemas, and guards
still operate on flat normalized `roles`, and the library still does not provide RBAC permission
matrices or policy DSLs.

## `oauth_account` shape

The library table (bundled `OAuthAccount`) includes at least:

- `id` — UUID primary key (from `UUIDBase`)
- `user_id` — FK to `user.id`, not null
- `oauth_name` — `String(100)`
- `account_id` — `String(255)`
- `account_email` — `String(320)`
- `access_token` — `EncryptedString`-backed (length 4096), Fernet when a key is configured
- `expires_at` — integer epoch or null
- `refresh_token` — optional, same encryption type as access token
- Unique constraint **`uq_oauth_account_provider_identity`** on `(oauth_name, account_id)`

Token encryption uses `litestar_auth.oauth_encryption` and `OAuthConfig.oauth_token_encryption_key` (see [OAuth guide](../guides/oauth.md)).

For audit columns (`created_at` / `updated_at`), use one mapped class per table; see [OAuth guide — audit columns](../guides/oauth.md#audit-columns-on-oauth_account).

::: litestar_auth.models
