# Models

Package `litestar_auth.models` exposes the reference **`User`**, **`Role`**, **`UserRole`**,
**`OAuthAccount`**, **`ApiKey`**, **`Organization`**, and **`OrganizationMembership`** ORM models
plus the side-effect-free mixins behind the bundled model family.
Names are loaded lazily (PEP 562) when accessed on the package.

## Import paths

| Goal | Import |
|------|--------|
| Shared auth-model mixins without registering reference mappers | `from litestar_auth.models.mixins import UserModelMixin, UserAuthRelationshipMixin, UserRoleRelationshipMixin, RoleMixin, UserRoleAssociationMixin, OrganizationMixin, OrganizationMembershipMixin, OAuthAccountMixin, ApiKeyMixin, AccessTokenMixin, RefreshTokenMixin` |
| Bundled `AccessToken` / `RefreshToken` / `RefreshTokenConsumedDigest` mapper bootstrap | `from litestar_auth.models import import_token_orm_models` |
| Bundled role tables without loading reference `User` | `from litestar_auth.models.role import Role, UserRole` |
| Bundled organization tables without loading root package models | `from litestar_auth.models.organization import Organization, OrganizationMembership` |
| API-key table contract **without** loading reference `User` | `from litestar_auth.models.api_key import ApiKey` |
| OAuth table contract **without** loading reference `User` | `from litestar_auth.models.oauth import OAuthAccount` |
| Reference `User` (and typical tests / quickstarts) | `from litestar_auth.models import User` or `from litestar_auth.models.user import User` |

Use [Configuration](../configuration/user_and_manager.md#custom-sqlalchemy-user-and-token-models) as the
main ORM setup guide for token bootstrap lifecycle, relational role composition, custom model
families, `SQLAlchemyUserDatabase`, and password-column customization. Use the [Custom user +
OAuth cookbook](../cookbook/custom_user_oauth.md) when the application owns the `user` table.

Avoid `from litestar_auth.models import User` (or the `user` submodule) in apps that already map table `user` to a custom model. That import registers the bundled reference mapper and conflicts with an app-owned mapping. Likewise, importing `OAuthAccount` from `litestar_auth.models.oauth` only keeps the reference `User` lazy; when the app owns a different user class, table, or registry, prefer an `OAuthAccountMixin` subclass that points back at the custom user contract.

`import_token_orm_models()` remains the explicit helper for bundled token metadata bootstrap and Alembic-style autogenerate. It returns `AccessToken`, `RefreshToken`, and `RefreshTokenConsumedDigest` so the bundled refresh-token consumed-digest lookup table is part of the documented bootstrap surface. `LitestarAuth.on_app_init()` also calls the same helper lazily for plugin-managed runtime when bundled DB-token models are active, so no extra import side effect is required only to make the plugin work. `DatabaseTokenModels` defaults to those same three classes at runtime; pass `consumed_refresh_token_digest_model=...` only when a custom consumed-digest lookup table should back refresh-token replay detection.

For custom SQLAlchemy models, compose the mixins on your own declarative base instead of copying
columns or relationship wiring from the reference classes.
[Configuration](../configuration/user_and_manager.md#custom-sqlalchemy-user-and-token-models) covers the full
support matrix and migration notes.

## `access_token` session ownership

`AccessTokenMixin.session_id` is a nullable, indexed copy of the public refresh-session id. Access-only
flows leave it `null`; login, TOTP verification, and refresh rotation link newly issued DB access tokens
to the corresponding refresh session. The DB strategy uses that index to invalidate only the access
tokens owned by a revoked, expired, or replay-compromised session.

## `refresh_token` session metadata

The bundled `RefreshTokenMixin` stores refresh tokens as keyed digests only. It also adds the DB-backed
session metadata required by session/device management:

- `session_id` — a generated UUID string used as the stable public session identifier. It is distinct
  from `token` and must be the only refresh-session identifier exposed by API responses.
- `created_at` — the original refresh session creation timestamp.
- `last_used_at` — nullable timestamp set when a refresh token is successfully rotated.
- `client_metadata` — nullable bounded JSON metadata derived from login/refresh requests. The built-in
  controller stores only a normalized `user_agent` value capped at 255 characters.

Refresh rotation keeps the same `session_id` and `created_at`, atomically replaces only the token digest,
records the consumed digest, updates `last_used_at`, and refreshes `client_metadata` when request metadata
is available. Re-presenting any consumed refresh token is treated as a compromise signal and revokes the
entire refresh-session chain. The bundled strategy also stores each consumed digest in
`refresh_token_consumed_digest`, keyed by digest with an index on `session_id`, so replay checks perform an
indexed equality lookup instead of scanning refresh-token rows.

Existing deployments using the bundled `refresh_token` table must add `session_id`, `last_used_at`, and
`client_metadata` columns before using this version. Deployments upgrading to refresh-token reuse detection
must also create the `refresh_token_consumed_digest` lookup table. Backfill `session_id` with a unique
non-sensitive UUID per existing row. If the deployment is upgrading from a version that stored legacy
digests in `refresh_token.consumed_token_digests`, backfill every legacy digest into
`refresh_token_consumed_digest`, then drop the legacy JSON column before serving traffic with the new code.
Skipping the lookup-table backfill means refresh tokens consumed before the upgrade and replayed after
it are rejected as ordinary missing tokens instead of revoking the compromised session chain until the
legacy sessions expire or are explicitly revoked. Existing custom refresh-token models passed through
`DatabaseTokenModels` must expose mapped `session_id`, `last_used_at`, and `client_metadata` attributes;
custom consumed-digest models must expose mapped `token_digest`, `session_id`, and `consumed_at` attributes.
Otherwise configuration fails fast with `ConfigurationError`.

## `api_key` shape

The bundled `ApiKeyMixin` stores API-key metadata and verifier material:

- `key_id` — public lookup id embedded in the raw credential.
- `hashed_secret` — keyed HMAC digest of the raw bearer secret.
- `encrypted_secret` — nullable encrypted raw secret for signing-required keys.
- `name`, `scopes`, `prefix_env`, `signing_required`, `expires_at`, `last_used_at`, `revoked_at`,
  `created_via`, and `client_metadata` — safe management metadata.

Import `ApiKey` from `litestar_auth.models.api_key` or lazily from `litestar_auth.models`. Use
`ApiKeyMixin` on a custom declarative base when the application owns the model family. The SQLAlchemy
store lives at `litestar_auth.db.sqlalchemy.SQLAlchemyApiKeyStore`; the lazy `litestar_auth.db`
package exports only `BaseApiKeyStore` and `ApiKeyData`.

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
- `from litestar_auth.models.organization import Organization, OrganizationMembership`

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

Relational role storage does not change the higher-level auth contract: managers, schemas, and
guards still operate on flat normalized `roles`, and the library does not provide RBAC permission
matrices or policy DSLs.

## Organization shape

The bundled organization family consists of:

- `organization.id` — UUID primary key
- `organization.slug` — normalized unique tenant slug, indexed
- `organization.name` — display name
- `organization.created_at` / `organization.updated_at` — server-managed audit timestamps
- `organization_membership.user_id` — foreign key to `user.id`, part of the composite primary key
- `organization_membership.organization_id` — foreign key to `organization.id`, part of the
  composite primary key
- `organization_membership.roles` — normalized JSON list of organization-scoped role names
- Unique constraint on `(user_id, organization_id)`

Import the reference models lazily from `litestar_auth.models` or directly from
`litestar_auth.models.organization`:

```python
from litestar_auth.models import Organization, OrganizationMembership
```

`OrganizationMixin` and `OrganizationMembershipMixin` are side-effect-free composition helpers for
custom declarative bases. The membership mixin reuses the same configurable user foreign-key
contract as other user-owned auth rows and adds configurable organization-table hooks.

Organization models are intentionally not exported from `litestar_auth` or `litestar_auth.db`.
`litestar_auth.db` exports only `BaseOrganizationStore`, `OrganizationData`, and `MembershipData`;
the SQLAlchemy adapter lives at `litestar_auth.db.sqlalchemy.SQLAlchemyOrganizationStore`.

Phase-1 organization persistence does not alter authorization behavior. There are no
organization-scoped guards, tenant-resolution middleware, JWT `org_id` claim, organization admin
routes, or automatic filters for application-owned tables.

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

Token encryption uses `litestar_auth.oauth_encryption` and `OAuthConfig.oauth_token_encryption_keyring` or the one-key `oauth_token_encryption_key` shortcut (see [OAuth guide](../guides/oauth.md)).

For audit columns (`created_at` / `updated_at`), use one mapped class per table; see [OAuth guide — audit columns](../guides/oauth.md#audit-columns-on-oauth_account).

::: litestar_auth.models
