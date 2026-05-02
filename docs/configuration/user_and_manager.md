# User and Manager

Use this page for user-model requirements, bundled ORM mixins, token model composition, role-capable user models, and the SQLAlchemy user store contract.

## Custom SQLAlchemy `User` and token models

`LitestarAuthConfig.user_model` must satisfy **`UserProtocol`** (see [Types](../api/types.md)): at minimum the fields and behaviors your chosen `BaseUserManager` and strategies use (`id`, `email`, `hashed_password`, `is_active`, `is_verified`, `totp_secret`, `recovery_codes` as applicable). When your app wants the library's flat role-membership contract, expose `roles: Sequence[str]` and satisfy **`RoleCapableUserProtocol`**; superuser status is derived from membership in the configured superuser role, not from a model attribute. The bundled `User` already provides that `roles` collection, and custom SQLAlchemy model families can add it with `UserRoleRelationshipMixin`.

When `totp_config` is set, plugin startup also validates that `user_model` exposes the
**`TotpUserProtocol`** fields (`email` and `totp_secret`). A model missing either field fails
before routes are mounted instead of failing on the first login request that reaches 2FA.
`UserModelMixin` also provides `recovery_codes`, a nullable JSON column that maps HMAC-SHA-256
lookup digests to Argon2 recovery-code hashes. `SQLAlchemyUserDatabase` exposes the
set/find/consume helpers that later recovery-code flows use; custom stores should keep the same
lookup-index contract and make consumption single-use.

The built-in `UserRead` / `UserUpdate` schemas now also assume that same `roles` attribute. Apps
that keep the default register/verify/reset/users controllers should either expose
`roles: Sequence[str]` on the user model or provide custom `user_read_schema` / `user_update_schema`
types that intentionally omit role fields. Plugin validation fails fast when an enabled built-in
route surface still uses a schema with `roles` against a `user_model` that does not expose that
attribute.

This section is the main ORM integration guide for bundled token bootstrap, mixin-composed
custom model families, relational role composition, `SQLAlchemyUserDatabase`, and
password-column hook.

| Need | Recommended path | Notes |
| ---- | -------------- | ----- |
| Bundled token metadata bootstrap | `from litestar_auth.models import import_token_orm_models` | Explicit helper for metadata registration and Alembic-style autogenerate. |
| Bundled token runtime bootstrap | `DatabaseTokenAuthConfig` / `LitestarAuthConfig(..., database_token_auth=...)` | `LitestarAuth.on_app_init()` calls the same helper lazily when bundled DB-token models are active. |
| App-owned ORM classes | `from litestar_auth.models.mixins import UserModelMixin, UserAuthRelationshipMixin, UserRoleRelationshipMixin, RoleMixin, UserRoleAssociationMixin, AccessTokenMixin, RefreshTokenMixin, OAuthAccountMixin` | Compose them on the application's own registry instead of copying mapper wiring. |
| App-owned relational role tables | `from litestar_auth.models.mixins import UserRoleRelationshipMixin, RoleMixin, UserRoleAssociationMixin` | Optional role persistence path that keeps `user.roles` as the normalized flat contract. |
| Custom token strategy tables | `DatabaseTokenModels(...)` | Only needed when `DatabaseTokenStrategy` should use custom token models at runtime. |
| SQLAlchemy user store | `litestar_auth.db.sqlalchemy.SQLAlchemyUserDatabase` | `user_model` is required; `oauth_account_model` is optional unless OAuth methods are used. |
| Custom password column name | `UserModelMixin.auth_hashed_password_column_name` | Keeps the runtime attribute contract on `user.hashed_password` when only the SQL column name changes. |

### Bundled `AccessToken` / `RefreshToken` lifecycle

`litestar_auth.models.import_token_orm_models()` is the explicit mapper-registration entrypoint for the library token models:

```python
from litestar_auth.models import import_token_orm_models

AccessToken, RefreshToken = import_token_orm_models()
```

Call that helper yourself during metadata registration or Alembic-style autogenerate so token discovery stays with the models boundary. For plugin-managed runtime, `LitestarAuth.on_app_init()` now calls the same helper lazily when the active DB-token strategy still uses the bundled `AccessToken` / `RefreshToken` classes, so apps no longer need a separate import side effect only to make the plugin work. Keep the explicit helper for metadata/Alembic flows or any non-plugin code path that needs the tables.

If you use the library `AccessToken` and `RefreshToken` models, your user class should declare relationships compatible with them instead of copying mapper wiring from the reference `User` class:

- Table names: `access_token`, `refresh_token`; `user_id` foreign keys target **`user.id`** (your user model’s table must be named `user`, or you must align FKs and relationships with your schema).
- Compose the side-effect-free model mixins from `litestar_auth.models.mixins` when you want the bundled field and relationship contract without copying boilerplate from the reference ORM classes:

```python
from advanced_alchemy.base import UUIDBase

from litestar_auth.models.mixins import UserAuthRelationshipMixin, UserModelMixin


class User(UserModelMixin, UserAuthRelationshipMixin, UUIDBase):
    __tablename__ = "user"
```

`UserModelMixin` provides the bundled email / password / account-state columns, while `UserAuthRelationshipMixin` provides the `access_tokens`, `refresh_tokens`, and `oauth_accounts` relationships with the same `back_populates="user"` wiring the bundled models expect. Leave its relationship-option hooks unset to keep the default contract: SQLAlchemy's normal loader behavior plus inferred foreign-key linkage for `oauth_accounts`. Set any `auth_*_model` hook to `None` when a custom user only composes part of the auth model family instead of all three relationships.

### Optional relational role contract

`UserModelMixin` no longer stores roles on the user row. When your app wants the library-managed
role contract, compose `UserRoleRelationshipMixin` on the user class and add the sibling role
tables with `RoleMixin` and `UserRoleAssociationMixin`. That keeps the public
`user.roles -> list[str]` surface while persisting membership through dedicated relational rows.

```python
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy.orm import DeclarativeBase

from litestar_auth.models.mixins import (
    RoleMixin,
    UserModelMixin,
    UserRoleAssociationMixin,
    UserRoleRelationshipMixin,
)


class RolesBase(DeclarativeBase):
    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class RolesUUIDBase(UUIDPrimaryKey, RolesBase):
    __abstract__ = True


class MyUser(UserModelMixin, UserRoleRelationshipMixin, RolesUUIDBase):
    __tablename__ = "my_user"

    auth_user_role_model = "MyUserRole"


class MyRole(RoleMixin, RolesBase):
    __tablename__ = "my_role"

    auth_user_role_model = "MyUserRole"


class MyUserRole(UserRoleAssociationMixin, RolesBase):
    __tablename__ = "my_user_role"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"
    auth_role_model = "MyRole"
    auth_role_table = "my_role"
```

That custom model family persists one normalized global role row per name plus one association row
per `(user, role)` pair. Managers, schemas, and guards still consume the flat normalized
`roles: list[str]` user contract.

Migration note: existing deployments that previously used the bundled `user.roles` JSON column (or
an app-owned copy of that column) should create the new `role` and `user_role` tables, normalize
and deduplicate existing role arrays, backfill association rows, and then remove or ignore the
legacy JSON column once application code points at the relational model family. Custom user models
that want role-capable typing and the built-in role-aware surfaces should compose the mixins above
or provide an equivalent normalized flat `roles` contract.

Recommended upgrade sequence:

1. Create the new `role` and `user_role` tables, or the equivalent custom tables built from
   `RoleMixin` and `UserRoleAssociationMixin`.
2. Read every legacy JSON roles array, trim/lowercase/deduplicate/sort the values with the same
   normalization semantics the manager uses, and upsert one `role` row per normalized name.
3. Backfill one association row per `(user_id, role_name)` pair.
4. Switch application imports and mappings to the bundled `Role` / `UserRole` models or the custom
   mixin-composed role family.
5. Drop or ignore the legacy JSON column after the application is fully reading from relational
   membership.

This redesign changes persistence only. Guards, DTOs, and manager APIs still exchange the same flat
normalized `user.roles` values, and the library still does not add permission matrices or policy
DSLs. The core plugin-owned auth/users route table does not auto-mount role-management endpoints;
use the plugin-owned [`litestar roles`](../guides/roles_cli.md) CLI surface or the opt-in
[HTTP role administration](../guides/role_admin_http.md) contrib controller when you need
catalog or assignment administration.

If the user table is not `user`, or if you want app-owned token / OAuth tables, compose the sibling mixins on your own declarative base and point the hooks at the app's class names and table names instead of copying relationship code:

```python
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy.orm import DeclarativeBase

from litestar_auth.models.mixins import (
    AccessTokenMixin,
    OAuthAccountMixin,
    RefreshTokenMixin,
    UserAuthRelationshipMixin,
    UserModelMixin,
)


class AppBase(DeclarativeBase):
    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class AppUUIDBase(UUIDPrimaryKey, AppBase):
    __abstract__ = True


class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "my_user"

    auth_access_token_model = "MyAccessToken"
    auth_refresh_token_model = "MyRefreshToken"
    auth_oauth_account_model = "MyOAuthAccount"
    auth_token_relationship_lazy = "noload"
    auth_oauth_account_relationship_lazy = "selectin"
    auth_oauth_account_relationship_foreign_keys = "MyOAuthAccount.user_id"


class MyAccessToken(AccessTokenMixin, AppBase):
    __tablename__ = "my_access_token"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"


class MyRefreshToken(RefreshTokenMixin, AppBase):
    __tablename__ = "my_refresh_token"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"


class MyOAuthAccount(OAuthAccountMixin, AppUUIDBase):
    __tablename__ = "my_oauth_account"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"
```

`auth_token_relationship_lazy` applies the same `lazy=` option to both token collections, while `auth_oauth_account_relationship_lazy` and `auth_oauth_account_relationship_foreign_keys` only affect `oauth_accounts`. Those hooks are intentionally narrow: use them for the documented loader-strategy or explicit-foreign-key cases, and keep app-owned relationship definitions only when you truly need behavior beyond that contract.

When those custom token classes back `DatabaseTokenStrategy`, pass them explicitly via `DatabaseTokenModels` so the strategy binds repositories, refresh rotation, logout cleanup, and expired-token cleanup to your tables instead of the bundled defaults. Model registration still starts in `litestar_auth.models`; `DatabaseTokenModels` only tells the strategy which mapped token classes to use at runtime:

```python
from litestar_auth.authentication import AuthenticationBackend
from litestar_auth.authentication.strategy import DatabaseTokenModels, DatabaseTokenStrategy
from litestar_auth.authentication.transport import BearerTransport

token_models = DatabaseTokenModels(
    access_token_model=MyAccessToken,
    refresh_token_model=MyRefreshToken,
)
backend = AuthenticationBackend(
    name="database",
    transport=BearerTransport(),
    strategy=DatabaseTokenStrategy(
        session=session,
        token_hash_secret="replace-with-32+-char-db-token-secret",
        token_models=token_models,
    ),
)
```

`DatabaseTokenAuthConfig` / `LitestarAuthConfig(..., database_token_auth=...)` remains the direct shortcut for the bundled `AccessToken` / `RefreshToken` tables. The plugin bootstraps those bundled token mappers at `on_app_init()` for runtime use, but that does not replace the explicit helper for metadata bootstrap or Alembic autogenerate. Use the manual backend assembly above only when you intentionally replace the token ORM classes or need another transport/strategy combination.

### `SQLAlchemyUserDatabase` contract

`LitestarAuthConfig.user_db_factory` defaults to a lazy `SQLAlchemyUserDatabase(session, user_model=config.user_model)` factory. Override it only when you need custom adapter wiring, usually to supply `oauth_account_model`:

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase


def user_db_factory(session):
    return SQLAlchemyUserDatabase(
        session,
        user_model=MyUser,
        oauth_account_model=MyOAuthAccount,
    )
```

`SQLAlchemyUserDatabase` requires **`user_model`** and accepts optional **`oauth_account_model`**. If you use OAuth methods (`get_by_oauth_account`, `upsert_oauth_account`) without providing `oauth_account_model`, a `TypeError` is raised.

For TOTP recovery codes, the adapter expects the user model to expose
`recovery_codes: dict[str, str] | None`. The bundled `UserModelMixin` maps this as JSON to keep
custom model composition simple; verification performs a keyed lookup before one Argon2 verify,
and consumption removes the matched lookup entry under a row-level lock when the database supports
`SELECT ... FOR UPDATE`.

`BaseUserStore` and `BaseOAuthAccountStore` are runtime-checkable `Protocol` contracts. Custom stores do not need to inherit from either symbol as long as they implement the documented async methods; explicit inheritance remains optional when you want to declare that compatibility on the class itself.

When `oauth_account_model` is provided, the adapter validates that its declared user contract matches `user_model`:

- Same declarative registry
- Matching `auth_user_model` / `auth_user_table` values when those hooks exist

Supported `oauth_account_model` choices are:

- The bundled `OAuthAccount` from `litestar_auth.models.oauth` only when the user side is still the same-registry `User` mapped to the `user` table
- An app-owned `OAuthAccountMixin` subclass whose `auth_user_model` / `auth_user_table` settings match the custom user class

If the custom user also needs a non-default loader strategy for `oauth_accounts`, set `auth_oauth_account_relationship_lazy` and, only when SQLAlchemy needs an explicit hint, `auth_oauth_account_relationship_foreign_keys`.

Migration note: older setups that paired `litestar_auth.models.oauth.OAuthAccount` with a renamed user class, a non-`user` table, or a different declarative registry should switch to an `OAuthAccountMixin` subclass before upgrading. See [Custom user + OAuth](../cookbook/custom_user_oauth.md).

### Custom password column names

If your schema stores password hashes under a different SQL column name, keep the runtime `hashed_password` attribute and set `auth_hashed_password_column_name` on the custom user model:

```python
class CustomUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "custom_user"

    auth_hashed_password_column_name = "password_hash"
```

`BaseUserManager`, `SQLAlchemyUserDatabase`, and JWT fingerprinting still interact with `user.hashed_password`; only the SQL column name changes. Use the hook above when the only customization is the SQL column name. If the app needs full control over the mapped attribute, it can still declare `hashed_password = mapped_column(...)` directly on its own model.
