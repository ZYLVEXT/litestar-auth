# Custom `User` model with OAuth mixins

Use this when your application maps auth tables to **your own** SQLAlchemy models (same Advanced Alchemy / declarative registry as the rest of the app) and you want to reuse the **library OAuth account contract** without copying mapper wiring from the reference models.

This page focuses on the custom user + OAuth pair and adapter wiring. For the bundled token
bootstrap lifecycle, relational role composition, `DatabaseTokenModels(...)`, and the supported
password-column hook, use
[Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models).

## Supported paths

- If your app keeps the default `user` table, the mapped class name `User`, and the same declarative registry, importing **`OAuthAccount` from `litestar_auth.models.oauth`** still works.
- If your user class name or table name changes, prefer a custom pair built from **`UserAuthRelationshipMixin`** and **`OAuthAccountMixin`** so you can point both sides of the relationship at your schema without hand-copying the bundled mapper definition.

```python
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy.orm import DeclarativeBase

from litestar_auth.models import OAuthAccountMixin, UserAuthRelationshipMixin, UserModelMixin


class AppBase(DeclarativeBase):
    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class AppUUIDBase(UUIDPrimaryKey, AppBase):
    __abstract__ = True


class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "my_user"

    auth_access_token_model = None
    auth_refresh_token_model = None
    auth_oauth_account_model = "MyOAuthAccount"


class MyOAuthAccount(OAuthAccountMixin, AppUUIDBase):
    __tablename__ = "my_oauth_account"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"
```

If the same custom user also needs the library-managed role contract, compose
`UserRoleRelationshipMixin` on `MyUser` and add sibling `RoleMixin` / `UserRoleAssociationMixin`
classes for your `role` and `user_role` tables. That keeps `user.roles` as the normalized flat
API while persisting membership relationally. The full pattern lives in
[Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models).

If the same custom user keeps a legacy password-hash column name, leave the runtime attribute as `hashed_password` and set the supported hook instead of redefining the field:

```python
class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "my_user"

    auth_access_token_model = None
    auth_refresh_token_model = None
    auth_oauth_account_model = "MyOAuthAccount"
    auth_hashed_password_column_name = "password_hash"
```

That keeps `BaseUserManager`, `SQLAlchemyUserDatabase`, and JWT fingerprinting on the normal `user.hashed_password` contract while the SQL column remains `password_hash`.

`from litestar_auth.models import User` (or `from litestar_auth.models.user import User`) loads the bundled reference `User` and registers a mapper for table `user`, which **conflicts** with your app model when you already map that table yourself.

The mixins exposed from `litestar_auth.models` are side-effect free: importing them does **not** register the bundled `User` or `OAuthAccount` mappers.

That same `litestar_auth.models` package is also the canonical ORM setup entrypoint for the bundled DB-token tables:

```python
from litestar_auth.models import import_token_orm_models

AccessToken, RefreshToken = import_token_orm_models()
```

Call that helper explicitly during metadata registration or Alembic setup when this app reuses the library `AccessToken` / `RefreshToken` models. `LitestarAuth.on_app_init()` now handles the matching plugin-runtime bootstrap path lazily when the configured DB-token strategy still uses the library classes, so no extra import side effect is needed only for runtime correctness.

## Plugin and user database

- Set **`user_model=MyUser`** on `LitestarAuthConfig`.
- When OAuth is enabled, pass **`oauth_account_model=MyOAuthAccount`** (or `OAuthAccount` when you truly reuse the bundled table) into `SQLAlchemyUserDatabase` via **`user_db_factory`**, for example:

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase

def user_db_factory(session):
    return SQLAlchemyUserDatabase(
        session,
        user_model=MyUser,
        oauth_account_model=MyOAuthAccount,
    )
```

Wire that factory in `LitestarAuthConfig(user_model=MyUser, user_db_factory=user_db_factory, oauth_config=...)`.

`SQLAlchemyUserDatabase` now validates that `oauth_account_model` points back at the same user contract. If you previously paired `litestar_auth.models.oauth.OAuthAccount` with a renamed user class, a non-`user` table, or a different declarative registry, that setup now fails fast with `TypeError`; replace it with an `OAuthAccountMixin` subclass whose `auth_user_model` / `auth_user_table` settings match `MyUser`.

## If you later add DB token tables

Keep the same models-owned workflow described in [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models):

- Reuse the bundled token tables with `from litestar_auth.models import import_token_orm_models`, keeping that helper for metadata registration and Alembic setup while plugin startup handles the runtime bootstrap path.
- Map your own token tables with `AccessTokenMixin` / `RefreshTokenMixin`, then pass `DatabaseTokenModels(...)` to `DatabaseTokenStrategy` so login, refresh rotation, logout cleanup, and expired-token cleanup target those classes.

## Token encryption

Set **`oauth_token_encryption_key`** on `OAuthConfig` in production when providers are configured. Plugin-managed OAuth flows bind that key onto each request-scoped `SQLAlchemyUserDatabase` automatically.

If you instantiate `SQLAlchemyUserDatabase` directly for OAuth persistence outside the plugin-managed request path, pass an explicit policy yourself:

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.oauth_encryption import OAuthTokenEncryption

def user_db_factory(session):
    return SQLAlchemyUserDatabase(
        session,
        user_model=MyUser,
        oauth_account_model=MyOAuthAccount,
        oauth_token_encryption=OAuthTokenEncryption("your-fernet-key"),
    )
```

For direct ORM session usage that loads `MyOAuthAccount` rows without going through the adapter, call `bind_oauth_token_encryption(session, OAuthTokenEncryption(...))` first so token columns decrypt on load. In tests, `OAuthTokenEncryption(key=None)` is the explicit plaintext/testing policy.

## Optional relationship tuning

Leave the relationship-option hooks on `UserAuthRelationshipMixin` unset when the default inverse contract is sufficient. That keeps the same `back_populates="user"` wiring, SQLAlchemy's default loader behavior, and the inferred `MyOAuthAccount.user_id` foreign-key link.

If this custom user needs eager OAuth loading or you want to spell the join column explicitly without copying the whole `declared_attr` body, add only the documented hooks:

```python
class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "my_user"

    auth_access_token_model = None
    auth_refresh_token_model = None
    auth_oauth_account_model = "MyOAuthAccount"
    auth_oauth_account_relationship_lazy = "selectin"
    auth_oauth_account_relationship_foreign_keys = "MyOAuthAccount.user_id"
```

If the same user later composes custom token tables too, `auth_token_relationship_lazy = "noload"` applies to both `access_tokens` and `refresh_tokens` without redefining either relationship.

## Relationship wiring

`OAuthAccountMixin` uses two class hooks so custom schemas do not need to rewrite the bundled relationship boilerplate:

- Set `auth_user_model = "MyUser"` to point `user = relationship(...)` at your mapped class name.
- Set `auth_user_table = "my_user"` to point `user_id = mapped_column(ForeignKey(...))` at your table.

`UserAuthRelationshipMixin` mirrors the inverse side. Set `auth_oauth_account_model = "MyOAuthAccount"` so `MyUser.oauth_accounts` points back at the custom OAuth class, and set `auth_access_token_model = None` / `auth_refresh_token_model = None` when this custom user does not also compose token-model relationships. Leave the relationship-option hooks unset to keep the bundled default behavior, or set `auth_oauth_account_relationship_lazy` and `auth_oauth_account_relationship_foreign_keys` for the documented OAuth-specific tuning path. If you also customize token model names or tables, replace those `None` hooks with `AccessTokenMixin` / `RefreshTokenMixin` classes as shown in [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models), then optionally set `auth_token_relationship_lazy` for both token collections. The mixin does not expose arbitrary `relationship()` kwargs beyond those hooks.

See also: canonical columns for `oauth_account` in [Models API](../api/models.md) and the optional audit-column pattern in [OAuth guide](../guides/oauth.md).
