# Custom `User` model with OAuth mixins

Use this when your application maps auth tables to **your own** SQLAlchemy models (same Advanced Alchemy / declarative registry as the rest of the app) and you want to reuse the **library OAuth account contract** without copying mapper wiring from the reference models.

## Supported paths

- If your app keeps the default `user` table and the mapped class name `User`, importing **`OAuthAccount` from `litestar_auth.models.oauth`** still works.
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

`from litestar_auth.models import User` (or `from litestar_auth.models.user import User`) loads the bundled reference `User` and registers a mapper for table `user`, which **conflicts** with your app model when you already map that table yourself.

The mixins exposed from `litestar_auth.models` are side-effect free: importing them does **not** register the bundled `User` or `OAuthAccount` mappers.

That same `litestar_auth.models` package is also the canonical ORM setup entrypoint for the bundled DB-token tables: use `from litestar_auth.models import import_token_orm_models` if this app later reuses the library `AccessToken` / `RefreshToken` models. The older `from litestar_auth.authentication.strategy import import_token_orm_models` path remains compatibility-only for existing imports.

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

## If you later add DB token tables

Keep the same models-owned workflow:

- Reuse the bundled token tables with `from litestar_auth.models import import_token_orm_models`.
- Map your own token tables with `AccessTokenMixin` / `RefreshTokenMixin`, then pass `DatabaseTokenModels(...)` to `DatabaseTokenStrategy` so login, refresh rotation, logout cleanup, and expired-token cleanup target those classes.

The full custom-token example lives in [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models).

## Token encryption

Set **`oauth_token_encryption_key`** on `OAuthConfig` in production when providers are configured. The same scope machinery applies as for the default models; use `oauth_token_encryption_scope` / `get_oauth_encryption_key_callable` consistently with the plugin (see [OAuth guide](../guides/oauth.md) and [Security](../security.md)).

## Relationship wiring

`OAuthAccountMixin` uses two class hooks so custom schemas do not need to rewrite the bundled relationship boilerplate:

- Set `auth_user_model = "MyUser"` to point `user = relationship(...)` at your mapped class name.
- Set `auth_user_table = "my_user"` to point `user_id = mapped_column(ForeignKey(...))` at your table.

`UserAuthRelationshipMixin` mirrors the inverse side. Set `auth_oauth_account_model = "MyOAuthAccount"` so `MyUser.oauth_accounts` points back at the custom OAuth class, and set `auth_access_token_model = None` / `auth_refresh_token_model = None` when this custom user does not also compose token-model relationships. If you also customize token model names or tables, replace those `None` hooks with `AccessTokenMixin` / `RefreshTokenMixin` classes as shown in [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models).

See also: canonical columns for `oauth_account` in [Models API](../api/models.md) and the optional audit-column pattern in [OAuth guide](../guides/oauth.md).
