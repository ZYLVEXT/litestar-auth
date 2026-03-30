# Custom `User` model with library `OAuthAccount`

Use this when your application maps the `user` table to **your own** SQLAlchemy model (same Advanced Alchemy / declarative registry as the rest of the app) but you want to reuse the **library OAuth account table contract** and `SQLAlchemyUserDatabase(..., oauth_account_model=...)`.

## Do not import the reference `User`

Import **`OAuthAccount` from `litestar_auth.models.oauth`**, not from `litestar_auth.models`:

```python
from litestar_auth.models.oauth import OAuthAccount
```

`from litestar_auth.models import User` (or `from litestar_auth.models.user import User`) loads the bundled reference `User` and registers a mapper for table `user`, which **conflicts** with your app model on the same table.

Lazy `from litestar_auth.models import OAuthAccount` is supported (PEP 562) but still prefer the **`models.oauth`** path so it is obvious you are not pulling in the reference user module.

## Plugin and user database

- Set **`user_model=MyUser`** on `LitestarAuthConfig`.
- When OAuth is enabled, pass **`oauth_account_model=OAuthAccount`** (or your subclass) into `SQLAlchemyUserDatabase` via **`user_db_factory`**, for example:

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models.oauth import OAuthAccount

def user_db_factory(session):
    return SQLAlchemyUserDatabase(
        session,
        user_model=MyUser,
        oauth_account_model=OAuthAccount,
    )
```

Wire that factory in `LitestarAuthConfig(user_model=MyUser, user_db_factory=user_db_factory, oauth_config=...)`.

## Token encryption

Set **`oauth_token_encryption_key`** on `OAuthConfig` in production when providers are configured. The same scope machinery applies as for the default models; use `oauth_token_encryption_scope` / `get_oauth_encryption_key_callable` consistently with the plugin (see [OAuth guide](../guides/oauth.md) and [Security](../security.md)).

## `OAuthAccount.user` and your `MyUser`

The bundled `OAuthAccount.user` relationship targets the declarative class named **`User`** in the registry (`relationship("User", ...)`). If your class is **`MyUser`**, either:

- Name your mapped class **`User`** in Python (table can still be `user`), or
- **Subclass `OAuthAccount`** and override `user` with `relationship("MyUser", foreign_keys="YourOAuthSubclass.user_id", ...)` and matching `back_populates` on `MyUser`, or
- Drop `back_populates` on one side and use `overlaps=` as needed if SQLAlchemy warns about ambiguous relationships.

See also: canonical columns for `oauth_account` in [Models API](../api/models.md) and the optional audit-column pattern in [OAuth guide](../guides/oauth.md).
