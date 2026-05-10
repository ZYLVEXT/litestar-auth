# Database adapters

The **`litestar_auth.db`** package exposes only the abstract persistence contracts and their lightweight data payloads: **`BaseUserStore`**, **`BaseOAuthAccountStore`**, **`BaseApiKeyStore`**, **`OAuthAccountData`**, and **`ApiKeyData`**. These protocols describe how the user manager talks to your storage layer without tying the library to a particular ORM.

The concrete **SQLAlchemy** implementations live in a dedicated submodule: import **`SQLAlchemyUserDatabase`** and **`SQLAlchemyApiKeyStore`** from **`litestar_auth.db.sqlalchemy`**. They are **not** re-exported from `litestar_auth.db` on purpose—eagerly importing the adapter would register SQLAlchemy mappers and break the lazy-import boundary described in the project guide. Use the submodule when you are ready to wire real tables.

For end-to-end ORM setup (session maker, models, plugin config), see [User and manager](../configuration/user_and_manager.md) and [Backends](../configuration/backends.md); the [Configuration index](../configuration.md) lists every split reference page. For customizing the user table while keeping OAuth accounts on the bundled model, see [Custom user + OAuth](../cookbook/custom_user_oauth.md).

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.db.sqlalchemy import SQLAlchemyApiKeyStore
```

::: litestar_auth.db
