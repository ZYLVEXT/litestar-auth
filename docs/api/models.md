# Models

Package `litestar_auth.models` exposes the reference **`User`** and **`OAuthAccount`** ORM models plus the side-effect-free mixins behind the bundled model family. Names are loaded lazily (PEP 562) when accessed on the package.

## Import paths

| Goal | Import |
|------|--------|
| Shared auth-model mixins without registering reference mappers | `from litestar_auth.models import UserModelMixin, UserAuthRelationshipMixin, OAuthAccountMixin, AccessTokenMixin, RefreshTokenMixin` |
| Bundled `AccessToken` / `RefreshToken` mapper bootstrap | `from litestar_auth.models import import_token_orm_models` |
| OAuth table contract **without** loading reference `User` | `from litestar_auth.models.oauth import OAuthAccount` |
| Reference `User` (and typical tests / quickstarts) | `from litestar_auth.models import User` or `from litestar_auth.models.user import User` |

Use [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models) as the canonical ORM setup guide for token bootstrap lifecycle, custom model families, `SQLAlchemyUserDatabase`, and the supported password-column hook. Use the [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md) when the application owns the `user` table.

Avoid `from litestar_auth.models import User` (or the `user` submodule) in apps that already map table `user` to a custom model. That import registers the bundled reference mapper and conflicts with an app-owned mapping. Likewise, importing `OAuthAccount` from `litestar_auth.models.oauth` only keeps the reference `User` lazy; when the app owns a different user class, table, or registry, prefer an `OAuthAccountMixin` subclass that points back at the custom user contract.

`import_token_orm_models()` remains the canonical explicit helper for bundled token metadata bootstrap and Alembic-style autogenerate. `LitestarAuth.on_app_init()` now calls the same helper lazily for plugin-managed runtime when bundled DB-token models are active, so no extra import side effect is required only to make the plugin work.

For custom SQLAlchemy models, compose the mixins on your own declarative base instead of copying columns or relationship wiring from the reference classes. [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models) covers the full support matrix and migration notes.

## `UserModelMixin` hook

`UserModelMixin` keeps the runtime attribute contract on `hashed_password`. When an app-owned user table uses a different SQL column name, set `auth_hashed_password_column_name` on the custom user class instead of redefining `hashed_password = mapped_column(...)`:

```python
class LegacyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "legacy_user"
    auth_hashed_password_column_name = "password_hash"
```

`BaseUserManager`, `SQLAlchemyUserDatabase`, and JWT password fingerprinting still read and write `user.hashed_password`; only the SQL column name changes. Direct field redefinition remains compatibility-only for older models that already depend on it.

## `UserAuthRelationshipMixin` hooks

`UserAuthRelationshipMixin` keeps the bundled inverse relationship contract by default: `back_populates="user"` on `access_tokens`, `refresh_tokens`, and `oauth_accounts`, with SQLAlchemy's normal loader behavior and inferred foreign-key linkage. Override only the narrow class hooks the mixin documents:

- `auth_access_token_model`, `auth_refresh_token_model`, `auth_oauth_account_model` point those inverse relationships at custom mapped classes, or to `None` when a branch is intentionally omitted.
- `auth_token_relationship_lazy` forwards one optional `lazy=` setting to both token collections.
- `auth_oauth_account_relationship_lazy` forwards one optional `lazy=` setting to `oauth_accounts`.
- `auth_oauth_account_relationship_foreign_keys` forwards one optional `foreign_keys=` hint to `oauth_accounts`.

The mixin does not accept arbitrary `relationship()` kwargs. For behavior outside those hooks, keep an app-owned explicit relationship definition.

## Canonical `oauth_account` shape

The library table (bundled `OAuthAccount`) includes at least:

- `id` — UUID primary key (from `UUIDBase`)
- `user_id` — FK to `user.id`, not null
- `oauth_name` — `String(100)`
- `account_id` — `String(255)`
- `account_email` — `String(320)`
- `access_token` — `EncryptedString`-backed (length 2048), Fernet when a key is configured
- `expires_at` — integer epoch or null
- `refresh_token` — optional, same encryption type as access token
- Unique constraint **`uq_oauth_account_provider_identity`** on `(oauth_name, account_id)`

Token encryption uses `litestar_auth.oauth_encryption` and `OAuthConfig.oauth_token_encryption_key` (see [OAuth guide](../guides/oauth.md)).

For audit columns (`created_at` / `updated_at`), use one mapped class per table; see [OAuth guide — audit columns](../guides/oauth.md#audit-columns-on-oauth_account).

::: litestar_auth.models
