# Models

Package `litestar_auth.models` exposes the reference **`User`** and **`OAuthAccount`** ORM models plus the side-effect-free mixins behind the bundled model family. Names are loaded lazily (PEP 562) when accessed on the package.

## Import paths

| Goal | Import |
|------|--------|
| Shared auth-model mixins without registering reference mappers | `from litestar_auth.models import UserModelMixin, UserAuthRelationshipMixin, OAuthAccountMixin, AccessTokenMixin, RefreshTokenMixin` |
| Bundled `AccessToken` / `RefreshToken` mapper bootstrap | `from litestar_auth.models import import_token_orm_models` |
| OAuth table contract **without** loading reference `User` | `from litestar_auth.models.oauth import OAuthAccount` |
| Reference `User` (and typical tests / quickstarts) | `from litestar_auth.models import User` or `from litestar_auth.models.user import User` |

Avoid `from litestar_auth.models import User` (or `user` submodule) in apps that already map table `user` to a custom model — it registers a second mapper and conflicts.

For the bundled token tables, call `import_token_orm_models()` explicitly during metadata bootstrap or Alembic-style autogenerate setup when you need the library `AccessToken` / `RefreshToken` mappers registered. The older `from litestar_auth.authentication.strategy import import_token_orm_models` path remains a compatibility alias for existing code, not the recommended new entrypoint, and neither the plugin nor `DatabaseTokenStrategy` auto-registers those mappers.

For custom SQLAlchemy models, prefer composing the mixins on your own declarative base instead of copying columns or relationship wiring from the reference classes. See [Configuration](../configuration.md#custom-sqlalchemy-user-and-token-models) and [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md).

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
