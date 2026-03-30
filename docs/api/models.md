# Models

Package `litestar_auth.models` exposes the reference **`User`** and **`OAuthAccount`** ORM models. Names `User` and `OAuthAccount` are loaded lazily (PEP 562) when accessed on the package.

## Import paths

| Goal | Import |
|------|--------|
| OAuth table contract **without** loading reference `User` | `from litestar_auth.models.oauth import OAuthAccount` |
| Reference `User` (and typical tests / quickstarts) | `from litestar_auth.models import User` or `from litestar_auth.models.user import User` |

Avoid `from litestar_auth.models import User` (or `user` submodule) in apps that already map table `user` to a custom model — it registers a second mapper and conflicts.

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
