# OAuth2 login and account linking

OAuth is optional and configured through `OAuthConfig` on `LitestarAuthConfig`.

## Canonical route registration

OAuth has two distinct route-registration paths:

- **OAuth login stays explicit.** Declare `oauth_providers` on `OAuthConfig`, then mount one login controller per provider with `litestar_auth.oauth.create_provider_oauth_controller(..., auth_path=config.auth_path)`. With the default `auth_path="/auth"`, the routes are:
  - `GET /auth/oauth/{provider}/authorize`
  - `GET /auth/oauth/{provider}/callback`
- **OAuth associate can be plugin-owned.** Set `include_oauth_associate=True` and configure `oauth_associate_providers`. The plugin then auto-mounts:
  - `GET /auth/associate/{provider}/authorize`
  - `GET /auth/associate/{provider}/callback`
- **Advanced escape hatch.** If you need a custom route table, custom path prefixes, or direct user-manager wiring, mount `create_oauth_controller()` / `create_oauth_associate_controller()` from `litestar_auth.controllers` yourself instead of using the canonical helper + plugin split.

The plugin does **not** auto-mount login routes from `oauth_providers`.

## Account association

For logged-in users linking another identity:

- Set `include_oauth_associate=True`.
- Configure `oauth_associate_providers`, `oauth_associate_redirect_base_url`, etc.

Routes use the `/auth/associate/{provider}/...` prefix by default.

## Token encryption

OAuth access and refresh tokens persisted on `OAuthAccount` should be protected. When providers are configured, set **`oauth_token_encryption_key`** on `OAuthConfig`. The plugin validates that encryption is available for configured providers in normal (non-testing) operation.

## Cookies

`oauth_cookie_secure` controls secure flag behavior for OAuth-related cookies (default `True`). Align with your deployment (HTTPS vs local HTTP).

## Provider email trust

For explicit OAuth login helpers, **`trust_provider_email_verified`** controls whether a provider's `email_verified` claim can drive auto-verification or login-time associate-by-email behavior. Enable it **only** for providers that cryptographically assert email ownership. Mismatched configuration yields **400** responses with `OAUTH_EMAIL_NOT_VERIFIED` or related codes (see [Errors](../errors.md)).

Default **`oauth_associate_by_email=False`** avoids implicit login-time linking by email alone. This flag affects explicit login controllers only; it does not change the plugin-owned associate routes.

## Code entry points

- Canonical login helper: `litestar_auth.oauth.create_provider_oauth_controller`
- Advanced custom-controller escape hatch: `litestar_auth.controllers.create_oauth_controller` and `create_oauth_associate_controller`
- Lazy client loader: `litestar_auth.oauth.load_httpx_oauth_client`

Use `create_provider_oauth_controller(...)` plus plugin-managed associate routes unless you intentionally assemble a custom route table.

## Custom `User` and `OAuthAccount`

If you own the `user` table with your own model, prefer composing **`UserModelMixin`**, **`UserAuthRelationshipMixin`**, and **`OAuthAccountMixin`** on your app's own declarative base so the columns and relationship hooks stay aligned with the bundled contract without inheriting the reference classes directly. Leave the relationship-option hooks on `UserAuthRelationshipMixin` unset to keep the default inverse wiring; when an OAuth-heavy app needs a different loader strategy for `oauth_accounts`, set `auth_oauth_account_relationship_lazy` and, only when SQLAlchemy needs an explicit hint, `auth_oauth_account_relationship_foreign_keys`. If the same custom user later owns token tables too, `auth_token_relationship_lazy` tunes both token collections without re-copying relationship bodies. If you truly reuse the bundled `oauth_account` table on `user.id`, importing **`OAuthAccount` from `litestar_auth.models.oauth`** remains supported. Configure `user_model`, `user_db_factory` with `oauth_account_model`, and token encryption like any other app. The mixin-based path is covered in the [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md).

### Audit columns on `oauth_account`

The bundled `OAuthAccount` extends `UUIDBase` (no `created_at` / `updated_at`). If your existing schema has audit columns, use a **single** mapped class for `oauth_account` (for example subclass `UUIDAuditBase` and copy the column set). You cannot map two classes to the same table name on shared metadata; see the commented example under `docs/snippets/oauth_account_audit_model.py`.

## Related

- [Configuration](../configuration.md) — `OAuthConfig` fields.
- [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md).
- [Security](security.md) — CSRF and cookie notes for browser flows.
