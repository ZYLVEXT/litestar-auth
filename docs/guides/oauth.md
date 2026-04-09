# OAuth2 login and account linking

OAuth is optional and configured through `OAuthConfig` on `LitestarAuthConfig`.

## Canonical route registration

OAuth has one plugin-owned route-registration contract plus a manual escape hatch:

- **Plugin-owned login routes.** Declare `oauth_providers` plus `oauth_redirect_base_url` on `OAuthConfig`. With the default `auth_path="/auth"`, the plugin auto-mounts:
  - `GET /auth/oauth/{provider}/authorize`
  - `GET /auth/oauth/{provider}/callback`
- **Plugin-owned associate routes.** Set `include_oauth_associate=True` to extend that same provider inventory with:
  - `GET /auth/associate/{provider}/authorize`
  - `GET /auth/associate/{provider}/callback`
- **Advanced escape hatch.** If you need a custom route table, custom path prefixes, or direct user-manager wiring, mount `create_provider_oauth_controller()` / `create_oauth_controller()` / `create_oauth_associate_controller()` yourself instead of using the plugin-owned route table.

The plugin no longer treats `oauth_providers` as inert metadata: if providers are declared, login routes are part of the plugin-owned HTTP surface.

For plugin-owned routes, production app init now fails closed unless `oauth_redirect_base_url` uses a non-loopback `https://...` origin. Keep localhost or plain-HTTP redirect bases behind `AppConfig(debug=True)` or `unsafe_testing=True` only.

For manual/custom controller wiring, `redirect_base_url` on `create_provider_oauth_controller()`, `create_oauth_controller()`, and `create_oauth_associate_controller()` must also use a non-loopback `https://...` origin. Unlike the plugin-owned route table, the low-level manual factories do not inspect `AppConfig(debug=True)` or `unsafe_testing=True`, so there is no localhost or plain-HTTP escape hatch on that API surface.

## Scope policy

OAuth scopes are **server-owned configuration**, not caller input.

- Plugin-owned routes: set `OAuthConfig.oauth_provider_scopes={"github": ["openid", "email"]}` to pin scopes per provider.
- Manual routes: pass `oauth_scopes=[...]` to `create_provider_oauth_controller()` or `create_oauth_controller()`.
- Runtime `GET /authorize?scopes=...` overrides are rejected with **400**.

## Account association

For logged-in users linking another identity:

- Set `include_oauth_associate=True`.
- Configure `oauth_providers` and `oauth_redirect_base_url`.

Routes use the `/auth/associate/{provider}/...` prefix by default, and the same provider inventory also owns the `/auth/oauth/{provider}/...` login routes. If you need associate-only plugin wiring or a different path layout, switch to manual controller factories for the whole OAuth route table.

Associate callbacks enforce the same active-account checks as login callbacks before linking a provider identity.

For manual `create_oauth_associate_controller(..., user_manager_dependency_key=...)` wiring, the dependency key must be a valid non-keyword Python identifier. Litestar resolves that dependency by matching the key to the generated callback parameter name.

## Token encryption

OAuth access and refresh tokens persisted on `OAuthAccount` should be protected. When providers are configured, set **`oauth_token_encryption_key`** on `OAuthConfig`. The plugin validates that encryption is available for configured providers in normal (non-testing) operation and now binds that key explicitly onto each request-scoped SQLAlchemy user-store path.

If you bypass the plugin and instantiate `SQLAlchemyUserDatabase` directly for OAuth persistence, supply an explicit policy yourself:

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.oauth_encryption import OAuthTokenEncryption

user_db = SQLAlchemyUserDatabase(
    session,
    user_model=User,
    oauth_account_model=OAuthAccount,
    oauth_token_encryption=OAuthTokenEncryption("your-fernet-key"),
)
```

For ad-hoc ORM queries against `OAuthAccount`, bind the same policy to the session with `bind_oauth_token_encryption(session, OAuthTokenEncryption(...))` before loading encrypted token columns. In tests you can use `OAuthTokenEncryption(key=None)` as the explicit plaintext policy; production OAuth deployments should always supply a Fernet key.

## Cookies

`oauth_cookie_secure` controls secure flag behavior for OAuth-related cookies (default `True`). Align with your deployment (HTTPS vs local HTTP).

## Provider email trust

For plugin-owned OAuth login routes, set **`oauth_trust_provider_email_verified=True`** when a provider's `email_verified` claim can safely drive auto-verification or login-time associate-by-email behavior. Manual controller factories use the lower-level **`trust_provider_email_verified`** flag directly and can also pin **`oauth_scopes`** per controller. Enable either form **only** for providers that cryptographically assert email ownership. Mismatched configuration yields **400** responses with `OAUTH_EMAIL_NOT_VERIFIED` or related codes (see [Errors](../errors.md)).

Default **`oauth_associate_by_email=False`** avoids implicit login-time linking by email alone. On the plugin-owned route table, this flag applies to the login callbacks derived from `oauth_providers`; it does not change the authenticated associate routes.

## Code entry points

- Canonical plugin-managed path: `LitestarAuthConfig(..., oauth_config=OAuthConfig(...))`
- Manual login helper: `litestar_auth.oauth.create_provider_oauth_controller`
- Advanced custom-controller escape hatch: `litestar_auth.controllers.create_oauth_controller` and `create_oauth_associate_controller`
- Lazy client loader: `litestar_auth.oauth.load_httpx_oauth_client`

Use `OAuthConfig` on `LitestarAuthConfig` for the default plugin-owned route table. Reach for `create_provider_oauth_controller(...)` or the lower-level controller factories only when you intentionally assemble a custom OAuth route layout.

## Custom `User` and `OAuthAccount`

If you own the `user` table with your own model, prefer composing **`UserModelMixin`**, **`UserAuthRelationshipMixin`**, and **`OAuthAccountMixin`** on your app's own declarative base so the columns and relationship hooks stay aligned with the bundled contract without inheriting the reference classes directly. Leave the relationship-option hooks on `UserAuthRelationshipMixin` unset to keep the default inverse wiring; when an OAuth-heavy app needs a different loader strategy for `oauth_accounts`, set `auth_oauth_account_relationship_lazy` and, only when SQLAlchemy needs an explicit hint, `auth_oauth_account_relationship_foreign_keys`. If the same custom user later owns token tables too, `auth_token_relationship_lazy` tunes both token collections without re-copying relationship bodies. If you truly reuse the bundled `oauth_account` table on `user.id`, importing **`OAuthAccount` from `litestar_auth.models.oauth`** remains supported. Configure `user_model`, `user_db_factory` with `oauth_account_model`, and token encryption like any other app. The mixin-based path is covered in the [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md).

### Audit columns on `oauth_account`

The bundled `OAuthAccount` extends `UUIDBase` (no `created_at` / `updated_at`). If your existing schema has audit columns, use a **single** mapped class for `oauth_account` (for example subclass `UUIDAuditBase` and copy the column set). You cannot map two classes to the same table name on shared metadata; see the commented example under `docs/snippets/oauth_account_audit_model.py`.

## Related

- [Configuration](../configuration.md) — `OAuthConfig` fields.
- [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md).
- [Security](security.md) — CSRF and cookie notes for browser flows.
