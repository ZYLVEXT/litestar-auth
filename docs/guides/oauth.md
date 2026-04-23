# OAuth2 login and account linking

OAuth is optional and configured through `OAuthConfig` on `LitestarAuthConfig`.

## Route registration

OAuth has one plugin-owned route-registration contract plus a manual route-table path:

- **Plugin-owned login routes.** Declare `oauth_providers` plus `oauth_redirect_base_url` on `OAuthConfig`. With the default `auth_path="/auth"`, the plugin auto-mounts:
  - `GET /auth/oauth/{provider}/authorize`
  - `GET /auth/oauth/{provider}/callback`
- **Plugin-owned associate routes.** Set `include_oauth_associate=True` to extend that same provider inventory with:
  - `GET /auth/associate/{provider}/authorize`
  - `GET /auth/associate/{provider}/callback`
- **Manual route table.** If you need a custom route table, custom path prefixes, or direct user-manager wiring, mount `create_provider_oauth_controller()` / `create_oauth_controller()` / `create_oauth_associate_controller()` yourself instead of using the plugin-owned route table.

The plugin no longer treats `oauth_providers` as inert metadata: if providers are declared, login routes are part of the plugin-owned HTTP surface.

For plugin-owned routes, production app init now fails closed unless `oauth_redirect_base_url` uses a non-loopback `https://...` origin. Keep localhost or plain-HTTP redirect bases behind `AppConfig(debug=True)` or `unsafe_testing=True` only.

For manual/custom controller wiring, `redirect_base_url` on `create_provider_oauth_controller()`, `create_oauth_controller()`, and `create_oauth_associate_controller()` must also use a non-loopback `https://...` origin and remain a clean callback base without embedded userinfo, query strings, or fragments. Unlike the plugin-owned route table, the low-level manual factories do not inspect `AppConfig(debug=True)` or `unsafe_testing=True`, so there is no localhost or plain-HTTP override on that API surface.

## Scope policy

OAuth scopes are **server-owned configuration**, not caller input.

- Plugin-owned routes: set `OAuthConfig.oauth_provider_scopes={"github": ["openid", "email"]}` to pin scopes per provider.
- Manual routes: pass `oauth_scopes=[...]` to `create_provider_oauth_controller()` or `create_oauth_controller()`.
- Runtime `GET /authorize?scopes=...` overrides are rejected with **400**.

## Manual OAuth client contract

Manual/custom OAuth controllers accept any client object that satisfies the supported contract. You do not need to subclass a litestar-auth base class, but the client must fail the same way a normal `httpx-oauth` provider client would.

The typed surface is exposed as structural protocols in `litestar_auth.oauth.client_adapter`:
`OAuthClientProtocol` covers the supported manual client shapes, with
`OAuthDirectIdentityClientProtocol`, `OAuthProfileClientProtocol`, and the optional
`OAuthEmailVerificationAsyncClientProtocol` documenting the async email-verification hook used by the
adapter. Sync-only verification clients can be wrapped explicitly with
`make_async_email_verification_client()`.

Supported provisioning paths:

- `oauth_client=...`: pass a pre-built client instance directly.
- `oauth_client_factory=...`: pass a zero-argument callable that returns the client instance.
- `oauth_client_class="package.module.Client"`: pass a fully qualified import path and optional `oauth_client_kwargs={...}`. `load_httpx_oauth_client()` imports the class lazily and forwards those kwargs to its constructor.

`create_provider_oauth_controller()` resolves those provisioning options through the same adapter boundary that powers `create_oauth_controller()` and `create_oauth_associate_controller()`, so all manual entry points enforce one normalized runtime contract.

Required client methods:

- `get_authorization_url(redirect_uri, state, *, scope: str | None = None) -> str`
  The return value must be a non-empty authorization URL string.
- `get_access_token(code, redirect_uri) -> payload`
  The payload may be a mapping or an object with attributes. It must expose a non-empty `access_token: str`, and may expose `expires_at: int | None` and `refresh_token: str | None`.

Identity resolution:

- Preferred direct contract: `get_id_email(access_token) -> tuple[str, str] | None`
  Return `(account_id, email)` as two non-empty strings, or return `None` to fall back to profile lookup.
- Profile fallback: `get_profile(access_token) -> payload`
  The payload may be a mapping or an object with attributes. It must expose `id` or `account_id`, plus `email` or `account_email`.

Optional email-verification contract:

- Dedicated hook: implement `OAuthEmailVerificationAsyncClientProtocol` with
  `async get_email_verified(access_token) -> bool`.
- Profile fallback: `get_profile()` may expose `email_verified` as `true`/`false` or the case-insensitive strings `"true"` / `"false"`.

Async clients should implement the hook directly:

```python
from litestar_auth.oauth import OAuthEmailVerificationAsyncClientProtocol


class ProviderClient(OAuthEmailVerificationAsyncClientProtocol):
    async def get_email_verified(self, access_token: str) -> bool:
        profile = await self.get_profile(access_token)
        return profile["email_verified"] is True
```

Sync-only clients must be wrapped before they are passed to manual OAuth controller factories:

```python
from litestar_auth.oauth import (
    OAuthEmailVerificationSyncClientProtocol,
    make_async_email_verification_client,
)


class SyncProviderClient(OAuthEmailVerificationSyncClientProtocol):
    def get_email_verified(self, access_token: str) -> bool:
        return self.fetch_profile(access_token)["email_verified"] is True


oauth_client = make_async_email_verification_client(SyncProviderClient())
```

!!! warning "Blocking in async context"

    Do not pass a blocking sync `get_email_verified()` implementation directly to async OAuth routes. Use
    `make_async_email_verification_client()` for truly blocking sync clients, or implement
    `OAuthEmailVerificationAsyncClientProtocol` directly for native async and cheap in-memory checks.

Fail-closed behavior:

- Invalid import paths, missing methods, malformed payloads, empty identifiers, and invalid `email_verified` values raise `ConfigurationError`.
- Missing profile email still returns **400** with `OAUTH_NOT_AVAILABLE_EMAIL`, because login and account association require a usable email address.
- When `trust_provider_email_verified=True`, sign-in and associate-by-email flows reject missing or false verification evidence with **400** `OAUTH_EMAIL_NOT_VERIFIED`.

## Account association

For logged-in users linking another identity:

- Set `include_oauth_associate=True`.
- Configure `oauth_providers` and `oauth_redirect_base_url`.

Routes use the `/auth/associate/{provider}/...` prefix by default, and the same provider inventory also owns the `/auth/oauth/{provider}/...` login routes. If you need associate-only plugin wiring or a different path layout, switch to manual controller factories for the whole OAuth route table.

Associate callbacks enforce the same active-account checks as login callbacks before linking a provider identity.

For manual `create_oauth_associate_controller(..., user_manager_dependency_key=...)` wiring, the dependency key must be a valid non-keyword Python identifier. Litestar resolves that dependency by matching the key to the associate callback parameter name.

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

For ad-hoc ORM queries against `OAuthAccount`, bind the same policy to the session with `bind_oauth_token_encryption(session, OAuthTokenEncryption(...))` before loading encrypted token columns. In tests you can use `OAuthTokenEncryption(key=None, unsafe_testing=True)` as the explicit plaintext policy; production OAuth deployments should always supply a Fernet key. Policy-shaped wrappers and objects retained across development/test module reloads are ignored or rejected; create a fresh `OAuthTokenEncryption(...)` before binding. The mapper listeners keep temporary plaintext snapshots only for the duration of a write and now clear them again if the ORM transaction rolls back.

## Cookies

`oauth_cookie_secure` controls secure flag behavior for OAuth-related cookies (default `True`). Align with your deployment (HTTPS vs local HTTP).

## Provider email trust

For plugin-owned OAuth login routes, set **`oauth_trust_provider_email_verified=True`** when a provider's `email_verified` claim can safely drive auto-verification or login-time associate-by-email behavior. Manual controller factories use the lower-level **`trust_provider_email_verified`** flag directly and can also pin **`oauth_scopes`** per controller. Enable either form **only** for providers that cryptographically assert email ownership. Mismatched configuration yields **400** responses with `OAUTH_EMAIL_NOT_VERIFIED` or related codes (see [Errors](../errors.md)).

Default **`oauth_associate_by_email=False`** avoids implicit login-time linking by email alone. On the plugin-owned route table, this flag applies to the login callbacks derived from `oauth_providers`; it does not change the authenticated associate routes.

## Code entry points

- Plugin-managed path: `LitestarAuthConfig(..., oauth_config=OAuthConfig(...))`
- Manual login helper: `litestar_auth.oauth.create_provider_oauth_controller`
- Manual custom-controller path: `litestar_auth.controllers.create_oauth_controller` and `create_oauth_associate_controller`
- Lazy client loader: `litestar_auth.oauth.load_httpx_oauth_client`

Use `OAuthConfig` on `LitestarAuthConfig` for the default plugin-owned route table. Reach for `create_provider_oauth_controller(...)` or the lower-level controller factories only when you intentionally assemble a custom OAuth route layout.
The legacy `litestar_auth.contrib.oauth` re-export path has been removed; import manual OAuth helpers from `litestar_auth.oauth`.

## Custom `User` and `OAuthAccount`

If you own the `user` table with your own model, prefer composing **`UserModelMixin`**, **`UserAuthRelationshipMixin`**, and **`OAuthAccountMixin`** on your app's own declarative base so the columns and relationship hooks stay aligned with the bundled contract without inheriting the reference classes directly. Leave the relationship-option hooks on `UserAuthRelationshipMixin` unset to keep the default inverse wiring; when an OAuth-heavy app needs a different loader strategy for `oauth_accounts`, set `auth_oauth_account_relationship_lazy` and, only when SQLAlchemy needs an explicit hint, `auth_oauth_account_relationship_foreign_keys`. If the same custom user later owns token tables too, `auth_token_relationship_lazy` tunes both token collections without re-copying relationship bodies. If you truly reuse the bundled `oauth_account` table on `user.id`, importing **`OAuthAccount` from `litestar_auth.models.oauth`** remains supported. Configure `user_model`, `user_db_factory` with `oauth_account_model`, and token encryption like any other app. The mixin-based path is covered in the [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md).

### Audit columns on `oauth_account`

The bundled `OAuthAccount` extends `UUIDBase` (no `created_at` / `updated_at`). If your existing schema has audit columns, use a **single** mapped class for `oauth_account` (for example subclass `UUIDAuditBase` and copy the column set). You cannot map two classes to the same table name on shared metadata; see the commented example under `docs/snippets/oauth_account_audit_model.py`.

## Related

- [Configuration](../configuration.md) — `OAuthConfig` fields.
- [Custom user + OAuth cookbook](../cookbook/custom_user_oauth.md).
- [Security](security.md) — CSRF and cookie notes for browser flows.
