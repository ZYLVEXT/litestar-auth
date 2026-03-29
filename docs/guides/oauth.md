# OAuth2 login and account linking

OAuth is optional and configured through `OAuthConfig` on `LitestarAuthConfig`.

## Provider setup

Set `oauth_config` with `oauth_providers`: a sequence of `(name, client)` tuples where `client` is an httpx-oauth (or compatible) client instance.

Typical routes (under `auth_path`):

- `GET /oauth/{provider}/authorize` — start login.
- `GET /oauth/{provider}/callback` — complete login.

## Account association

For logged-in users linking another identity:

- Set `include_oauth_associate=True`.
- Configure `oauth_associate_providers`, `oauth_associate_redirect_base_url`, etc.

Routes use the `/associate/{provider}/...` prefix.

## Token encryption

OAuth access and refresh tokens persisted on `OAuthAccount` should be protected. When providers are configured, set **`oauth_token_encryption_key`** on `OAuthConfig`. The plugin validates that encryption is available for configured providers in normal (non-testing) operation.

## Cookies

`oauth_cookie_secure` controls secure flag behavior for OAuth-related cookies (default `True`). Align with your deployment (HTTPS vs local HTTP).

## Provider email trust

For `create_provider_oauth_controller` / associate flows, **`trust_provider_email_verified`** controls whether a provider’s `email_verified` claim can drive auto-verification or associate-by-email behavior. Enable it **only** for providers that cryptographically assert email ownership. Mismatched configuration yields **400** responses with `OAUTH_EMAIL_NOT_VERIFIED` or related codes (see [Errors](../errors.md)).

Default **`oauth_associate_by_email=False`** avoids implicit linking by email alone.

## Code entry points

- `litestar_auth.oauth.create_oauth_controller` / `create_provider_oauth_controller`
- `litestar_auth.oauth.load_httpx_oauth_client`

Use the plugin configuration rather than calling these directly unless you assemble routes yourself.

## Related

- [Configuration](../configuration.md) — `OAuthConfig` fields.
- [Security](security.md) — CSRF and cookie notes for browser flows.
