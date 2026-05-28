# Cookbook: Linking OAuth to an existing account

**Associate** flow lets an **already authenticated** user connect a provider identity without logging in again.

## Configuration

On `OAuthConfig`:

```python
from litestar_auth import FernetKeyringConfig, OAuthConfig, OAuthProviderConfig

OAuthConfig(
    oauth_providers=[
        OAuthProviderConfig(name="github", client=oauth_client),
    ],
    oauth_redirect_base_url="https://your.app/auth",
    include_oauth_associate=True,
    oauth_token_encryption_keyring=FernetKeyringConfig(
        active_key_id=settings.oauth_token_active_key_id,
        keys=settings.oauth_token_fernet_keys,
    ),
    oauth_flow_cookie_secret="replace-with-32+-char-oauth-flow-secret",
)
```

The plugin mounts login plus associate routes for the same provider inventory:

- `GET {auth_path}/oauth/{provider}/authorize`
- `GET {auth_path}/oauth/{provider}/callback`

- `POST {auth_path}/associate/{provider}/authorize`
- `GET {auth_path}/associate/{provider}/callback`

This cookbook focuses on the authenticated associate flow. If you need associate-only routing or a different OAuth path layout, switch to manual controller factories instead of the plugin-owned OAuth route table.

## Why associate authorize is POST

Login authorize is anonymous and side-effect free apart from setting the encrypted flow cookie, so a cross-site GET cannot abuse a victim's session — there is no victim to abuse. Associate authorize is different: it binds the provider account to the **currently authenticated** user. A cross-site top-level navigation (a victim clicking an attacker link) would otherwise attach a `SameSite=Lax` session cookie and trigger a forced association.

Switching the route to POST forces Litestar's CSRF middleware to validate a same-origin token before the body runs. Cross-site requests cannot read the CSRF cookie to mirror its value into the configured `csrf_header_name`, so forced-association attacks fail closed at the middleware layer regardless of the configured `samesite` policy on the auth cookie.

## Triggering associate from the browser

Because the route is POST and CSRF-protected, you cannot drive associate from a plain `<a href>`. Use a JavaScript-driven submit, e.g.:

```js
async function startAssociate(provider) {
  const csrfToken = readCookie("litestar_auth_csrf");
  const response = await fetch(`/auth/associate/${provider}/authorize`, {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    redirect: "manual",
  });
  if (response.status === 302) {
    window.location.href = response.headers.get("Location");
  } else {
    throw new Error(`Associate authorize failed: ${response.status}`);
  }
}
```

For server-rendered apps that prefer a button, render a `<form method="post" action="/auth/associate/{provider}/authorize">` with the CSRF value posted as a hidden field plus a server-side bridge that mirrors the field value into the request header — or stick with the JS pattern above.

Bearer-only deployments do not wire the CSRF middleware (the plugin auto-enables it only for cookie transports), so the `X-CSRF-Token` header is unnecessary; the POST itself plus the `Authorization` header is the cross-origin gate.

## Security defaults

- Associate routes require an authenticated `request.user`; they do not use `oauth_associate_by_email`.
- Associate authorize is POST + CSRF-protected by default; cookie-transport clients must mirror the plugin-managed CSRF cookie into the configured `csrf_header_name`.
- Keep **`oauth_token_encryption_keyring`** configured in production so stored provider tokens are encrypted at rest.
- Keep **`oauth_flow_cookie_secret`** distinct and configured so OAuth state and the PKCE verifier are encrypted/authenticated in the short-lived flow cookie.

## See also

- [OAuth guide](../guides/oauth.md)
- [HTTP API — OAuth account linking](../http_api.md#oauth-account-linking-associate)
- [Deployment checklist](../deployment.md)
