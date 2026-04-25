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

- `GET {auth_path}/associate/{provider}/authorize`
- `GET {auth_path}/associate/{provider}/callback`

This cookbook focuses on the authenticated associate flow. If you need associate-only routing or a different OAuth path layout, switch to manual controller factories instead of the plugin-owned OAuth route table.

## Security defaults

- Associate routes require an authenticated `request.user`; they do not use `oauth_associate_by_email`.
- Keep **`oauth_token_encryption_keyring`** configured in production so stored provider tokens are encrypted at rest.
- Keep **`oauth_flow_cookie_secret`** distinct and configured so OAuth state and the PKCE verifier are encrypted/authenticated in the short-lived flow cookie.

## See also

- [OAuth guide](../guides/oauth.md)
- [HTTP API — Associate](../http_api.md)
- [Deployment checklist](../deployment.md)
