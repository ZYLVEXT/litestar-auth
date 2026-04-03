# Cookbook: Linking OAuth to an existing account

**Associate** flow lets an **already authenticated** user connect a provider identity without logging in again.

## Configuration

On `OAuthConfig`:

```python
OAuthConfig(
    include_oauth_associate=True,
    oauth_associate_providers=[("github", oauth_client), ...],
    oauth_associate_redirect_base_url="https://your.app/auth/associate",
    oauth_token_encryption_key="...",  # required when OAuth is on
)
```

The plugin mounts:

- `GET {auth_path}/associate/{provider}/authorize`
- `GET {auth_path}/associate/{provider}/callback`

This cookbook covers the plugin-owned associate flow only. OAuth login routes remain an explicit helper path mounted separately with `litestar_auth.oauth.create_provider_oauth_controller(...)`.

## Security defaults

- Associate routes require an authenticated `request.user`; they do not use `oauth_associate_by_email`.
- Keep **`oauth_token_encryption_key`** configured in production so stored provider tokens are encrypted at rest.

## See also

- [OAuth guide](../guides/oauth.md)
- [HTTP API — Associate](../http_api.md)
- [Deployment checklist](../deployment.md)
