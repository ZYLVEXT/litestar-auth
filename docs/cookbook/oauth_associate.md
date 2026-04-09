# Cookbook: Linking OAuth to an existing account

**Associate** flow lets an **already authenticated** user connect a provider identity without logging in again.

## Configuration

On `OAuthConfig`:

```python
OAuthConfig(
    oauth_providers=[("github", oauth_client), ...],
    oauth_redirect_base_url="https://your.app/auth",
    include_oauth_associate=True,
    oauth_token_encryption_key="...",  # required when OAuth is on
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
- Keep **`oauth_token_encryption_key`** configured in production so stored provider tokens are encrypted at rest.

## See also

- [OAuth guide](../guides/oauth.md)
- [HTTP API — Associate](../http_api.md)
- [Deployment checklist](../deployment.md)
