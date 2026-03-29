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
    oauth_associate_by_email=False,  # safe default
)
```

Routes are mounted under `{auth_path}/associate/{provider}`.

## Security defaults

- **`oauth_associate_by_email=False`** avoids implicitly binding users by email alone.
- If you enable associate-by-email, you must pair it with **`trust_provider_email_verified=True`** only for providers that assert verified email in the token response; otherwise the callback returns **400** (`OAUTH_EMAIL_NOT_VERIFIED`).

## See also

- [OAuth guide](../guides/oauth.md)
- [HTTP API — Associate](../http_api.md)
- [Deployment checklist](../deployment.md)
