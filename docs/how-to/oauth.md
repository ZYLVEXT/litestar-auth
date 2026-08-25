# OAuth (relying party)

Human OAuth is Authorization Code with **PKCE** only. AuthWeave is an OAuth relying party and
Resource Server client surface, not an Authorization Server or STS.

State and the PKCE verifier live in an encrypted flow cookie (`oauth_flow_cookie_secret`). They are
not challenge JWTs and not the opaque browser session. See [credentials and tokens](../credentials.md).

Install extras:

```bash
uv add 'litestar-auth[oauth]'
```

Configure `OAuthConfig` / `OAuthProviderConfig` on `LitestarAuthConfig`, keep redirect URIs on an
allowlist, and encrypt stored provider tokens at rest with a dedicated Fernet key (production fails
closed without one).

Optional FAPI message-signing client behaviour belongs to the human OAuth path in `litestar-auth`.
It does not mint tokens. External issuer trust, JWKS policy, and egress remain deployment-owned.

## Related

- [Credentials and tokens](../credentials.md)
- [Secrets and stores](../secrets.md)
- [Architecture](../architecture.md) (external Authorization Server ADR)
- [Security posture](../security.md)
