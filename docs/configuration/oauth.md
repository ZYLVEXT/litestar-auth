# OAuth

Use this page for `OAuthConfig`, OAuth provider inventory, redirect validation, provider scopes, and token-encryption settings.

## OAuth — `oauth_config: OAuthConfig | None`

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `oauth_cookie_secure` | `True` | Secure flag for OAuth cookies. |
| `oauth_providers` | `None` | Single plugin-owned OAuth provider inventory as :class:`~litestar_auth.config.OAuthProviderConfig` entries. Each provider auto-mounts `GET {auth_path}/oauth/{provider}/authorize` and `GET {auth_path}/oauth/{provider}/callback`. |
| `oauth_provider_scopes` | `{}` | Optional server-owned OAuth scopes keyed by provider name. Each provider authorize route uses only these configured scopes; runtime query overrides are rejected. |
| `oauth_associate_by_email` | `False` | Policy for plugin-owned OAuth login routes. When enabled, login callbacks may associate an existing local user by email if provider email ownership is also trusted. |
| `oauth_trust_provider_email_verified` | `False` | Trust provider `email_verified` claims for plugin-owned OAuth login routes. Use only with providers that cryptographically assert email ownership. |
| `include_oauth_associate` | `False` | Also auto-mount authenticated associate routes for the same `oauth_providers` inventory under `GET {auth_path}/associate/{provider}/authorize` and `GET {auth_path}/associate/{provider}/callback`. |
| `oauth_redirect_base_url` | `""` | Required public HTTPS redirect base for plugin-owned OAuth callbacks. The plugin derives `{oauth_redirect_base_url}/oauth/{provider}/callback` and, when associate routes are enabled, `{oauth_redirect_base_url}/associate/{provider}/callback`. |
| `oauth_token_encryption_keyring` | `None` | Preferred production token-at-rest keyring. Use `FernetKeyringConfig(active_key_id=..., keys=...)` so old key ids remain readable during rotation. |
| `oauth_token_encryption_key` | `None` | One-key token-at-rest shortcut. Mutually exclusive with `oauth_token_encryption_keyring`; encoded under the `default` key id. |
| `oauth_flow_cookie_secret` | `None` | **Required** for any declared provider inventory — encrypts and authenticates the transient OAuth state + PKCE verifier flow cookie. Keep it distinct from token, CSRF, TOTP, verification, and reset secrets. |

Provider names are security-sensitive because they are embedded in route paths,
OAuth state cookie names, and callback URLs. Use stable slugs only: 1-64 ASCII
letters, digits, underscores, or hyphens, starting and ending with an
alphanumeric character. Examples: `github`, `github-enterprise`, `github_enterprise`.

For manual custom controllers, `create_provider_oauth_controller(...)` / `create_oauth_controller(...)` still take **`trust_provider_email_verified`** and optional **`oauth_scopes`** directly (see [OAuth guide](../guides/oauth.md)). They also require **`oauth_flow_cookie_secret`** because they own the same encrypted state + PKCE verifier flow cookie as plugin-owned routes. Their `redirect_base_url` fails closed unless it uses a non-loopback `https://...` origin; unlike the plugin-owned route table, the manual factories do not have an `AppConfig(debug=True)` or `unsafe_testing=True` override. The plugin-owned route table maps `OAuthConfig.oauth_trust_provider_email_verified` and `OAuthConfig.oauth_provider_scopes` onto the same runtime behavior.

Preferred construction (import from ``litestar_auth`` or ``litestar_auth.config``):

```python
from litestar_auth import FernetKeyringConfig, OAuthConfig, OAuthProviderConfig

OAuthConfig(
    oauth_providers=[
        OAuthProviderConfig(name="github", client=github_oauth_client),
    ],
    oauth_redirect_base_url="https://app.example.com",
    oauth_token_encryption_keyring=FernetKeyringConfig(
        active_key_id=settings.oauth_token_active_key_id,
        keys=settings.oauth_token_fernet_keys,
    ),
    oauth_flow_cookie_secret="replace-with-32+-char-oauth-flow-secret",
)
```

Stored OAuth `access_token` and `refresh_token` values are written as
`fernet:v1:<key_id>:<ciphertext>` when token encryption is configured. The key id lets the
configured keyring select the decrypting key; it is not a secret, but the ciphertext is still
sensitive. The one-key `oauth_token_encryption_key` shortcut writes with the `default` key id and is
not a complete rotation plan.

For rotation, add the new key id to `oauth_token_encryption_keyring.keys`, deploy that read-capable
keyring everywhere, switch `active_key_id` to the new id, then run an application-owned migration
over the persisted OAuth token columns. `OAuthTokenEncryption.requires_reencrypt(value)` detects
values under a non-active configured key, and `OAuthTokenEncryption.reencrypt(value)` rewrites one
stored value with the active key. Verify that a scan returns no values requiring re-encryption before
retiring the old key id. See [Deployment](../deployment.md#versioned-fernet-key-rotation) for the
full staged runbook.

Direct SQLAlchemy OAuth persistence must receive a real `OAuthTokenEncryption` instance from the
current `litestar_auth.oauth_encryption` module. Policy-shaped wrappers and objects retained across
development/test module reloads are not a supported compatibility surface; create a fresh policy
before passing it to `SQLAlchemyUserDatabase(...)` or `bind_oauth_token_encryption(...)`.
Direct calls to `OAuthTokenEncryption.encrypt(...)`, `.decrypt(...)`, `.requires_reencrypt(...)`,
and `.reencrypt(...)` also fail closed when no key/keyring is configured unless the policy explicitly
sets `unsafe_testing=True`.

Legacy unversioned Fernet token rows do not identify the decrypting key. Treat them as explicit
migration input that must be decrypted with known old key material and rewritten to the versioned
format before normal keyring-only operation; do not depend on automatic runtime compatibility.

Route-registration contract:

- `oauth_providers` is the single plugin-owned provider inventory; there is no separate associate-only provider list.
- `oauth_redirect_base_url` is required whenever `oauth_providers` is configured. The plugin appends `/oauth` and `/associate` per route family instead of guessing a localhost fallback.
- `oauth_flow_cookie_secret` is required whenever `oauth_providers` is configured. The plugin uses it to Fernet-encrypt and authenticate the browser-held flow cookie that contains OAuth `state` and the PKCE `code_verifier`.
- Provider names must be route-safe slugs because they become `{provider}` path segments, OAuth state cookie names, and callback URL components.
- In production app init, plugin-owned OAuth routes now fail closed unless `oauth_redirect_base_url` uses a non-loopback `https://...` origin. Keep localhost or plain-HTTP redirect bases behind `AppConfig(debug=True)` or `unsafe_testing=True` only.
- Manual/custom OAuth controller factories use the same non-loopback `https://...` redirect-origin baseline, but they enforce it immediately at controller construction time with no debug/testing override.
- Both plugin-owned and manual OAuth redirect bases must remain clean callback bases without embedded userinfo, query strings, or fragments.
- Plugin-owned OAuth login routes always use the primary startup backend from `config.resolve_startup_backends()`. If you need provider-specific backend selection, build manual controllers instead of relying on the plugin-owned route table.
- `include_oauth_associate=True` extends that same provider inventory with authenticated account-linking routes. If you need a custom route table, custom prefixes, or manual manager wiring, mount the controller factories yourself instead of mixing plugin-owned and manual ownership.
