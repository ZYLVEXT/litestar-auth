# OAuth router helpers

The `litestar_auth.oauth` package uses **lazy imports** (PEP 562) so optional dependencies such as
`httpx-oauth` are not loaded until OAuth helpers are used. If your IDE does not resolve symbols on
`litestar_auth.oauth`, import from **`litestar_auth.oauth.router`** directly—the module that
implements the helpers re-exported from the package.

These helpers cover the supported manual OAuth client contract used by `create_provider_oauth_controller()`,
`create_oauth_controller()`, and `OAuthClientAdapter`.

- Typed contract: `litestar_auth.oauth.client_adapter.OAuthClientProtocol` with the narrower
  `OAuthDirectIdentityClientProtocol`, `OAuthProfileClientProtocol`, and optional
  `OAuthEmailVerificationAsyncClientProtocol` capability protocols. Wrap sync-only verification clients with
  `make_async_email_verification_client()`.
- Provisioning: pass `oauth_client`, `oauth_client_factory`, or `oauth_client_class` plus `oauth_client_kwargs`.
- Flow-cookie secret: every manual controller factory requires `oauth_flow_cookie_secret` for the encrypted,
  authenticated OAuth state + PKCE verifier cookie. The secret is HKDF-derived into Fernet key material for the
  short-lived `v2` flow-cookie envelope.
- Authorization: the client must provide `get_authorization_url(...) -> str` and accept PKCE S256 challenge
  keyword arguments.
- Token exchange: the client must provide `get_access_token(...)` with an `access_token` payload and accept the
  PKCE `code_verifier` keyword argument.
- Identity: provide `get_id_email(...)` or `get_profile(...)` with account id and email fields.
- Optional verification: provide async `get_email_verified(...)` or an `email_verified` field on the profile payload.
- Invalid import paths, missing methods, or malformed payloads fail closed with `ConfigurationError`.

See [OAuth2 login and account linking](../guides/oauth.md#manual-oauth-client-contract) for the full behavioral contract.

## Token encryption policy

OAuth token persistence is configured with `OAuthConfig.oauth_token_encryption_keyring` for
plugin-managed routes or with an explicit `OAuthTokenEncryption(...)` policy for direct
`SQLAlchemyUserDatabase(...)` usage. Encrypted stored values use the
`fernet:v1:<key_id>:<ciphertext>` envelope. The one-key `oauth_token_encryption_key` shortcut and
`OAuthTokenEncryption(key=...)` path write with the `default` key id; use a
`FernetKeyringConfig(active_key_id=..., keys=...)` or `OAuthTokenEncryption(active_key_id=..., keys=...)`
when you need rotation.

`OAuthTokenEncryption.requires_reencrypt(value)` and `OAuthTokenEncryption.reencrypt(value)` operate
on one stored token value at a time. Migration jobs should apply them to both `access_token` and
`refresh_token` columns, commit rewritten values, scan again, and remove retired key ids only after
no rows require rotation. Legacy unversioned Fernet values need explicit old-key migration input
because the stored value does not identify its decrypting key.
These public helpers fail closed unless the policy has a configured key/keyring or explicitly sets
`unsafe_testing=True`; keyless plaintext mode is only a test-owned override.

::: litestar_auth.oauth_encryption

Public OAuth helpers are implemented in `litestar_auth.oauth.router` (the `litestar_auth.oauth` package re-exports them lazily).
The old `litestar_auth.contrib.oauth` package is no longer a compatibility import path.

::: litestar_auth.oauth.router
