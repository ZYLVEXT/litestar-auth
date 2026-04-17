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
- Authorization: the client must provide `get_authorization_url(...) -> str`.
- Token exchange: the client must provide `get_access_token(...)` with an `access_token` payload.
- Identity: provide `get_id_email(...)` or `get_profile(...)` with account id and email fields.
- Optional verification: provide async `get_email_verified(...)` or an `email_verified` field on the profile payload.
- Invalid import paths, missing methods, or malformed payloads fail closed with `ConfigurationError`.

See [OAuth2 login and account linking](../guides/oauth.md#manual-oauth-client-contract) for the full behavioral contract.

Public OAuth helpers are implemented in `litestar_auth.oauth.router` (the `litestar_auth.oauth` package re-exports them lazily).

::: litestar_auth.oauth.router
