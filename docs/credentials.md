# Credentials and tokens

AuthWeave separates four credential classes. Mixing them in documentation or configuration is the
most common integration mistake.

## Opaque browser session

The supported human request path is a secure cookie carrying an opaque server-side session token
backed by a database or Redis store. The client never receives a self-describing access JWT for
everyday authenticated requests. With `LitestarAuthConfig.enable_refresh=True`, refresh tokens
rotate; reuse of a consumed refresh token revokes the active chain.

See the [quickstart](quickstart.md) and [Redis sessions](how-to/redis-sessions.md).

## Challenge JWTs

Short-lived signed JWTs appear only as narrowly scoped account artifacts. Each has a distinct
`aud`, time bounds, and `jti` replay protection. They are **not** browser sessions and must not be
accepted as general request authentication.

| Audience | Purpose | Secret role |
| --- | --- | --- |
| `litestar-auth:verify` | Email verification | `verification_token_secret` |
| `litestar-auth:reset-password` | Password reset | `reset_password_token_secret` |
| `litestar-auth:organization-invitation` | Organization invitation | `organization_invitation_token_secret` |
| `litestar-auth:2fa-pending` | TOTP pending login | `totp_pending_secret` |
| `litestar-auth:2fa-enroll` | TOTP enrollment | `totp_pending_secret` |

Audience constants live in `litestar_auth._secret_roles`. Use distinct high-entropy secrets per
role; see [secrets and stores](secrets.md).

## OAuth state and PKCE

OAuth Authorization Code + PKCE stores state and the PKCE verifier in an **encrypted cookie**, not
in a JWT. The flow is relying-party only. AuthWeave is not an Authorization Server.

See [OAuth](how-to/oauth.md).

## Workload credentials

mTLS, certificate-bound JWT, DPoP, SPIFFE X.509-SVID, and sender-constrained introspection belong
to `authweave-workload`. They never substitute for the human opaque-session path, and a human
session cannot satisfy a machine route.

See [architecture](architecture.md) and the merchant workload guides under Workload how-to.

## Summary

| Artifact | Where it lives | Authenticates requests? |
| --- | --- | --- |
| Opaque session cookie | DB or Redis session store | Yes (human routes) |
| Challenge JWT | Signed artifact with scoped `aud` | No — only the named flow |
| OAuth state / PKCE | Encrypted flow cookie | No — OAuth handshake only |
| Workload JWT / mTLS / DPoP | `authweave-workload` profile | Yes (machine routes only) |
