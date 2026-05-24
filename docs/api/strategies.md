# Strategies

Token **strategies** validate or issue credentials and pair with transports inside an `AuthenticationBackend` (see [Backends: transports and strategies](../concepts/backends.md)). Three concrete implementations ship with litestar-auth:

- **`JWTStrategy`** issues and verifies stateless signed JWTs with your configured signing keys. Library-issued access tokens include JOSE `typ=JWT`; decode rejects tokens with a missing or unexpected `typ` header before the normal signed validation. This header check is defense-in-depth against token-class confusion and does not replace signature, algorithm allowlist, audience, issuer, or required-claim validation. Use this strategy when you want bearer or cookie flows without storing each access token in a database or Redis—scaling and rotation are typically driven by expiry and refresh semantics rather than per-token rows. Use `JWTStrategyConfig(...)` when you want the signing, validation, revocation, lifetime, and session-fingerprint settings carried as one typed object.

- **`DatabaseTokenStrategy`** stores opaque tokens in your application database (hashed at rest). Use it when you need durable revocation, per-token metadata, refresh-session/device listing, or audit trails aligned with your ORM models. Use `DatabaseTokenStrategyConfig(...)` when the session, token models, token hash secret, access lifetime, refresh lifetime, and token-size settings should travel together.

- **`RedisTokenStrategy`** keeps opaque token state in Redis with TTL-backed keys and a per-user
  token index. Use it when you want fast invalidation and shared token state across app instances
  without adding DB round-trips for every validation. `invalidate_all_tokens(...)` atomically bumps
  a per-user invalidation epoch and deletes indexed token and TOTP step-up marker keys. Token reads
  validate that epoch, so orphaned token keys missing from the per-user index are rejected on their
  next use after invalidation without a keyspace scan. The per-user index key hashes the serialized
  user id before adding it to the Redis key, so custom id values cannot inject key delimiters or
  reshape the namespace. You can construct it with
  `RedisTokenStrategyConfig(...)` when you want the Redis client, hash secret, TTL, key prefix,
  token byte count, and optional subject decoder carried as one typed settings object.

- **`ApiKeyStrategy`** verifies user-owned API keys against a `BaseApiKeyStore`. Configure it with
  `ApiKeyStrategyConfig` or equivalent keyword arguments. Bearer keys compare the presented secret
  with the stored HMAC digest. Signing-required keys use the encrypted stored secret to verify
  `LSA1-HMAC-SHA256` normalized request signatures, validate `X-Auth-Date` within
  `signing_skew_seconds`, and reject replayed `X-Auth-Nonce` values through an `ApiKeyNonceStore`.
  Successful reads return `ApiKeyAuthenticationResult` with the resolved user and `ApiKeyContext`;
  middleware exposes that context as `request.auth`.

For plugin-oriented setup, **`DatabaseTokenAuthConfig`** on `LitestarAuthConfig` is the direct shortcut for wiring opaque database-backed tokens (hash secret, optional backend naming, and related compatibility flags) without hand-assembling the strategy and related pieces in isolation. Full wiring for the preset, route flags, and related options is covered in [Backends](../configuration/backends.md#opaque-db-token-preset); ORM mixins, token tables, and `SQLAlchemyUserDatabase` contracts are covered in [User and manager](../configuration/user_and_manager.md).

## Refresh-session management support

The session/device HTTP API is backed by a strategy protocol rather than by controller-side database
queries. `DatabaseTokenStrategy` implements that protocol and can:

- list the authenticated user's active, non-expired refresh sessions;
- revoke one current-user session by public `session_id`;
- revoke all other current-user sessions, preserving the current session when the current refresh
  credential can be identified;
- identify a public `session_id` from a raw refresh token by hashing the supplied value and comparing
  it with stored digests;
- record consumed refresh-token digests during rotation and revoke the whole refresh-session chain when
  a consumed token is presented again.

`JWTStrategy` and `RedisTokenStrategy` do not currently provide the session/device dashboard
contract. If plugin-owned session/device routes are enabled against an unsupported strategy, the
route returns `400` with `SESSION_MANAGEMENT_UNSUPPORTED`; it does not synthesize empty session data.
The API never returns raw tokens, access tokens, refresh tokens, stored token digests, or keyed token
digests.

::: litestar_auth.authentication.strategy
