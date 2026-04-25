# Strategies

Token **strategies** validate or issue credentials and pair with transports inside an `AuthenticationBackend` (see [Backends: transports and strategies](../concepts/backends.md)). Three concrete implementations ship with litestar-auth:

- **`JWTStrategy`** issues and verifies stateless signed JWTs with your configured signing keys. Library-issued access tokens include JOSE `typ=JWT`; decode rejects tokens with a missing or unexpected `typ` header before the normal signed validation. This header check is defense-in-depth against token-class confusion and does not replace signature, algorithm allowlist, audience, issuer, or required-claim validation. Use this strategy when you want bearer or cookie flows without storing each access token in a database or Redis—scaling and rotation are typically driven by expiry and refresh semantics rather than per-token rows.

- **`DatabaseTokenStrategy`** stores opaque tokens in your application database (hashed at rest). Use it when you need durable revocation, per-token metadata, or audit trails aligned with your ORM models.

- **`RedisTokenStrategy`** keeps opaque token state in Redis with TTL-backed keys and a per-user
  token index. Use it when you want fast invalidation and shared token state across app instances
  without adding DB round-trips for every validation. `invalidate_all_tokens(...)` deletes only
  tokens present in that per-user index; orphaned keys from older deployments that never wrote the
  index are left to expire by their Redis TTL instead of being discovered by a keyspace scan. The
  per-user index key hashes the serialized user id before adding it to the Redis key, so custom id
  values cannot inject key delimiters or reshape the namespace.

For plugin-oriented setup, **`DatabaseTokenAuthConfig`** on `LitestarAuthConfig` is the direct shortcut for wiring opaque database-backed tokens (hash secret, optional backend naming, and related compatibility flags) without hand-assembling the strategy and related pieces in isolation. Full wiring for secrets, ORM mixins, and related options is covered in [Configuration](../configuration.md).

::: litestar_auth.authentication.strategy
