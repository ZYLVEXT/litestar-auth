# API keys

API-key authentication is opt-in. Set `LitestarAuthConfig.api_keys` with `ApiKeyConfig(enabled=True, ...)` to add the
API-key backend, self-service routes under `/api-keys`, admin routes under `/users/{user_id}/api-keys`, and the
`apiKeyAuth` OpenAPI security scheme.

```python
from datetime import timedelta

from litestar_auth import ApiKeyConfig, LitestarAuthConfig

config = LitestarAuthConfig(
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    backends=[jwt_backend],
    api_keys=ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read:reports", "write:reports"),
        max_keys_per_user=5,
        default_ttl=timedelta(days=365),
    ),
    user_manager_security=UserManagerSecurity(
        api_key_hash_secret="replace-with-a-csprng-generated-secret",
        verification_token_secret="replace-with-a-distinct-secret",
        reset_password_token_secret="replace-with-another-distinct-secret",
    ),
)
```

When enabled, startup validation is fail-closed: `api_key_hash_secret` must be configured, must be distinct from other
secret roles, and must satisfy the production secret policy outside `unsafe_testing=True`. The default store factory is
deferred to `SQLAlchemyApiKeyStore`; pass `store_factory=` when you own a custom `BaseApiKeyStore`.

## Credential format

Issued bearer credentials have this shape:

```text
ak_<environment_marker>_<key_id>.<secret>
```

The stored row keeps `key_id`, `prefix_env`, scopes, timestamps, revocation state, and an HMAC digest of the secret.
The raw secret is returned only once from create responses and is not persisted for bearer keys.

Clients may send bearer API keys in either header:

```http
Authorization: Bearer ak_prod_k123.secret
X-API-Key: ak_prod_k123.secret
```

The OpenAPI scheme name is `apiKeyAuth`; it is an HTTP bearer scheme with bearer format `API key`.

## Management routes

The plugin mounts these self-service routes when API keys are enabled:

| Route | Purpose |
| ---- | ---- |
| `POST /api-keys` | Create a key and return the raw `api_key` once plus safe metadata. Requires a password session through `requires_password_session`; also requires `current_password` by default. |
| `GET /api-keys` | List active keys for the current user. |
| `GET /api-keys/{key_id}` | Read safe metadata for one current-user key. Missing or foreign keys return `API_KEY_INVALID` as a 404. |
| `PATCH /api-keys/{key_id}` | Update name or scopes. Requires a password session through `requires_password_session`. |
| `DELETE /api-keys/{key_id}` | Soft-revoke one current-user key. Requires a password session through `requires_password_session`. |

Admin routes are guarded by `is_superuser` and use the path user id as authority:
`POST /users/{user_id}/api-keys`, `GET /users/{user_id}/api-keys`, and
`DELETE /users/{user_id}/api-keys/{key_id}`. Request bodies never choose the target user, and admin
create requests do not require the target user's `current_password`.

## Rate-limit slots

API-key management uses the shared `AuthRateLimitConfig` endpoint slots. `api_key_create` protects self-service
`POST /api-keys` password re-verification failures, while `api_key_update` protects self-service
`PATCH /api-keys/{key_id}` failures caused by a bad `current_password` or denied scope request. A successful create or
update resets that route's counter for the request key.

`AuthRateLimitConfig.api_key_update` defaults to `None`, so PATCH remains unthrottled unless you opt in:

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, RedisRateLimiter

rate_limits = AuthRateLimitConfig(
    api_key_update=EndpointRateLimit(
        backend=RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=300),
        scope="ip",
        namespace="api-key-update",
    ),
)
```

## Policy fields

| Field | Default | Behavior |
| ---- | ---- | ---- |
| `enabled` | `False` | Adds the backend, routes, DI wiring, and OpenAPI security scheme. |
| `environment_marker` | `"prod"` | Embedded in issued credentials and checked during authentication. |
| `max_keys_per_user` | `5` | Active-key cap; exceeding it raises `API_KEY_LIMIT_REACHED`. |
| `default_ttl` | 365 days | Applied when create requests omit `expires_at`; `None` creates non-expiring keys and emits a security warning. |
| `require_step_up_on_create` | `True` | Requires `current_password` on self-service create requests. Setting it to `False` keeps `requires_password_session` but skips password re-verification for create. |
| `allowed_scopes` | `()` | Scope catalog used by create/update validation when `scope_subset_check=True`. |
| `scope_subset_check` | `True` | Re-checks API-key scopes against the configured scope authority at guard time. |
| `scope_authority` | `None` | Optional callable receiving `(connection, api_key_scopes)` and returning whether those key scopes remain allowed. `None` uses the bundled default authority. |
| `last_used_write_strategy` | `"throttled"` | Controls persistence of `last_used_at`: `disabled`, `immediate`, or `throttled`. |
| `last_used_throttle_seconds` | `300` | Minimum interval between throttled `last_used_at` writes. |
| `signed_body_max_bytes` | 1 MiB | Maximum buffered body size for signed requests before pre-auth rejection with `REQUEST_BODY_INVALID`. |
| `signed_body_max_messages` | `1024` | Maximum ASGI request-message frames buffered for signed requests before the same rejection contract. |

When `scope_subset_check=True`, API-key scopes are downscoped by a scope authority at guard time. The default authority
is `litestar_auth.guards._api_key_guards.default_api_key_scope_authority`; it implements the v1 scopes-as-role-names
contract by allowing only keys whose normalized scopes are a subset of the current user's normalized role names. For
example, a key scoped to `read:reports` remains effective only while the user has a `read:reports` role. If your
application models scopes and roles separately, provide `scope_authority=` so the guard can ask your permissions model
instead of comparing scope names to role names.

The bundled `SQLAlchemyApiKeyStore` enforces `max_keys_per_user` inside the create operation and locks the owning user
row before counting active keys, so multi-worker SQL databases serialize concurrent key creation for the same user.
Custom `BaseApiKeyStore` implementations must provide the same atomic check-and-create behavior.

## Request signing

Set `api_keys.signing_enabled=True`, configure `api_keys.secret_encryption_keyring`, and provide a nonce store before
creating signing-required keys. Signing-required keys store an encrypted copy of the raw secret so the server can verify
future request signatures. This is a deliberate reversible-storage trade-off; use bearer keys when digest-only storage is
more important than request integrity.

Signed requests use `Authorization: LSA1-HMAC-SHA256 Credential=<key_id>, SignedHeaders=<headers>, Signature=<hex>`
with `Host`, `X-Auth-Date`, and `X-Auth-Nonce`. `host` must appear lowercased in `SignedHeaders`; clients should sign the
exact `Host` header value they send on the wire, including the port when present. The signed request string includes
method, path, sorted query parameters, declared headers, and the SHA-256 body digest. `apiKeyHmacAuth` appears in OpenAPI
only when signing support is configured.

`X-Auth-Date` must be an ISO-8601 timestamp accepted by Python `datetime.fromisoformat`; a trailing `Z` is accepted as
UTC. RFC 5322 / HTTP-date strings such as `Mon, 09 May 2026 23:36:35 GMT` are rejected. A Python client can generate a
portable UTC header value with:

```python
from datetime import UTC, datetime

x_auth_date = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
```

Signed-request body buffering is bounded by both `api_keys.signed_body_max_bytes` and
`api_keys.signed_body_max_messages`. Tune the frame-count limit alongside the byte limit if your ASGI stack emits
unusually small request-body frames.

For a request to `api.example.com`, the minimum signed header set is:

```http
Host: api.example.com
X-Auth-Date: 2026-05-09T19:00:00Z
X-Auth-Nonce: unique-client-nonce
Authorization: LSA1-HMAC-SHA256 Credential=kabc, SignedHeaders=host;x-auth-date;x-auth-nonce, Signature=<hex>
```

Use `RedisApiKeyNonceStore` for multi-worker deployments. `InMemoryApiKeyNonceStore` is process-local and suitable only
for development, tests, or explicitly single-process runtime.

## Explicit non-goals

API keys are user-owned delegated credentials in this release. The following are intentionally out of scope:
service-account-only keys, HKDF child keys, IP allowlists, a per-key audit table, and mTLS binding.
