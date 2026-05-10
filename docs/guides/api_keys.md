# API keys

Use API keys for developer or automation access to routes that should not require a browser session. The feature is
disabled by default and is mounted only when `ApiKeyConfig(enabled=True)` is present on `LitestarAuthConfig`.

## Enable API keys

```python
from litestar_auth import ApiKeyConfig, LitestarAuthConfig

config = LitestarAuthConfig(
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    backends=[jwt_backend],
    api_keys=ApiKeyConfig(
        enabled=True,
        allowed_scopes=("reports:read", "reports:write"),
    ),
    user_manager_security=UserManagerSecurity(
        api_key_hash_secret="replace-with-a-distinct-csprng-secret",
        verification_token_secret="replace-with-a-different-secret",
        reset_password_token_secret="replace-with-another-secret",
    ),
)
```

For the full field reference, see [Configuration — API keys](../configuration/api_keys.md).

## Issue a key

API-key management requests require a real password-backed session. By default create requests also require
`current_password`; disabling `api_keys.require_step_up_on_create` keeps the password-session boundary but skips that
re-verification. API-key callers cannot list, inspect, create, update, or revoke API keys because those routes use
`requires_password_session`.

For password re-verification endpoints, configure `AuthRateLimitConfig.api_key_create` for `POST /api-keys` and
`AuthRateLimitConfig.api_key_update` for `PATCH /api-keys/{key_id}`. The update slot increments on wrong `current_password` and
denied scope changes, returns `429 Too Many Requests` with `Retry-After` when exhausted, and resets after a successful
update.

```http
POST /api-keys
Authorization: Bearer <user-access-token>
Content-Type: application/json

{
  "name": "ci deploy",
  "current_password": "correct horse battery staple",
  "scopes": ["reports:read"]
}
```

The response includes the raw `api_key` exactly once:

```json
{
  "api_key": "ak_prod_kabc.secret",
  "key": {
    "key_id": "kabc",
    "name": "ci deploy",
    "scopes": ["reports:read"],
    "prefix_env": "prod",
    "created_at": "2026-05-09T19:00:00Z",
    "expires_at": "2027-05-09T19:00:00Z",
    "last_used_at": null,
    "revoked_at": null
  }
}
```

Persist only the raw credential on the client side. Server-side API-key rows store an HMAC digest, safe metadata, and an
optional encrypted signing secret for signing-required keys.

Superusers can create, list, and revoke keys for another user through the `/users/{user_id}/api-keys` admin routes.
Those routes are guarded by both `is_superuser` and `requires_password_session`, so an API-key-authenticated superuser
cannot manage another user's key inventory. Admin create takes the target user from the path and does not require the
target user's `current_password`.

## Protect routes by key and scope

```python
from litestar import get

from litestar_auth.guards import has_scope, requires_api_key


@get("/reports", guards=[requires_api_key, has_scope("reports:read")])
async def reports() -> dict[str, bool]:
    return {"ok": True}
```

During API-key authentication, `request.auth` is an `ApiKeyContext` containing `key_id`, `scopes`, `prefix_env`, and
the configured scope-subset policy. With `scope_subset_check=True`, scope guards check both the key scopes and the
configured scope authority, so revoking the authority behind a key immediately removes effective access.

By default, the scope authority is the bundled v1 scopes-as-role-names check: normalized API-key scopes must be a subset
of the current user's normalized role names. That means a key with `reports:read` remains effective only while the user
also has a `reports:read` role. If your application keeps permissions separate from role names, pass
`ApiKeyConfig(scope_authority=...)`; the callable receives `(connection, api_key_scopes)` and returns `True` when those
key scopes are still allowed.

## Use a bearer API key

```http
GET /reports
Authorization: Bearer ak_prod_kabc.secret
```

or:

```http
GET /reports
X-API-Key: ak_prod_kabc.secret
```

Use bearer keys only over TLS. They are digest-only at rest, but possession of the raw credential is enough to call the
API until expiry or revocation. Bearer authentication failures use HTTP 401 with structured API-key error codes; see
[Security model — Bearer failure-code taxonomy](../security.md#bearer-failure-code-taxonomy) for the deliberate
`API_KEY_INVALID`, `API_KEY_REVOKED`, and `API_KEY_EXPIRED` trade-off.

## Use signed requests

Request signing binds the credential to one method, path, query string, selected headers, timestamp, nonce, and body
digest. It reduces replay and body-tampering risk for automation clients, but it requires reversible encrypted storage
of the key secret.

Enable signing support with a Fernet keyring and nonce store, then create keys with `"signing_required": true`.

```python
from litestar_auth import ApiKeyConfig
from litestar_auth.authentication.strategy import InMemoryApiKeyNonceStore
from litestar_auth.manager import FernetKeyringConfig

api_keys = ApiKeyConfig(
    enabled=True,
    signing_enabled=True,
    nonce_store=InMemoryApiKeyNonceStore(),
    secret_encryption_keyring=FernetKeyringConfig(
        active_key_id="2026-05",
        keys={"2026-05": "base64-fernet-key"},
    ),
)
```

Production multi-worker apps should use `RedisApiKeyNonceStore` instead of the in-memory nonce store.
Signed-request body buffering is bounded by both `api_keys.signed_body_max_bytes` and
`api_keys.signed_body_max_messages`; requests that exceed either limit fail with `REQUEST_BODY_INVALID`.

Signed clients send:

```http
Host: api.example.com
Authorization: LSA1-HMAC-SHA256 Credential=kabc, SignedHeaders=host;x-auth-date;x-auth-nonce, Signature=<hex>
X-Auth-Date: 2026-05-09T19:00:00Z
X-Auth-Nonce: unique-client-nonce
```

`host`, `x-auth-date`, and `x-auth-nonce` are required in `SignedHeaders`. Sign the exact `Host` header value sent by the
client, including a port when the request uses a non-default port, so the signature is bound to the target host.
`X-Auth-Date` must be an ISO-8601 timestamp accepted by Python `datetime.fromisoformat`; a trailing `Z` is accepted as
UTC. Do not send RFC 5322 / HTTP-date strings such as `Mon, 09 May 2026 23:36:35 GMT`.

```python
from datetime import UTC, datetime

x_auth_date = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
```

Timestamp skew returns `API_KEY_SIGNATURE_TIMESTAMP_SKEW`, nonce replay returns
`API_KEY_SIGNATURE_NONCE_REPLAY`, and other signing failures return `API_KEY_SIGNATURE_INVALID`.
