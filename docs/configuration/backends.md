# Backends

Use this page for the database-token preset, backend lifecycle helpers, route path flags, and built-in auth payloads.

## Opaque DB-token preset

Use `DatabaseTokenAuthConfig` plus direct `LitestarAuthConfig(..., database_token_auth=...)`
construction for the common bearer + database-token flow. This is the documented entrypoint for
opaque DB tokens; it builds the `AuthenticationBackend`, `BearerTransport`, and
`DatabaseTokenStrategy` for you.

```python
from uuid import UUID

from litestar import Litestar

from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User

config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret="replace-with-32+-char-db-token-secret",
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
)
app = Litestar(plugins=[LitestarAuth(config)])
```

Here, `session_maker` means a callable session factory the plugin can invoke as `session_maker()` to obtain the request-local `AsyncSession`. `async_sessionmaker(...)` is the most common implementation, but any factory with that runtime contract is supported.

If you previously hand-assembled `AuthenticationBackend(..., transport=BearerTransport(), strategy=DatabaseTokenStrategy(...))`, migrate that setup to the direct `database_token_auth=DatabaseTokenAuthConfig(...)` form above. Keep manual `backends=` assembly only when you need multiple backends, custom token models, or another custom transport/strategy mix.

When you use `database_token_auth=...`, `config.backends` stays empty by design. `config.resolve_startup_backends()` returns startup-only `StartupBackendTemplate` values for plugin assembly and validation, while `config.resolve_backends(session)` returns the request-scoped runtime `AuthenticationBackend` instances bound to the active `AsyncSession` for every supported backend configuration.

### Default precedence

Feature defaults are resolved once from the config snapshot used for plugin startup:

- Explicit values on `DatabaseTokenAuthConfig`, `ApiKeyConfig`, `TotpConfig`, and `OAuthConfig` win.
- Omitted feature objects keep that feature disabled, except `LitestarAuthConfig.api_keys`, whose default object is disabled with `enabled=False`.
- Omitted `user_db_factory` falls back to the lazy SQLAlchemy store factory at request binding time.
- Omitted `TotpConfig.totp_backend_name` selects the primary startup backend.

`None` is meaningful only where documented, such as `ApiKeyConfig.default_ttl=None` for non-expiring keys. Other omitted fallback targets are normalized internally before startup wiring so defaults stay coherent across route, backend, and manager assembly.

### Backend lifecycle contract

Treat the two backend helpers as distinct surfaces:

- `config.resolve_startup_backends()` is the plugin's startup inventory. Manual backends are wrapped as `StartupBackendTemplate` values, and the DB-token preset also contributes a `StartupBackendTemplate` that is valid for plugin assembly, validation, and route selection only.
- `config.resolve_backends(session)` realizes request-scoped `AuthenticationBackend` instances aligned with `config.resolve_startup_backends()` order. Use this surface whenever runtime login, refresh, logout, token validation, or other request-time work needs the active `AsyncSession`.
- Startup-only DB-token templates fail closed if they are used for runtime database-token work before `resolve_backends(session)` supplies a request session.

Controller selection follows that startup inventory:

- The primary backend mounts at `{auth_path}`.
- Additional backends mount at `{auth_path}/{backend.name}` in configured order.
- Plugin-owned OAuth login routes use the primary startup backend.
- TOTP uses the primary startup backend unless `TotpConfig.totp_backend_name` selects another named backend from the same startup inventory.

## API-key backend

`ApiKeyConfig` is opt-in through `LitestarAuthConfig.api_keys`. Set `api_keys.enabled=True` to add
the bearer-mode API-key backend, management controllers, rate-limit slots, and the OpenAPI
`apiKeyAuth` security scheme. When disabled, the plugin does not add an API-key backend,
dependency, OpenAPI security scheme, or controller surface.

```python
from uuid import UUID

from litestar_auth import ApiKeyConfig, LitestarAuthConfig
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User

config = LitestarAuthConfig[User, UUID](
    api_keys=ApiKeyConfig(
        enabled=True,
        environment_marker="prod",
        allowed_scopes=("read", "write"),
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
        api_key_hash_secret="replace-with-32+-char-api-key-hmac-secret",
    ),
)
```

The plugin appends the generated API-key backend after any manually configured backends or the
database-token preset, so existing primary-backend route selection stays caller-controlled. Request
authentication accepts API keys through either `Authorization: Bearer ak_<env>_<key_id>.<secret>`
or `X-API-Key: ak_<env>_<key_id>.<secret>`.

API-key backends are standalone authenticators and do not participate in refresh-token flows. When
`enable_refresh=True`, startup refresh-capability validation still applies to refresh-relevant
Bearer/Cookie/database/Redis token backends, but intentionally skips `ApiKeyTransport` backends.

Set `signing_required=true` on `ApiKeyCreateRequest` or pass
`create_api_key(..., signing_required=True)` to issue a key that can only authenticate signed
requests. Signing mode uses `Authorization: LSA1-HMAC-SHA256 Credential=<key_id>,
SignedHeaders=<semicolon-separated-lowercase-header-names>, Signature=<hex-hmac>` plus
`X-Auth-Date` and `X-Auth-Nonce`. The signed request string is method, path, sorted query string,
the declared signed headers, the signed header list, and the SHA-256 body digest. Bearer attempts for
signing-required keys fail with `API_KEY_SIGNATURE_INVALID`.

To enable signing, configure `api_keys.signing_enabled=True`, `api_keys.nonce_store`, and
`api_keys.secret_encryption_keyring`. Nonce TTL is `2 * signing_skew_seconds`; timestamp failures
return `API_KEY_SIGNATURE_TIMESTAMP_SKEW`, nonce replays return `API_KEY_SIGNATURE_NONCE_REPLAY`,
and other signature failures return `API_KEY_SIGNATURE_INVALID`. The encryption keyring must be
distinct from the API-key hash secret and all other configured secret roles. In multi-worker
deployments, use `RedisApiKeyNonceStore`; the in-memory nonce store is process-local and intended
for tests or single-process development. Signed requests are buffered before authentication so the
server can verify the raw body digest; `api_keys.signed_body_max_bytes` caps that pre-auth buffer
and defaults to `1048576` bytes. Requests over the cap fail with HTTP 413 and
`REQUEST_BODY_INVALID`.

With API keys enabled, the plugin mounts self-service routes at `/api-keys`:

- `POST /api-keys` creates a key and returns `ApiKeyCreateResponse` with the raw `api_key` exactly
  once plus safe `key` metadata. The request body is `ApiKeyCreateRequest` and requires
  `current_password` by default when `api_keys.require_step_up_on_create=True`.
- `GET /api-keys` returns `ApiKeyListResponse`.
- `GET /api-keys/{key_id}` returns safe `ApiKeyRead` metadata for a key owned by the current user.
- `PATCH /api-keys/{key_id}` accepts `ApiKeyUpdateRequest` for name/scope changes and requires
  `current_password`.
- `DELETE /api-keys/{key_id}` soft-revokes a current-user key.

Admin routes are nested under the configured `users_path` and guarded by `is_superuser`:
`POST /users/{user_id}/api-keys`, `GET /users/{user_id}/api-keys`, and
`DELETE /users/{user_id}/api-keys/{key_id}`. The `user_id` always comes from the path; request
bodies cannot select another user, and admin create requests do not require the target user's
`current_password`. Self-service lookups for another user's `key_id` return `API_KEY_INVALID` as a
404 so key existence is not disclosed.

Startup validation is fail-closed when `api_keys.enabled=True`: `api_key_hash_secret` is required on
`UserManagerSecurity`, `max_keys_per_user` must be greater than zero, and `allowed_scopes` must be
non-empty while `scope_subset_check=True`. The default SQLAlchemy API-key store is imported lazily at
request binding time; pass `store_factory=` to use a custom `BaseApiKeyStore`.

`default_ttl` defaults to 365 days. Setting `default_ttl=None` is accepted for explicit non-expiring
key policies, but production startup emits `SecurityWarning` unless `unsafe_testing=True`.

Request-scoped `BaseUserManager` instances receive the API-key store and config when
`api_keys.enabled=True`. Use the manager surface to issue and maintain keys:

- `create_api_key(user, name=..., scopes=..., current_password=...)` returns an `ApiKeyCreateResult`
  whose `secret.get_secret_value()` is the only place the raw `ak_<env>_<key_id>.<secret>` value is
  exposed. The persisted row stores only the HMAC digest for bearer keys. Signing-required keys also
  store the raw signing secret encrypted as `fernet:v1:<keyring-key-id>:<ciphertext>`.
- `list_api_keys()` and `get_api_key()` return metadata rows only; pass `include_inactive=True` when
  an operator view needs revoked or expired keys.
- `update_api_key()` can rename a key and replace its scope list. Create and update reject scopes
  outside `allowed_scopes` while `scope_subset_check=True`.
- `revoke_api_key()` is soft and idempotent; repeated calls preserve the first `revoked_at`.
- `record_api_key_used()` honors `last_used_write_strategy` and `last_used_throttle_seconds`, so
  regular API-key authentication does not write the same row on every request.
- `api_key_signing_secret_requires_reencrypt(row)` and
  `reencrypt_api_key_signing_secret(row_or_key_id)` are explicit row-level helpers for rotating
  signing-required keys after `api_keys.secret_encryption_keyring.active_key_id` changes. They
  require an API-key store and keyring, reject bearer rows and missing `encrypted_secret` values,
  never return plaintext signing secrets, and do not run create/revoke/use lifecycle hooks.

`create_api_key()` and `update_api_key()` verify `current_password` when it is supplied. The
generated HTTP create route requires that field by default through
`api_keys.require_step_up_on_create=True`; setting it to `False` keeps the password-session guard but
skips password re-verification for create. The update route always requires `current_password`.
API-key-authenticated callers cannot create or mutate keys because the generated routes also use
`requires_password_session`.
Applications can override `on_after_api_key_created`, `on_after_api_key_revoked`, and
`on_after_api_key_used` for audit events; the `used` hook fires only when a last-used write is
actually persisted.

API-key management failures use stable machine-readable codes: `API_KEY_SCOPE_DENIED` for scopes
outside `allowed_scopes`, `API_KEY_LIMIT_REACHED` for `max_keys_per_user`, and `API_KEY_INVALID`
for missing or foreign key ids. API-key authentication failures distinguish `API_KEY_INVALID`,
`API_KEY_REVOKED`, and `API_KEY_EXPIRED` where the credential can be parsed and the key row can be
resolved.

Rate limiting exposes two API-key slots in `AuthRateLimitConfig`: `api_key_create` for
`POST /api-keys`, and `api_key_use` for failed API-key authentication attempts keyed by the parsed
`key_id` when available. Successful API-key requests update `last_used_at` according to the manager
throttle policy, but do not consume the invalid-attempt bucket. The `api_key_use` identity uses the same rightmost `X-Forwarded-For`
trusted-proxy handling as the other auth rate-limit helpers for its IP component.

## Paths and HTTP feature flags

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `auth_path` | `"/auth"` | Base path for generated auth controllers. |
| `users_path` | `"/users"` | Base path for user CRUD when enabled. |
| `include_register` | `True` | `POST .../register` |
| `include_verify` | `True` | Verify + request-verify-token |
| `include_reset_password` | `True` | Forgot + reset password |
| `include_users` | `False` | User management routes |
| `enable_refresh` | `False` | `POST .../refresh` |
| `include_session_devices` | `False` | `GET .../sessions`, `POST .../sessions`, `DELETE .../sessions/{session_id}`, `POST .../sessions/revoke-others` |
| `requires_verification` | `True` | Stricter login / TOTP-verify policy |
| `hard_delete` | `False` | Physical vs soft delete semantics for user delete |
| `login_identifier` | `"email"` | `"email"` or `"username"` for `POST {auth_path}/login` credential lookup |

**Multiple backends:** first backend → `{auth_path}`; others → `{auth_path}/{backend-name}/...`.

When `requires_verification=True`, the shared account-state policy is consistent across login,
refresh, and TOTP verification: inactive users fail first, and unverified users fail next.

When refresh is enabled with `CookieTransport`, `include_session_devices=True` routes read the
dedicated refresh cookie to identify the current refresh session for `is_current` markers and
revoke-others preservation. Bearer clients do not have a refresh cookie; they may pass the existing
`RefreshTokenRequest` body to `POST {auth_path}/sessions` and
`POST {auth_path}/sessions/revoke-others` when they need current-session detection. If no current
refresh credential can be resolved, revoke-others fails closed; with the built-in DB token strategy,
that means all active refresh sessions for the current user are revoked.

### Session/device management setup

Use `include_session_devices=True` only with a backend strategy that implements refresh-session
management. The built-in DB token strategy does; JWT and Redis token strategies do not provide a
session/device dashboard in this slice and return `SESSION_MANAGEMENT_UNSUPPORTED` if these routes
are mounted against them.

The plugin-managed bearer DB-token preset is the shortest setup:

```python
config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret="replace-with-32+-char-db-token-secret",
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=user_manager_security,
    enable_refresh=True,
    include_session_devices=True,
)
```

Bearer clients receive refresh tokens in response bodies. To mark the current session in a list
response, call:

```http
POST /auth/sessions
Authorization: Bearer <access-token>
Content-Type: application/json

{"refresh_token": "<current-refresh-token>"}
```

For browser refresh sessions, assemble a DB-token backend with `CookieTransport` and the same
request-scoped session-binding contract. The transport keeps the access token in `cookie_name` and
the refresh token in the dedicated `<cookie_name>_refresh` HttpOnly cookie:

```python
from datetime import timedelta
from uuid import UUID

from litestar_auth import AuthenticationBackend, CookieTransport, LitestarAuthConfig
from litestar_auth.authentication.strategy import DatabaseTokenStrategy
from litestar_auth.models import User

cookie_db_backend = AuthenticationBackend[User, UUID](
    name="database-cookie",
    transport=CookieTransport(
        cookie_name="app_auth",
        max_age=15 * 60,
        refresh_max_age=30 * 24 * 60 * 60,
    ),
    strategy=DatabaseTokenStrategy[User, UUID](
        session=session_maker(),
        token_hash_secret="replace-with-32+-char-db-token-secret",
        max_age=timedelta(minutes=15),
        refresh_max_age=timedelta(days=30),
    ),
)

config = LitestarAuthConfig[User, UUID](
    backends=(cookie_db_backend,),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=user_manager_security,
    csrf_secret="replace-with-32+-char-csrf-secret",
    enable_refresh=True,
    include_session_devices=True,
)
```

`AuthenticationBackend.with_session(...)` rebinds `DatabaseTokenStrategy` for each request when the
plugin resolves runtime backends. Keep `session_maker` configured so the generated controllers,
refresh flow, and session/device routes all use the same request-local SQLAlchemy session.

## Built-in auth payload boundary

The generated controllers do not use one universal credential field. `login_identifier` only changes how `LoginCredentials.identifier` is interpreted on `POST {auth_path}/login`.

| Route | Built-in request schema | Published fields |
| ----- | ---------------------- | ---------------- |
| `POST {auth_path}/login` | `LoginCredentials` | `identifier`, `password` |
| `POST {auth_path}/register` | `UserCreate` | `email`, `password` |
| `POST {auth_path}/request-verify-token` | `RequestVerifyToken` | `email` |
| `POST {auth_path}/verify` | `VerifyToken` | `token` |
| `POST {auth_path}/forgot-password` | `ForgotPassword` | `email` |
| `POST {auth_path}/reset-password` | `ResetPassword` | `token`, `password` |

Verify and reset token values are signed JWTs issued by the manager security service. Library-issued
tokens include JOSE `typ=JWT`, and decode rejects tokens with a missing or unexpected `typ` header
before the normal signed audience, required-claim, and password-fingerprint validation. Custom test
fixtures or advanced integrations that mint these tokens directly must set the same header; the
header check is not a replacement for the existing signed JWT validation.

By default, built-in TOTP routes publish `TotpEnableRequest`, `TotpConfirmEnableRequest`, `TotpVerifyRequest`, and `TotpDisableRequest`. `TotpVerifyRequest.code` and `TotpDisableRequest.code` accept either a current TOTP code or an unused recovery code where documented. The built-in TOTP flow still uses `user.email` for the otpauth URI and password step-up, even when `login_identifier="username"`.
