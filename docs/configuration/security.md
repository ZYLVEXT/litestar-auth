# Security and DI

Use this page for CSRF settings, token downgrade policy, schemas, dependency keys, and shared configuration helpers.

## Security and token policy

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `csrf_secret` | `None` | Enables Litestar CSRF config when cookie transports are used. |
| `csrf_header_name` | `"X-CSRF-Token"` | Header Litestar expects for CSRF token. |
| `unsafe_testing` | `False` | Explicit per-config test-only override for generated fallback secrets, single-process validation shortcuts, and startup-warning suppression. Never enable it for production traffic. |
| `login_minimum_response_seconds` | `0.4` | Minimum wall-clock duration for plugin-owned `POST /auth/login` account-state failure, pending-TOTP, and success responses. |
| `register_minimum_response_seconds` | `0.4` | Minimum wall-clock duration for plugin-owned `POST /auth/register` success and domain-failure responses. This is defense-in-depth against registration timing enumeration and is independent of rate limiting. |
| `verify_minimum_response_seconds` | `0.4` | Minimum wall-clock duration for plugin-owned `POST /auth/verify` success and invalid-token responses. |
| `request_verify_minimum_response_seconds` | `0.4` | Minimum wall-clock duration for plugin-owned `POST /auth/request-verify-token` responses, including manager failures after rate-limit accounting runs. |
| `id_parser` | `None` | Parse path/query user ids (e.g. `UUID`). Effective parser: `user_manager_security.id_parser` when set; otherwise `LitestarAuthConfig.id_parser` is applied (including the no-`user_manager_security` default builder path). |

### CSRF cookie name and login telemetry

When `csrf_secret` is set, the plugin wires Litestar CSRF for cookie transports using
the cookie name **`litestar_auth_csrf`** (same as `DEFAULT_CSRF_COOKIE_NAME` in
`litestar_auth.plugin` / `litestar_auth._plugin.config`). Frontend code must read that
cookie to mirror the value into `csrf_header_name` (default `X-CSRF-Token`); see also
[cookie CSRF cookbook](../cookbook/cookie_csrf.md) and [OAuth associate](../cookbook/oauth_associate.md).

Failed-login **telemetry** is not a `LitestarAuthConfig` field: set optional
`UserManagerSecurity.login_identifier_telemetry_secret` so structured logs can carry an
HMAC digest of the identifier on failures (no raw identifier in logs). Details:
[Manager customization — Login failure telemetry secret](manager.md#login-failure-telemetry-secret).

The plugin-managed JWT/TOTP security surfaces use the same shared posture wording as runtime startup and validation:

--8<-- "docs/snippets/plugin_security_tradeoffs.md"

For direct/manual wiring, the underlying runtime objects report their own posture explicitly:

- `JWTStrategy(secret=..., denylist_store=RedisJWTDenylistStore(...))` reports `revocation_posture.key == "shared_store"` and `revocation_is_durable == True`.
- `JWTStrategy(secret=..., allow_inmemory_denylist=True)` reports `revocation_posture.key == "in_memory"` and `revocation_is_durable == False`. `InMemoryJWTDenylistStore` fails closed when its `max_entries` cap is hit and no expired JTIs can be pruned: new revocations are skipped (logged) rather than dropping an active revocation entry. `JWTDenylistStore.deny` returns `False` in that case; `JWTStrategy.destroy_token` raises `TokenError`, and plugin HTTP logout surfaces **503** with `TOKEN_PROCESSING_FAILED`. The same capacity signal applies to TOTP pending-login JTI recording after a successful code check: verification responds with **503** instead of issuing a session when the pending-token denylist cannot store the spent JTI.
- Direct `BaseUserManager(..., security=UserManagerSecurity(...))` reports `totp_secret_storage_posture.key == "fernet_encrypted"` for persisted TOTP secrets. Setting `user_manager_security.totp_secret_keyring=FernetKeyringConfig(...)` on `LitestarAuthConfig` (passed through to `UserManagerSecurity`) or on a direct `UserManagerSecurity(...)` bundle enables encrypted reads and writes with active-key rotation. The one-key `totp_secret_key` field remains available for single-key deployments; omitting both key inputs leaves disabled TOTP (`None`) readable but makes non-null TOTP secret persistence fail closed. The TOTP controller uses the same keyring/key to encrypt pending-enrollment secret values before writing them to `totp_enrollment_store`.
- `ApiKeyConfig(signing_enabled=True, secret_encryption_keyring=FernetKeyringConfig(...))` enables
  encrypted storage for signing-required API-key secrets. The config field is intentionally named
  `api_keys.secret_encryption_keyring` in operator docs because it belongs to the nested API-key
  config, not `UserManagerSecurity`. Rotate it with the same staged keyring shape as OAuth and TOTP:
  deploy old+new ids, switch `active_key_id`, re-encrypt rows, verify, then remove the retired id.

### API-key signing-secret rotation

Only signing-required API-key rows participate in `api_keys.secret_encryption_keyring` rotation.
Bearer rows remain digest-only (`hashed_secret` only), do not have recoverable plaintext, cannot be
upgraded to signing mode, and should not be passed to signing-secret rotation helpers.

Use the manager helpers for one row at a time:

- `BaseUserManager.api_key_signing_secret_requires_reencrypt(row)` returns whether the row's
  `encrypted_secret` is readable but not encrypted under the active key id.
- `await BaseUserManager.reencrypt_api_key_signing_secret(row_or_key_id)` rewrites that one
  signing-required row under the active key id and returns the updated row metadata. It does not
  print, log, or return the plaintext signing secret, and it does not run API-key create, revoke, or
  use lifecycle hooks.

Failure handling is intentionally fail-closed. Missing `api_keys.secret_encryption_keyring`,
bearer rows, signing rows without `encrypted_secret`, raw bearer credential input, unknown key ids,
malformed envelopes, and replacement races surface as errors for the migration job to handle. Treat
those as operator cleanup cases; do not remove retired Fernet key ids until a fresh verification scan
finds no signing-required rows that still need re-encryption.

### Password hash policy

`PasswordHelper.from_defaults()`, bare `PasswordHelper()`, `BaseUserManager(..., password_helper=None)`,
and `config.resolve_password_helper()` now use an Argon2-only default policy. Unsupported stored
password hashes therefore fail closed: verification returns `False`, and `verify_and_update()`
does not emit a replacement hash for an unsupported stored value.

Before deploying that default into an environment with unsupported stored hashes, rotate or reset
those credentials out of band. If you inject `UserManagerSecurity(password_helper=...)`, that
password policy is fully application-owned and outside the library default described here.

## Schemas and DI

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `user_read_schema` | `None` | msgspec struct for safe user responses returned by register/verify/reset/users flows. The built-in `UserRead` includes normalized `roles`. |
| `user_create_schema` | `None` | msgspec struct for registration/create request bodies; built-in registration defaults to `UserCreate`. |
| `user_update_schema` | `None` | msgspec struct for user PATCH bodies on the self-service `/users/me` route. The built-in `UserUpdate` accepts `email` plus `current_password` proof for email changes — privileged fields (`is_active`, `is_verified`, `roles`) live on `AdminUserUpdate` for the privileged `PATCH /users/{id}` route, and self-service requests that include them are rejected at msgspec decode (`forbid_unknown_fields=True`). |
| `db_session_dependency_key` | `"db_session"` | Litestar DI key for `AsyncSession`. Must be a valid non-keyword Python identifier because Litestar matches dependency keys to callable parameter names. |
| `db_session_dependency_provided_externally` | `False` | Skip plugin session provider when your app already registers the key. |
| `session_scope_key` | `None` (uses Advanced Alchemy `SESSION_SCOPE_KEY`) | Advanced Alchemy scope key for the request session. When using `SQLAlchemyPlugin`, prefer `bind_auth_session_to_alchemy(alchemy_config)` or set this to `SQLAlchemyAsyncConfig.session_scope_key` after the config is constructed. |

`user_*_schema` customizes registration and user CRUD surfaces. It does not rename the built-in auth lifecycle request structs: `LoginCredentials`, `RefreshTokenRequest`, `RequestVerifyToken`, `VerifyToken`, `ForgotPassword`, `ResetPassword`, or the TOTP payloads.

If you keep the built-in role-aware user surface, align custom read/update schemas with that
contract by adding `roles` to both types. If you intentionally omit `roles`, treat that as an
explicit compatibility choice for role-less user models rather than the default library contract.

When app-owned `user_create_schema` or `user_update_schema` structs keep `email` or `password`
fields, import `UserEmailField` / `UserPasswordField` from `litestar_auth.schemas` instead of
copying the built-in email regex or local `msgspec.Meta(min_length=12, max_length=128)`
annotations. See
[Manager password surface](manager.md#manager-password-surface) for the full contract:
those aliases keep schema metadata aligned, while runtime password validation still flows through
`password_validator_factory` or the manager's default validator.

## Dependency keys (constants)

Used by the plugin internally; override only if you integrate custom controllers:

- `litestar_auth_config`, `litestar_auth_user_manager`, `litestar_auth_backends`, `litestar_auth_user_model` (see `litestar_auth._plugin.config`).

## Shared helpers — `litestar_auth.config` {#shared-helpers--litestar_authconfig}

`validate_production_secret`, `validate_secret_length`, `_resolve_token_secret`, `MINIMUM_SECRET_LENGTH`, and the secret-role helpers keep token validation and explicit unsafe-testing behavior consistent. Production secrets must clear both the length floor and the default entropy floor; repeated fixture strings are accepted only behind explicit `unsafe_testing=True` paths.

## Related

- [HTTP API](../http_api.md) — routes controlled by the flags above.
- [Security](../security.md) — production interpretation of sensitive flags.
- [Plugin API](../api/plugin.md) — mkdocstrings for `LitestarAuth`, configs, and `litestar_auth.config`.
