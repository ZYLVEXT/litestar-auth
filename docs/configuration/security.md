# Security and DI

Use this page for CSRF settings, token downgrade policy, schemas, dependency keys, and shared configuration helpers.

## Security and token policy

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `csrf_secret` | `None` | Enables Litestar CSRF config when cookie transports are used. |
| `csrf_header_name` | `"X-CSRF-Token"` | Header Litestar expects for CSRF token. |
| `unsafe_testing` | `False` | Explicit per-config test-only override for generated fallback secrets, single-process validation shortcuts, and startup-warning suppression. Never enable it for production traffic. |
| `id_parser` | `None` | Parse path/query user ids (e.g. `UUID`). Defaults from `user_manager_security.id_parser` when that typed contract is configured. |

The plugin-managed JWT/TOTP security surfaces use the same shared posture wording as runtime startup and validation:

--8<-- "docs/snippets/plugin_security_tradeoffs.md"

For direct/manual wiring, the underlying runtime objects report their own posture explicitly:

- `JWTStrategy(secret=..., denylist_store=RedisJWTDenylistStore(...))` reports `revocation_posture.key == "shared_store"` and `revocation_is_durable == True`.
- `JWTStrategy(secret=..., allow_inmemory_denylist=True)` reports `revocation_posture.key == "in_memory"` and `revocation_is_durable == False`. `InMemoryJWTDenylistStore` fails closed when its `max_entries` cap is hit and no expired JTIs can be pruned: new revocations are skipped (logged) rather than dropping an active revocation entry. `JWTDenylistStore.deny` returns `False` in that case; `JWTStrategy.destroy_token` raises `TokenError`, and plugin HTTP logout surfaces **503** with `TOKEN_PROCESSING_FAILED`. The same capacity signal applies to TOTP pending-login JTI recording after a successful code check: verification responds with **503** instead of issuing a session when the pending-token denylist cannot store the spent JTI.
- Direct `BaseUserManager(..., security=UserManagerSecurity(...))` reports `totp_secret_storage_posture.key == "fernet_encrypted"` for persisted TOTP secrets. Setting `user_manager_security.totp_secret_key` on `LitestarAuthConfig` (passed through to `UserManagerSecurity`) or supplying a non-`None` `totp_secret_key` on a direct `UserManagerSecurity(...)` bundle enables encrypted reads and writes; omitting the key leaves disabled TOTP (`None`) readable but makes non-null TOTP secret persistence fail closed. The TOTP controller uses that same key to encrypt pending-enrollment secret values before writing them to `totp_enrollment_store`.

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
| `user_update_schema` | `None` | msgspec struct for user PATCH bodies. The built-in `UserUpdate` accepts optional `roles`; `/users/me` still strips them while admin `PATCH /users/{id}` can persist them. |
| `db_session_dependency_key` | `"db_session"` | Litestar DI key for `AsyncSession`. Must be a valid non-keyword Python identifier because Litestar matches dependency keys to callable parameter names. |
| `db_session_dependency_provided_externally` | `False` | Skip plugin session provider when your app already registers the key. |

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

## Shared helpers — `litestar_auth.config`

`validate_secret_length`, `_resolve_token_secret`, `MINIMUM_SECRET_LENGTH`, and the secret-role helpers keep token validation and explicit unsafe-testing behavior consistent.

## Related

- [HTTP API](../http_api.md) — routes controlled by the flags above.
- [Security](../security.md) — production interpretation of sensitive flags.
- [Plugin API](../api/plugin.md) — mkdocstrings for `LitestarAuth`, configs, and `litestar_auth.config`.
