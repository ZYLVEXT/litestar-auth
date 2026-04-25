# User manager

For plugin-managed apps, the authoritative wiring for `user_manager_security`,
`password_validator_factory`, `PasswordHelper` sharing, and `UserEmailField` /
`UserPasswordField` reuse lives in
[Configuration](../configuration.md#manager-password-surface). This page focuses on the
direct `BaseUserManager` API once those inputs have already been resolved.

The default plugin builder now treats `user_manager_security` as an end-to-end constructor
contract. When that typed bundle is present, the plugin calls
`user_manager_class(..., password_helper=..., security=UserManagerSecurity(...), password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)`
and folds the effective `id_parser` into `security` first. If your manager narrows or renames that
`BaseUserManager`-style constructor surface, `user_manager_factory` is the explicit customization
path. That changes who constructs the manager; it does not create a
second implicit injection path for `password_helper`, `password_validator`, or security kwargs.
Custom factories must wire those inputs themselves when they still want them.

When you instantiate `BaseUserManager` yourself, pass secrets and optional `id_parser` through the
typed `security=UserManagerSecurity(...)` bundle only. Pair that with `PasswordHelper.from_defaults()`
when you want the library's default Argon2-only hasher policy. Unsupported stored password hashes
fail closed under that default, so rotate or reset those credentials before rollout. Use
`PasswordHelper(password_hash=...)` only for deliberate application-owned custom pwdlib
composition.

Across plugin-managed and direct-manager flows, the stable account-state policy surface remains
`require_account_state(user, *, require_verified=False)`. The built-in implementation delegates to
`UserPolicy.require_account_state`; custom managers or adapters should preserve the same callable
shape and semantics when they customize account-state enforcement. The built-in ordering is
inactive first, then unverified when `require_verified=True`.

The generated register and users controllers now require strict request schemas:
the built-in `UserCreate` / `UserUpdate` DTOs use `forbid_unknown_fields=True`,
and custom `user_create_schema` / `user_update_schema` values passed to the
controller factories must do the same. Undeclared keys therefore fail request
validation with `ErrorCode.REQUEST_BODY_INVALID` instead of being silently
ignored. Assign the configured superuser role to grant elevated access.

`BaseUserManager.update(...)` also fails closed on privileged fields by default. Direct callers
must pass `allow_privileged=True` when they intentionally mutate `is_active`, `is_verified`, or
`roles`. Public self-service HTTP flows never set those fields; admin-only routes, OAuth
verification bootstrap, and role-administration helpers do so explicitly.

`BaseUserManager` is now explicitly documented as a façade over three service entrypoints:
`manager.users` for CRUD and password lifecycle flows, `manager.tokens` for verify/reset token
flows, and `manager.totp` for TOTP secret storage. Low-level JWT helpers sit under
`manager.tokens.security`. The convenience methods on `BaseUserManager` still forward to those
services, so existing call sites continue to work; prefer the service properties when you are
working within one subsystem directly.

The default no-op lifecycle hook implementations live on `UserManagerHooks`, which
`BaseUserManager` inherits. Subclass `BaseUserManager` exactly as before; the mixin split only
keeps the manager surface easier to navigate and document.

`BaseUserManager.totp_secret_storage_posture` is the stable direct-manager contract for persisted
TOTP secrets. It reports the Fernet-encrypted at-rest posture; providing a Fernet key through
`security=UserManagerSecurity(totp_secret_keyring=FernetKeyringConfig(...))` enables encrypted
storage and decryption with active-key rotation. The one-key
`security=UserManagerSecurity(totp_secret_key=...)` shortcut remains available and is encoded under
the `default` key id. Leaving both fields unset is valid for direct managers that do not persist TOTP
secrets, but non-null TOTP secret writes and unprefixed legacy plaintext reads fail closed. When the
plugin owns TOTP wiring, its validation path reads the same posture contract instead of
special-casing manager instances. New persisted TOTP secret writes use the versioned Fernet-at-rest
envelope `fernet:v1:<key_id>:<ciphertext>`. `manager.totp_secret_requires_reencrypt(stored)` detects
whether a stored value is under a non-active configured key, and
`manager.reencrypt_totp_secret_for_storage(stored)` rewrites a stored value with the active key while
preserving `None` for users without TOTP enabled. Those helpers are row-level migration primitives:
your job should scan persisted user rows, rewrite values that need rotation, verify no values still
return `True`, and only then remove retired key ids from `FernetKeyringConfig.keys`. Legacy
unversioned Fernet rows need explicit old-key migration code, and plaintext TOTP rows remain
unsupported.

For production, keep `verification_token_secret`, `reset_password_token_secret`,
`login_identifier_telemetry_secret`, and every configured TOTP Fernet key distinct on
`UserManagerSecurity`. Outside testing, `BaseUserManager(...)` raises `ConfigurationError` when one
configured value is reused across those roles (as resolved from the `security` bundle). Distinct
audiences (`litestar-auth:verify` and `litestar-auth:reset-password`) already scope the JWT flows
correctly, but separate secrets still reduce blast radius and keep TOTP encryption and failed-login
telemetry independent of JWT signing. `login_identifier_telemetry_secret` is optional; when it is
omitted, failed-login logs do not include an `identifier_digest`. For plugin-managed apps,
`LitestarAuth(config)` validation
enforces the broader config-owned surface, including `totp_config.totp_pending_secret` and its
`litestar-auth:2fa-pending` / `litestar-auth:2fa-enroll` controller flow when TOTP is enabled. If a
custom `user_manager_factory` constructs `BaseUserManager` with a different verification/reset/TOTP
secret surface, the manager applies the same fail-closed validation for the roles it actually
receives.

::: litestar_auth.manager
