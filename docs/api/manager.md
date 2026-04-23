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
when you want the library's default hasher policy, or pass `PasswordHelper(password_hash=...)` when
you intentionally diverge with custom pwdlib composition.

Across plugin-managed and direct-manager flows, the stable account-state policy surface remains
`require_account_state(user, *, require_verified=False)`. The built-in implementation delegates to
`UserPolicy.require_account_state`; custom managers or adapters should preserve the same callable
shape and semantics when they customize account-state enforcement.

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
TOTP secrets. On `security=UserManagerSecurity(...)`, leaving `totp_secret_key` unset or `None` keeps
the compatibility-grade `compatibility_plaintext` branch so legacy plaintext secrets still
round-trip, while providing a Fernet key on that same bundle flips the posture to `fernet_encrypted`
and causes newly persisted secrets to be encrypted at rest. When the plugin owns TOTP wiring, its
validation path reads the same posture contract instead of special-casing manager instances.

For production, keep `verification_token_secret`, `reset_password_token_secret`, and
`totp_secret_key` distinct on `UserManagerSecurity`. Outside testing, `BaseUserManager(...)` warns
when one configured value is reused across those roles (as resolved from the `security` bundle).
Distinct audiences (`litestar-auth:verify` and `litestar-auth:reset-password`) already scope the JWT
flows correctly, but separate secrets still reduce blast radius and keep TOTP encryption independent
of JWT signing. For plugin-managed apps,
that broader config-owned warning is emitted during `LitestarAuth(config)` validation. The
request-scoped manager instance does not warn a second time when its effective
verification/reset/TOTP secret surface matches the validated plugin config. If a custom
`user_manager_factory` constructs `BaseUserManager` with a different verification/reset/TOTP secret
surface, the manager emits an additional warning for the divergent manager-owned roles it actually
receives. When the plugin also owns `totp_config.totp_pending_secret`, validation extends the
config-owned warning to the `litestar-auth:2fa-pending` / `litestar-auth:2fa-enroll` controller
flow.

::: litestar_auth.manager
