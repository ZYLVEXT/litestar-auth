# User manager

For plugin-managed apps, the authoritative wiring for `user_manager_security`,
`user_manager_kwargs`, `password_validator_factory`, `PasswordHelper` sharing, and
`UserEmailField` / `UserPasswordField` reuse lives in
[Configuration](../configuration.md#canonical-manager-password-surface). This page focuses on the
direct `BaseUserManager` API once those inputs have already been resolved.

The default plugin builder now treats `user_manager_security` as an end-to-end constructor
contract. When that typed bundle is present, the plugin calls
`user_manager_class(..., password_helper=..., security=UserManagerSecurity(...), password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)`
and folds the effective `id_parser` into `security` first. If your manager narrows or renames that
canonical `BaseUserManager`-style constructor surface, `user_manager_factory` is the explicit
escape hatch.

When you instantiate `BaseUserManager` yourself, you can either pass the legacy explicit
`verification_token_secret` / `reset_password_token_secret` / `totp_secret_key` / `id_parser`
kwargs, or use the typed `security=UserManagerSecurity(...)` contract. Do not mix the two forms in
one constructor call. Pair that with `PasswordHelper.from_defaults()` when you want the library's
canonical hasher policy, or pass `PasswordHelper(password_hash=...)` when you intentionally diverge
with custom pwdlib composition.

For production, keep `verification_token_secret`, `reset_password_token_secret`, and
`totp_secret_key` distinct. Outside testing, `BaseUserManager(...)` warns when one configured value
is reused across those roles. Distinct audiences (`litestar-auth:verify` and
`litestar-auth:reset-password`) already scope the JWT flows correctly, but separate secrets still
reduce blast radius and keep TOTP encryption independent of JWT signing. For plugin-managed apps,
that broader config-owned warning is emitted during `LitestarAuth(config)` validation. The
request-scoped manager instance does not warn a second time when its effective
verification/reset/TOTP secret surface matches the validated plugin config. If a custom
`user_manager_factory` constructs `BaseUserManager` with a different verification/reset/TOTP secret
surface, the manager emits an additional warning for the divergent manager-owned roles it actually
receives. When the plugin also owns `totp_config.totp_pending_secret`, validation extends the
config-owned warning to the `litestar-auth:2fa-pending` / `litestar-auth:2fa-enroll` controller
flow.

::: litestar_auth.manager
