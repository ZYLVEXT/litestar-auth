# Password helpers

The plugin-owned password wiring now lives in
[Configuration](../configuration.md#manager-password-surface). `PasswordHelper` is the
hashing boundary itself. Use `PasswordHelper.from_defaults()` when you want the library's default
pwdlib configuration: Argon2 only for new hashes and verification. Unsupported stored password
hashes fail closed under that default, so rotate or reset those credentials before rollout. Use
`PasswordHelper(password_hash=...)` only for deliberate application-owned custom pwdlib
composition.

For plugin-managed apps that also hash or verify passwords in domain services, CLI tasks, or data
migrations, call `config.resolve_password_helper()` once after constructing
`LitestarAuthConfig(...)`. That method returns the explicit
`user_manager_security.password_helper` when you already supplied one; otherwise it memoizes
`PasswordHelper.from_defaults()` on the config, and the plugin injects that same memoized helper
into every request-scoped manager so the plugin and app-owned code reuse the same instance.

::: litestar_auth.password
