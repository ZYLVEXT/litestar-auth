# Password helpers

The canonical plugin-owned password wiring now lives in
[Configuration](../configuration.md#canonical-manager-password-surface). `PasswordHelper` is the
hashing boundary itself. Use `PasswordHelper.from_defaults()` when you want the library's canonical
pwdlib configuration: Argon2 for new hashes, bcrypt verification fallback for legacy hashes, plus
`verify_and_update()` for opportunistic upgrades. Existing `PasswordHelper()` call sites remain
source-compatible, but `PasswordHelper.from_defaults()` is the named public "use the library
default" path. Keep `PasswordHelper(password_hash=...)` for the deliberate custom-policy case where
your application intentionally diverges.

For plugin-managed apps that also hash or verify passwords in domain services, CLI tasks, or data
migrations, call `config.resolve_password_helper()` once after constructing
`LitestarAuthConfig(...)`. That method returns the explicit
`user_manager_kwargs["password_helper"]` when you already supplied one; otherwise it memoizes
`PasswordHelper.from_defaults()` on the config (without mutating the user-supplied
`user_manager_kwargs`) and the plugin injects the same memoized helper into every request-scoped
manager so the plugin and app-owned code reuse the same instance.

::: litestar_auth.password
