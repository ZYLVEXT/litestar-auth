# Registration, verification, and password reset

Enable or disable slices of the auth HTTP API with flags on `LitestarAuthConfig`.

The built-in lifecycle controllers do not use one generic credential field. `identifier` belongs to login
(`LoginCredentials`) only. Registration, email verification, password reset, and the built-in TOTP flow keep their
current email/token-oriented request contracts unless you replace the relevant controller. The public API reference for
those built-in request and response structs now lives on the [Payloads and schemas API](../api/schemas.md) page.

## Registration

With `include_register=True` (default), clients can call `POST {auth_path}/register`.

- **Built-in request body** — `UserCreate` publishes `email` and `password` in OpenAPI.
- **Login identifier** — `login_identifier` is `"email"` or `"username"` and selects how `POST .../login` resolves `LoginCredentials.identifier`. It does not rename the built-in registration fields.
- **Safe creation** — registration uses `BaseUserManager.create(..., safe=True)` so only expected fields (e.g. email + password) are accepted; privileged flags like `is_superuser` are stripped from public registration payloads unless you explicitly opt into dangerous behavior in your manager.

## Email verification

With `include_verify=True`:

- `POST .../request-verify-token` — `RequestVerifyToken` with `email`; issues a new verification token.
- `POST .../verify` — `VerifyToken` with `token`; consumes a verification token.

The library **does not send email**. Implement `on_after_request_verify_token` and related hooks on your user manager to enqueue mail or notifications.

## Password reset

With `include_reset_password=True`:

- `POST .../forgot-password` — `ForgotPassword` with `email`; returns **202 Accepted** with the same shape whether the email exists (enumeration-safe). When rate limits apply, the counter increments after handler completion without exposing whether the user existed.
- `POST .../reset-password` — `ResetPassword` with `token` + `password`.

Reset tokens are tied to a password fingerprint so they invalidate after a successful password change. Implement `on_after_forgot_password` to send the link out-of-band.

## TOTP boundary

`login_identifier="username"` does not make the built-in 2FA flow username-based. TOTP enrollment and default password step-up still use `user.email`, and the enrollment response still returns an email-based otpauth URI.

## Password limits

Schemas enforce a **maximum password length** (OWASP-style mitigation for hash DoS). The default minimum length is enforced via `require_password_length` when using the default password validator.

## Related

- [Configuration](../configuration.md) — `include_register`, `include_verify`, `include_reset_password`, `login_identifier`.
- [Extending](extending.md) — hooks on `BaseUserManager`.
- [Payloads and schemas API](../api/schemas.md) — built-in auth lifecycle DTOs from `litestar_auth.payloads` plus the default user CRUD schemas from `litestar_auth.schemas`.
