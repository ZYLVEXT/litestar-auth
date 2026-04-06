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

Built-in `UserCreate` and `UserUpdate` use the public `litestar_auth.schemas.UserPasswordField` alias for their password metadata. Reuse that same alias in app-owned `user_create_schema` / `user_update_schema` structs when you want the documented password bounds without copying raw `12` / `128` literals:

```python
import msgspec

from litestar_auth.schemas import UserPasswordField


class RegistrationSchema(msgspec.Struct):
    email: str
    password: UserPasswordField
    display_name: str
```

That schema metadata catches obviously too-short or too-long passwords during payload decoding and keeps custom structs aligned with the built-in registration surface.

Runtime validation still flows through `require_password_length` when the plugin uses its default password validator. Schema metadata alone is not the whole password policy; use `password_validator_factory` when your application needs stricter runtime checks than the shared length bounds.

## Related

- [Configuration](../configuration.md) — `include_register`, `include_verify`, `include_reset_password`, `login_identifier`.
- [Extending](extending.md) — hooks on `BaseUserManager`.
- [Payloads and schemas API](../api/schemas.md) — built-in auth lifecycle DTOs from `litestar_auth.payloads` plus the default user CRUD schemas from `litestar_auth.schemas`.
