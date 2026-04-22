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
- **Safe creation** — registration uses `BaseUserManager.create(..., safe=True)` so only expected fields (e.g. email + password) are accepted; privileged flags like `is_superuser` and `roles` are stripped from public registration payloads unless you explicitly opt into dangerous behavior in your manager.
- **Built-in response body** — successful register/verify/reset responses use `UserRead`, which includes normalized `roles` alongside the existing account-state fields. New users start with `roles=[]` unless a privileged path assigns them.
- **Persistence boundary** — relational `role` / `user_role` tables are an internal storage detail of the ORM layer. Registration still accepts flat user fields only, and this route surface does not expose role-catalog management or RBAC policy payloads. Use the opt-in [HTTP role administration](role_admin_http.md) guide or the operator CLI when you need admin workflows.

## Email verification

With `include_verify=True`:

- `POST .../request-verify-token` — `RequestVerifyToken` with `email`; issues a new verification
  token when the email belongs to an existing unverified user, while keeping the public response and
  manager hook contract enumeration-resistant.
- `POST .../verify` — `VerifyToken` with `token`; consumes a verification token.

`LitestarAuthConfig.requires_verification` now defaults to `True`, so newly registered accounts must
verify their email before `/login` or built-in `/2fa/verify` can complete unless you opt out
explicitly.

The library **does not send email**. Implement `on_after_request_verify_token` and related hooks on
your user manager to enqueue mail or notifications, and make sure the hook performs equivalent async
work even when it receives `user=None` / `token=None` for unknown or already-verified emails.

## Password reset

With `include_reset_password=True`:

- `POST .../forgot-password` — `ForgotPassword` with `email`; returns **202 Accepted** with the same shape whether the email exists (enumeration-safe). When rate limits apply, the counter increments after handler completion without exposing whether the user existed.
- `POST .../reset-password` — `ResetPassword` with `token` + `password`.

Reset tokens are tied to a password fingerprint so they invalidate after a successful password change. Implement `on_after_forgot_password` to send the link out-of-band.

## TOTP boundary

`login_identifier="username"` does not make the built-in 2FA flow username-based. TOTP enrollment and default password step-up still use `user.email`, and the enrollment response still returns an email-based otpauth URI.

## User schema helpers

The password-wiring contract now lives in
[Configuration](../configuration.md#manager-password-surface). For custom registration
DTOs, reuse `litestar_auth.schemas.UserEmailField` and `litestar_auth.schemas.UserPasswordField`
when you want the built-in email/password metadata without copying local constraints. Existing
`UserPasswordField` imports remain valid; add `UserEmailField` only when you also want the
built-in email contract. Those aliases only affect schema validation and OpenAPI. Runtime password
policy still comes from `password_validator_factory` or the manager's default
`require_password_length` validator.

When you keep the built-in register/verify/reset/users controllers but replace `user_read_schema`
or `user_update_schema`, keep the default role-aware contract in mind: built-in `UserRead` includes
`roles`, built-in `UserUpdate` accepts optional `roles`, `/users/me` strips them from self-service
updates, and admin `PATCH /users/{id}` can persist them. Outside the built-in controllers,
direct `BaseUserManager.update(...)` calls must pass `allow_privileged=True` before mutating
`is_active`, `is_verified`, `is_superuser`, or `roles`.

## Related

- [Configuration](../configuration.md) — `include_register`, `include_verify`, `include_reset_password`, `login_identifier`.
- [Extending](extending.md) — hooks on `BaseUserManager`.
- [Payloads and schemas API](../api/schemas.md) — built-in auth lifecycle DTOs from `litestar_auth.payloads` plus the default user CRUD schemas from `litestar_auth.schemas`.
