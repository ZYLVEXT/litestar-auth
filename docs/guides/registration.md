# Registration, verification, and password reset

Enable or disable slices of the auth HTTP API with flags on `LitestarAuthConfig`.

## Registration

With `include_register=True` (default), clients can call `POST {auth_path}/register`.

- **Login identifier** — `login_identifier` is `"email"` or `"username"` and selects which field is used for credential lookup.
- **Safe creation** — registration uses `BaseUserManager.create(..., safe=True)` so only expected fields (e.g. email + password) are accepted; privileged flags like `is_superuser` are stripped from public registration payloads unless you explicitly opt into dangerous behavior in your manager.

## Email verification

With `include_verify=True`:

- `POST .../verify` — consume a verification token.
- `POST .../request-verify-token` — issue a new verification token.

The library **does not send email**. Implement `on_after_request_verify_token` and related hooks on your user manager to enqueue mail or notifications.

## Password reset

With `include_reset_password=True`:

- `POST .../forgot-password` — returns **202 Accepted** with the same shape whether the email exists (enumeration-safe). When rate limits apply, the counter increments after handler completion without exposing whether the user existed.
- `POST .../reset-password` — accepts reset token + new password.

Reset tokens are tied to a password fingerprint so they invalidate after a successful password change. Implement `on_after_forgot_password` to send the link out-of-band.

## Password limits

Schemas enforce a **maximum password length** (OWASP-style mitigation for hash DoS). The default minimum length is enforced via `require_password_length` when using the default password validator.

## Related

- [Configuration](../configuration.md) — `include_register`, `include_verify`, `include_reset_password`, `login_identifier`.
- [Extending](extending.md) — hooks on `BaseUserManager`.
- [Schemas API](../api/schemas.md) — request/response structs.
