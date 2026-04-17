# Error codes

Auth-related HTTP errors use Litestar `ClientException` (or guard failures) with a machine-readable **`code`** in `extra` where the library controls the response. Clients should rely on **`code`**, not only on `detail` text.

Typical response shape (conceptual):

```json
{
  "status_code": 400,
  "detail": "Human-readable message",
  "extra": { "code": "LOGIN_BAD_CREDENTIALS" }
}
```

Exact JSON layout follows your Litestar exception handler configuration.

## `ErrorCode` reference

| Code | Typical HTTP | Meaning |
| ---- | ------------ | ------- |
| `UNKNOWN` | varies | Generic fallback: base `LitestarAuthError` default, or plugin JSON `code` when `extra` omits a string `code`. |
| `AUTHENTICATION_FAILED` | 401 | Generic authentication failure (guards / middleware). |
| `TOKEN_PROCESSING_FAILED` | 401 / 400 / 503 | Invalid or unusable token in ordinary validation paths (**401** / **400**); **503** when a bundled route cannot persist a required JWT revocation or TOTP pending-login JTI because the denylist is at capacity (fail-closed; see [Security](security.md) and [Guides — Security](guides/security.md)). |
| `CONFIGURATION_INVALID` | 500 / startup | Misconfiguration. |
| `USER_NOT_FOUND` | 404 | User id does not exist. |
| `REGISTER_USER_ALREADY_EXISTS` | 400 | Duplicate registration. |
| `REGISTER_INVALID_PASSWORD` | 400 | Password policy rejected. |
| `LOGIN_BAD_CREDENTIALS` | 400 | Wrong password or unknown user (login). |
| `LOGIN_USER_INACTIVE` | 403 | Account disabled. |
| `LOGIN_USER_NOT_VERIFIED` | 403 | Verification required (`requires_verification` / flow). |
| `AUTHORIZATION_DENIED` | 403 | Guard denied access. |
| `INSUFFICIENT_ROLES` | 403 | Role-based guard denial with structured missing-role context. |
| `RESET_PASSWORD_BAD_TOKEN` | 400 | Reset token invalid/expired. |
| `RESET_PASSWORD_INVALID_PASSWORD` | 400 | New password rejected. |
| `VERIFY_USER_BAD_TOKEN` | 400 | Verification token invalid. |
| `VERIFY_USER_ALREADY_VERIFIED` | 400 | Already verified. |
| `UPDATE_USER_EMAIL_ALREADY_EXISTS` | 400 | Email collision on update. |
| `UPDATE_USER_INVALID_PASSWORD` | 400 | Current password wrong / policy. |
| `SUPERUSER_CANNOT_DELETE_SELF` | 400 | Self-delete forbidden. |
| `OAUTH_NOT_AVAILABLE_EMAIL` | 400 | Provider did not supply email. |
| `OAUTH_STATE_INVALID` | 400 | OAuth state cookie missing/invalid. |
| `OAUTH_EMAIL_NOT_VERIFIED` | 400 | Associate-by-email requires verified provider email. |
| `OAUTH_USER_ALREADY_EXISTS` | 400 | OAuth would create duplicate against policy. |
| `OAUTH_ACCOUNT_ALREADY_LINKED` | 400 | Provider identity bound to another user. |
| `REQUEST_BODY_INVALID` | 422 | Body failed validation. |
| `LOGIN_PAYLOAD_INVALID` | 422 | Login body shape invalid. |
| `REFRESH_TOKEN_INVALID` | 401 | Refresh rejected. |
| `TOTP_PENDING_BAD_TOKEN` | 400 | Pending login token invalid. |
| `TOTP_CODE_INVALID` | 400 | Wrong or reused TOTP code. |
| `TOTP_ALREADY_ENABLED` | 400 | TOTP already active. |
| `TOTP_ENROLL_BAD_TOKEN` | 400 | Enrollment token invalid. |

Source of truth in code: `litestar_auth.exceptions.ErrorCode` and controller `ClientException` sites. Full exception hierarchy: [Python API — Exceptions](api/exceptions.md).

## Enumeration safety

`POST .../forgot-password` is intentionally **enumeration-resistant** (see [Registration guide](guides/registration.md)): successful response does not reveal whether the email exists.
