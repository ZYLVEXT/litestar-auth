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
| `USER_ALREADY_EXISTS` | 400 | Duplicate user in a non-endpoint-specific default exception context. |
| `REGISTER_FAILED` | 400 | Generic registration failure. |
| `LOGIN_BAD_CREDENTIALS` | 400 | Wrong password or unknown user (login). |
| `LOGIN_ACCOUNT_UNAVAILABLE` | 400 | Account-state policy blocked sign-in, refresh, OAuth local session issue, or another account-state gated flow. |
| `AUTHORIZATION_DENIED` | 403 | Guard denied access. |
| `INSUFFICIENT_ROLES` | 403 | Role-based guard denial. Structured role context stays on the exception object but is omitted from default HTTP responses. |
| `ROLE_ALREADY_EXISTS` | 409 | Opt-in contrib role-admin create conflict. |
| `ROLE_NOT_FOUND` | 404 | Opt-in contrib role-admin requested role missing. |
| `ROLE_STILL_ASSIGNED` | 409 | Opt-in contrib role-admin delete refused while users still hold the role. |
| `ROLE_ASSIGNMENT_USER_NOT_FOUND` | 404 | Opt-in contrib role-admin assignment target user missing. |
| `ROLE_NAME_INVALID` | 422 | Opt-in contrib role-admin role name invalid or immutable-name patch attempted. |
| `RESET_PASSWORD_BAD_TOKEN` | 400 | Reset token invalid/expired. |
| `RESET_PASSWORD_INVALID_PASSWORD` | 400 | New password rejected. |
| `VERIFY_USER_BAD_TOKEN` | 400 | Verification token invalid. |
| `VERIFY_USER_ALREADY_VERIFIED` | 400 | Already verified. |
| `UPDATE_USER_EMAIL_ALREADY_EXISTS` | 400 | Email collision on update. |
| `UPDATE_USER_INVALID_PASSWORD` | 400 | Current password wrong / policy. |
| `SUPERUSER_CANNOT_DELETE_SELF` | 403 | Self-delete forbidden. |
| `OAUTH_NOT_AVAILABLE_EMAIL` | 400 | Provider did not supply email. |
| `OAUTH_STATE_INVALID` | 400 | OAuth state cookie missing/invalid. |
| `OAUTH_EMAIL_NOT_VERIFIED` | 400 | Associate-by-email requires verified provider email. |
| `OAUTH_USER_ALREADY_EXISTS` | 400 | OAuth would create duplicate against policy. |
| `OAUTH_ACCOUNT_ALREADY_LINKED` | 400 | Provider identity bound to another user. |
| `REQUEST_BODY_INVALID` | 400 / 422 | Body failed validation or request decoding rejected undeclared fields. |
| `LOGIN_PAYLOAD_INVALID` | 422 | Login body shape invalid. |
| `REFRESH_TOKEN_INVALID` | 401 | Refresh rejected. |
| `TOTP_PENDING_BAD_TOKEN` | 400 | Pending login token invalid. |
| `TOTP_CODE_INVALID` | 400 | Wrong or reused TOTP code. |
| `TOTP_ALREADY_ENABLED` | 400 | TOTP already active. |
| `TOTP_ENROLL_BAD_TOKEN` | 400 | Enrollment token invalid. |
| `TOTP_STEPUP_REQUIRED` | 403 | A protected operation requires a recent TOTP verification marker or a valid inline TOTP code. Prompt the user for TOTP and retry the operation from the same session; see [TOTP step-up for sensitive operations](configuration/totp.md#totp-step-up-for-sensitive-operations). |
| `API_KEY_INVALID` | 401 / 404 | API-key credential is absent, malformed, unknown, foreign to the current user, or failed non-enumerating lookup. Self-service metadata routes use 404 for missing or foreign key ids. |
| `API_KEY_REVOKED` | 401 | Parsed API-key credential belongs to a revoked key. |
| `API_KEY_EXPIRED` | 401 | Parsed API-key credential belongs to an expired key. |
| `API_KEY_SCOPE_DENIED` | 400 / 403 | Requested key scopes are outside `allowed_scopes`, or an API-key route guard denied the current request because required scopes or role-downscoped access were missing. |
| `API_KEY_LIMIT_REACHED` | 400 | User has reached `ApiKeyConfig.max_keys_per_user` active keys. |
| `API_KEY_SIGNATURE_INVALID` | 401 | Signed API-key request is malformed, uses the wrong key mode, has a bad signature, lacks signing secret material, or cannot use the configured nonce store. |
| `API_KEY_SIGNATURE_TIMESTAMP_SKEW` | 401 | Signed API-key request `X-Auth-Date` is outside the configured skew window. |
| `API_KEY_SIGNATURE_NONCE_REPLAY` | 401 | Signed API-key request reused a nonce within the nonce-store TTL. |

`USER_ALREADY_EXISTS`, `REGISTER_FAILED`, and `UPDATE_USER_INVALID_PASSWORD` keep stable HTTP mappings even though the corresponding Python exceptions now use keyword-only structured context.

Source of truth in code: `litestar_auth._error_codes.ErrorCode` (re-exported from `litestar_auth.exceptions`) and controller `ClientException` sites. Full exception hierarchy: [Python API — Exceptions](api/exceptions.md).

`LOGIN_ACCOUNT_UNAVAILABLE` intentionally uses one opaque 400 response for inactive and unverified
account-state failures so external observers cannot enumerate account state after valid credentials.
Operators can correlate the internal `inactive` / `unverified` reason through the `account_state_failure`
structured log event emitted on the `litestar_auth.security` logger.

## Enumeration safety

`POST .../register` is intentionally **enumeration-resistant** for domain failures:
duplicate identifiers, password-policy failures, and manager authorization rejections all
use the same 400 / `REGISTER_FAILED` response. `POST .../forgot-password` is also
enumeration-resistant: successful response does not reveal whether the email exists.
See [Registration guide](guides/registration.md).
