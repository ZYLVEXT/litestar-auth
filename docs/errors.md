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
| `LOGIN_BAD_CREDENTIALS` | 400 | Wrong password, unknown user, **or** a valid password against an inactive/unverified account on the password-login route (the account-state failure is deliberately folded into this generic code to prevent credential-stuffing enumeration). |
| `LOGIN_ACCOUNT_UNAVAILABLE` | 400 | Account-state policy blocked a non-password-login flow (refresh, OAuth local session issue, or another account-state gated flow where the caller has already proven identity). The password-login route never emits this code; see `LOGIN_BAD_CREDENTIALS`. |
| `AUTHORIZATION_DENIED` | 403 | Guard denied access. |
| `INSUFFICIENT_ROLES` | 403 | Role-based guard denial. Structured role context stays on the exception object but is omitted from default HTTP responses. |
| `INSUFFICIENT_PERMISSIONS` | 403 | Permission-based guard denial. Structured required/granted permission context stays on the exception object but is omitted from default HTTP responses. |
| `INSUFFICIENT_ORGANIZATION_ROLES` | 403 | Organization role guard denial from `has_organization_role()`. Emitted when the request lacks verified organization context or the current membership does not have all required organization roles. |
| `INSUFFICIENT_ORGANIZATION_PERMISSIONS` | 403 | Organization permission guard denial from `has_organization_permission()`. Emitted when the request lacks verified organization context, lacks required organization-scoped effective permissions, or an API key does not delegate the required permission. |
| `ORGANIZATION_SWITCH_DENIED` | 403 | Opt-in `POST /auth/switch-organization` denied the active-organization switch because the requested slug could not be normalized, the organization could not be found, or authenticated-user membership could not be verified. |
| `ORGANIZATION_ALREADY_EXISTS` | 409 | Opt-in organization-admin create/update conflict for a normalized organization slug. |
| `ORGANIZATION_NOT_FOUND` | 404 | Opt-in organization-admin organization lookup failed, including malformed organization ids on the bundled HTTP controller. |
| `ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS` | 409 | Opt-in organization-admin membership add conflict for an existing `(organization_id, user_id)` membership. |
| `ORGANIZATION_MEMBERSHIP_NOT_FOUND` | 404 | Opt-in organization-admin membership lookup failed, including malformed user ids on the bundled HTTP controller. |
| `ORGANIZATION_LAST_PRIVILEGED_MEMBER` | 409 | Opt-in organization-admin refused to remove or demote the final privileged member of an organization. |
| `ORGANIZATION_INVITATION_INVALID` | 400 | Organization invitation token validation failed because the token is malformed, signed for the wrong audience, references no pending row, or the row was consumed or revoked. |
| `ORGANIZATION_INVITATION_EXPIRED` | 400 | Organization invitation token validation failed because the signed token or stored invitation row expired. |
| `ORGANIZATION_INVITATION_EMAIL_MISMATCH` | 400 | Organization invitation accept/decline was attempted by an authenticated user whose normalized email does not match the invitation email. |
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
| `SESSION_MANAGEMENT_UNSUPPORTED` | 400 | Session/device routes are mounted but the active strategy does not implement refresh-session management. |
| `REFRESH_SESSION_NOT_FOUND` | 404 | Session/device revoke path did not find a matching active session for the authenticated user. |
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

`USER_ALREADY_EXISTS`, `REGISTER_FAILED`, and `UPDATE_USER_INVALID_PASSWORD` keep stable HTTP mappings; the corresponding Python exceptions use keyword-only structured context.

Source of truth in code: `litestar_auth._error_codes.ErrorCode` (re-exported from `litestar_auth.exceptions`) and controller `ClientException` sites. Full exception hierarchy: [Python API — Exceptions](api/exceptions.md).

`INSUFFICIENT_PERMISSIONS` is emitted by permission guard failures through
`InsufficientPermissionsError`. The exception keeps `required_permissions`,
`granted_permissions`, and `require_all` on the Python object for handlers or logs,
but the default HTTP response does not expose permission names.

`INSUFFICIENT_ORGANIZATION_ROLES` is emitted by `has_organization_role()` through
`InsufficientOrganizationRolesError`. `INSUFFICIENT_ORGANIZATION_PERMISSIONS` is emitted by
`has_organization_permission()` through `InsufficientOrganizationPermissionsError`. These exceptions
keep required and granted role or permission context on the Python object, but default responses do
not expose the names.

`ORGANIZATION_SWITCH_DENIED` is emitted by the opt-in switch-organization controller. It is
intentionally non-enumerating: invalid slugs, unknown organizations, missing ids, and missing
memberships all collapse to the same 403 so clients cannot probe the organization catalog or another
user's membership state. Malformed switch request bodies use `REQUEST_BODY_INVALID` instead.

The organization-admin codes are emitted by the opt-in `/organizations` controller from
`litestar_auth.contrib.organization_admin` and by the shared `SQLAlchemyOrganizationAdmin` operations
layer as Python exceptions:

- `ORGANIZATION_ALREADY_EXISTS` maps normalized slug collisions during organization create/update.
- `ORGANIZATION_NOT_FOUND` maps unknown organization reads, updates, deletes, member listing, and
  member additions to unknown organizations. The HTTP controller also maps malformed organization
  identifiers to this code.
- `ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS` maps duplicate membership creation.
- `ORGANIZATION_MEMBERSHIP_NOT_FOUND` maps unknown membership reads, role replacement, and removal.
  The HTTP controller also maps malformed user identifiers to this code.
- `ORGANIZATION_LAST_PRIVILEGED_MEMBER` maps attempts to remove or demote the final membership whose
  roles include `owner` or `admin`.

Organization invitation codes are emitted by both invitation surfaces:

- The operator `/organizations/{organization_id}/invitations` routes and `litestar organizations`
  invitation CLI commands create, list, and revoke pending invitations. Admin create/list uses
  `ORGANIZATION_NOT_FOUND` for unknown or malformed organization ids. Admin revoke uses
  `ORGANIZATION_INVITATION_INVALID` when the invitation id is malformed, unknown, already consumed,
  already revoked, or no longer pending.
- The authenticated `{auth}/organization-invitations/accept` and
  `{auth}/organization-invitations/decline` routes require an active, verified authenticated user and
  validate the signed token and stored pending row before changing state. Inactive or unverified
  users receive the standard 403 permission-denied response before invitation-specific error mapping.
  `ORGANIZATION_INVITATION_INVALID` covers malformed tokens, wrong JWT audience, missing token-hash
  rows, consumed rows, and revoked rows. `ORGANIZATION_INVITATION_EXPIRED` covers either an expired
  signed token or an expired stored row.
- `ORGANIZATION_INVITATION_EMAIL_MISMATCH` is the anti-hijack failure for accept/decline. A valid
  token alone is not enough: the authenticated user's normalized email must match the invitation's
  normalized `invited_email`.

Invitation error responses deliberately share the same human-readable detail,
`"Organization invitation cannot be used."`, so callers can branch on `code` without exposing token,
row-state, or email-ownership details in response text.

On the **password-login route**, inactive/unverified account-state failures are folded into
`LOGIN_BAD_CREDENTIALS`: a caller holding a valid password cannot distinguish "account exists but
disabled/unverified" from "wrong credentials" (CWE-203). The login rate-limit counter is still
incremented on the account-state failure so the channel cannot be probed cheaply.

`LOGIN_ACCOUNT_UNAVAILABLE` remains the opaque 400 for the other account-state-gated flows (refresh,
OAuth local session issue), where the caller has already proven identity, and still folds inactive and
unverified into one response. Operators can correlate the internal `inactive` / `unverified` reason
through the `account_state_failure` structured log event emitted on the `litestar_auth.security` logger.

## Enumeration safety

`POST .../register` is intentionally **enumeration-resistant** for domain failures:
duplicate identifiers, password-policy failures, and manager authorization rejections all
use the same 400 / `REGISTER_FAILED` response. `POST .../forgot-password` is also
enumeration-resistant: successful response does not reveal whether the email exists.
See [Registration guide](guides/registration.md).
