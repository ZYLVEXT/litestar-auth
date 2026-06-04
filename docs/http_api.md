# HTTP API reference

Unless noted, paths are relative to your app root. Defaults: `auth_path="/auth"`, `users_path="/users"`.

Placeholders:

- `{auth}` — value of `auth_path` without trailing slash ambiguity (routes are registered under `auth_path`).
- `{users}` — `users_path`.
- `{provider}` — OAuth provider name from `OAuthConfig.oauth_providers` or a manual controller factory.

Generated OpenAPI publishes the built-in request/response payload names from `litestar_auth.payloads`. `login_identifier` only changes how `LoginCredentials.identifier` is resolved during login; it does not rename the email/token fields used by the built-in registration, verification, reset-password, refresh, or TOTP routes.
For plugin-mounted protected routes, `LitestarAuth` publishes per-operation OpenAPI security
requirements derived from the configured auth transports, so Swagger and other OpenAPI UIs can
authorize requests with the standard mechanism. Disable that metadata with
`include_openapi_security=False`.
For app-owned protected routes, reuse `config.resolve_openapi_security_requirements()`. If you
mount protected controllers manually, pass `security=` to the relevant controller factory.

## Auth core

| Method | Path | Request body | Enabled when | Description |
| ------ | ---- | ------------ | ------------ | ----------- |
| POST | `{auth}/login` | `LoginCredentials` (`identifier`, `password`) | Always (auth controller) | Credentials → tokens / session. |
| POST | `{auth}/logout` | None | Always | Authenticated; clears session per strategy. |
| POST | `{auth}/refresh` | `RefreshTokenRequest` (`refresh_token`) | `enable_refresh=True` | New access token from refresh token / cookie. |
| GET | `{auth}/sessions` | None | `include_session_devices=True` | Authenticated; list the current user's active DB-backed refresh sessions. CookieTransport clients can be marked current from the refresh cookie. |
| POST | `{auth}/sessions` | `RefreshTokenRequest` (`refresh_token`) | `include_session_devices=True` | Authenticated; list active refresh sessions while identifying the current bearer refresh session. |
| DELETE | `{auth}/sessions/{session_id}` | None | `include_session_devices=True` | Authenticated; revoke one of the current user's refresh sessions by public session id. |
| POST | `{auth}/sessions/revoke-others` | Optional `RefreshTokenRequest` (`refresh_token`) for bearer clients | `include_session_devices=True` | Authenticated; revoke the current user's other refresh sessions. |
| POST | `{auth}/switch-organization` | `SwitchOrganizationRequest` (`organization_slug`) | `organization_config.enabled=True`, `organization_config.include_switch_organization=True`, and a JWT-capable non-API-key backend | Authenticated; verifies target organization membership and returns an organization-bound JWT through the configured transport. |
| POST | `{auth}/organization-invitations/accept` | `OrganizationInvitationTokenRequest` (`token`) | `organization_config.enabled=True`, `organization_config.include_organization_invitations=True` | Authenticated; validates a single-use invitation token, requires the authenticated user's normalized email to match the invitation, creates membership roles from the invitation, and consumes the invitation. |
| POST | `{auth}/organization-invitations/decline` | `OrganizationInvitationTokenRequest` (`token`) | `organization_config.enabled=True`, `organization_config.include_organization_invitations=True` | Authenticated; validates the token and authenticated email, then revokes the pending invitation without creating membership. |

## Session/device response contracts

Session/device management routes use response DTOs from `litestar_auth.payloads`. Bearer clients use
`POST {auth}/sessions` with the existing `RefreshTokenRequest` body when they want the server to
identify the current refresh session in a list response, and may include the same body on
`POST {auth}/sessions/revoke-others`. Cookie clients do not submit that body; the
controller reads the configured `CookieTransport` refresh cookie instead.

`RefreshSessionRead` serializes one active DB-backed refresh session:

- `session_id` — stable public session identifier. It is not the raw refresh token, access token,
  token digest, or keyed token digest.
- `created_at` — original refresh-session creation timestamp.
- `last_used_at` — timestamp of the last successful refresh rotation, or `null` when the session has
  not been used after login.
- `is_current` — `true` / `false` when the current refresh credential can be matched to the row, or
  `null` when the route cannot compute that marker.
- `client_metadata` — optional bounded safe client hints. The built-in DB strategy stores only
  normalized `user_agent` metadata capped at 255 characters; exact IP addresses and token material
  are not part of this contract.

List responses use `RefreshSessionListResponse`:

```json
{
  "sessions": [
    {
      "session_id": "a4ff5e6a-60f8-4a8e-9684-7239150fd91b",
      "created_at": "2026-05-09T01:20:00Z",
      "last_used_at": "2026-05-09T01:25:00Z",
      "is_current": true,
      "client_metadata": {
        "user_agent": "Example Browser/1.0"
      }
    }
  ]
}
```

Plugin-owned session/device routes are opt-in with `include_session_devices=True` and are mounted
under `auth_path`. They are authenticated routes and always scope strategy calls to `request.user`.
The first controller slice supports strategies implementing the refresh-session management protocol,
including the built-in DB token strategy. JWT and Redis token strategies do not provide a session
dashboard in this slice.

| Status | Error code | Applies to | Meaning |
| ------ | ---------- | ---------- | ------- |
| 400 | `SESSION_MANAGEMENT_UNSUPPORTED` | All session/device routes | The configured strategy does not implement refresh-session management. |
| 401 | None | All session/device routes | Authentication credentials are absent or invalid. |
| 404 | `REFRESH_SESSION_NOT_FOUND` | `DELETE {auth}/sessions/{session_id}` | The public session id is missing or does not belong to the authenticated user. |

Current-session detection is available when the configured strategy can identify a public session id
from the current raw refresh credential. The built-in DB token strategy supports that lookup by
hashing the supplied refresh token and comparing it to stored digests; it does not store or expose raw
refresh tokens. When the credential is available and matches one of the current user's active refresh
sessions, cookie clients can use `GET {auth}/sessions` and bearer clients can use
`POST {auth}/sessions` to mark exactly that item with `is_current: true` and the other active items
with `false`; `POST {auth}/sessions/revoke-others` preserves that session.

When no current refresh credential is present or resolvable (for example invalid, expired, owned by
another user, or unsupported by the current strategy), the current session is unresolved.
In that fallback, list responses keep `is_current: null`, and revoke-others passes an unknown
current-session marker to the strategy.
For the built-in DB strategy, this revokes all active refresh sessions for the current user.

## Organization activation

`POST {auth}/switch-organization` is an opt-in organization route mounted under the backend's auth
path. The primary backend uses `{auth}`. Additional capable backends use `{auth}/{backend_name}`,
matching the rest of the backend-specific controller layout.

Request body:

```json
{
  "organization_slug": "acme"
}
```

The route requires an authenticated user and is mounted only when
`OrganizationConfig.include_switch_organization=True` on an enabled organization config. The backend
must use a strategy that implements `write_token_for_organization(user, organization)`, such as
`JWTStrategy`; API-key transports are skipped. Database-token, Redis-token, and API-key strategies do
not receive signed active-organization semantics and continue to use configured tenant resolvers such
as headers or subdomains.

On success, the controller returns the same login-token shape as the configured transport. A bearer
JWT backend returns the new bearer token response. A cookie JWT backend sets the configured login
cookie. The token carries a signed `org` claim normalized from `organization_slug`.

The route verifies membership before minting the token: it normalizes the slug, fetches the
organization by slug, fetches the authenticated user's membership for that organization id, then
calls `JWTStrategy.write_token_for_organization()`. Failures are fail closed and do not distinguish
unknown organizations from non-membership.

| Status | Error code | Meaning |
| ------ | ---------- | ------- |
| 200 | None | Organization-bound token issued through the backend transport. |
| 400 / 422 | `REQUEST_BODY_INVALID` | Body failed decoding or schema validation. |
| 401 | None | Authentication credentials are absent or invalid. |
| 403 | `ORGANIZATION_SWITCH_DENIED` | Slug invalid, organization missing, user or organization id unavailable, or membership cannot be verified. |

After a successful switch, later requests authenticated by the new JWT expose
`JWTContext.organization` from the fully verified signed claim. With the default resolver selected by
`include_switch_organization=True`, `ClaimTenantResolver` reads that trusted context before the
middleware performs the ordinary organization-store lookup and membership verification required to
publish `litestar_auth_current_organization`.

## Organization administration (opt-in)

When `OrganizationConfig(enabled=True, include_organization_admin=True, store_factory=...)` is set,
the plugin mounts the bundled organization-admin controller under `/organizations`. The route surface
is opt-in and defaults to `guards=[is_superuser]`. Manual mounting uses
`litestar_auth.contrib.organization_admin.create_organization_admin_controller(...)`; keep the
default guard posture unless the application supplies an equivalent operator-only guard. Passing
`guards=[]` is rejected during controller assembly so this admin surface cannot be mounted without
an explicit guard.

The controller depends on `litestar_auth_organization_store`, parses path and query identifiers
through the configured `id_parser`, and delegates all writes through the shared
`SQLAlchemyOrganizationAdmin` operations layer. That layer normalizes slugs and membership roles,
fails closed on slug collisions and unknown targets, and protects the final privileged organization
member from removal or demotion. The default privileged role names are `owner` and `admin`.

Payload contracts live in `litestar_auth.contrib.organization_admin._schemas`:
`OrganizationCreate`, `OrganizationUpdate`, `OrganizationRead`, `MembershipCreate`,
`MembershipRolesUpdate`, `MembershipRead`, `OrganizationInvitationCreate`, and
`OrganizationInvitationRead`. Organization create/update payloads reject unknown fields and enforce
the same `1..128` slug bound used by the switch-organization route; organization names are also
bounded to `1..128` characters. Organization-admin role payloads accept at most 64 role names, with
each role name bounded to `1..255` characters before normalization and persistence. Paginated list
routes return `{"items": [...], "total": int, "limit": int, "offset": int}`.

| Method | Path | Request body | Success | Other documented statuses | Error code(s) |
| ------ | ---- | ------------ | ------- | ------------------------- | ------------- |
| `GET` | `/organizations?user_id={user_id}` | None | `200` paginated `OrganizationRead` page | `401`, `403`, `404`, `422` | `ORGANIZATION_MEMBERSHIP_NOT_FOUND` for malformed `user_id` |
| `POST` | `/organizations` | `OrganizationCreate` (`slug`, `name`) | `201` `OrganizationRead` | `401`, `403`, `409`, `422` | `ORGANIZATION_ALREADY_EXISTS`, `REQUEST_BODY_INVALID` |
| `GET` | `/organizations/{organization_id}` | None | `200` `OrganizationRead` | `401`, `403`, `404`, `422` | `ORGANIZATION_NOT_FOUND` |
| `PATCH` | `/organizations/{organization_id}` | `OrganizationUpdate` (`slug`, `name`) | `200` `OrganizationRead` | `401`, `403`, `404`, `409`, `422` | `ORGANIZATION_NOT_FOUND`, `ORGANIZATION_ALREADY_EXISTS`, `REQUEST_BODY_INVALID` |
| `DELETE` | `/organizations/{organization_id}` | None | `204` empty body | `401`, `403`, `404`, `422` | `ORGANIZATION_NOT_FOUND` |
| `POST` | `/organizations/{organization_id}/members/{user_id}` | `MembershipCreate` (`roles`) | `201` `MembershipRead` | `401`, `403`, `404`, `409`, `422` | `ORGANIZATION_NOT_FOUND`, `ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS`, `ORGANIZATION_MEMBERSHIP_NOT_FOUND`, `REQUEST_BODY_INVALID` |
| `POST` | `/organizations/{organization_id}/invitations` | `OrganizationInvitationCreate` (`invited_email`, `roles`) | `201` `OrganizationInvitationRead` | `401`, `403`, `404`, `422` | `ORGANIZATION_NOT_FOUND`, `REQUEST_BODY_INVALID` |
| `GET` | `/organizations/{organization_id}/invitations` | None | `200` paginated `OrganizationInvitationRead` page | `401`, `403`, `404`, `422` | `ORGANIZATION_NOT_FOUND` |
| `DELETE` | `/organizations/invitations/{invitation_id}` | None | `204` empty body | `401`, `403`, `400`, `422` | `ORGANIZATION_INVITATION_INVALID` |
| `GET` | `/organizations/{organization_id}/members` | None | `200` paginated `MembershipRead` page | `401`, `403`, `404`, `422` | `ORGANIZATION_NOT_FOUND` |
| `PATCH` | `/organizations/{organization_id}/members/{user_id}/roles` | `MembershipRolesUpdate` (`roles`) | `200` `MembershipRead` | `401`, `403`, `404`, `409`, `422` | `ORGANIZATION_MEMBERSHIP_NOT_FOUND`, `ORGANIZATION_LAST_PRIVILEGED_MEMBER`, `REQUEST_BODY_INVALID` |
| `DELETE` | `/organizations/{organization_id}/members/{user_id}` | None | `204` empty body | `401`, `403`, `404`, `409`, `422` | `ORGANIZATION_MEMBERSHIP_NOT_FOUND`, `ORGANIZATION_LAST_PRIVILEGED_MEMBER` |

Malformed organization ids collapse to `ORGANIZATION_NOT_FOUND`; malformed user ids collapse to
`ORGANIZATION_MEMBERSHIP_NOT_FOUND`. Malformed invitation ids on the revoke route collapse to
`ORGANIZATION_INVITATION_INVALID`.

Invitation admin routes create, list, and revoke pending invitations through the same
`SQLAlchemyOrganizationAdmin` operations layer used by the CLI. `POST /organizations/{id}/invitations`
normalizes the invited email and roles, revokes any existing unexpired pending invitation for the
same normalized email in that organization, stores only a token hash, and dispatches
`BaseUserManager.on_after_organization_invitation(invitation, token)` for delivery. The raw token is
not included in `OrganizationInvitationRead` and is never returned by the HTTP API.

The operator controller is separate from the authenticated invitee-facing invitation accept/decline
routes and does not scope application-owned tables. Tenant foreign keys and query filtering for
application data remain the application's responsibility.

## Organization invitations (invitee)

Invitee-facing invitation routes are mounted under the backend auth path when
`OrganizationConfig.include_organization_invitations=True` and organizations are enabled. They are
authenticated routes for active, verified accounts and use `OrganizationInvitationTokenRequest` with
one `token` field. The token field uses the same non-empty `1..2048` character bound as other
long-lived account-token payloads before JWT parsing.

| Method | Path | Request body | Success | Other documented statuses | Error code(s) |
| ------ | ---- | ------------ | ------- | ------------------------- | ------------- |
| `POST` | `{auth}/organization-invitations/accept` | `OrganizationInvitationTokenRequest` (`token`) | `200` `MembershipRead` | `400`, `401`, `403`, `422` | `ORGANIZATION_INVITATION_INVALID`, `ORGANIZATION_INVITATION_EXPIRED`, `ORGANIZATION_INVITATION_EMAIL_MISMATCH`, `REQUEST_BODY_INVALID` |
| `POST` | `{auth}/organization-invitations/decline` | `OrganizationInvitationTokenRequest` (`token`) | `204` empty body | `400`, `401`, `403`, `422` | `ORGANIZATION_INVITATION_INVALID`, `ORGANIZATION_INVITATION_EXPIRED`, `ORGANIZATION_INVITATION_EMAIL_MISMATCH`, `REQUEST_BODY_INVALID` |

A valid signed token is not sufficient to accept or decline an invitation. The route validates the
JWT signature, organization-invitation audience, expiry, stored token hash, pending row state, and
the authenticated user's active, verified account state and normalized email. Inactive or unverified
authenticated users receive the standard permission-denied response before the invitation row is
mutated. If the authenticated email does not match
`OrganizationInvitationRead.invited_email`, the route fails with
`ORGANIZATION_INVITATION_EMAIL_MISMATCH`. Accept consumes the invitation row before creating
membership with the stored roles; decline revokes the row without creating membership.

## Registration and email

| Method | Path | Request body | Enabled when | Description |
| ------ | ---- | ------------ | ------------ | ----------- |
| POST | `{auth}/register` | `UserCreate` (`email`, `password`) | `include_register=True` | Create user; triggers hooks (e.g. send verification email). |
| POST | `{auth}/verify` | `VerifyToken` (`token`) | `include_verify=True` | Confirm email with token. |
| POST | `{auth}/request-verify-token` | `RequestVerifyToken` (`email`) | `include_verify=True` | Re-issue verification token. |

When you replace the built-in `UserCreate` request body with `user_create_schema`, reuse
`litestar_auth.schemas.UserEmailField` and `litestar_auth.schemas.UserPasswordField` for `email` / `password` when
you want the documented built-in validation metadata. Existing `UserPasswordField` imports remain valid; add
`UserEmailField` when you also want the built-in email regex and max length. The default runtime validator still
enforces password length through `require_password_length`. See
[Configuration](configuration/manager.md#manager-password-surface) for the full schema-helper,
password-validator, and shared-helper contract.

Built-in user-returning responses from `POST {auth}/register`, `POST {auth}/verify`, and
`POST {auth}/reset-password` use `UserRead`, which serializes `id`, `email`, `is_active`,
`is_verified`, and normalized `roles`.

That response contract is role-centric after the superuser migration.
The HTTP API exposes one flat `roles` array, not a superuser boolean, raw `role` / `user_role`
rows, permission matrices, or role-catalog/user-assignment endpoints on core plugin-owned auth
routes.
For operational catalog and user-role administration, use the plugin-owned
[`litestar roles`](guides/roles_cli.md) CLI surface or mount the opt-in contrib controller from
[HTTP role administration](guides/role_admin_http.md).

## Password reset

| Method | Path | Request body | Enabled when | Description |
| ------ | ---- | ------------ | ------------ | ----------- |
| POST | `{auth}/forgot-password` | `ForgotPassword` (`email`) | `include_reset_password=True` | Always returns 202; enumeration-safe. |
| POST | `{auth}/reset-password` | `ResetPassword` (`token`, `password`) | `include_reset_password=True` | Apply new password with reset token. |

## TOTP (2FA)

Mounted under `{auth}/2fa/...` when `totp_config` is set.

| Method | Path | Request body | Notes |
| ------ | ---- | ------------ | ----- |
| POST | `{auth}/2fa/enable` | `TotpEnableRequest` (`password`) by default; no body when `totp_enable_requires_password=False` | Authenticated; starts enrollment. |
| POST | `{auth}/2fa/enable/confirm` | `TotpConfirmEnableRequest` (`enrollment_token`, `code`) | Authenticated; confirms enrollment and returns one-time recovery codes. |
| POST | `{auth}/2fa/verify` | `TotpVerifyRequest` (`pending_token`, `code`) | Completes login when TOTP is enabled; `code` accepts either a current TOTP code or an unused recovery code. Successful app-code verification records the server-side recent-TOTP marker used by downstream step-up checks; recovery-code verification only does so when `totp_stepup_allow_recovery=True`. |
| POST | `{auth}/2fa/disable` | `TotpDisableRequest` (`code`) | Authenticated; disables TOTP. `code` accepts either a current TOTP code or an unused recovery code. A recovery code remains accepted for lockout recovery. |
| POST | `{auth}/2fa/recovery-codes/regenerate` | `TotpRegenerateRecoveryCodesRequest` (optional `current_password`, optional `totp_code`) | Authenticated; replaces the stored recovery-code set and returns the new plaintext codes once. `current_password` is required when `totp_enable_requires_password=True`; `totp_code` can satisfy the TOTP step-up gate. |

`TotpConfirmEnableResponse` and `TotpRecoveryCodesResponse` carry `recovery_codes`; those plaintext
values are returned once and only their hashes are stored. Generated recovery codes are 28 lowercase
hex characters (112 bits). `TotpEnableResponse` necessarily carries the plaintext TOTP secret and
otpauth URI for QR-code rendering, so production deployments must serve `{auth}/2fa/enable` only
over HTTPS. Pending-login JWTs are client-bound by default with `cip` / `uaf` fingerprints, so a
`/2fa/verify` request from a different client receives the same `TOTP_PENDING_BAD_TOKEN` response as
an invalid pending token.

The built-in TOTP flow remains email-oriented internally: the otpauth URI and default password step-up for `POST {auth}/2fa/enable` use `request.user.email`, not `login_identifier`.

Sensitive operations use `LitestarAuthConfig.totp_stepup_policy` and default to `required_when_enrolled`
for `users.update_self`, `api_keys.create`, `api_keys.update`, `api_keys.revoke`, `oauth.associate`,
`totp.disable`, and `totp.regenerate_recovery_codes`. Enrolled users must present either a recent
server-side TOTP marker from `/2fa/verify` or a valid inline `totp_code` field where the request body
supports it. Missing proof returns HTTP 403 with `TOTP_STEPUP_REQUIRED`; users without TOTP are not
blocked unless the endpoint policy is `always_required`. The full configuration and per-endpoint
default table lives in
[TOTP step-up for sensitive operations](configuration/totp.md#totp-step-up-for-sensitive-operations).

## OAuth2 login

When `oauth_config.oauth_providers` is configured with `oauth_redirect_base_url`, the plugin auto-mounts login routes under `{auth}/oauth/{provider}`.

| Method | Path pattern | Description |
| ------ | ------------ | ----------- |
| GET | `{auth}/oauth/{provider}/authorize` | Redirect to provider. |
| GET | `{auth}/oauth/{provider}/callback` | Provider redirect; completes the plugin-owned OAuth login flow. |

If you mount `create_provider_oauth_controller()` or `create_oauth_controller()` directly for a custom route table, the prefix may differ from `{auth}/oauth/{provider}`.

## OAuth account linking (associate)

When `oauth_config.include_oauth_associate=True`, the plugin auto-mounts associate routes under `{auth}/associate/{provider}` for the same `oauth_providers` inventory.

| Method | Path pattern | Description |
| ------ | ------------ | ----------- |
| POST | `{auth}/associate/{provider}/authorize` | Authenticated user starts linking. CSRF-protected: cookie-transport deployments must mirror the plugin-managed CSRF cookie into the configured `csrf_header_name` (defaults to `X-CSRF-Token`); bearer-only deployments rely on the cross-origin attachment of `Authorization` to be impossible. The route is **POST** (not GET) so Litestar's CSRF middleware can enforce that token check before the body runs and forced-association attacks fail closed. |
| GET | `{auth}/associate/{provider}/callback` | Completes linking for `request.user`. Stays GET because OAuth providers redirect there with GET. |

## Users CRUD

When `include_users=True`, routes are under `{users}`.

| Method | Path | Guard |
| ------ | ---- | ----- |
| GET | `{users}/me` | Authenticated |
| PATCH | `{users}/me` | Authenticated |
| POST | `{users}/me/change-password` | Authenticated |
| GET | `{users}/{id}` | Superuser |
| PATCH | `{users}/{id}` | Superuser |
| DELETE | `{users}/{id}` | Superuser |
| GET | `{users}` | Superuser (list) |

The built-in users surface also serializes `UserRead`, so all `/users` reads include normalized
`roles`. `PATCH {users}/me` strips `roles` and the other privileged fields from self-service
payloads even when a custom `user_update_schema` includes them. Email changes use `UserUpdate`
(`email`, optional `current_password`, optional `totp_code`) and require `current_password`; non-email self-service
updates from custom schemas do not. `PATCH {users}/me` does not rotate passwords.
Authenticated password rotation uses `POST {users}/me/change-password` with `ChangePasswordRequest`
(`current_password`, `new_password`); the controller re-verifies the current password before
delegating the replacement password through the manager update lifecycle. Wrong or missing
current-password submissions on email changes and password rotation return `400` with
`LOGIN_BAD_CREDENTIALS`, invalid replacement passwords return `400` with
`UPDATE_USER_INVALID_PASSWORD`, malformed request payloads use `REQUEST_BODY_INVALID`,
unauthenticated requests return `401`, and configured rate limits return `429` with `Retry-After`.
Superuser `PATCH {users}/{id}` uses `AdminUserUpdate`, can persist validated `roles`, and remains
the admin-initiated password rotation path.

Relational role tables do not get separate CRUD endpoints in the core plugin. Built-in users routes
continue to manage only the normalized flat `roles` contract on the user boundary.
Operator-driven catalog and assignment administration lives on the
[`litestar roles`](guides/roles_cli.md) CLI surface, while applications that need an HTTP admin
surface can opt into [HTTP role administration](guides/role_admin_http.md).

## Contrib role administration (opt-in)

If you mount `litestar_auth.contrib.role_admin.create_role_admin_controller(...)`, the library
adds an admin-only HTTP role-management surface under its configured prefix (default `/roles`).
The factory defaults to `guards=[is_superuser]`; see
[HTTP role administration](guides/role_admin_http.md) for mounting and override guidance.
In the route table below, `{roles}` means the configured contrib role-admin prefix (default `/roles`).

Payload contracts live in `litestar_auth.contrib.role_admin._schemas`:
`RoleCreate`, `RoleUpdate`, `RoleRead`, and `UserBrief`. Paginated list routes return
`{"items": [...], "total": int, "limit": int, "offset": int}`. The controller also reserves
these machine-readable `ErrorCode` values for role-catalog and assignment failures:
`ROLE_ALREADY_EXISTS`, `ROLE_NOT_FOUND`, `ROLE_STILL_ASSIGNED`,
`ROLE_ASSIGNMENT_USER_NOT_FOUND`, and `ROLE_NAME_INVALID`.

| Method | Path | Request body | Success | Other documented statuses | Error code(s) |
| ------ | ---- | ------------ | ------- | ------------------------- | ------------- |
| `GET` | `{roles}` | None | `200` paginated `RoleRead` page | `403`, `422` | None |
| `POST` | `{roles}` | `RoleCreate` | `201` `RoleRead` | `403`, `409`, `422` | `ROLE_ALREADY_EXISTS`, `ROLE_NAME_INVALID` |
| `GET` | `{roles}/{role_name}` | None | `200` `RoleRead` | `403`, `404`, `422` | `ROLE_NOT_FOUND`, `ROLE_NAME_INVALID` |
| `PATCH` | `{roles}/{role_name}` | `RoleUpdate` | `200` `RoleRead` | `403`, `404`, `422` | `ROLE_NOT_FOUND`, `ROLE_NAME_INVALID` |
| `DELETE` | `{roles}/{role_name}` | None | `204` empty body | `403`, `404`, `409`, `422` | `ROLE_NOT_FOUND`, `ROLE_STILL_ASSIGNED`, `ROLE_NAME_INVALID` |
| `POST` | `{roles}/{role_name}/users/{user_id}` | None | `200` `RoleRead` | `403`, `404`, `422` | `ROLE_NOT_FOUND`, `ROLE_ASSIGNMENT_USER_NOT_FOUND`, `ROLE_NAME_INVALID` |
| `DELETE` | `{roles}/{role_name}/users/{user_id}` | None | `204` empty body | `403`, `404`, `422` | `ROLE_ASSIGNMENT_USER_NOT_FOUND`, `ROLE_NAME_INVALID` |
| `GET` | `{roles}/{role_name}/users` | None | `200` paginated `UserBrief` page | `403`, `404`, `422` | `ROLE_NOT_FOUND`, `ROLE_NAME_INVALID` |

Assignment writes are idempotent and run through the manager lifecycle instead of mutating
association rows behind `BaseUserManager`.
The `user_id` path parameter is parsed UUID-first, then falls back to the configured model's
primary-key shape, so the same controller works with bundled UUID users and integer-key custom
models.

## API keys

When `api_keys.enabled=True`, the plugin mounts self-service routes under `/api-keys` and
superuser inventory routes under `{users}` (`users_path`, default `/users`).

All API-key inventory routes require `requires_password_session`, so callers authenticated with an
API key cannot list, create, update, or revoke API keys. Sensitive mutations also use the TOTP
step-up policy for `api_keys.create`, `api_keys.update`, and `api_keys.revoke`.

| Method | Path | Request body | Success | Other documented statuses | Error code(s) |
| ------ | ---- | ------------ | ------- | ------------------------- | ------------- |
| `POST` | `/api-keys` | `ApiKeyCreateRequest` | `201` `ApiKeyCreateResponse` | `400`, `401`, `403`, `422`, `429` | `LOGIN_BAD_CREDENTIALS`, `API_KEY_SCOPE_DENIED`, `API_KEY_LIMIT_REACHED`, `REQUEST_BODY_INVALID`, `TOTP_STEPUP_REQUIRED` |
| `GET` | `/api-keys` | None | `200` `ApiKeyListResponse` | `401`, `403` | `AUTHORIZATION_DENIED` |
| `GET` | `/api-keys/{key_id}` | None | `200` `ApiKeyRead` | `401`, `403`, `404` | `AUTHORIZATION_DENIED`, `API_KEY_INVALID` |
| `PATCH` | `/api-keys/{key_id}` | `ApiKeyUpdateRequest` | `200` `ApiKeyRead` | `400`, `401`, `403`, `404`, `422`, `429` | `LOGIN_BAD_CREDENTIALS`, `API_KEY_SCOPE_DENIED`, `AUTHORIZATION_DENIED`, `API_KEY_INVALID`, `REQUEST_BODY_INVALID`, `TOTP_STEPUP_REQUIRED` |
| `DELETE` | `/api-keys/{key_id}` | None | `200` `ApiKeyRead` | `401`, `403`, `404` | `AUTHORIZATION_DENIED`, `API_KEY_INVALID`, `TOTP_STEPUP_REQUIRED` |
| `POST` | `{users}/{user_id}/api-keys` | `ApiKeyAdminCreateRequest` | `201` `ApiKeyCreateResponse` | `400`, `401`, `403`, `404` | `API_KEY_SCOPE_DENIED`, `API_KEY_LIMIT_REACHED`, `AUTHORIZATION_DENIED`, `TOTP_STEPUP_REQUIRED` |
| `GET` | `{users}/{user_id}/api-keys` | None | `200` `ApiKeyListResponse` | `401`, `403`, `404` | `AUTHORIZATION_DENIED` |
| `DELETE` | `{users}/{user_id}/api-keys/{key_id}` | None | `200` `ApiKeyRead` | `401`, `403`, `404` | `AUTHORIZATION_DENIED`, `API_KEY_INVALID`, `TOTP_STEPUP_REQUIRED` |

`ApiKeyCreateResponse` returns the raw `api_key` only once at create time plus safe metadata in
`key`. Subsequent list/get/update/revoke responses expose only `ApiKeyRead` metadata. Credential
formats and optional request-signing headers are documented in [API keys](guides/api_keys.md).

## Multiple backends

If more than one backend is configured, the **first** uses `{auth}` as above. **Additional** backends use `{auth}/{backend-name}/...` for their auth routes (see [Backends](concepts/backends.md)).

## Rate limiting

When `rate_limit_config` is set, selected endpoints may return **429** with `Retry-After`. See the [Rate limiting guide](guides/rate_limiting.md) and the [Python API](api/ratelimit.md).
