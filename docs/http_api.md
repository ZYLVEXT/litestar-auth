# HTTP API reference

Unless noted, paths are relative to your app root. Defaults: `auth_path="/auth"`, `users_path="/users"`.

Placeholders:

- `{auth}` — value of `auth_path` without trailing slash ambiguity (routes are registered under `auth_path`).
- `{users}` — `users_path`.
- `{provider}` — OAuth provider name from `OAuthConfig.oauth_providers` or a manual controller factory.

Generated OpenAPI publishes the built-in request/response payload names from `litestar_auth.payloads`. `login_identifier` only changes how `LoginCredentials.identifier` is resolved during login; it does not rename the email/token fields used by the built-in registration, verification, reset-password, refresh, or TOTP routes.
For plugin-mounted protected routes, `LitestarAuth` also publishes per-operation OpenAPI security requirements derived from the configured auth transports so Swagger / other OpenAPI UIs can authorize requests with the standard mechanism. Disable that metadata with `include_openapi_security=False`. For app-owned protected routes, reuse `config.resolve_openapi_security_requirements()`; if you mount protected controllers manually, pass `security=` to the relevant controller factory.

## Auth core

| Method | Path | Request body | Enabled when | Description |
| ------ | ---- | ------------ | ------------ | ----------- |
| POST | `{auth}/login` | `LoginCredentials` (`identifier`, `password`) | Always (auth controller) | Credentials → tokens / session. |
| POST | `{auth}/logout` | None | Always | Authenticated; clears session per strategy. |
| POST | `{auth}/refresh` | `RefreshTokenRequest` (`refresh_token`) | `enable_refresh=True` | New access token from refresh token / cookie. |

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
[Configuration](configuration.md#canonical-manager-password-surface) for the full schema-helper,
password-validator, and shared-helper contract.

Built-in user-returning responses from `POST {auth}/register`, `POST {auth}/verify`, and
`POST {auth}/reset-password` use `UserRead`, which now serializes `id`, `email`, `is_active`,
`is_verified`, `is_superuser`, and normalized `roles`.

That response contract is intentionally unchanged by the relational-role migration. The HTTP API
still exposes one flat `roles` array, not raw `role` / `user_role` rows, permission matrices, or
role-management endpoints.

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
| POST | `{auth}/2fa/enable/confirm` | `TotpConfirmEnableRequest` (`enrollment_token`, `code`) | Authenticated; confirms enrollment. |
| POST | `{auth}/2fa/verify` | `TotpVerifyRequest` (`pending_token`, `code`) | Completes login when TOTP is enabled (pending token). |
| POST | `{auth}/2fa/disable` | `TotpDisableRequest` (`code`) | Authenticated; disables TOTP. |

The built-in TOTP flow remains email-oriented internally: the otpauth URI and default password step-up for `POST {auth}/2fa/enable` use `request.user.email`, not `login_identifier`.

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
| GET | `{auth}/associate/{provider}/authorize` | Authenticated user starts linking. |
| GET | `{auth}/associate/{provider}/callback` | Completes linking for `request.user`. |

## Users CRUD

When `include_users=True`, routes are under `{users}`.

| Method | Path | Guard |
| ------ | ---- | ----- |
| GET | `{users}/me` | Authenticated |
| PATCH | `{users}/me` | Authenticated |
| GET | `{users}/{id}` | Superuser |
| PATCH | `{users}/{id}` | Superuser |
| DELETE | `{users}/{id}` | Superuser |
| GET | `{users}` | Superuser (list) |

The built-in users surface also serializes `UserRead`, so all `/users` reads include normalized
`roles`. `PATCH {users}/me` strips `roles` and the other privileged fields from self-service
payloads even when a custom `user_update_schema` includes them, while superuser
`PATCH {users}/{id}` can persist validated `roles` through the same schema.

The storage redesign does not add separate CRUD endpoints for the relational role tables. Built-in
users routes continue to manage only the normalized flat `roles` contract on the user boundary.

## Multiple backends

If more than one backend is configured, the **first** uses `{auth}` as above. **Additional** backends use `{auth}/{backend-name}/...` for their auth routes (see [Backends](concepts/backends.md)).

## Rate limiting

When `rate_limit_config` is set, selected endpoints may return **429** with `Retry-After`. See the [Rate limiting guide](guides/rate_limiting.md) and the [Python API](api/ratelimit.md).
