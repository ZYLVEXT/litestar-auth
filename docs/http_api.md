# HTTP API reference

Unless noted, paths are relative to your app root. Defaults: `auth_path="/auth"`, `users_path="/users"`.

Placeholders:

- `{auth}` — value of `auth_path` without trailing slash ambiguity (routes are registered under `auth_path`).
- `{users}` — `users_path`.
- `{provider}` — OAuth provider name from your controller factory.

Generated OpenAPI publishes the built-in request/response payload names from `litestar_auth.payloads`. `login_identifier` only changes how `LoginCredentials.identifier` is resolved during login; it does not rename the email/token fields used by the built-in registration, verification, reset-password, refresh, or TOTP routes.

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

Login routes are the explicit-helper path: declaring `oauth_providers` on `OAuthConfig` does **not** make the plugin auto-mount them. The canonical helper is `litestar_auth.oauth.create_provider_oauth_controller(..., auth_path=config.auth_path)`, which uses the `{auth}/oauth/{provider}` prefix.

| Method | Path pattern | Description |
| ------ | ------------ | ----------- |
| GET | `{auth}/oauth/{provider}/authorize` | Redirect to provider. |
| GET | `{auth}/oauth/{provider}/callback` | Provider redirect; completes the explicit OAuth login flow. |

If you mount `create_oauth_controller()` directly for a custom route table, the prefix may differ from `{auth}/oauth/{provider}`.

## OAuth account linking (associate)

When `oauth_config.include_oauth_associate=True` and `oauth_associate_providers` is non-empty, the plugin auto-mounts associate routes under `{auth}/associate/{provider}`.

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

## Multiple backends

If more than one backend is configured, the **first** uses `{auth}` as above. **Additional** backends use `{auth}/{backend-name}/...` for their auth routes (see [Backends](concepts/backends.md)).

## Rate limiting

When `rate_limit_config` is set, selected endpoints may return **429** with `Retry-After`. See the [Rate limiting guide](guides/rate_limiting.md) and the [Python API](api/ratelimit.md).
