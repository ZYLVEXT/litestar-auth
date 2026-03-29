# HTTP API reference

Unless noted, paths are relative to your app root. Defaults: `auth_path="/auth"`, `users_path="/users"`.

Placeholders:

- `{auth}` — value of `auth_path` without trailing slash ambiguity (routes are registered under `auth_path`).
- `{users}` — `users_path`.
- `{provider}` — OAuth provider name from your controller factory.

## Auth core

| Method | Path | Enabled when | Description |
| ------ | ---- | -------------- | ----------- |
| POST | `{auth}/login` | Always (auth controller) | Credentials → tokens / session. |
| POST | `{auth}/logout` | Always | Authenticated; clears session per strategy. |
| POST | `{auth}/refresh` | `enable_refresh=True` | New access token from refresh token / cookie. |

## Registration and email

| Method | Path | Enabled when | Description |
| ------ | ---- | -------------- | ----------- |
| POST | `{auth}/register` | `include_register=True` | Create user; triggers hooks (e.g. send verification email). |
| POST | `{auth}/verify` | `include_verify=True` | Confirm email with token. |
| POST | `{auth}/request-verify-token` | `include_verify=True` | Re-issue verification token. |

## Password reset

| Method | Path | Enabled when | Description |
| ------ | ---- | -------------- | ----------- |
| POST | `{auth}/forgot-password` | `include_reset_password=True` | Always returns 202; enumeration-safe. |
| POST | `{auth}/reset-password` | `include_reset_password=True` | Apply new password with reset token. |

## TOTP (2FA)

Mounted under `{auth}/2fa/...` when `totp_config` is set.

| Method | Path | Notes |
| ------ | ---- | ----- |
| POST | `{auth}/2fa/enable` | Authenticated; starts enrollment. |
| POST | `{auth}/2fa/enable/confirm` | Authenticated; confirms enrollment. |
| POST | `{auth}/2fa/verify` | Completes login when TOTP is enabled (pending token). |
| POST | `{auth}/2fa/disable` | Authenticated; disables TOTP. |

## OAuth2 login

Provider-specific controllers are usually mounted at `{auth}/oauth/{provider}` (authorize + callback). Exact path prefix depends on how you register `create_provider_oauth_controller` / plugin wiring; see [OAuth guide](guides/oauth.md).

| Method | Path pattern | Description |
| ------ | ------------ | ----------- |
| GET | `.../authorize` | Redirect to provider. |
| GET | `.../callback` | Provider redirect; creates session or links user. |

## OAuth account linking (associate)

When `oauth_config.include_oauth_associate=True` and `oauth_associate_providers` is non-empty, associate routes live under `{auth}/associate/{provider}`.

| Method | Path pattern | Description |
| ------ | ------------ | ----------- |
| GET | `.../authorize` | Authenticated user starts linking. |
| GET | `.../callback` | Completes linking for `request.user`. |

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
