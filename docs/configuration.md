# Configuration

The plugin is driven by **`LitestarAuthConfig`** (import from `litestar_auth` or `litestar_auth.plugin`). This page lists **all** fields grouped by concern. Generated detail lives in the [Plugin API](api/plugin.md) (mkdocstrings).

ORM models and the SQLAlchemy adapter are imported from their own modules — the root package does not re-export them:

```python
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.models import User  # or your own model
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
```

## Custom SQLAlchemy `User` and token models

`LitestarAuthConfig.user_model` must satisfy **`UserProtocol`** (see [Types](types.md)): at minimum the fields and behaviors your chosen `BaseUserManager` and strategies use (`id`, `email`, `hashed_password`, `is_active`, `is_verified`, `is_superuser`, `totp_secret` as applicable).

**Database-backed JWT / refresh** (`DatabaseTokenStrategy`): if you use the library’s `AccessToken` and `RefreshToken` from `litestar_auth.authentication.strategy.db_models`, your user class should declare relationships compatible with theirs:

- Table names: `access_token`, `refresh_token`; `user_id` foreign keys target **`user.id`** (your user model’s table must be named `user`, or you must align FKs and relationships with your schema).
- Match the default wiring in `litestar_auth.models.User`: `access_tokens` and `refresh_tokens` relationships with `back_populates="user"` pointing at those token classes. Diverging names or missing relationships can break mapper configuration or strategy code.

**OAuth persistence**: `SQLAlchemyUserDatabase` requires **`user_model`** and accepts optional **`oauth_account_model`**. If you use OAuth methods (`get_by_oauth_account`, `upsert_oauth_account`) without providing `oauth_account_model`, a `TypeError` is raised. A custom OAuth class should keep the same columns and uniqueness as the library model (`oauth_name`, `account_id`, encrypted token fields, `user_id` FK to your user table’s primary key). If your user table is not `user`, supply an OAuth model whose foreign keys match your schema. If you map `user` yourself, import **`OAuthAccount` from `litestar_auth.models.oauth`** so the reference `User` mapper is never registered — see [Custom user + OAuth](cookbook/custom_user_oauth.md).

## Required (at runtime)

| Field | Role |
| ----- | ---- |
| `backends` | Non-empty sequence of `AuthenticationBackend` (transport + strategy). |
| `user_model` | User ORM type (e.g. subclass of `litestar_auth.models.User`). |
| `user_manager_class` | Concrete subclass of `BaseUserManager`. |
| `session_maker` | `async_sessionmaker[AsyncSession]` for scoped DB access. |

On the `LitestarAuthConfig` dataclass, `session_maker` is typed as optional for advanced construction flows, but **`LitestarAuth` raises if it is missing** when the plugin is instantiated. Treat it as required for normal apps.

## Core wiring

| Field | Default | Role |
| ----- | ------- | ---- |
| `user_db_factory` | `None` → built from `user_model` | `Callable[[AsyncSession], BaseUserStore]`. When `None`, the plugin builds a default factory using `config.user_model`. Override for custom persistence. |
| `user_manager_kwargs` | `{}` | Passed to `user_manager_class` (e.g. `password_helper`, token secrets). |
| `password_validator_factory` | `None` | Build custom password policy; else default length validator when manager accepts it. |
| `user_manager_factory` | `None` | Full control over request-scoped manager construction (`UserManagerFactory`). |
| `rate_limit_config` | `None` | `AuthRateLimitConfig` for auth endpoint throttling. |

## Paths and HTTP feature flags

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `auth_path` | `"/auth"` | Base path for generated auth controllers. |
| `users_path` | `"/users"` | Base path for user CRUD when enabled. |
| `include_register` | `True` | `POST .../register` |
| `include_verify` | `True` | Verify + request-verify-token |
| `include_reset_password` | `True` | Forgot + reset password |
| `include_users` | `False` | User management routes |
| `enable_refresh` | `False` | `POST .../refresh` |
| `requires_verification` | `False` | Stricter login / TOTP-verify policy |
| `hard_delete` | `False` | Physical vs soft delete semantics for user delete |
| `login_identifier` | `"email"` | `"email"` or `"username"` for `POST {auth_path}/login` credential lookup |

**Multiple backends:** first backend → `{auth_path}`; others → `{auth_path}/{backend-name}/...`.

## Built-in auth payload boundary

The generated controllers do not use one universal credential field. `login_identifier` only changes how `LoginCredentials.identifier` is interpreted on `POST {auth_path}/login`.

| Route | Built-in request schema | Published fields |
| ----- | ---------------------- | ---------------- |
| `POST {auth_path}/login` | `LoginCredentials` | `identifier`, `password` |
| `POST {auth_path}/register` | `UserCreate` | `email`, `password` |
| `POST {auth_path}/request-verify-token` | `RequestVerifyToken` | `email` |
| `POST {auth_path}/verify` | `VerifyToken` | `token` |
| `POST {auth_path}/forgot-password` | `ForgotPassword` | `email` |
| `POST {auth_path}/reset-password` | `ResetPassword` | `token`, `password` |

By default, built-in TOTP routes publish `TotpEnableRequest`, `TotpConfirmEnableRequest`, `TotpVerifyRequest`, and `TotpDisableRequest`. The built-in TOTP flow still uses `user.email` for the otpauth URI and password step-up, even when `login_identifier="username"`.

## TOTP — `totp_config: TotpConfig | None`

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `totp_pending_secret` | (required) | Secret for pending-2FA JWTs; must align with auth controller. |
| `totp_backend_name` | `None` | Which named `AuthenticationBackend` issues tokens after 2FA. |
| `totp_issuer` | `"litestar-auth"` | Issuer in otpauth URI. |
| `totp_algorithm` | `"SHA256"` | TOTP hash algorithm. |
| `totp_used_tokens_store` | `None` | Replay store for consumed TOTP codes (required outside tests when replay protection is on). |
| `totp_require_replay_protection` | `True` | Fail startup without a store when not in testing mode. |
| `totp_enable_requires_password` | `True` | Step-up password for `/2fa/enable`. |

Routes: `{auth_path}/2fa/...`. See [TOTP guide](guides/totp.md).

!!! note "Pending-token JTI store"
    `create_totp_controller(..., pending_jti_store=...)` supports a shared JWT JTI denylist for pending login tokens. The plugin’s internal `build_totp_controller` does not pass this parameter; advanced deployments can mount a custom controller if they need a Redis-backed pending JTI store across workers.

## OAuth — `oauth_config: OAuthConfig | None`

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `oauth_cookie_secure` | `True` | Secure flag for OAuth cookies. |
| `oauth_providers` | `None` | Sequence of `(name, httpx_oauth_client)` for login. |
| `oauth_associate_by_email` | `False` | Allow linking by email (unsafe without provider guarantees). |
| `include_oauth_associate` | `False` | Enable associate flow routes. |
| `oauth_associate_providers` | `None` | Providers for logged-in linking. |
| `oauth_associate_redirect_base_url` | `""` | Redirect base for associate callbacks. |
| `oauth_token_encryption_key` | `None` | **Required** for configured providers in production — encrypts tokens at rest. |

Provider controllers may take **`trust_provider_email_verified`** (see [OAuth guide](guides/oauth.md)).

## Security and token policy

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `csrf_secret` | `None` | Enables Litestar CSRF config when cookie transports are used. |
| `csrf_header_name` | `"X-CSRF-Token"` | Header Litestar expects for CSRF token. |
| `allow_legacy_plaintext_tokens` | `False` | **Migration only** — accept legacy plaintext DB tokens. |
| `allow_nondurable_jwt_revocation` | `False` | Opt-in to in-memory JWT denylist semantics. |
| `id_parser` | `None` | Parse path/query user ids (e.g. `UUID`). |

## Schemas and DI

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `user_read_schema` | `None` | msgspec struct for safe user responses returned by register/verify/reset/users flows. |
| `user_create_schema` | `None` | msgspec struct for registration/create request bodies; built-in registration defaults to `UserCreate`. |
| `user_update_schema` | `None` | msgspec struct for user PATCH bodies. |
| `db_session_dependency_key` | `"db_session"` | Litestar DI key for `AsyncSession`. |
| `db_session_dependency_provided_externally` | `False` | Skip plugin session provider when your app already registers the key. |

`user_*_schema` customizes registration and user CRUD surfaces. It does not rename the built-in auth lifecycle request structs: `LoginCredentials`, `RefreshTokenRequest`, `RequestVerifyToken`, `VerifyToken`, `ForgotPassword`, `ResetPassword`, or the TOTP payloads.

## Dependency keys (constants)

Used by the plugin internally; override only if you integrate custom controllers:

- `litestar_auth_config`, `litestar_auth_user_manager`, `litestar_auth_backends`, `litestar_auth_user_model` (see `litestar_auth._plugin.config`).

## Shared helpers — `litestar_auth.config`

`validate_secret_length`, `is_testing`, `MINIMUM_SECRET_LENGTH`, etc., keep token and testing behavior consistent.

## Related

- [HTTP API](http_api.md) — routes controlled by the flags above.
- [Security](security.md) — production interpretation of sensitive flags.
- [Plugin API](api/plugin.md) — mkdocstrings for `LitestarAuth`, configs, and `litestar_auth.config`.
