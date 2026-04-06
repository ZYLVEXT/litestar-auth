# Configuration

The plugin is driven by **`LitestarAuthConfig`** (import from `litestar_auth` or `litestar_auth.plugin`). This page lists **all** fields grouped by concern. Generated detail lives in the [Plugin API](api/plugin.md) (mkdocstrings).

ORM models and the SQLAlchemy adapter are imported from their own modules — the root package does not re-export them:

```python
from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.models import User  # or your own model
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
```

## Canonical opaque DB-token preset

Use `DatabaseTokenAuthConfig` plus `LitestarAuthConfig.with_database_token_auth()` for the common bearer + database-token flow. This is the documented entrypoint for opaque DB tokens; it builds the `AuthenticationBackend`, `BearerTransport`, and `DatabaseTokenStrategy` for you.

```python
from uuid import UUID

from litestar import Litestar

from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.models import User

config = LitestarAuthConfig[User, UUID].with_database_token_auth(
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret="replace-with-32+-char-db-token-secret",
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_kwargs={
        "verification_token_secret": "replace-with-32+-char-secret",
        "reset_password_token_secret": "replace-with-32+-char-secret",
    },
)
app = Litestar(plugins=[LitestarAuth(config)])
```

Here, `session_maker` means a callable session factory the plugin can invoke as `session_maker()` to obtain the request-local `AsyncSession`. `async_sessionmaker(...)` is the most common implementation, but any factory with that runtime contract is supported.

If you previously hand-assembled `AuthenticationBackend(..., transport=BearerTransport(), strategy=DatabaseTokenStrategy(...))`, migrate that setup to the preset above. Keep manual `backends=` assembly only when you need multiple backends, custom token models, or another non-canonical transport/strategy mix.

## Custom SQLAlchemy `User` and token models

`LitestarAuthConfig.user_model` must satisfy **`UserProtocol`** (see [Types](types.md)): at minimum the fields and behaviors your chosen `BaseUserManager` and strategies use (`id`, `email`, `hashed_password`, `is_active`, `is_verified`, `is_superuser`, `totp_secret` as applicable).

Treat the ORM setup as three explicit layers instead of one implicit reference-model recipe:

1. `from litestar_auth.models import import_token_orm_models` is the canonical mapper-registration helper for the bundled `AccessToken` / `RefreshToken` tables.
2. `UserModelMixin`, `UserAuthRelationshipMixin`, `AccessTokenMixin`, `RefreshTokenMixin`, and `OAuthAccountMixin` are the canonical customization path when your application owns the mapped classes.
3. `DatabaseTokenModels(...)` is the strategy-side bridge only when `DatabaseTokenStrategy` should persist to custom token tables instead of the bundled defaults.

Migration note:

```python
# Canonical mapper-registration import
from litestar_auth.models import import_token_orm_models

# Compatibility-only legacy import for existing call sites
from litestar_auth.authentication.strategy import (
    import_token_orm_models as import_token_orm_models_compat,
)
```

**Database-backed JWT / refresh** (`DatabaseTokenStrategy`): the canonical explicit mapper-registration entrypoint for the library token models now lives under `litestar_auth.models`:

```python
from litestar_auth.models import import_token_orm_models

AccessToken, RefreshToken = import_token_orm_models()
```

Call that helper yourself during metadata registration or Alembic-style autogenerate setup so token model discovery stays with the models boundary. Neither the plugin nor `DatabaseTokenStrategy` auto-registers the bundled token mappers for you. The older `from litestar_auth.authentication.strategy import import_token_orm_models` path remains supported only as a compatibility import while existing code migrates. If you use the library `AccessToken` and `RefreshToken` models, your user class should declare relationships compatible with them instead of copying mapper wiring from the reference `User` class:

- Table names: `access_token`, `refresh_token`; `user_id` foreign keys target **`user.id`** (your user model’s table must be named `user`, or you must align FKs and relationships with your schema).
- Compose the side-effect-free model mixins from `litestar_auth.models` when you want the bundled field and relationship contract without copying boilerplate from the reference ORM classes:

```python
from advanced_alchemy.base import UUIDBase

from litestar_auth.models import UserAuthRelationshipMixin, UserModelMixin


class User(UserModelMixin, UserAuthRelationshipMixin, UUIDBase):
    __tablename__ = "user"
```

`UserModelMixin` provides the bundled email / password / account-state columns, while `UserAuthRelationshipMixin` provides the `access_tokens`, `refresh_tokens`, and `oauth_accounts` relationships with the same `back_populates="user"` wiring the bundled models expect. Leave its relationship-option hooks unset to keep the default contract: SQLAlchemy's normal loader behavior plus inferred foreign-key linkage for `oauth_accounts`. Set any `auth_*_model` hook to `None` when a custom user only composes part of the auth model family instead of all three relationships.

If you need custom token or OAuth classes instead of the bundled `AccessToken`, `RefreshToken`, and `OAuthAccount`, compose their sibling mixins on your application's own declarative base / registry and override the class-name / table-name hooks instead of copying relationship code:

```python
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy.orm import DeclarativeBase

from litestar_auth.models import (
    AccessTokenMixin,
    OAuthAccountMixin,
    RefreshTokenMixin,
    UserAuthRelationshipMixin,
    UserModelMixin,
)


class AppBase(DeclarativeBase):
    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class AppUUIDBase(UUIDPrimaryKey, AppBase):
    __abstract__ = True


class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "my_user"

    auth_access_token_model = "MyAccessToken"
    auth_refresh_token_model = "MyRefreshToken"
    auth_oauth_account_model = "MyOAuthAccount"
    auth_token_relationship_lazy = "noload"
    auth_oauth_account_relationship_lazy = "selectin"
    auth_oauth_account_relationship_foreign_keys = "MyOAuthAccount.user_id"


class MyAccessToken(AccessTokenMixin, AppBase):
    __tablename__ = "my_access_token"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"


class MyRefreshToken(RefreshTokenMixin, AppBase):
    __tablename__ = "my_refresh_token"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"


class MyOAuthAccount(OAuthAccountMixin, AppUUIDBase):
    __tablename__ = "my_oauth_account"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"
```

`auth_token_relationship_lazy` applies the same `lazy=` option to both token collections, while `auth_oauth_account_relationship_lazy` and `auth_oauth_account_relationship_foreign_keys` only affect `oauth_accounts`. Those hooks are intentionally narrow: use them for the documented loader-strategy or explicit-foreign-key cases, and keep app-owned relationship definitions only when you truly need behavior beyond that contract.

When those custom token classes back `DatabaseTokenStrategy`, pass them explicitly via `DatabaseTokenModels` so the strategy binds repositories, refresh rotation, logout cleanup, and expired-token cleanup to your tables instead of the bundled defaults. Model registration still starts in `litestar_auth.models`; `DatabaseTokenModels` only tells the strategy which mapped token classes to use at runtime:

```python
from litestar_auth.authentication import AuthenticationBackend
from litestar_auth.authentication.strategy import DatabaseTokenModels, DatabaseTokenStrategy
from litestar_auth.authentication.transport import BearerTransport

token_models = DatabaseTokenModels(
    access_token_model=MyAccessToken,
    refresh_token_model=MyRefreshToken,
)
backend = AuthenticationBackend(
    name="database",
    transport=BearerTransport(),
    strategy=DatabaseTokenStrategy(
        session=session,
        token_hash_secret="replace-with-32+-char-db-token-secret",
        token_models=token_models,
    ),
)
```

`DatabaseTokenAuthConfig` / `LitestarAuthConfig.with_database_token_auth()` remains the canonical shortcut for the bundled `AccessToken` / `RefreshToken` tables. Use the manual backend assembly above only when you intentionally replace the token ORM classes or need another non-canonical transport/strategy combination.

**OAuth persistence**: `SQLAlchemyUserDatabase` requires **`user_model`** and accepts optional **`oauth_account_model`**. If you use OAuth methods (`get_by_oauth_account`, `upsert_oauth_account`) without providing `oauth_account_model`, a `TypeError` is raised. A custom OAuth class can be composed from `OAuthAccountMixin` so the bundled column set, uniqueness rule, and `user` relationship stay aligned without inheriting the reference `OAuthAccount` class directly. Pair it with `UserAuthRelationshipMixin` on the user side, point `auth_oauth_account_model` at the custom class, and set the unused token hooks to `None` when you are not also composing custom token models. If that custom user also needs a non-default loader strategy for `oauth_accounts`, set `auth_oauth_account_relationship_lazy` and, only when SQLAlchemy needs an explicit hint, `auth_oauth_account_relationship_foreign_keys`. If your app still reuses the bundled `oauth_account` table on `user.id`, importing **`OAuthAccount` from `litestar_auth.models.oauth`** remains supported; otherwise prefer a mixin-based custom OAuth model whose `auth_user_model` / `auth_user_table` settings match your schema. See [Custom user + OAuth](cookbook/custom_user_oauth.md).

## Required (at runtime)

| Field | Role |
| ----- | ---- |
| `backends` | Non-empty sequence of `AuthenticationBackend` when calling `LitestarAuthConfig(...)` directly. The canonical DB bearer preset builds this automatically via `with_database_token_auth()`. |
| `user_model` | User ORM type (e.g. subclass of `litestar_auth.models.User`). |
| `user_manager_class` | Concrete subclass of `BaseUserManager`. |
| `session_maker` | Callable request-session factory for scoped DB access (`session_maker() -> AsyncSession`). `async_sessionmaker(...)` is the common implementation. |

On the `LitestarAuthConfig` dataclass, `session_maker` is typed as optional for advanced construction flows, but **`LitestarAuth` raises if it is missing** when the plugin is instantiated. Treat a compatible session factory as required for normal apps.

## Core wiring

| Field | Default | Role |
| ----- | ------- | ---- |
| `user_db_factory` | `None` → built from `user_model` | `Callable[[AsyncSession], BaseUserStore]`. When `None`, the plugin builds a default factory using `config.user_model`. Override for custom persistence. |
| `user_manager_kwargs` | `{}` | Passed to `user_manager_class` (e.g. `password_helper`, token secrets). |
| `password_validator_factory` | `None` | Build custom password policy; else default length validator when manager accepts it. |
| `user_manager_factory` | `None` | Full control over request-scoped manager construction (`UserManagerFactory`). |
| `rate_limit_config` | `None` | `AuthRateLimitConfig` for auth endpoint throttling. For the common shared-backend recipe, build it with `AuthRateLimitConfig.from_shared_backend()`. |

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

## Canonical shared-backend rate limiting

For the usual Redis deployment, pass one shared backend to `AuthRateLimitConfig.from_shared_backend()` and let the library fill in the standard auth endpoint slots:

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, RedisRateLimiter

rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60),
)
```

`from_shared_backend()` exposes typed public builder identifiers from `litestar_auth.ratelimit`:

```python
from litestar_auth.ratelimit import AuthRateLimitEndpointGroup, AuthRateLimitEndpointSlot
```

- `AuthRateLimitEndpointSlot` names the per-endpoint keys accepted by `enabled`, `disabled`, `scope_overrides`, `namespace_overrides`, and `endpoint_overrides`.
- `AuthRateLimitEndpointGroup` names the shared-backend keys accepted by `group_backends`.

The private catalog that stores these defaults remains internal, but the values below are the supported builder surface:

| `AuthRateLimitEndpointSlot` value | `AuthRateLimitEndpointGroup` value | Default scope | Default namespace token |
| --------------------------------- | ---------------------------------- | ------------- | ----------------------- |
| `login` | `login` | `ip_email` | `login` |
| `refresh` | `refresh` | `ip` | `refresh` |
| `register` | `register` | `ip` | `register` |
| `forgot_password` | `password_reset` | `ip_email` | `forgot-password` |
| `reset_password` | `password_reset` | `ip` | `reset-password` |
| `totp_enable` | `totp` | `ip` | `totp-enable` |
| `totp_confirm_enable` | `totp` | `ip` | `totp-confirm-enable` |
| `totp_verify` | `totp` | `ip` | `totp-verify` |
| `totp_disable` | `totp` | `ip` | `totp-disable` |
| `verify_token` | `verification` | `ip` | `verify-token` |
| `request_verify_token` | `verification` | `ip_email` | `request-verify-token` |

Accepted `AuthRateLimitEndpointGroup` values are exactly `login`, `refresh`, `register`, `password_reset`, `totp`, and `verification`.

Builder precedence is:

1. `endpoint_overrides` wins per slot and can replace the limiter or set it to `None`.
2. Otherwise, only slots enabled by `enabled` (defaults to every supported slot) and not listed in `disabled` are materialized.
3. Generated limiters start from `backend`, then `group_backends` can swap the backend for the slot's group.
4. `scope_overrides` and `namespace_overrides` adjust the generated limiter for that slot.

If you already depend on custom key names or scope choices, preserve them with `namespace_overrides` and `scope_overrides`. Use `disabled` to leave unused slots such as `verify_token` or `request_verify_token` unset. Keep direct `EndpointRateLimit(...)` assembly only for advanced per-endpoint exceptions.

Migration example for an older Redis recipe: this keeps login, register, and password-reset style routes on one backend, splits out refresh and TOTP budgets, preserves legacy underscore namespaces, and leaves verification slots unset. It uses only the current shared-builder arguments; it is not a separate preset.

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, RedisRateLimiter

credential_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60)
refresh_backend = RedisRateLimiter(redis=redis_client, max_attempts=10, window_seconds=300)
totp_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=300)

rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    credential_backend,
    group_backends={"refresh": refresh_backend, "totp": totp_backend},
    disabled={"verify_token", "request_verify_token"},
    namespace_overrides={
        "forgot_password": "forgot_password",
        "reset_password": "reset_password",
        "totp_enable": "totp_enable",
        "totp_confirm_enable": "totp_confirm_enable",
        "totp_verify": "totp_verify",
        "totp_disable": "totp_disable",
    },
)
```

Add `scope_overrides` only when an existing key shape also depends on a non-default scope for a specific slot.

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
| `oauth_providers` | `None` | Declared login-provider inventory for explicit login-controller registration. The canonical helper mounts `GET {auth_path}/oauth/{provider}/authorize` and `GET {auth_path}/oauth/{provider}/callback` when you pass `auth_path=config.auth_path`; the plugin does **not** auto-mount those routes from this field. |
| `oauth_associate_by_email` | `False` | Login-controller policy for explicit OAuth login helpers. Only meaningful when `oauth_providers` is declared and you mount login controllers explicitly. It does not affect plugin-owned associate routes. |
| `include_oauth_associate` | `False` | Enable plugin-owned associate flow routes. |
| `oauth_associate_providers` | `None` | Providers auto-mounted by the plugin under `GET {auth_path}/associate/{provider}/authorize` and `GET {auth_path}/associate/{provider}/callback` when `include_oauth_associate=True`. |
| `oauth_associate_redirect_base_url` | `""` | Public redirect base for plugin-owned associate callbacks. Invalid unless the plugin owns associate routes. |
| `oauth_token_encryption_key` | `None` | **Required** for any declared provider inventory in production — encrypts OAuth tokens at rest. |

Explicit login controllers may take **`trust_provider_email_verified`** (see [OAuth guide](guides/oauth.md)).

Route-registration contract:

- `oauth_providers` declares login-provider inventory only; mount login controllers explicitly with `litestar_auth.oauth.create_provider_oauth_controller(..., auth_path=config.auth_path)`.
- `include_oauth_associate=True` plus non-empty `oauth_associate_providers` is the plugin-owned OAuth auto-mount path for `{auth_path}/associate/{provider}/...`.
- Ambiguous associate-only no-op configs now fail during plugin construction instead of silently producing no routes.

## Security and token policy

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `csrf_secret` | `None` | Enables Litestar CSRF config when cookie transports are used. |
| `csrf_header_name` | `"X-CSRF-Token"` | Header Litestar expects for CSRF token. |
| `allow_legacy_plaintext_tokens` | `False` | **Migration only** — accept legacy plaintext DB tokens for manual `DatabaseTokenStrategy` setups. The canonical preset derives this from `DatabaseTokenAuthConfig.accept_legacy_plaintext_tokens`. |
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

When app-owned `user_create_schema` or `user_update_schema` structs keep a `password` field, import `UserPasswordField` from `litestar_auth.schemas` instead of copying raw `12` / `128` limits into local `msgspec.Meta(...)` annotations:

```python
import msgspec

from litestar_auth.schemas import UserPasswordField


class AppUserCreate(msgspec.Struct):
    email: str
    password: UserPasswordField
    display_name: str


class AppUserUpdate(msgspec.Struct, omit_defaults=True):
    password: UserPasswordField | None = None
```

That alias keeps schema metadata aligned with the built-in `UserCreate` and `UserUpdate` structs. Runtime validation still flows through `require_password_length` when the plugin uses its default `password_validator_factory`, so schema metadata does not replace the manager-side password validator.

## Dependency keys (constants)

Used by the plugin internally; override only if you integrate custom controllers:

- `litestar_auth_config`, `litestar_auth_user_manager`, `litestar_auth_backends`, `litestar_auth_user_model` (see `litestar_auth._plugin.config`).

## Shared helpers — `litestar_auth.config`

`validate_secret_length`, `is_testing`, `MINIMUM_SECRET_LENGTH`, etc., keep token and testing behavior consistent.

## Related

- [HTTP API](http_api.md) — routes controlled by the flags above.
- [Security](security.md) — production interpretation of sensitive flags.
- [Plugin API](api/plugin.md) — mkdocstrings for `LitestarAuth`, configs, and `litestar_auth.config`.
