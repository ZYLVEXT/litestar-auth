# Configuration

The plugin is driven by **`LitestarAuthConfig`** (import from `litestar_auth` or `litestar_auth.plugin`). This page lists **all** fields grouped by concern. Generated detail lives in the [Plugin API](api/plugin.md) (mkdocstrings).

ORM models and the SQLAlchemy adapter are imported from their own modules — the root package does not re-export them:

```python
from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.models import User  # or your own model
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
```

## Canonical opaque DB-token preset

Use `DatabaseTokenAuthConfig` plus `LitestarAuthConfig(..., database_token_auth=...)` for the common bearer + database-token flow. This is the documented entrypoint for opaque DB tokens; it builds the `AuthenticationBackend`, `BearerTransport`, and `DatabaseTokenStrategy` for you.

```python
from uuid import UUID

from litestar import Litestar

from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User

config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret="replace-with-32+-char-db-token-secret",
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
)
app = Litestar(plugins=[LitestarAuth(config)])
```

Here, `session_maker` means a callable session factory the plugin can invoke as `session_maker()` to obtain the request-local `AsyncSession`. `async_sessionmaker(...)` is the most common implementation, but any factory with that runtime contract is supported.

If you previously hand-assembled `AuthenticationBackend(..., transport=BearerTransport(), strategy=DatabaseTokenStrategy(...))`, migrate that setup to the direct `database_token_auth=DatabaseTokenAuthConfig(...)` form above. Keep manual `backends=` assembly only when you need multiple backends, custom token models, or another non-canonical transport/strategy mix.

When you use `database_token_auth=...`, `config.backends` stays empty by design. `config.resolve_startup_backends()` now returns startup-only `StartupBackendTemplate` values for plugin assembly and validation, while `config.resolve_request_backends(session)` returns request-scoped runtime `AuthenticationBackend` instances bound to the active `AsyncSession`. `config.resolve_backends()` remains limited to the explicit manual `backends=` surface.

### Backend lifecycle contract

Treat the three backend helpers as distinct surfaces:

- `config.resolve_backends()` returns only the explicit manual `backends=` inventory. It rejects the canonical `database_token_auth=...` preset so callers do not accidentally treat the preset as a ready-to-run runtime backend.
- `config.resolve_startup_backends()` is the plugin's startup inventory. Manual backends are wrapped as `StartupBackendTemplate` values, and the canonical DB-token preset also contributes a `StartupBackendTemplate` that is valid for plugin assembly, validation, and route selection only.
- `config.resolve_request_backends(session)` realizes request-scoped `AuthenticationBackend` instances aligned with `config.resolve_startup_backends()` order. Use this surface whenever runtime login, refresh, logout, token validation, or other request-time work needs the active `AsyncSession`.
- Startup-only DB-token templates fail closed if they are used for runtime database-token work before `resolve_request_backends(session)` supplies a request session.

Controller selection follows that startup inventory:

- The primary backend mounts at `{auth_path}`.
- Additional backends mount at `{auth_path}/{backend.name}` in configured order.
- Plugin-owned OAuth login routes use the primary startup backend.
- TOTP uses the primary startup backend unless `TotpConfig.totp_backend_name` selects another named backend from the same startup inventory.

## Custom SQLAlchemy `User` and token models

`LitestarAuthConfig.user_model` must satisfy **`UserProtocol`** (see [Types](types.md)): at minimum the fields and behaviors your chosen `BaseUserManager` and strategies use (`id`, `email`, `hashed_password`, `is_active`, `is_verified`, `is_superuser`, `totp_secret` as applicable). When your app wants the library's flat role-membership contract, expose `roles: Sequence[str]` and satisfy **`RoleCapableUserProtocol`** instead of inferring role support from arbitrary attributes. The bundled `User` already provides that `roles` collection, and custom SQLAlchemy model families can add it with `UserRoleRelationshipMixin`.

The built-in `UserRead` / `UserUpdate` schemas now also assume that same `roles` attribute. Apps
that keep the default register/verify/reset/users controllers should either expose
`roles: Sequence[str]` on the user model or provide custom `user_read_schema` / `user_update_schema`
types that intentionally omit role fields. Plugin validation fails fast when an enabled built-in
route surface still uses a schema with `roles` against a `user_model` that does not expose that
attribute.

This section is the canonical ORM integration guide for bundled token bootstrap, mixin-composed
custom model families, relational role composition, `SQLAlchemyUserDatabase`, and the supported
password-column hook.

| Need | Canonical path | Notes |
| ---- | -------------- | ----- |
| Bundled token metadata bootstrap | `from litestar_auth.models import import_token_orm_models` | Explicit helper for metadata registration and Alembic-style autogenerate. |
| Bundled token runtime bootstrap | `DatabaseTokenAuthConfig` / `LitestarAuthConfig(..., database_token_auth=...)` | `LitestarAuth.on_app_init()` calls the same helper lazily when bundled DB-token models are active. |
| App-owned ORM classes | `UserModelMixin`, `UserAuthRelationshipMixin`, `UserRoleRelationshipMixin`, `RoleMixin`, `UserRoleAssociationMixin`, `AccessTokenMixin`, `RefreshTokenMixin`, `OAuthAccountMixin` | Compose them on the application's own registry instead of copying mapper wiring. |
| App-owned relational role tables | `UserRoleRelationshipMixin`, `RoleMixin`, `UserRoleAssociationMixin` | Optional role persistence path that keeps `user.roles` as the normalized flat contract. |
| Custom token strategy tables | `DatabaseTokenModels(...)` | Only needed when `DatabaseTokenStrategy` should use custom token models at runtime. |
| SQLAlchemy user store | `litestar_auth.db.sqlalchemy.SQLAlchemyUserDatabase` | `user_model` is required; `oauth_account_model` is optional unless OAuth methods are used. |
| Legacy password column name | `UserModelMixin.auth_hashed_password_column_name` | Keeps the runtime attribute contract on `user.hashed_password`. |

### Plugin role CLI

`LitestarAuth.on_cli_init()` also registers a plugin-owned `litestar roles` command group when the
active app configuration satisfies all role-admin prerequisites:

- The app is using `LitestarAuth(config)` rather than only manual controllers.
- `LitestarAuthConfig.session_maker` is configured so the CLI can open SQLAlchemy sessions.
- `LitestarAuthConfig.user_model` is a relational role-capable SQLAlchemy model family: the
  bundled `User`, a custom `UserRoleRelationshipMixin` + `RoleMixin` /
  `UserRoleAssociationMixin` family, or an equivalent mapped relationship contract.

If any prerequisite is missing, the CLI fails closed with a clear operator-facing error instead of
guessing how to mutate role state.

- `litestar roles list` prints the normalized role catalog in deterministic sorted order.
- `litestar roles create <role>` normalizes the requested name with the same trim/lowercase rules
  as `user.roles` and is idempotent when that normalized catalog row already exists.
- `litestar roles delete <role>` fails closed while dependent user-role assignments still exist.
  Pass `--force` only when you intentionally want to remove both the catalog row and those
  dependent assignment rows.
- `litestar roles assign --email user@example.com <role>...` adds normalized roles to one user and
  preserves the flat `user.roles` boundary.
- `litestar roles unassign --email user@example.com <role>...` removes only the requested
  normalized roles and is idempotent when some of them are already absent.
- `litestar roles show-user --email user@example.com` prints the target user's current normalized
  membership.

The CLI resolves the active role model family from `LitestarAuthConfig.user_model`, so the same
commands work with the bundled `Role` / `UserRole` tables and with custom
`RoleMixin` / `UserRoleAssociationMixin` table names. See
[Role management CLI](guides/roles_cli.md) for end-to-end command examples, destructive-delete
semantics, and custom-model compatibility limits.

### Bundled `AccessToken` / `RefreshToken` lifecycle

`litestar_auth.models.import_token_orm_models()` is the canonical explicit mapper-registration entrypoint for the library token models:

```python
from litestar_auth.models import import_token_orm_models

AccessToken, RefreshToken = import_token_orm_models()
```

Call that helper yourself during metadata registration or Alembic-style autogenerate so token discovery stays with the models boundary. For plugin-managed runtime, `LitestarAuth.on_app_init()` now calls the same helper lazily when the active DB-token strategy still uses the bundled `AccessToken` / `RefreshToken` classes, so apps no longer need a separate import side effect only to make the plugin work. Keep the explicit helper for metadata/Alembic flows or any non-plugin code path that needs the tables.

Existing code can keep the strategy-layer import temporarily:

```python
from litestar_auth.authentication.strategy import (
    import_token_orm_models as import_token_orm_models_compat,
)
```

Treat that path as compatibility-only. New code should import from `litestar_auth.models`.

If you use the library `AccessToken` and `RefreshToken` models, your user class should declare relationships compatible with them instead of copying mapper wiring from the reference `User` class:

- Table names: `access_token`, `refresh_token`; `user_id` foreign keys target **`user.id`** (your user model’s table must be named `user`, or you must align FKs and relationships with your schema).
- Compose the side-effect-free model mixins from `litestar_auth.models` when you want the bundled field and relationship contract without copying boilerplate from the reference ORM classes:

```python
from advanced_alchemy.base import UUIDBase

from litestar_auth.models import UserAuthRelationshipMixin, UserModelMixin


class User(UserModelMixin, UserAuthRelationshipMixin, UUIDBase):
    __tablename__ = "user"
```

`UserModelMixin` provides the bundled email / password / account-state columns, while `UserAuthRelationshipMixin` provides the `access_tokens`, `refresh_tokens`, and `oauth_accounts` relationships with the same `back_populates="user"` wiring the bundled models expect. Leave its relationship-option hooks unset to keep the default contract: SQLAlchemy's normal loader behavior plus inferred foreign-key linkage for `oauth_accounts`. Set any `auth_*_model` hook to `None` when a custom user only composes part of the auth model family instead of all three relationships.

### Optional relational role contract

`UserModelMixin` no longer stores roles on the user row. When your app wants the library-managed
role contract, compose `UserRoleRelationshipMixin` on the user class and add the sibling role
tables with `RoleMixin` and `UserRoleAssociationMixin`. That keeps the public
`user.roles -> list[str]` surface while persisting membership through dedicated relational rows.

```python
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy.orm import DeclarativeBase

from litestar_auth.models import (
    RoleMixin,
    UserModelMixin,
    UserRoleAssociationMixin,
    UserRoleRelationshipMixin,
)


class RolesBase(DeclarativeBase):
    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class RolesUUIDBase(UUIDPrimaryKey, RolesBase):
    __abstract__ = True


class MyUser(UserModelMixin, UserRoleRelationshipMixin, RolesUUIDBase):
    __tablename__ = "my_user"

    auth_user_role_model = "MyUserRole"


class MyRole(RoleMixin, RolesBase):
    __tablename__ = "my_role"

    auth_user_role_model = "MyUserRole"


class MyUserRole(UserRoleAssociationMixin, RolesBase):
    __tablename__ = "my_user_role"

    auth_user_model = "MyUser"
    auth_user_table = "my_user"
    auth_role_model = "MyRole"
    auth_role_table = "my_role"
```

That custom model family persists one normalized global role row per name plus one association row
per `(user, role)` pair. Managers, schemas, and guards still consume the flat normalized
`roles: list[str]` user contract.

Migration note: existing deployments that previously used the bundled `user.roles` JSON column (or
an app-owned copy of that column) should create the new `role` and `user_role` tables, normalize
and deduplicate existing role arrays, backfill association rows, and then remove or ignore the
legacy JSON column once application code points at the relational model family. Custom user models
that want role-capable typing and the built-in role-aware surfaces should compose the mixins above
or provide an equivalent normalized flat `roles` contract.

Recommended upgrade sequence:

1. Create the new `role` and `user_role` tables, or the equivalent custom tables built from
   `RoleMixin` and `UserRoleAssociationMixin`.
2. Read every legacy JSON roles array, trim/lowercase/deduplicate/sort the values with the same
   normalization semantics the manager uses, and upsert one `role` row per normalized name.
3. Backfill one association row per `(user_id, role_name)` pair.
4. Switch application imports and mappings to the bundled `Role` / `UserRole` models or the custom
   mixin-composed role family.
5. Drop or ignore the legacy JSON column after the application is fully reading from relational
   membership.

This redesign changes persistence only. Guards, DTOs, and manager APIs still exchange the same flat
normalized `user.roles` values, and the library still does not add permission matrices, policy
DSLs, or role-management HTTP endpoints. Operator-driven catalog and user-role administration now
lives on the plugin-owned [`litestar roles`](guides/roles_cli.md) CLI surface.

If the user table is not `user`, or if you want app-owned token / OAuth tables, compose the sibling mixins on your own declarative base and point the hooks at the app's class names and table names instead of copying relationship code:

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

`DatabaseTokenAuthConfig` / `LitestarAuthConfig(..., database_token_auth=...)` remains the canonical shortcut for the bundled `AccessToken` / `RefreshToken` tables. The plugin bootstraps those bundled token mappers at `on_app_init()` for runtime use, but that does not replace the explicit helper for metadata bootstrap or Alembic autogenerate. Use the manual backend assembly above only when you intentionally replace the token ORM classes or need another non-canonical transport/strategy combination.

### `SQLAlchemyUserDatabase` contract

`LitestarAuthConfig.user_db_factory` defaults to a lazy `SQLAlchemyUserDatabase(session, user_model=config.user_model)` factory. Override it only when you need custom adapter wiring, usually to supply `oauth_account_model`:

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase


def user_db_factory(session):
    return SQLAlchemyUserDatabase(
        session,
        user_model=MyUser,
        oauth_account_model=MyOAuthAccount,
    )
```

`SQLAlchemyUserDatabase` requires **`user_model`** and accepts optional **`oauth_account_model`**. If you use OAuth methods (`get_by_oauth_account`, `upsert_oauth_account`) without providing `oauth_account_model`, a `TypeError` is raised.

`BaseUserStore` and `BaseOAuthAccountStore` are runtime-checkable `Protocol` contracts. Custom stores do not need to inherit from either symbol as long as they implement the documented async methods; explicit inheritance remains optional when you want to declare that compatibility on the class itself.

When `oauth_account_model` is provided, the adapter validates that its declared user contract matches `user_model`:

- Same declarative registry
- Matching `auth_user_model` / `auth_user_table` values when those hooks exist

Supported `oauth_account_model` choices are:

- The bundled `OAuthAccount` from `litestar_auth.models.oauth` only when the user side is still the same-registry `User` mapped to the `user` table
- An app-owned `OAuthAccountMixin` subclass whose `auth_user_model` / `auth_user_table` settings match the custom user class

If the custom user also needs a non-default loader strategy for `oauth_accounts`, set `auth_oauth_account_relationship_lazy` and, only when SQLAlchemy needs an explicit hint, `auth_oauth_account_relationship_foreign_keys`.

Migration note: older setups that paired `litestar_auth.models.oauth.OAuthAccount` with a renamed user class, a non-`user` table, or a different declarative registry should switch to an `OAuthAccountMixin` subclass before upgrading. See [Custom user + OAuth](cookbook/custom_user_oauth.md).

### Legacy password column names

If your schema stores password hashes under a legacy SQL column name, keep the runtime `hashed_password` attribute and set the supported `auth_hashed_password_column_name` hook on the custom user model:

```python
class LegacyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):
    __tablename__ = "legacy_user"

    auth_hashed_password_column_name = "password_hash"
```

`BaseUserManager`, `SQLAlchemyUserDatabase`, and JWT fingerprinting still interact with `user.hashed_password`; only the SQL column name changes. Older models that already redefine `hashed_password = mapped_column(...)` remain source-compatible, but the hook above is the supported path going forward.

## Required (at runtime)

| Field | Role |
| ----- | ---- |
| `backends` | Explicit non-preset authentication backends. Leave empty when using `database_token_auth`. |
| `user_model` | User ORM type (e.g. subclass of `litestar_auth.models.User`). |
| `user_manager_class` | Concrete subclass of `BaseUserManager`. |
| `session_maker` | Callable request-session factory for scoped DB access (`session_maker() -> AsyncSession`). `async_sessionmaker(...)` is the common implementation. |

On the `LitestarAuthConfig` dataclass, `session_maker` is typed as optional for advanced construction flows, but **`LitestarAuth` raises if it is missing** when the plugin is instantiated. Treat a compatible session factory as required for normal apps.

## Core wiring

| Field | Default | Role |
| ----- | ------- | ---- |
| `user_db_factory` | `None` → built from `user_model` | `Callable[[AsyncSession], BaseUserStore]`. When `None`, the plugin builds a default factory using `config.user_model`. Override for custom persistence. |
| `user_manager_security` | `None` | Canonical typed contract for verification/reset secrets, optional TOTP encryption, and optional `id_parser`. |
| `user_manager_kwargs` | `{}` | Additional manager constructor kwargs for non-security dependencies such as `password_helper`. The default plugin builder no longer reads manager secrets or `id_parser` from this mapping; use `user_manager_factory` when a custom builder must own that wiring instead. |
| `password_validator_factory` | `None` | Build custom password policy; otherwise the default builder injects the shared minimum-length validator. |
| `user_manager_factory` | `None` | Full control over request-scoped manager construction (`UserManagerFactory`). When set, the factory owns any non-canonical constructor wiring, including password-validator injection and manager-specific secret handling. |
| `rate_limit_config` | `None` | `AuthRateLimitConfig` for auth endpoint throttling. For the common one-client Redis recipe, build it through `litestar_auth.contrib.redis.RedisAuthPreset`; keep `AuthRateLimitConfig.from_shared_backend()` for lower-level shared-backend wiring. |

### User manager customization (quick decision)

These three fields overlap; pick **one** primary path. This matches the `LitestarAuthConfig` class docstring.

| Situation | Primary field | Notes |
| --- | --- | --- |
| Subclass `BaseUserManager` and accept the default plugin builder’s keyword-only constructor surface | `user_manager_class` | Most apps. Put verification/reset/TOTP secrets and `id_parser` in `user_manager_security`, not in `user_manager_kwargs`. |
| Non-canonical `__init__`, extra dependencies, or you must own all construction (including secrets/validators) | `user_manager_factory` | Receives `session`, `user_db`, `config`, and request-scoped `backends`. Inject `password_validator` and helpers inside the factory if you need them. |
| Small tweaks to the default builder (e.g. `password_helper`, legacy `password_validator`) without replacing construction | `user_manager_kwargs` | Only with `user_manager_class` and the default builder. Never put secrets or `id_parser` here. |

## Plugin customization hooks

| Field | Default | Role |
| ----- | ------- | ---- |
| `exception_response_hook` | `None` | Replaces the plugin-owned default auth `ClientException` formatter. The hook receives a `LitestarAuthError` plus `Request` and returns the `Response` to send. |
| `middleware_hook` | `None` | Receives the constructed auth `DefineMiddleware` after the plugin has derived auth-cookie names and CSRF settings; return the middleware definition to insert into `app_config.middleware`. |
| `controller_hook` | `None` | Receives the built controller list before registration; return the controller list that should be added to `app_config.route_handlers`. |

Compatibility and migration:

- All three hooks are opt-in and default to `None`, so existing plugin behavior stays unchanged.
- `exception_response_hook` replaces the plugin's default auth-error adapter for plugin-owned routes only. Route-local request-body validation/decode handlers keep their current payload contract unless you mount custom controllers.
- `middleware_hook` wraps the already-built auth middleware; it should not rebuild CSRF configuration manually.
- `controller_hook` can intentionally remove plugin routes. Filtering the list also removes the corresponding exception-handler wiring for those controllers.

## Canonical manager password surface

For plugin-managed apps, keep the manager/password surface on one path:

1. Configure verification/reset/TOTP secrets and optional `id_parser` through `user_manager_security`.
2. Use `password_validator_factory` when the plugin should own runtime password policy.
3. Call `config.resolve_password_helper()` only when app-owned code outside `BaseUserManager` also hashes or verifies passwords.
4. Reuse `litestar_auth.schemas.UserEmailField` and `litestar_auth.schemas.UserPasswordField` in app-owned `msgspec.Struct` registration/update schemas.

For non-standard manager construction, keep the plugin-owned security surface on `user_manager_security` and switch to `user_manager_factory` instead of smuggling manager secrets or `id_parser` through `user_manager_kwargs`. The factory receives `session`, `user_db`, `config`, and request-bound `backends`; it must opt into any custom `password_helper`, `password_validator`, or legacy secret wiring itself.

One integrated example:

```python
from collections.abc import Callable
from functools import partial
from uuid import UUID

import msgspec

from litestar_auth import LitestarAuthConfig, require_password_length
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.schemas import UserEmailField, UserPasswordField


class AppUserCreate(msgspec.Struct):
    email: UserEmailField
    password: UserPasswordField
    display_name: str


def password_policy(_config: LitestarAuthConfig[User, UUID]) -> Callable[[str], None]:
    return partial(require_password_length, minimum_length=16)


config = LitestarAuthConfig[User, UUID](
    ...,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
    ),
    password_validator_factory=password_policy,
    user_create_schema=AppUserCreate,
)
# Optional: share the same helper with app-owned password flows.
password_helper = config.resolve_password_helper()
```

Use the returned `password_helper` for CLI tasks, data migrations, or domain services that should share the same
hashing policy as the plugin-managed manager. If your app never hashes passwords outside `BaseUserManager`, you can
skip `config.resolve_password_helper()`.

The detailed contracts for each surface are:

| Surface | Current contract | Notes |
| ------- | ---------------- | ----- |
| `user_manager_security.verification_token_secret` | Signs email-verification tokens. | Required in production unless the owning manager/config explicitly sets `unsafe_testing=True`. |
| `user_manager_security.reset_password_token_secret` | Signs reset-password tokens and password fingerprints. | Required in production unless the owning manager/config explicitly sets `unsafe_testing=True`. |
| `user_manager_security.totp_secret_key` | Encrypts persisted TOTP secrets at rest. | Required in production when `totp_config` is enabled. |
| `totp_config.totp_pending_secret` | Signs pending/enrollment TOTP JWTs. | Required when `totp_config` is enabled; configured on `TotpConfig`, not `UserManagerSecurity`. |
| `user_manager_security.id_parser` | Supplies the manager/controller JWT subject parser once. | When set, `LitestarAuthConfig.id_parser` defaults to the same callable. Do not configure both with different values. |
| `user_manager_kwargs["password_helper"]` | Injects the `PasswordHelper` instance used by `BaseUserManager`. | Prefer `config.resolve_password_helper()` to memoize the default helper, or set this key explicitly when you intentionally use a custom pwdlib policy. |
| `password_validator_factory` | Builds the runtime password validator for plugin-managed managers. | When omitted, the default plugin builder injects the default `require_password_length` validator. |
| `user_manager_kwargs["password_validator"]` | Legacy direct runtime validator override. | Mutually exclusive with `password_validator_factory`; keep it only for compatibility. |
| `litestar_auth.schemas.UserEmailField` | Shares the built-in email regex and max-length metadata with app-owned `msgspec.Struct` schemas. | Schema metadata only; it does not add manager-side normalization or custom app policy. |
| `litestar_auth.schemas.UserPasswordField` | Shares built-in password-length metadata with app-owned `msgspec.Struct` schemas. | Schema metadata only; it does not replace the runtime validator. |

The default plugin builder now treats `user_manager_security` as an end-to-end constructor contract. When that
typed bundle is present, the plugin always passes `security=UserManagerSecurity(...)`, folds the effective
`id_parser` into that bundle first, and does not also send `verification_token_secret` /
`reset_password_token_secret` / `totp_secret_key` / `id_parser` kwargs in the same call. Managers that do not
follow the canonical `BaseUserManager` constructor surface must be built through `user_manager_factory`.

The supported production posture is one distinct high-entropy value per secret role. Outside
explicit `unsafe_testing`, `LitestarAuth(config)` validation is the authoritative warning owner for the
config-managed secret surface: it warns once when one configured value is reused across
verification, reset-password, and TOTP roles, including `totp_config.totp_pending_secret` when
that controller flow is enabled. Request-scoped `BaseUserManager` construction receives the same
validated baseline and suppresses the duplicate warning when the effective
`verification_token_secret` / `reset_password_token_secret` / `totp_secret_key` values match the
config-owned surface. If a custom `user_manager_factory` diverges from that validated secret
surface, the manager constructor surfaces an additional warning for the manager-owned roles it
actually wires. Direct `BaseUserManager(..., security=UserManagerSecurity(...))` construction still
applies the same warning for the manager-owned secret roles supplied on that bundle
(`verification_token_secret`, `reset_password_token_secret`, and `totp_secret_key`). A future major
release may reject reused secret material.

| Setting | Token audience or flow | Supported production posture |
| ------- | ---------------------- | ---------------------------- |
| `user_manager_security.verification_token_secret` | `litestar-auth:verify` | Dedicated secret used only for email-verification JWTs. |
| `user_manager_security.reset_password_token_secret` | `litestar-auth:reset-password` | Dedicated secret used only for reset-password JWTs and password fingerprints. |
| `totp_config.totp_pending_secret` | `litestar-auth:2fa-pending`, `litestar-auth:2fa-enroll` | Dedicated secret used only for pending/enrollment TOTP JWTs. |
| `user_manager_security.totp_secret_key` | Stored TOTP secret encryption at rest; no JWT audience | Dedicated Fernet key kept separate from all JWT signing secrets. |

Distinct audiences already prevent token cross-use between verification, reset-password, and TOTP
JWTs. Separate secrets still matter because they reduce blast radius if one secret leaks and avoid
coupling unrelated rotation events.

Compatibility and migration:

- Configure plugin-managed `verification_token_secret`, `reset_password_token_secret`, `totp_secret_key`, and
  `id_parser` through `user_manager_security`. The default plugin builder now rejects those keys in
  `user_manager_kwargs` instead of treating them as a second config-owned security surface.
- If you intentionally need factory-owned security wiring, set `user_manager_factory` and read whatever extra
  kwargs your factory owns from `user_manager_kwargs` there.
- The default plugin builder calls the canonical `BaseUserManager`-style constructor surface:
  `user_manager_class(user_db, *, password_helper=..., security=..., password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)`.
  It always passes `security=UserManagerSecurity(...)`. When `user_manager_security` is unset, the effective parser
  from `LitestarAuthConfig.id_parser` is folded into that bundle (not as a standalone `id_parser=` kwarg on the
  builder call). If your manager narrows or renames that surface, configure `user_manager_factory`.
- When `user_manager_security` is present, the effective manager parser comes from
  `user_manager_security.id_parser` first and otherwise falls back to `LitestarAuthConfig.id_parser`. When
  `user_manager_security` is absent, the default builder still materializes `security=UserManagerSecurity(...)`
  with that resolved parser folded in (see `ManagerConstructorInputs` in the library for how unset secret fields
  are resolved alongside `id_parser`).
- Existing `UserPasswordField` imports remain valid. Add `UserEmailField` only when you also want the built-in
  email regex/max-length contract on app-owned schemas.
- Existing `PasswordHelper()` and `PasswordHelper(password_hash=...)` call sites remain source-compatible. Prefer
  `PasswordHelper.from_defaults()` when you mean "use the library default hasher policy" and reserve
  `PasswordHelper(password_hash=...)` for deliberate custom pwdlib composition.

If your application also hashes or verifies passwords outside `BaseUserManager`, call
`config.resolve_password_helper()` once after constructing `LitestarAuthConfig(...)`. When
`user_manager_kwargs["password_helper"]` already points at an explicit helper override,
`config.resolve_password_helper()` returns that object unchanged. Otherwise it memoizes
`PasswordHelper.from_defaults()` on the config and the plugin will inject the same helper into
each request-scoped manager, so the plugin and app-owned code share the same Argon2-primary helper
with bcrypt fallback. The user-provided `user_manager_kwargs` mapping is left untouched. This
helper path does not inherit anything from `password_validator_factory`, `user_manager_security`,
or token settings; it only resolves the password-hash policy itself.

If app-owned code never hashes or verifies passwords directly, you can skip calling
`config.resolve_password_helper()`: the default plugin builder still materializes and injects the
shared helper for each request-scoped manager on demand.

Use `password_validator_factory` when the plugin should own runtime password-policy construction.
If you do not provide it, the default plugin builder injects the default `require_password_length` validator. Keep `user_manager_kwargs["password_validator"]` only
for legacy direct overrides, and do not mix it with `password_validator_factory`. When `user_manager_factory` is set, the plugin still validates this configuration surface but does not inject a resolved validator into your factory automatically; the factory must build and pass whatever validator policy it wants to own.

Plugin-managed account-state checks also rely on one stable callable surface resolved from
`user_manager_class`: `require_account_state(user, *, require_verified=False)`.
`BaseUserManager` supplies the default behavior, and custom manager classes or adapters should
preserve the same user argument plus keyword-only verification flag when they customize that
policy.

For app-owned `user_create_schema` / `user_update_schema` structs, import `UserEmailField` and
`UserPasswordField` from `litestar_auth.schemas` instead of copying the built-in email regex or raw
`12` / `128` bounds. If you already import `UserPasswordField`, keep it and replace `email: str`
with `UserEmailField` when you also want the built-in email contract. Those aliases keep schema
metadata aligned with the built-in `UserCreate` and `UserUpdate` structs; runtime password
validation still happens in the manager through `password_validator_factory` or the manager's
default validator.

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

## Canonical Redis-backed auth surface

This section is the canonical Redis integration guide for the currently implemented auth surface.
Use it for the shared-backend rate-limit contract, migration of existing Redis key shapes, TOTP
replay protection, pending-login-token JTI deduplication, and the stable split between
`litestar_auth.ratelimit` and `litestar_auth.contrib.redis`.

### Shared-backend rate limiting

For the usual Redis deployment where one async Redis client should back auth rate limiting, TOTP
replay protection, and pending-login-token JTI deduplication, start with
`litestar_auth.contrib.redis.RedisAuthPreset` plus the verification-slot helper from
`litestar_auth.ratelimit`:

For strict typing, annotate the shared client with
`litestar_auth.contrib.redis.RedisAuthClientProtocol`. The canonical one-client recipe assumes a
`redis.asyncio.Redis`-compatible runtime client. The shared protocol covers the combined operations
used by the preset's rate-limiter, used-code replay, and pending-token denylist helpers:
`eval(...)`, `delete(...)`, `set(name, value, nx=True, px=ttl_ms)`, `get(...)`, and `setex(...)`.

```python
from litestar_auth import TotpConfig
from litestar_auth.contrib.redis import (
    RedisAuthClientProtocol,
    RedisAuthPreset,
    RedisAuthRateLimitTier,
)
from litestar_auth.ratelimit import AUTH_RATE_LIMIT_VERIFICATION_SLOTS

redis_client: RedisAuthClientProtocol
redis_auth = RedisAuthPreset(
    redis=redis_client,
    rate_limit_tier=RedisAuthRateLimitTier(max_attempts=5, window_seconds=60),
    group_rate_limit_tiers={
        "refresh": RedisAuthRateLimitTier(max_attempts=10, window_seconds=300),
        "totp": RedisAuthRateLimitTier(max_attempts=5, window_seconds=300),
    },
)
rate_limit_config = redis_auth.build_rate_limit_config(
    disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    namespace_style="snake_case",
)
totp_config = TotpConfig(
    totp_pending_secret="replace-with-32+-char-secret",
    totp_pending_jti_store=redis_auth.build_totp_pending_jti_store(),
    totp_used_tokens_store=redis_auth.build_totp_used_tokens_store(),
)
```

`RedisAuthPreset` is the preferred one-client Redis path. Keep the module split explicit:

- `litestar_auth.contrib.redis` owns the higher-level convenience entrypoints such as `RedisAuthPreset`,
  `RedisAuthRateLimitTier`, `RedisAuthClientProtocol`, `RedisTokenStrategy`, and `RedisUsedTotpCodeStore`.
- `litestar_auth.ratelimit` owns the lower-level shared-builder surface such as
  `AuthRateLimitConfig.from_shared_backend()`, `RedisRateLimiter`, the typed slot/group aliases, and
  the slot-set helpers.

`RedisAuthPreset.build_rate_limit_config()` forwards the current shared-builder inputs such as
`enabled`, `disabled`, `group_backends`, `scope_overrides`, `namespace_style`,
`namespace_overrides`, and `endpoint_overrides`. Explicit `group_backends` still win over any
preset `group_rate_limit_tiers`. `RedisAuthPreset.group_rate_limit_tiers` is snapshotted into a
read-only mapping at construction time, so later mutations to the caller's source `dict` do not
silently change the preset's runtime budget layout.
`build_totp_used_tokens_store()` and `build_totp_pending_jti_store()` follow the same precedence:
per-call `key_prefix=` wins over the preset default, and `None` preserves each low-level store's
current built-in prefix.

The shared builder itself exposes typed public identifiers and slot-set helpers from
`litestar_auth.ratelimit`:

```python
from litestar_auth.ratelimit import (
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS,
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP,
    AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    AuthRateLimitEndpointGroup,
    AuthRateLimitEndpointSlot,
    AuthRateLimitNamespaceStyle,
)
```

- `AUTH_RATE_LIMIT_ENDPOINT_SLOTS` exposes the ordered supported slot inventory for explicit
  `enabled=...` calls.
- `AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP` exposes read-only group-to-slot frozensets keyed by
  `AuthRateLimitEndpointGroup`.
- `AUTH_RATE_LIMIT_VERIFICATION_SLOTS` is the convenience alias for
  `AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"]`, which is useful for `disabled=...`
  when verification routes stay off.
- `AuthRateLimitEndpointSlot` names the per-endpoint keys accepted by `enabled`, `disabled`, `scope_overrides`, `namespace_overrides`, and `endpoint_overrides`.
- `AuthRateLimitEndpointGroup` names the shared-backend keys accepted by `group_backends`.
- `AuthRateLimitNamespaceStyle` names the supported namespace families accepted by `namespace_style`.

### Low-level Redis builder path

Keep direct `AuthRateLimitConfig.from_shared_backend()` plus direct `RedisRateLimiter(...)`,
`RedisUsedTotpCodeStore(...)`, and `RedisJWTDenylistStore(...)` construction as the low-level
escape hatch when you need separate backends, bespoke key prefixes, or fully manual wiring:

```python
from litestar_auth.ratelimit import (
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS,
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP,
    AuthRateLimitConfig,
    RedisRateLimiter,
)
from litestar_auth.totp import RedisUsedTotpCodeStore

shared_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60)
rate_limit_config = AuthRateLimitConfig.from_shared_backend(
    shared_backend,
    enabled=AUTH_RATE_LIMIT_ENDPOINT_SLOTS,
    disabled=AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"],
    namespace_style="snake_case",
)
totp_used_tokens_store = RedisUsedTotpCodeStore(redis=redis_client)
```

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
4. `namespace_style` chooses the supported namespace family for generated limiters.
5. `scope_overrides` and `namespace_overrides` adjust the generated limiter for that slot.

The supported namespace families are:

- `route` (default): route-oriented tokens such as `forgot-password`, `totp-confirm-enable`, and `request-verify-token`
- `snake_case`: slot-aligned tokens such as `forgot_password`, `totp_confirm_enable`, and `request_verify_token`

If you already depend on slot-style Redis keys, start with `namespace_style="snake_case"`. Keep
`namespace_overrides` only for bespoke key names, preserve non-default scopes with
`scope_overrides`, and use `AUTH_RATE_LIMIT_VERIFICATION_SLOTS` or
`AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"]` to leave unused verification slots
unset. Keep direct `EndpointRateLimit(...)` assembly only for advanced per-endpoint exceptions.

Migration example for an older Redis recipe: this keeps login, register, and password-reset style
routes on one backend, splits out refresh and TOTP budgets, preserves legacy underscore
namespaces, and leaves verification slots unset. The preset is just a higher-level wrapper around
the current shared-builder surface, so the same slot and override rules still apply.

```python
from litestar_auth.contrib.redis import RedisAuthPreset, RedisAuthRateLimitTier
from litestar_auth.ratelimit import AUTH_RATE_LIMIT_VERIFICATION_SLOTS

redis_auth = RedisAuthPreset(
    redis=redis_client,
    rate_limit_tier=RedisAuthRateLimitTier(max_attempts=5, window_seconds=60),
    group_rate_limit_tiers={
        "refresh": RedisAuthRateLimitTier(max_attempts=10, window_seconds=300),
        "totp": RedisAuthRateLimitTier(max_attempts=5, window_seconds=300),
    },
)

rate_limit_config = redis_auth.build_rate_limit_config(
    disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    namespace_style="snake_case",
)
```

Add `namespace_overrides` only when an existing deployment needs names that do not match either
supported family. Add `scope_overrides` only when an existing key shape also depends on a
non-default scope for a specific slot.

### Redis TOTP replay protection and pending-token deduplication

Use `RedisUsedTotpCodeStore` for `TotpConfig.totp_used_tokens_store` when TOTP codes must not be
reusable across workers or restarts, and use `RedisJWTDenylistStore` for
`TotpConfig.totp_pending_jti_store` when pending login tokens must not be replayed across workers
or restarts. `RedisAuthPreset.build_totp_used_tokens_store()` plus
`RedisAuthPreset.build_totp_pending_jti_store()` is the preferred one-client path when the same
Redis client also backs auth rate limiting. The direct low-level store implementations remain
available when you intentionally want bespoke wiring or separate Redis backends.

```python
from litestar_auth import RedisJWTDenylistStore, TotpConfig
from litestar_auth.contrib.redis import RedisUsedTotpCodeStore

totp_config = TotpConfig(
    totp_pending_secret="replace-with-32+-char-secret",
    totp_pending_jti_store=RedisJWTDenylistStore(redis=redis_client),
    totp_used_tokens_store=RedisUsedTotpCodeStore(redis=redis_client),
)
```

`totp_pending_secret` still signs pending-2FA JWTs for the controller flow; it does not replace
replay stores. Configure `TotpConfig.totp_pending_jti_store` for pending login-token JTI
deduplication and `TotpConfig.totp_used_tokens_store` for TOTP-code replay protection.

### Redis contrib import boundary

`litestar_auth.contrib.redis` is the public Redis convenience boundary. It exposes
`RedisAuthClientProtocol`, `RedisAuthPreset`, `RedisAuthRateLimitTier`, `RedisTokenStrategy`, and
`RedisUsedTotpCodeStore`.
The high-level one-client preset lives there, while the typed slot/group aliases and low-level
shared-backend builder surface remain on `litestar_auth.ratelimit`.

## TOTP — `totp_config: TotpConfig | None`

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `totp_pending_secret` | (required) | Secret for pending-2FA JWTs; must align with auth controller. |
| `totp_backend_name` | `None` | Which named `AuthenticationBackend` issues tokens after 2FA. |
| `totp_issuer` | `"litestar-auth"` | Issuer in otpauth URI. |
| `totp_algorithm` | `"SHA256"` | TOTP hash algorithm. |
| `totp_pending_jti_store` | `None` | JWT JTI denylist for pending login tokens. Required unless the owning config/controller explicitly sets `unsafe_testing=True`. Use a shared store such as `RedisJWTDenylistStore` for multi-worker deployments. |
| `totp_used_tokens_store` | `None` | Replay store for consumed TOTP codes (required unless the owning config/controller explicitly sets `unsafe_testing=True`). See [Canonical Redis-backed auth surface](#canonical-redis-backed-auth-surface) for the Redis setup and import paths. |
| `totp_require_replay_protection` | `True` | Fail startup without a store unless `unsafe_testing=True`. |
| `totp_enable_requires_password` | `True` | Step-up password for `/2fa/enable`. |

Routes: `{auth_path}/2fa/...`. See [TOTP guide](guides/totp.md).

`totp_pending_secret` signs pending-2FA JWTs for the controller flow. It is separate from
`user_manager_security.totp_secret_key`, which only encrypts the persisted TOTP secret stored on
the user record.

If `totp_backend_name` is omitted, the plugin uses the primary startup backend. Set a backend name
only when a secondary startup backend should issue post-2FA tokens.

!!! note "Pending-token JTI store"
    The plugin-owned controller forwards `TotpConfig.totp_pending_jti_store` into `create_totp_controller(..., pending_jti_store=...)`. In production, missing pending-token replay storage now fails closed unless `unsafe_testing=True`.

## OAuth — `oauth_config: OAuthConfig | None`

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `oauth_cookie_secure` | `True` | Secure flag for OAuth cookies. |
| `oauth_providers` | `None` | Single plugin-owned OAuth provider inventory. Prefer :class:`~litestar_auth.config.OAuthProviderConfig` entries; legacy ``(name, client)`` tuples are coerced at the route boundary. Each provider auto-mounts `GET {auth_path}/oauth/{provider}/authorize` and `GET {auth_path}/oauth/{provider}/callback`. |
| `oauth_provider_scopes` | `{}` | Optional server-owned OAuth scopes keyed by provider name. Each provider authorize route uses only these configured scopes; runtime query overrides are rejected. |
| `oauth_associate_by_email` | `False` | Policy for plugin-owned OAuth login routes. When enabled, login callbacks may associate an existing local user by email if provider email ownership is also trusted. |
| `oauth_trust_provider_email_verified` | `False` | Trust provider `email_verified` claims for plugin-owned OAuth login routes. Use only with providers that cryptographically assert email ownership. |
| `include_oauth_associate` | `False` | Also auto-mount authenticated associate routes for the same `oauth_providers` inventory under `GET {auth_path}/associate/{provider}/authorize` and `GET {auth_path}/associate/{provider}/callback`. |
| `oauth_redirect_base_url` | `""` | Required public HTTPS redirect base for plugin-owned OAuth callbacks. The plugin derives `{oauth_redirect_base_url}/oauth/{provider}/callback` and, when associate routes are enabled, `{oauth_redirect_base_url}/associate/{provider}/callback`. |
| `oauth_token_encryption_key` | `None` | **Required** for any declared provider inventory in production — encrypts OAuth tokens at rest. |

For manual custom controllers, `create_provider_oauth_controller(...)` / `create_oauth_controller(...)` still take **`trust_provider_email_verified`** and optional **`oauth_scopes`** directly (see [OAuth guide](guides/oauth.md)). Their `redirect_base_url` also now fails closed unless it uses a non-loopback `https://...` origin; unlike the plugin-owned route table, the manual factories do not have an `AppConfig(debug=True)` or `unsafe_testing=True` escape hatch. The plugin-owned route table maps `OAuthConfig.oauth_trust_provider_email_verified` and `OAuthConfig.oauth_provider_scopes` onto the same runtime behavior.

Preferred construction (import from ``litestar_auth`` or ``litestar_auth.config``):

```python
from litestar_auth import OAuthConfig, OAuthProviderConfig

OAuthConfig(
    oauth_providers=[
        OAuthProviderConfig(name="github", client=github_oauth_client),
    ],
    oauth_redirect_base_url="https://app.example.com",
    oauth_token_encryption_key="...",  # required when providers are set
)
```

Legacy ``("github", client)`` tuples remain accepted and are normalized internally.

Route-registration contract:

- `oauth_providers` is the single plugin-owned provider inventory; there is no separate associate-only provider list.
- `oauth_redirect_base_url` is required whenever `oauth_providers` is configured. The plugin appends `/oauth` and `/associate` per route family instead of guessing a localhost fallback.
- In production app init, plugin-owned OAuth routes now fail closed unless `oauth_redirect_base_url` uses a non-loopback `https://...` origin. Keep localhost or plain-HTTP redirect bases behind `AppConfig(debug=True)` or `unsafe_testing=True` only.
- Manual/custom OAuth controller factories use the same non-loopback `https://...` redirect-origin baseline, but they enforce it immediately at controller construction time with no debug/testing override.
- Both plugin-owned and manual OAuth redirect bases must remain clean callback bases without embedded userinfo, query strings, or fragments.
- Plugin-owned OAuth login routes always use the primary startup backend from `config.resolve_startup_backends()`. If you need provider-specific backend selection, build manual controllers instead of relying on the plugin-owned route table.
- `include_oauth_associate=True` extends that same provider inventory with authenticated account-linking routes. If you need a custom route table, custom prefixes, or manual manager wiring, mount the controller factories yourself instead of mixing plugin-owned and manual ownership.

## Security and token policy

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `csrf_secret` | `None` | Enables Litestar CSRF config when cookie transports are used. |
| `csrf_header_name` | `"X-CSRF-Token"` | Header Litestar expects for CSRF token. |
| `unsafe_testing` | `False` | Explicit per-config test-only escape hatch for generated fallback secrets, single-process validation shortcuts, and startup-warning suppression. Never enable it for production traffic. |
| `allow_legacy_plaintext_tokens` | `False` | **Migration only** — accept legacy plaintext DB tokens for manual `DatabaseTokenStrategy` setups. The canonical preset reads this from `DatabaseTokenAuthConfig.accept_legacy_plaintext_tokens` instead. |
| `allow_nondurable_jwt_revocation` | `False` | Opt in to the compatibility-grade `JWTStrategy.revocation_posture` reported by the default in-memory denylist. |
| `id_parser` | `None` | Parse path/query user ids (e.g. `UUID`). Defaults from `user_manager_security.id_parser` when that typed contract is configured. |

The plugin-managed JWT/TOTP downgrade surfaces use the same shared posture wording as runtime startup and validation:

--8<-- "docs/snippets/plugin_security_tradeoffs.md"

For direct/manual wiring, these flags only decide whether plugin-managed validation accepts a compatibility-grade branch; the underlying runtime objects still report that branch explicitly:

- `JWTStrategy(secret=...)` reports `revocation_posture.key == "compatibility_in_memory"` and `revocation_is_durable == False` until you pass a shared denylist store. The default `InMemoryJWTDenylistStore` fails closed when its `max_entries` cap is hit and no expired JTIs can be pruned: new revocations are skipped (logged) rather than dropping an active revocation entry. `JWTDenylistStore.deny` returns `False` in that case; `JWTStrategy.destroy_token` raises `TokenError`, and plugin HTTP logout surfaces **503** with `TOKEN_PROCESSING_FAILED`. The same capacity signal applies to TOTP pending-login JTI recording after a successful code check: verification responds with **503** instead of issuing a session when the pending-token denylist cannot store the spent JTI.
- Direct `BaseUserManager(..., security=UserManagerSecurity(...))` with `totp_secret_key` omitted or `None` reports `totp_secret_storage_posture.key == "compatibility_plaintext"`. Setting `user_manager_security.totp_secret_key` on `LitestarAuthConfig` (passed through to `UserManagerSecurity`) or supplying a non-`None` `totp_secret_key` on a direct `UserManagerSecurity(...)` bundle flips the posture to `fernet_encrypted`.

## Schemas and DI

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `user_read_schema` | `None` | msgspec struct for safe user responses returned by register/verify/reset/users flows. The built-in `UserRead` includes normalized `roles`. |
| `user_create_schema` | `None` | msgspec struct for registration/create request bodies; built-in registration defaults to `UserCreate`. |
| `user_update_schema` | `None` | msgspec struct for user PATCH bodies. The built-in `UserUpdate` accepts optional `roles`; `/users/me` still strips them while admin `PATCH /users/{id}` can persist them. |
| `db_session_dependency_key` | `"db_session"` | Litestar DI key for `AsyncSession`. Must be a valid non-keyword Python identifier because Litestar matches dependency keys to callable parameter names. |
| `db_session_dependency_provided_externally` | `False` | Skip plugin session provider when your app already registers the key. |

`user_*_schema` customizes registration and user CRUD surfaces. It does not rename the built-in auth lifecycle request structs: `LoginCredentials`, `RefreshTokenRequest`, `RequestVerifyToken`, `VerifyToken`, `ForgotPassword`, `ResetPassword`, or the TOTP payloads.

If you keep the built-in role-aware user surface, align custom read/update schemas with that
contract by adding `roles` to both types. If you intentionally omit `roles`, treat that as a
deliberate compatibility shim for role-less user models rather than the default library contract.

When app-owned `user_create_schema` or `user_update_schema` structs keep `email` or `password`
fields, import `UserEmailField` / `UserPasswordField` from `litestar_auth.schemas` instead of
copying the built-in email regex or local `msgspec.Meta(min_length=12, max_length=128)`
annotations. See
[Canonical manager password surface](#canonical-manager-password-surface) for the full contract:
those aliases keep schema metadata aligned, while runtime password validation still flows through
`password_validator_factory` or the manager's default validator.

## Dependency keys (constants)

Used by the plugin internally; override only if you integrate custom controllers:

- `litestar_auth_config`, `litestar_auth_user_manager`, `litestar_auth_backends`, `litestar_auth_user_model` (see `litestar_auth._plugin.config`).

## Shared helpers — `litestar_auth.config`

`validate_secret_length`, `_resolve_token_secret`, `MINIMUM_SECRET_LENGTH`, and the secret-role helpers keep token validation and explicit unsafe-testing behavior consistent.

## Related

- [HTTP API](http_api.md) — routes controlled by the flags above.
- [Security](security.md) — production interpretation of sensitive flags.
- [Plugin API](api/plugin.md) — mkdocstrings for `LitestarAuth`, configs, and `litestar_auth.config`.
