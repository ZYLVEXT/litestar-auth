# Manager Customization

Use this page for required runtime fields, request-scoped manager construction, plugin hooks, and the password-helper surface.

## Plugin role CLI

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
[Role management CLI](../guides/roles_cli.md) for end-to-end command examples, destructive-delete
semantics, and custom-model compatibility limits.

## Required (at runtime)

| Field | Role |
| ----- | ---- |
| `backends` | Explicit non-preset authentication backends. Leave empty when using `database_token_auth`. |
| `user_model` | User ORM type (e.g. subclass of `litestar_auth.models.User`). |
| `user_manager_class` | Concrete subclass of `BaseUserManager` for the default construction path. Set it directly on `LitestarAuthConfig(...)`. |
| `session_maker` | Callable request-session factory for scoped DB access (`session_maker() -> AsyncSession`). `async_sessionmaker(...)` is the common implementation. |

On the `LitestarAuthConfig` dataclass, `session_maker` is typed as optional for advanced construction flows, but **`LitestarAuth` raises if it is missing** when the plugin is instantiated. Treat a compatible session factory as required for normal apps.

## Core wiring

| Field | Default | Role |
| ----- | ------- | ---- |
| `user_db_factory` | `None` → built from `user_model` | `Callable[[AsyncSession], BaseUserStore]`. When `None`, the plugin builds a default factory using `config.user_model`. Override for custom persistence. |
| `user_manager_security` | `None` | Typed contract for verification/reset secrets, optional TOTP encryption, and optional `id_parser`. |
| `password_validator_factory` | `None` | Build custom password policy; otherwise the default builder injects the shared minimum-length validator. |
| `user_manager_factory` | `None` | Full control over request-scoped manager construction (`UserManagerFactory`). Set it directly on `LitestarAuthConfig(...)` when you need caller-owned manager wiring. When set, the factory owns any custom constructor wiring, including password-validator injection and manager-specific secret handling. |
| `rate_limit_config` | `None` | `AuthRateLimitConfig` for auth endpoint throttling. For the common one-client Redis recipe, build it through `litestar_auth.contrib.redis.RedisAuthPreset`; keep `AuthRateLimitConfig.from_shared_backend()` for lower-level shared-backend wiring. |
| `superuser_role_name` | `"superuser"` | Role name treated as superuser membership by plugin-managed managers and guards. Values are normalized with the same trim/lowercase rules as `user.roles` and must not be empty. |

### User manager customization

Choose one direct-construction path for new code:

| Situation | Configuration path | Notes |
| --- | --- | --- |
| Subclass `BaseUserManager` and accept the default plugin builder's keyword-only constructor surface | `LitestarAuthConfig(..., user_manager_class=...)` | Most apps. Put verification/reset/TOTP secrets, password-helper overrides, password-validator overrides, and `id_parser` in `user_manager_security`. |
| Custom `__init__`, extra dependencies, or caller-owned construction | `LitestarAuthConfig(..., user_manager_factory=...)` | Receives `session`, `user_db`, `config`, and request-scoped `backends`. The factory injects any custom dependencies, password policy, and manager-specific secret wiring it owns. |

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
- `superuser_role_name` is additive and defaults to `"superuser"`. Existing apps keep the same default behavior; set it only when your deployment uses another normalized role such as `"admin"`.

## Manager password surface

For plugin-managed apps, keep the manager/password surface on one path:

1. Configure verification/reset/TOTP secrets and optional `id_parser` through `user_manager_security`.
2. Use `password_validator_factory` when the plugin should own runtime password policy.
3. Call `config.resolve_password_helper()` only when app-owned code outside `BaseUserManager` also hashes or verifies passwords.
4. Reuse `litestar_auth.schemas.UserEmailField` and `litestar_auth.schemas.UserPasswordField` in app-owned `msgspec.Struct` registration/update schemas.

For non-standard manager construction, keep the plugin-owned security surface on
`user_manager_security` and set `user_manager_factory` on `LitestarAuthConfig(...)`. The factory
receives `session`, `user_db`, `config`, and request-bound `backends`; it must opt into any
custom `password_helper`, `password_validator`, or legacy secret wiring itself.

One integrated example:

```python
from collections.abc import Callable
from functools import partial
from uuid import UUID

import msgspec

from litestar_auth import LitestarAuthConfig
from litestar_auth.config import require_password_length
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.schemas import UserEmailField, UserPasswordField


class AppUserCreate(msgspec.Struct, forbid_unknown_fields=True):
    email: UserEmailField
    password: UserPasswordField
    display_name: str


def password_policy(_config: LitestarAuthConfig[User, UUID]) -> Callable[[str], None]:
    return partial(require_password_length, minimum_length=16)


config = LitestarAuthConfig[User, UUID](
    ...,
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
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

Set `user_manager_factory` only when the default builder cannot call your manager directly:

```python
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth import LitestarAuthConfig
from litestar_auth.db import BaseUserStore
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User


def build_user_manager(
    *,
    session: AsyncSession,
    user_db: BaseUserStore[User, UUID],
    config: LitestarAuthConfig[User, UUID],
    backends: tuple[object, ...] = (),
) -> UserManager:
    del session
    security = config.user_manager_security
    if security is None:
        msg = "UserManagerSecurity is required for this manager factory."
        raise RuntimeError(msg)
    return UserManager(
        user_db=user_db,
        audit_sink=audit_sink,
        password_helper=config.resolve_password_helper(),
        security=security,
        backends=backends,
    )


config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_factory=build_user_manager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret",
        reset_password_token_secret="replace-with-32+-char-secret",
        login_identifier_telemetry_secret="replace-with-32+-char-secret-for-login-telemetry",
    ),
)
```

The detailed contracts for each surface are:

| Surface | Current contract | Notes |
| ------- | ---------------- | ----- |
| `user_manager_security.verification_token_secret` | Signs email-verification tokens. | Required in production unless the owning manager/config explicitly sets `unsafe_testing=True`. |
| `user_manager_security.reset_password_token_secret` | Signs reset-password tokens and password fingerprints. | Required in production unless the owning manager/config explicitly sets `unsafe_testing=True`. |
| `user_manager_security.login_identifier_telemetry_secret` | Keys the non-reversible failed-login `identifier_digest` log field. | Optional. When omitted, failed-login logs do not include `identifier_digest`; when set, it must be high-entropy and distinct from other auth secrets. |
| `user_manager_security.totp_secret_keyring` | Versioned Fernet keyring for persisted TOTP secrets and pending-enrollment secret values at rest. | Required in production when `totp_config` is enabled; prefer `FernetKeyringConfig(active_key_id=..., keys=...)` for rotation. |
| `user_manager_security.totp_secret_key` | One-key TOTP Fernet shortcut encoded under the `default` key id. | Mutually exclusive with `totp_secret_keyring`; useful when a single active key is enough. |
| `totp_config.totp_pending_secret` | Signs pending/enrollment TOTP JWTs. | Required when `totp_config` is enabled; configured on `TotpConfig`, not `UserManagerSecurity`. |
| `user_manager_security.id_parser` | Supplies the manager/controller JWT subject parser once. | When set, `LitestarAuthConfig.id_parser` defaults to the same callable. Do not configure both with different values. |
| `user_manager_security.password_helper` | Injects the `PasswordHelper` instance used by `BaseUserManager`. | Prefer `config.resolve_password_helper()` to memoize the default helper when app-owned code also needs one. |
| `password_validator_factory` | Builds the runtime password validator for plugin-managed managers. | When omitted, the default plugin builder injects the default `require_password_length` validator. |
| `user_manager_security.password_validator` | Direct runtime validator override. | Mutually exclusive with `password_validator_factory`; prefer the factory when the validator depends on configuration. |
| `litestar_auth.schemas.UserEmailField` | Shares the built-in email regex and max-length metadata with app-owned `msgspec.Struct` schemas. | Schema metadata only; it does not add manager-side normalization or custom app policy. |
| `litestar_auth.schemas.UserPasswordField` | Shares built-in password-length metadata with app-owned `msgspec.Struct` schemas. | Schema metadata only; it does not replace the runtime validator. |

The default plugin builder now treats `user_manager_security` as an end-to-end constructor contract. When that
typed bundle is present, the plugin always passes `security=UserManagerSecurity(...)`, folds the effective
`id_parser` into that bundle first, and does not also send `verification_token_secret` /
`reset_password_token_secret` / `login_identifier_telemetry_secret` / `totp_secret_key` /
`totp_secret_keyring` / `id_parser` kwargs in the same call. Managers that do not
follow the default `BaseUserManager` constructor surface must be configured with
`user_manager_factory=...`.

The supported production posture is one distinct high-entropy value per secret role. Outside
explicit `unsafe_testing`, `LitestarAuth(config)` validation raises `ConfigurationError` when one
configured value is reused across verification, reset-password, failed-login telemetry, and TOTP
roles, including every configured key in `user_manager_security.totp_secret_keyring` and
`totp_config.totp_pending_secret` when that controller flow is enabled. Direct
`BaseUserManager(..., security=UserManagerSecurity(...))` construction applies the same
fail-closed validation for the manager-owned secret roles supplied on that bundle
(`verification_token_secret`, `reset_password_token_secret`, `login_identifier_telemetry_secret`,
and TOTP Fernet keys). Custom `user_manager_factory` implementations should keep their
manager-owned secret wiring aligned with `user_manager_security`; if they construct a manager with
reused secret material, that manager constructor raises for the roles it actually receives.

| Setting | Token audience or flow | Supported production posture |
| ------- | ---------------------- | ---------------------------- |
| `user_manager_security.verification_token_secret` | `litestar-auth:verify` | Dedicated secret used only for email-verification JWTs. |
| `user_manager_security.reset_password_token_secret` | `litestar-auth:reset-password` | Dedicated secret used only for reset-password JWTs and password fingerprints. |
| `user_manager_security.login_identifier_telemetry_secret` | Failed-login telemetry; no JWT audience | Dedicated secret used only to produce non-reversible failed-login identifier digests. |
| `totp_config.totp_pending_secret` | `litestar-auth:2fa-pending`, `litestar-auth:2fa-enroll` | Dedicated secret used only for pending/enrollment TOTP JWTs. |
| `user_manager_security.totp_secret_keyring` / `totp_secret_key` | Stored TOTP secret encryption at rest; no JWT audience | Dedicated Fernet key material kept separate from all JWT signing secrets. |

Distinct audiences already prevent token cross-use between verification, reset-password, and TOTP
JWTs. Separate secrets still matter because they reduce blast radius if one secret leaks and avoid
coupling unrelated rotation events.

Compatibility and migration:

- Configure plugin-managed `verification_token_secret`, `reset_password_token_secret`,
  `login_identifier_telemetry_secret`, `totp_secret_keyring`, and `id_parser` through
  `user_manager_security`.
- If you intentionally need factory-owned security wiring, set `user_manager_factory` directly and pass explicit
  dependencies through your factory closure or another typed app-owned dependency surface.
- The default plugin builder calls the `BaseUserManager`-style constructor surface:
  `user_manager_class(user_db, *, password_helper=..., security=..., password_validator=..., backends=..., login_identifier=..., superuser_role_name=..., unsafe_testing=...)`.
  It always passes `security=UserManagerSecurity(...)`. When `user_manager_security` is unset, the effective parser
  from `LitestarAuthConfig.id_parser` is folded into that bundle (not as a standalone `id_parser=` kwarg on the
  builder call). If your manager narrows or renames that surface, configure it with
  `user_manager_factory=...`.
- Direct manager construction can also use `BaseUserManagerConfig(...)` to pass the same settings
  as one typed object. The plugin builder still uses the keyword constructor surface so subclass
  constructors remain straightforward.
- When `user_manager_security` is present, the effective manager parser comes from
  `user_manager_security.id_parser` first and otherwise falls back to `LitestarAuthConfig.id_parser`. When
  `user_manager_security` is absent, the default builder still materializes `security=UserManagerSecurity(...)`
  with that resolved parser folded in (see `ManagerConstructorInputs` in the library for how unset secret fields
  are resolved alongside `id_parser`).
- Existing `UserPasswordField` imports remain valid. Add `UserEmailField` only when you also want the built-in
  email regex/max-length contract on app-owned schemas.
- Prefer `PasswordHelper.from_defaults()` when you mean "use the library default Argon2-only hasher policy."
  Use `PasswordHelper(password_hash=...)` only for deliberate application-owned custom pwdlib composition.
- Keep password-helper and password-validator overrides on `user_manager_security`. Use
  `UserManagerSecurity(password_helper=..., password_validator=...)` for direct overrides, or
  `password_validator_factory` when the validator should be derived from config at runtime.
- Custom manager classes on the default builder path must accept `superuser_role_name`; subclassing
  `BaseUserManager` without narrowing its constructor already satisfies this.

If your application also hashes or verifies passwords outside `BaseUserManager`, call
`config.resolve_password_helper()` once after constructing `LitestarAuthConfig(...)`. When
`user_manager_security.password_helper` already points at an explicit helper override,
`config.resolve_password_helper()` returns that object unchanged. Otherwise it memoizes
`PasswordHelper.from_defaults()` on the config and the plugin will inject the same helper into
each request-scoped manager, so the plugin and app-owned code share the same Argon2-only helper.
Under that default helper, unsupported stored password hashes fail closed. Rotate or reset those
credentials before upgrading a deployment that still depends on them. An explicit
`user_manager_security.password_helper` override changes only the password-hash policy itself; it
does not inherit validator or token settings.

If app-owned code never hashes or verifies passwords directly, you can skip calling
`config.resolve_password_helper()`: the default plugin builder still materializes and injects the
shared helper for each request-scoped manager on demand.

Use `password_validator_factory` when the plugin should own runtime password-policy construction.
If you do not provide it, the default plugin builder injects the default `require_password_length` validator. Keep `user_manager_security.password_validator` only
for direct overrides, and do not mix it with `password_validator_factory`. When
`user_manager_factory` is used, the plugin still validates this configuration surface but does not
inject a resolved validator into your factory automatically; the factory must build and pass
whatever validator policy it wants to own.

Plugin-managed account-state checks also rely on one stable callable surface resolved from
`user_manager_class`: `require_account_state(user, *, require_verified=False)`.
`BaseUserManager` supplies the default behavior, and custom manager classes or adapters should
preserve the same user argument plus keyword-only verification flag when they customize that
policy.

For app-owned registration, admin-update, or password-rotation structs, import `UserEmailField`
and `UserPasswordField` from `litestar_auth.schemas` instead of copying the built-in email regex
or raw `12` / `128` bounds. `UserPasswordField` is not for self-service profile update DTOs:
`UserUpdate` intentionally excludes `password`, and authenticated users rotate their own password
through `ChangePasswordRequest`. Those aliases keep schema metadata aligned with the built-in
credential-bearing structs; runtime password validation still happens in the manager through
`password_validator_factory` or the manager's default validator.
