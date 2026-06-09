# Extensions

`litestar-auth` exposes the public extension-author surface from one module:

```python
from litestar_auth import AuthExtension, AuthExtensionRegistrationContext, AuthExtensionValidationContext
from litestar_auth.extensions import create_auth_controller
from litestar_auth.plugin import LitestarAuthConfig
from myapp.models import User

config = LitestarAuthConfig(
    user_model=User,
    extensions=(my_extension,),
)
```

External extensions should import extension contracts and supported helper factories from
`litestar_auth.extensions`. Imports from `litestar_auth._plugin.*` are private implementation
details and are unsupported for out-of-tree packages. Internal first-party extensions may still use
private modules where they need implementation-only access.

`LitestarAuthConfig.extensions` is public API. It stores a tuple of `AuthExtension` objects and
defaults to `()`, so applications with no extensions keep the existing plugin configuration shape.
Configured extensions are validated and registered during plugin startup:

- `validate(context)` runs in configured extension order before app-init wiring starts.
- `register(context)` runs in configured extension order during plugin app-init.
- Duplicate extension names are rejected before namespaced extension state can collide.
- `register_cli(cli, config)` is optional and runs only during Litestar CLI initialization for
  extensions that implement `AuthCliExtension`.

`LitestarAuthConfig.auto_discover_extensions` defaults to `False`. With the default setting,
`litestar-auth` does not inspect Python package entry points and does not import discovered
extension modules. When set to `True`, the plugin discovers external extensions from the canonical
`litestar_auth.extensions` entry-point group. Explicitly configured extensions are resolved first,
then internal extensions derived from enabled plugin feature flags, then discovered entry points.
Discovered entry points are loaded in deterministic order sorted by entry-point name and then entry
point value.

External extension distributions should use the `litestar_auth_ext_*` naming convention. For
example, an audit extension distribution should be named `litestar_auth_ext_audit`; its import
package can use the same name or another clear package name owned by that distribution. The
distribution name is a packaging convention for discoverability. The canonical runtime discovery
surface is still the `litestar_auth.extensions` entry-point group.

A runnable public-boundary authoring template lives at
`examples/demo_external_extension/`. It demonstrates explicit `extensions=(...)` registration,
documents entry-point registration for separately shipped packages, and keeps extension imports on
the `litestar_auth.extensions` facade.

Entry-point discovery is intentionally fail-closed. A load/import failure, a factory/class
instantiation failure, or a loaded object that does not structurally satisfy `AuthExtension` raises
`ConfigurationError`. Successfully discovered extensions are merged into the same memoized
`resolve_extensions()` tuple as explicit and internal extensions, so they pass through the existing
enabled filter, extension API version gate, validation, duplicate-name guard, registration, CLI
gating, and app wiring paths. A discovered extension with `enabled = False` is inert in the same way
as a disabled explicitly configured extension.

External packages can register an extension object, extension class, or zero-argument factory:

```toml
[project]
name = "litestar-auth-audit"

[project.entry-points."litestar_auth.extensions"]
audit = "litestar_auth_ext_audit:AuditExtension"
```

An extension is any object that structurally satisfies `AuthExtension`:

- `name: str`
- optional `requires_api: tuple[int, int] | None`
- `validate(context: AuthExtensionValidationContext) -> None`
- `register(context: AuthExtensionRegistrationContext) -> None`

`enabled` is intentionally optional runtime metadata, not a required member of the
`AuthExtension` protocol. Extensions that omit `enabled` are treated as enabled.
Set `enabled = False` to keep an extension in configuration while making it inert
for the current application startup.

Extensions may also structurally satisfy `AuthEventSubscriberExtension` when they need to
observe manager lifecycle events such as registration and login:

```python
from litestar_auth.extensions import (
    AuthEventSubscriberExtension,
    ExtensionManagerHookEvent,
    ExtensionManagerHookSubscriber,
)


class AuditExtension:
    name = "audit"

    def validate(self, context) -> None:
        ...

    def register(self, context) -> None:
        ...

    def manager_hook_subscribers(self) -> tuple[ExtensionManagerHookSubscriber, ...]:
        return (self._record_event,)

    async def _record_event(self, event: ExtensionManagerHookEvent) -> None:
        ...


extension: AuthEventSubscriberExtension = AuditExtension()
```

During app startup registration, enabled extensions that implement
`AuthEventSubscriberExtension` contribute subscribers that are attached to every
per-request `BaseUserManager` hook bus. Each manager instance gets a fresh bus; subscribers
are registered once at manager construction and do not accumulate across requests.

Extension subscribers receive `ExtensionManagerHookEvent` payloads, not the raw internal
hook arguments. Token-bearing lifecycle events (`after_register`, `after_forgot_password`,
`after_request_verify_token`, and `after_organization_invitation`) are redacted so the final
string token argument is delivered as `None`. For `after_update`, the extension-facing
`update_dict` is a fresh dict with credential fields removed: `current_password`,
`hashed_password`, `new_password`, and `password`. Non-secret fields such as `email`,
`is_verified`, and `roles` remain available to subscribers. Other non-token events such as
`after_login` pass through unchanged.

Event-subject model objects themselves are still delivered to subscribers. Treat credential-derived
attributes on those objects as sensitive: user objects may expose `hashed_password`,
organization-invitation objects delivered to `after_organization_invitation` carry `token_hash`,
and API-key rows delivered to `after_api_key_created`, `after_api_key_revoked`, and
`after_api_key_used` carry `hashed_secret` plus optional `encrypted_secret`. Do not log or persist those attributes. The raw
organization-invitation token is still delivered to subscribers as `None`, and plaintext API keys
are returned to the API-key creation caller separately and are never delivered to manager hooks or
extension subscribers.

Subscriber dispatch uses the same fail-closed semantics as the internal hook bus: if one
subscriber raises, the exception propagates and aborts the surrounding manager operation.

Disabled extensions, extensions filtered out by the extension API version gate, and
extensions that fail `validate()` do not contribute manager hook subscribers.

Extensions may also structurally satisfy `AuthCliExtension` when they need to contribute
plugin-owned CLI commands:

```python
from typing import Any

from litestar.cli._utils import Group
from litestar_auth.extensions import AuthCliExtension
from litestar_auth.plugin import LitestarAuthConfig


class MyCliExtension:
    def register_cli(self, cli: Group, config: LitestarAuthConfig[Any, Any]) -> None:
        ...


extension: AuthCliExtension = MyCliExtension()
```

`LitestarAuth.on_cli_init()` first resolves enabled extensions through the same extension API
version gate used by app startup. It then runs `validate()` for objects that implement
`AuthCliExtension` before registering any CLI commands, including built-in role commands. This is
intentional fail-closed parity with app startup: an incompatible `requires_api` declaration,
malformed `requires_api` declaration, or failed CLI-extension prerequisite raises
`ConfigurationError` before the CLI surface is wired. CLI registration is still separate from app
startup: `on_cli_init()` does not call extension `register()`, does not run app-init wiring, and
should not perform async I/O. The built-in organization administration CLI is registered through an
internal `AuthCliExtension`, while extension objects that implement only `AuthExtension` contribute
no CLI commands.

Disabled extensions are filtered out before version compatibility checks, validation, registration,
duplicate-name checks, and app wiring, so they contribute no routes, dependencies, middleware,
exception handlers, OpenAPI security schemes, startup hooks, shutdown hooks, or CLI commands.

`EXTENSION_API_VERSION` is exported from `litestar_auth.extensions` as the version of this extension-author
boundary. The current value is `(1, 0)`. External extension packages may set `requires_api` to the
extension API version they were authored against:

```python
from litestar_auth.extensions import EXTENSION_API_VERSION


class MyExtension:
    name = "my_extension"
    requires_api = EXTENSION_API_VERSION
```

Compatibility is major-version based: the declared major version must match the library's
`EXTENSION_API_VERSION` major version, and the declared minor version must be less than or equal to
the library's minor version. Extensions that omit `requires_api` are accepted, but they do not get a
startup compatibility check. Invalid declarations, newer minor versions, or different major versions
raise `ConfigurationError` during extension validation before extension registration or app-config
wiring can run. The same compatibility check runs during CLI initialization before any CLI commands
are registered.

Only the `litestar_auth.extensions` extension-author boundary is versioned this way. The rest of
`litestar-auth` still follows the project's current posture that breaking changes are allowed when
they materially improve correctness, security, maintainability, or API ergonomics.

`AuthExtensionValidationContext` exposes the resolved plugin state an extension can inspect before
registration: `config`, `feature_registry`, resolved defaults, user-manager construction shape,
startup backend inventory and names, derived OpenAPI security requirements, organization feature
state, optional dependency loaders, and the production-secret validator.

`AuthExtensionRegistrationContext` adds Litestar's `app_config` and the public registration helpers
for contributed state:

- `dependency_keys` exposes plugin-owned dependency keys for extension providers;
- `add_dependency()`, `add_middleware()`, `add_openapi_security_scheme()`, `add_controller()`,
  `add_startup_hook()`, `add_shutdown_hook()`, and `add_exception_handler()` accumulate
  registration contributions for the later plugin phases;
- `mark_auth_route_handler()` and `is_auth_route_handler()` mark extension routes as
  `litestar-auth` owned for auth-route exception handling;
- `state_for_extension()`, `set_local_state()`, and `get_local_state()` provide namespaced
  extension-local state during one registration pass.

These interfaces let extensions validate and register against the same resolved feature snapshot the
plugin uses without importing private `litestar_auth._plugin` modules, ORM modules, or SQLAlchemy
adapter modules.

Extension-contributed dependencies may use `allow_override=True` only for plugin dependency keys
that are intentionally replaceable. Authentication- and authorization-critical keys fail closed
during app initialization even with `allow_override=True`, including the config, user-manager,
authentication-backends, OAuth-associate user-manager, resolved-permissions, current-organization,
and organization-store dependencies. Applications migrating an extension that previously replaced
one of these keys should move that behavior to the corresponding documented plugin configuration,
manager, backend, OAuth-associate, or organization integration point instead of overriding the DI
key directly.

## Public facade

`litestar_auth.extensions` deliberately exports:

- the extension API version and discovery constants plus protocols: `EXTENSION_API_VERSION`,
  `EXTENSION_ENTRY_POINT_GROUP`, `AuthExtension`, `AuthCliExtension`, `AuthEventSubscriberExtension`,
  `AuthExtensionValidationContext`, and `AuthExtensionRegistrationContext`;
- extension lifecycle event types: `ExtensionManagerHookEvent` and `ExtensionManagerHookSubscriber`;
- stable built-in controller factory configs and functions from the public controller packages, such
  as `AuthControllerConfig`, `create_auth_controller`, `RegisterControllerConfig`,
  `create_register_controller`, `UsersControllerConfig`, `create_users_controller`,
  `ApiKeysControllerConfig`, `create_api_keys_controllers`, `OrganizationControllerConfig`,
  `create_organization_controller`, `OAuthControllerConfig`, `create_oauth_controller`,
  `OAuthAssociateControllerConfig`, `create_oauth_associate_controller`, `TotpControllerOptions`,
  and `create_totp_controller`;
- stable optional public controller helpers that extension packages may wrap explicitly:
  `ProviderOAuthControllerConfig`, `create_provider_oauth_controller`,
  `RoleAdminControllerConfig`, `create_role_admin_controller`,
  `OrganizationAdminControllerConfig`, `create_organization_admin_controller`,
  `OrganizationInvitationControllerConfig`, and `create_organization_invitation_controller`.

The facade is import-light. Importing `litestar_auth.extensions` only loads the protocol module and
lazy export table; it does not import ORM models, the SQLAlchemy adapter, concrete bundled extension
implementations, OAuth/TOTP/Redis optional implementations, or controller modules until a specific
helper is accessed.

During registration, the library constructs the concrete registration context, invokes each
extension's hook, and applies accumulated extension contributions in the normal app-init phases:

- dependency providers are registered alongside plugin-owned dependency providers;
- middleware is inserted immediately after the core auth middleware;
- OpenAPI security schemes are merged into the Litestar OpenAPI config when OpenAPI is enabled;
- controllers and route handlers are appended with the plugin-generated auth controllers;
- startup and shutdown hooks are appended to `app_config.on_startup` and `app_config.on_shutdown`;
- app-level exception handlers are registered before generated auth-route exception handling runs.

Extension OpenAPI security scheme names must be unique across both core auth schemes and all
extension contributions. Core scheme names are reserved because they are already wired into the
plugin-generated route security requirements. A collision raises `ConfigurationError` during app
initialization before the Litestar app is usable. Core names are derived from the actually
registered startup backends: bearer and cookie backends use `backend.name`, API-key backends reserve
`apiKeyAuth`, and signed API-key support additionally reserves `apiKeyHmacAuth`.

This page documents the current public contract. The concrete context builders, accumulated
contribution dataclasses, registry helpers, and later app-init wiring functions under
`litestar_auth._plugin` remain private and are not part of the public extension API. Do not import
them from external extension packages.
