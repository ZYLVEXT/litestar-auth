"""Public extension contracts for plugin-owned extension points."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping
    from types import ModuleType

    from litestar.cli._utils import Group
    from litestar.config.app import AppConfig
    from litestar.openapi.spec import SecurityRequirement, SecurityScheme

    from litestar_auth._manager.hooks import ExtensionManagerHookSubscriber
    from litestar_auth._plugin.extensions._context import ExtensionDependencyKeys
    from litestar_auth._plugin.features import FeatureRegistry, StartupBackendInventory, StartupBackendTemplate
    from litestar_auth.plugin import LitestarAuthConfig

type ExceptionHandlerKey = int | type[Exception]
type ExtensionApiVersion = tuple[int, int]

EXTENSION_API_VERSION: ExtensionApiVersion = (1, 0)
EXTENSION_ENTRY_POINT_GROUP = "litestar_auth.extensions"


class AuthExtensionValidationContext(Protocol):
    """Read-only inputs available while an auth extension validates its configuration."""

    @property
    def config(self) -> LitestarAuthConfig[Any, Any]:
        """The plugin configuration being validated."""
        ...

    @property
    def feature_registry(self) -> FeatureRegistry[Any, Any]:
        """The resolved feature registry for this plugin instance."""
        ...

    @property
    def resolved_defaults(self) -> object:
        """The canonical resolved-defaults snapshot for the plugin config."""
        ...

    @property
    def user_model(self) -> type[Any]:
        """The configured user model type."""
        ...

    @property
    def user_manager_class(self) -> type[object] | None:
        """The configured plugin-managed user manager class."""
        ...

    @property
    def user_manager_factory(self) -> object | None:
        """The configured custom user-manager factory."""
        ...

    @property
    def manager_construction_mode(self) -> str:
        """The active manager construction path name."""
        ...

    @property
    def startup_backend_inventory(self) -> StartupBackendInventory[Any, Any]:
        """The canonical startup backend inventory."""
        ...

    @property
    def startup_backends(self) -> tuple[StartupBackendTemplate[Any, Any], ...]:
        """Canonical startup backend templates."""
        ...

    @property
    def backend_names(self) -> tuple[str, ...]:
        """Configured startup backend names in registration order."""
        ...

    @property
    def security_requirements(self) -> list[SecurityRequirement]:
        """Derived OpenAPI security requirements for configured backends."""
        ...

    @property
    def organization_enabled(self) -> bool:
        """Whether organization support is enabled."""
        ...

    @property
    def organization_config(self) -> object:
        """The organization feature config object."""
        ...

    @property
    def organization_model(self) -> type[object] | None:
        """A statically discoverable organization model, if the store exposes one."""
        ...

    @property
    def tenant_resolver(self) -> object | None:
        """The configured tenant resolver when organizations are enabled."""
        ...

    @property
    def unsafe_testing(self) -> bool:
        """Whether explicit unsafe testing shortcuts are enabled."""
        ...

    @staticmethod
    def require_redis_asyncio(*, feature_name: str) -> ModuleType:
        """Require the optional Redis asyncio dependency for an extension feature."""
        ...

    @staticmethod
    def require_cryptography_fernet(*, install_hint: str) -> ModuleType:
        """Require the optional cryptography Fernet dependency for an extension feature."""
        ...

    def validate_production_secret(
        self,
        secret: str,
        *,
        label: str,
        minimum_length: int = ...,
        minimum_entropy_bits: float = ...,
    ) -> None:
        """Validate extension-owned production secret material."""
        ...


class AuthExtensionRegistrationContext(AuthExtensionValidationContext, Protocol):
    """Inputs available while an auth extension registers Litestar application state."""

    @property
    def app_config(self) -> AppConfig:
        """The Litestar application config being initialized."""
        ...

    @property
    def dependency_keys(self) -> ExtensionDependencyKeys:
        """plugin-owned dependency keys visible to extension providers."""
        ...

    def add_controller(self, controller: object) -> None:
        """Accumulate a controller or route handler for later registration."""
        ...

    def add_dependency(
        self,
        extension_name: str,
        key: str,
        provider: object,
        *,
        allow_override: bool = False,
    ) -> None:
        """Accumulate a dependency provider contribution."""
        ...

    def add_middleware(self, middleware: object) -> None:
        """Accumulate a middleware contribution for later registration."""
        ...

    def add_openapi_security_scheme(self, extension_name: str, name: str, scheme: SecurityScheme) -> None:
        """Accumulate an OpenAPI security scheme contribution."""
        ...

    def add_startup_hook(self, hook: Callable[[], object]) -> None:
        """Accumulate a startup hook contribution."""
        ...

    def add_shutdown_hook(self, hook: Callable[[], object]) -> None:
        """Accumulate a shutdown hook contribution."""
        ...

    def add_exception_handler(self, extension_name: str, key: ExceptionHandlerKey, handler: object) -> None:
        """Accumulate an exception handler contribution."""
        ...

    @staticmethod
    def mark_auth_route_handler[RouteHandlerT](route_handler: RouteHandlerT) -> RouteHandlerT:
        """Mark an extension route handler as owned by litestar-auth."""
        ...

    @staticmethod
    def is_auth_route_handler(route_handler: object) -> bool:
        """Return whether a route handler is marked as litestar-auth owned."""
        ...

    def state_for_extension(self, extension_name: str) -> MutableMapping[str, object]:
        """Return mutable local state namespaced to one extension name."""
        ...

    def set_local_state(self, extension_name: str, key: str, value: object) -> None:
        """Store one extension-local value under a namespaced key."""
        ...

    def get_local_state(self, extension_name: str, key: str, default: object | None = None) -> object | None:
        """Return one extension-local value without reading another extension's namespace."""
        ...


class AuthExtension(Protocol):
    """Structural contract for first-phase litestar-auth extensions."""

    @property
    def name(self) -> str:
        """Extension name used for registration and diagnostics."""
        ...

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Validate extension configuration before plugin startup wiring runs."""
        ...

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Register extension state into the Litestar application config."""
        ...


@runtime_checkable
class AuthCliExtension(Protocol):
    """Optional structural contract for extensions that contribute CLI commands."""

    def register_cli(self, cli: Group, config: LitestarAuthConfig[Any, Any]) -> None:
        """Register extension-owned CLI commands on the active Litestar CLI group."""
        ...


@runtime_checkable
class AuthEventSubscriberExtension(Protocol):
    """Optional structural contract for extensions that observe manager lifecycle events."""

    def manager_hook_subscribers(self) -> tuple[ExtensionManagerHookSubscriber, ...]:
        """Return subscribers wired into every per-request user manager."""
        ...


__all__ = (
    "EXTENSION_API_VERSION",
    "EXTENSION_ENTRY_POINT_GROUP",
    "AuthCliExtension",
    "AuthEventSubscriberExtension",
    "AuthExtension",
    "AuthExtensionRegistrationContext",
    "AuthExtensionValidationContext",
)
