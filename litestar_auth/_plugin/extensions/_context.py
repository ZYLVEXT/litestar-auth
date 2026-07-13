"""Concrete context objects for plugin extension validation and registration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.config import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
    DEFAULT_DB_SESSION_DEPENDENCY_KEY,
    DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY,
    DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    LitestarAuthConfig,
)
from litestar_auth._plugin.config._resolvers import resolve_backend_inventory
from litestar_auth.config import MINIMUM_SECRET_ENTROPY_BITS, MINIMUM_SECRET_LENGTH, validate_production_secret
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping
    from types import ModuleType

    from litestar.config.app import AppConfig
    from litestar.openapi.spec import SecurityRequirement, SecurityScheme

    from litestar_auth._manager.hooks import ExtensionManagerHookSubscriber
    from litestar_auth._plugin.extensions import AuthExtension
    from litestar_auth._plugin.features import FeatureRegistry, StartupBackendInventory, StartupBackendTemplate

type ExceptionHandlerKey = int | type[Exception]


def _find_duplicate_extension_names(extensions: tuple[AuthExtension, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for extension in extensions:
        name = extension.name
        if name in seen:
            duplicates.add(name)
        else:
            seen.add(name)
    return tuple(sorted(duplicates))


def validate_unique_extension_names(extensions: tuple[AuthExtension, ...]) -> None:
    """Reject duplicate extension names before namespaced state can collide.

    Raises:
        ValueError: If two configured extensions expose the same ``name``.
    """
    duplicates = _find_duplicate_extension_names(extensions)
    if not duplicates:
        return
    msg = f"Duplicate auth extension names are not allowed: {', '.join(duplicates)}"
    raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ExtensionDependencyContribution:
    """Dependency provider contributed by one auth extension."""

    extension_name: str
    key: str
    provider: object
    allow_override: bool = False


@dataclass(frozen=True, slots=True)
class ExtensionOpenAPISecurityContribution:
    """OpenAPI security scheme contributed by one auth extension."""

    extension_name: str
    name: str
    scheme: SecurityScheme


@dataclass(frozen=True, slots=True)
class ExtensionExceptionHandlerContribution:
    """Exception handler contributed by one auth extension."""

    extension_name: str
    key: ExceptionHandlerKey
    handler: object


@dataclass(frozen=True, slots=True)
class ExtensionRegistrationContributions:
    """Accumulated extension contributions consumed by the later wiring phase."""

    controllers: list[object] = field(default_factory=list)
    dependencies: list[ExtensionDependencyContribution] = field(default_factory=list)
    middleware: list[object] = field(default_factory=list)
    openapi_security_schemes: list[ExtensionOpenAPISecurityContribution] = field(default_factory=list)
    startup_hooks: list[Callable[[], object]] = field(default_factory=list)
    shutdown_hooks: list[Callable[[], object]] = field(default_factory=list)
    exception_handlers: list[ExtensionExceptionHandlerContribution] = field(default_factory=list)
    manager_hook_subscribers: list[ExtensionManagerHookSubscriber] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ExtensionDependencyKeys:
    """Plugin-owned dependency keys exposed to extension registration."""

    config: str
    user_manager: str
    backends: str
    user_model: str
    resolved_permissions: str
    session: str
    current_organization: str | None
    organization_store: str | None


@dataclass(slots=True)
class ExtensionValidationContext[UP: UserProtocol[Any], ID]:
    """Concrete read-only context passed to extension validation hooks."""

    config: LitestarAuthConfig[UP, ID]
    feature_registry: FeatureRegistry[UP, ID]

    @classmethod
    def from_config(cls, config: LitestarAuthConfig[UP, ID]) -> ExtensionValidationContext[UP, ID]:
        """Build the validation context from canonical config state.

        Returns:
            The concrete validation context for ``config``.
        """
        validate_unique_extension_names(config.resolve_extensions())
        return cls(config=config, feature_registry=config.resolve_feature_registry())

    @property
    def resolved_defaults(self) -> object:
        """The canonical resolved-defaults snapshot for the plugin config."""
        return self.config.resolve_defaults()

    @property
    def user_model(self) -> type[UP]:
        """The configured user model type."""
        return self.config.user_model

    @property
    def user_manager_class(self) -> type[object] | None:
        """The configured plugin-managed user manager class."""
        return self.config.user_manager_class

    @property
    def user_manager_factory(self) -> object | None:
        """The configured custom user-manager factory."""
        return self.config.user_manager_factory

    @property
    def manager_construction_mode(self) -> str:
        """The active manager construction path name."""
        return "factory" if self.config.user_manager_factory is not None else "class"

    @property
    def startup_backend_inventory(self) -> StartupBackendInventory[UP, ID]:
        """The canonical startup backend inventory."""
        return resolve_backend_inventory(self.config)

    @property
    def startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        """Canonical startup backend templates."""
        return self.startup_backend_inventory.startup_backends()

    @property
    def backend_names(self) -> tuple[str, ...]:
        """Configured startup backend names in registration order."""
        return tuple(backend.name for backend in self.startup_backends)

    @property
    def security_requirements(self) -> list[SecurityRequirement]:
        """Derived OpenAPI security requirements for configured backends."""
        return self.config.resolve_openapi_security_requirements()

    @property
    def organization_enabled(self) -> bool:
        """Whether organization support is enabled."""
        return self.feature_registry.is_enabled("organization")

    @property
    def organization_config(self) -> object:
        """The organization feature config object."""
        return self.config.organization_config

    @property
    def organization_model(self) -> type[object] | None:
        """A statically discoverable organization model, if the store exposes one."""
        store_factory = self.config.organization_config.store_factory
        model = getattr(store_factory, "organization_model", None)
        return model if isinstance(model, type) else None

    @property
    def tenant_resolver(self) -> object | None:
        """The configured tenant resolver when organizations are enabled."""
        if not self.organization_enabled:
            return None
        return self.config.organization_config.tenant_resolver

    @property
    def unsafe_testing(self) -> bool:
        """Whether explicit unsafe testing shortcuts are enabled."""
        return self.config.unsafe_testing

    @staticmethod
    def require_redis_asyncio(*, feature_name: str) -> ModuleType:
        """Require the optional Redis asyncio dependency for an extension feature.

        Returns:
            The imported ``redis.asyncio`` module.
        """
        from litestar_auth._optional_deps import _require_redis_asyncio  # noqa: PLC0415

        return _require_redis_asyncio(feature_name=feature_name)

    @staticmethod
    def require_cryptography_fernet(*, install_hint: str) -> ModuleType:
        """Require the optional cryptography Fernet dependency for an extension feature.

        Returns:
            The imported ``cryptography.fernet`` module.
        """
        from litestar_auth._optional_deps import require_cryptography_fernet  # noqa: PLC0415

        return require_cryptography_fernet(install_hint=install_hint)

    def validate_production_secret(
        self,
        secret: str,
        *,
        label: str,
        minimum_length: int = MINIMUM_SECRET_LENGTH,
        minimum_entropy_bits: float = MINIMUM_SECRET_ENTROPY_BITS,
    ) -> None:
        """Validate extension-owned production secret material using the plugin safety flag."""
        validate_production_secret(
            secret,
            label=label,
            unsafe_testing=self.config.unsafe_testing,
            minimum_length=minimum_length,
            minimum_entropy_bits=minimum_entropy_bits,
        )


@dataclass(slots=True)
class ExtensionRegistrationContext[UP: UserProtocol[Any], ID](ExtensionValidationContext[UP, ID]):
    """Concrete context passed to extension registration hooks."""

    app_config: AppConfig
    contributions: ExtensionRegistrationContributions = field(default_factory=ExtensionRegistrationContributions)
    _local_state: dict[str, dict[str, object]] = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def from_app_config(
        cls,
        *,
        app_config: AppConfig,
        config: LitestarAuthConfig[UP, ID],
    ) -> ExtensionRegistrationContext[UP, ID]:
        """Build the registration context from canonical plugin and AppConfig state.

        Returns:
            The concrete registration context for ``config`` and ``app_config``.
        """
        validate_unique_extension_names(config.resolve_extensions())
        return cls(app_config=app_config, config=config, feature_registry=config.resolve_feature_registry())

    @property
    def dependency_keys(self) -> ExtensionDependencyKeys:
        """plugin-owned dependency keys visible to extension providers."""
        return ExtensionDependencyKeys(
            config=DEFAULT_CONFIG_DEPENDENCY_KEY,
            user_manager=DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
            backends=DEFAULT_BACKENDS_DEPENDENCY_KEY,
            user_model=DEFAULT_USER_MODEL_DEPENDENCY_KEY,
            resolved_permissions=DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
            session=self.config.db_session_dependency_key or DEFAULT_DB_SESSION_DEPENDENCY_KEY,
            current_organization=(DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY if self.organization_enabled else None),
            organization_store=DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY if self.organization_enabled else None,
        )

    def add_controller(self, controller: object) -> None:
        """Accumulate a controller or route handler for later registration."""
        self.contributions.controllers.append(controller)

    def add_dependency(
        self,
        extension_name: str,
        key: str,
        provider: object,
        *,
        allow_override: bool = False,
    ) -> None:
        """Accumulate a dependency provider contribution."""
        self.contributions.dependencies.append(
            ExtensionDependencyContribution(
                extension_name=extension_name,
                key=key,
                provider=provider,
                allow_override=allow_override,
            ),
        )

    def add_middleware(self, middleware: object) -> None:
        """Accumulate a middleware contribution for later registration."""
        self.contributions.middleware.append(middleware)

    def add_openapi_security_scheme(self, extension_name: str, name: str, scheme: SecurityScheme) -> None:
        """Accumulate an OpenAPI security scheme contribution."""
        self.contributions.openapi_security_schemes.append(
            ExtensionOpenAPISecurityContribution(extension_name=extension_name, name=name, scheme=scheme),
        )

    def add_startup_hook(self, hook: Callable[[], object]) -> None:
        """Accumulate a startup hook contribution."""
        self.contributions.startup_hooks.append(hook)

    def add_shutdown_hook(self, hook: Callable[[], object]) -> None:
        """Accumulate a shutdown hook contribution."""
        self.contributions.shutdown_hooks.append(hook)

    def add_exception_handler(self, extension_name: str, key: ExceptionHandlerKey, handler: object) -> None:
        """Accumulate an exception handler contribution."""
        self.contributions.exception_handlers.append(
            ExtensionExceptionHandlerContribution(extension_name=extension_name, key=key, handler=handler),
        )

    @staticmethod
    def mark_auth_route_handler[RouteHandlerT](route_handler: RouteHandlerT) -> RouteHandlerT:
        """Mark an extension route handler as owned by litestar-auth.

        Returns:
            The same route handler marked for auth-specific exception wiring.
        """
        from litestar_auth.controllers._utils import _mark_litestar_auth_route_handler  # noqa: PLC0415

        return _mark_litestar_auth_route_handler(route_handler)

    @staticmethod
    def is_auth_route_handler(route_handler: object) -> bool:
        """Return whether a route handler is marked as litestar-auth owned."""
        from litestar_auth.controllers._utils import _is_litestar_auth_route_handler  # noqa: PLC0415

        return _is_litestar_auth_route_handler(route_handler)

    def state_for_extension(self, extension_name: str) -> MutableMapping[str, object]:
        """Return mutable local state namespaced to one extension name."""
        return self._local_state.setdefault(extension_name, {})

    def set_local_state(self, extension_name: str, key: str, value: object) -> None:
        """Store one extension-local value under a namespaced key."""
        self.state_for_extension(extension_name)[key] = value

    def get_local_state(self, extension_name: str, key: str, default: object | None = None) -> object | None:
        """Return one extension-local value without reading another extension's namespace."""
        return self.state_for_extension(extension_name).get(key, default)


def build_extension_validation_context[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> ExtensionValidationContext[UP, ID]:
    """Build the concrete validation context for extension hooks.

    Returns:
        The concrete validation context for ``config``.
    """
    return ExtensionValidationContext.from_config(config)


def build_extension_registration_context[UP: UserProtocol[Any], ID](
    *,
    app_config: AppConfig,
    config: LitestarAuthConfig[UP, ID],
) -> ExtensionRegistrationContext[UP, ID]:
    """Build the concrete registration context for extension hooks.

    Returns:
        The concrete registration context for ``config`` and ``app_config``.
    """
    return ExtensionRegistrationContext.from_app_config(app_config=app_config, config=config)


__all__ = (
    "ExceptionHandlerKey",
    "ExtensionDependencyContribution",
    "ExtensionDependencyKeys",
    "ExtensionExceptionHandlerContribution",
    "ExtensionOpenAPISecurityContribution",
    "ExtensionRegistrationContext",
    "ExtensionRegistrationContributions",
    "ExtensionValidationContext",
    "build_extension_registration_context",
    "build_extension_validation_context",
    "validate_unique_extension_names",
)
