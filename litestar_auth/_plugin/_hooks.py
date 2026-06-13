"""Plugin hook protocols and table-driven startup wiring descriptors."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from litestar.connection import Request
    from litestar.middleware import DefineMiddleware
    from litestar.response import Response
    from litestar.types import ControllerRouterHandler

    from litestar_auth.exceptions import LitestarAuthError

type FeatureWiringKey = str
type StartupHookName = str
type AppInitHookName = str
type DependencyProviderName = str
type ExceptionHandlerName = str
type FeatureWiringPredicate = Callable[[object], bool]


class ExceptionResponseHook(Protocol):
    """Format plugin-owned auth errors as Litestar responses."""

    def __call__(
        self,
        exc: LitestarAuthError,
        request: Request[Any, Any, Any],
        /,
    ) -> Response[Any]:
        pass


class MiddlewareHook(Protocol):
    """Adjust the constructed auth middleware before plugin insertion."""

    def __call__(self, middleware: DefineMiddleware, /) -> DefineMiddleware:
        pass


class ControllerHook(Protocol):
    """Adjust the built plugin controller list before registration."""

    def __call__(
        self,
        controllers: list[ControllerRouterHandler],
        /,
    ) -> list[ControllerRouterHandler]:
        pass


def _always_enabled(_config: object) -> bool:
    """Return true for wiring phases whose hook functions own their no-op checks."""
    return True


def _has_extensions(config: object) -> bool:
    """Return whether extension-specific phases need to run."""
    resolve_extensions = getattr(config, "resolve_extensions", None)
    if callable(resolve_extensions):
        return bool(resolve_extensions())
    return bool(getattr(config, "extensions", ()))


@dataclass(frozen=True, slots=True)
class FeatureWiring:
    """Ordered plugin feature wiring descriptor.

    The descriptor list is the single inventory for app-init phases that used to
    be scattered across procedural startup and dependency registration code.
    Hook names are resolved by the phase owner so this module stays import-light
    and keeps config import cycles out of the protocol definitions.
    """

    order: int
    feature: FeatureWiringKey
    enabled: FeatureWiringPredicate = _always_enabled
    before_startup: tuple[StartupHookName, ...] = ()
    after_startup: tuple[AppInitHookName, ...] = ()
    on_shutdown: tuple[AppInitHookName, ...] = ()
    exception_handlers: tuple[ExceptionHandlerName, ...] = ()
    dependency_providers: tuple[DependencyProviderName, ...] = ()
    description: str = field(default="", compare=False)


FEATURE_WIRING: tuple[FeatureWiring, ...] = (
    FeatureWiring(
        order=0,
        feature="extension_registration",
        enabled=_has_extensions,
        after_startup=("register_extensions",),
        description="Configured auth extension contribution collection.",
    ),
    FeatureWiring(
        order=10,
        feature="core",
        before_startup=(
            "require_shared_rate_limit_backends_for_multiworker",
            "require_shared_account_lockout_store_for_multiworker",
            "require_refreshable_strategy_when_enable_refresh",
            "warn_insecure_plugin_startup_defaults",
        ),
        after_startup=(
            "register_dependencies",
            "register_middleware",
            "register_openapi_security",
            "register_controllers",
        ),
        exception_handlers=("register_exception_handlers",),
        dependency_providers=(
            "config",
            "user_manager",
            "backends",
            "user_model",
            "resolved_permissions",
            "current_organization",
            "organization_store",
            "db_session",
        ),
        description="Core auth plugin guards, DI, middleware, OpenAPI, controllers, and route error handlers.",
    ),
    FeatureWiring(
        order=15,
        feature="extension_validation",
        enabled=_has_extensions,
        before_startup=("validate_extensions",),
        description="Configured auth extension validation after core startup guards.",
    ),
    FeatureWiring(
        order=20,
        feature="oauth",
        dependency_providers=("oauth_associate_user_manager",),
        description="Optional OAuth associate-route user-manager DI.",
    ),
    FeatureWiring(
        order=30,
        feature="database_token",
        before_startup=("bootstrap_bundled_token_orm_models",),
        description="Database-token ORM bootstrap hook.",
    ),
)


def iter_feature_wiring(config: object) -> tuple[FeatureWiring, ...]:
    """Return enabled feature wiring descriptors in deterministic startup order."""
    return tuple(wiring for wiring in sorted(FEATURE_WIRING, key=lambda item: item.order) if wiring.enabled(config))
