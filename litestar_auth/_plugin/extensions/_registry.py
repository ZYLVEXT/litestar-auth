"""Extension validation, registration, and contribution application."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.extensions._context import (
    ExtensionRegistrationContext,
    build_extension_registration_context,
    build_extension_validation_context,
)
from litestar_auth._plugin.extensions._contracts import EXTENSION_API_VERSION, AuthEventSubscriberExtension
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Collection, Sequence

    from litestar.config.app import AppConfig
    from litestar.middleware import DefineMiddleware
    from litestar.types import ControllerRouterHandler, ExceptionHandler

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth._plugin.extensions._context import ExtensionRegistrationContributions
    from litestar_auth._plugin.extensions._contracts import AuthExtension, ExtensionApiVersion


def _format_extension_api_version(version: tuple[int, int]) -> str:
    return ".".join(str(part) for part in version)


def _is_compatible_extension_api_version(required: ExtensionApiVersion) -> bool:
    current_major, current_minor = EXTENSION_API_VERSION
    required_major, required_minor = required
    return required_major == current_major and required_minor <= current_minor


def _validate_extension_api_version(extension: AuthExtension) -> None:
    required = getattr(extension, "requires_api", None)
    if required is None:
        return
    if (
        not isinstance(required, tuple)
        or len(required) != len(EXTENSION_API_VERSION)
        or not all(isinstance(part, int) for part in required)
    ):
        msg = (
            f"Auth extension {extension.name!r} declares invalid requires_api={required!r}; expected a "
            "two-integer extension API version tuple."
        )
        raise ConfigurationError(msg)
    if _is_compatible_extension_api_version(required):
        return
    msg = (
        f"Auth extension {extension.name!r} requires extension API "
        f"{_format_extension_api_version(required)}, but litestar-auth provides "
        f"{_format_extension_api_version(EXTENSION_API_VERSION)}."
    )
    raise ConfigurationError(msg)


def _validate_extension_api_versions(extensions: tuple[AuthExtension, ...]) -> None:
    for extension in extensions:
        _validate_extension_api_version(extension)


def resolve_version_gated_extensions[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> tuple[AuthExtension, ...]:
    """Return resolved extensions after enforcing extension API compatibility."""
    extensions = config.resolve_extensions()
    _validate_extension_api_versions(extensions)
    return extensions


def validate_extensions[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Run configured extension validation hooks in config order."""
    context = build_extension_validation_context(config)
    extensions = resolve_version_gated_extensions(config)
    for extension in extensions:
        extension.validate(context)


def register_extensions[UP: UserProtocol[Any], ID](
    *,
    app_config: AppConfig,
    config: LitestarAuthConfig[UP, ID],
) -> ExtensionRegistrationContext[UP, ID]:
    """Run configured extension registration hooks and apply lifecycle contributions.

    Returns:
        The concrete registration context containing all accumulated extension contributions.
    """
    context = build_extension_registration_context(app_config=app_config, config=config)
    for extension in resolve_version_gated_extensions(config):
        extension.register(context)
        if isinstance(extension, AuthEventSubscriberExtension):
            context.contributions.manager_hook_subscribers.extend(extension.manager_hook_subscribers())

    contributions = context.contributions
    app_config.on_startup.extend(contributions.startup_hooks)
    app_config.on_shutdown.extend(contributions.shutdown_hooks)
    return context


def apply_extension_middleware(
    app_config: AppConfig,
    *,
    contributions: ExtensionRegistrationContributions,
    after_index: int,
) -> None:
    """Insert extension middleware at a deterministic position after core auth middleware."""
    middleware = cast("Sequence[DefineMiddleware]", contributions.middleware)
    if middleware:
        app_config.middleware[after_index:after_index] = middleware


def register_extension_openapi_security(
    app_config: AppConfig,
    *,
    contributions: ExtensionRegistrationContributions,
    core_security_scheme_names: Collection[str] | None = None,
) -> dict[str, object]:
    """Merge extension-contributed OpenAPI security schemes into AppConfig.

    Returns:
        The registered extension security schemes keyed by scheme name.

    Raises:
        ConfigurationError: If an extension scheme name conflicts with a core auth scheme name.
        ValueError: If two extensions contribute the same security scheme name.
    """
    schemes: dict[str, object] = {}
    owners: dict[str, str] = {}
    reserved_scheme_names = frozenset() if core_security_scheme_names is None else core_security_scheme_names
    for contribution in contributions.openapi_security_schemes:
        if contribution.name in reserved_scheme_names:
            msg = (
                "Auth extension OpenAPI security scheme "
                f"{contribution.name!r} from extension {contribution.extension_name!r} conflicts with a core auth "
                "security scheme of the same name."
            )
            raise ConfigurationError(msg)
        owner = owners.get(contribution.name)
        if owner is not None:
            msg = (
                "Auth extension OpenAPI security scheme "
                f"{contribution.name!r} from extension {contribution.extension_name!r} conflicts with extension "
                f"{owner!r}."
            )
            raise ValueError(msg)
        owners[contribution.name] = contribution.extension_name
        schemes[contribution.name] = contribution.scheme

    if not schemes or not app_config.openapi_config:
        return schemes

    from litestar_auth._plugin.openapi import merge_openapi_security_components  # noqa: PLC0415

    merge_openapi_security_components(app_config, schemes)
    return schemes


def build_extension_controllers(
    *,
    contributions: ExtensionRegistrationContributions,
) -> list[ControllerRouterHandler]:
    """Return extension-contributed route handlers in contribution order."""
    return list(cast("Sequence[ControllerRouterHandler]", contributions.controllers))


def register_extension_exception_handlers(
    app_config: AppConfig,
    *,
    contributions: ExtensionRegistrationContributions,
) -> None:
    """Register extension-contributed app-level exception handlers."""
    for contribution in contributions.exception_handlers:
        app_config.exception_handlers[contribution.key] = cast("ExceptionHandler", contribution.handler)


__all__ = (
    "apply_extension_middleware",
    "build_extension_controllers",
    "register_extension_exception_handlers",
    "register_extension_openapi_security",
    "register_extensions",
    "validate_extensions",
)
