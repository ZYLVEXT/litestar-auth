"""Internal package boundary for auth extension contracts and contexts."""

from __future__ import annotations

from litestar_auth._plugin.extensions._context import (
    ExtensionDependencyContribution,
    ExtensionDependencyKeys,
    ExtensionExceptionHandlerContribution,
    ExtensionOpenAPISecurityContribution,
    ExtensionRegistrationContext,
    ExtensionRegistrationContributions,
    ExtensionValidationContext,
    build_extension_registration_context,
    build_extension_validation_context,
)
from litestar_auth._plugin.extensions._contracts import (
    EXTENSION_API_VERSION,
    EXTENSION_ENTRY_POINT_GROUP,
    AuthCliExtension,
    AuthEventSubscriberExtension,
    AuthExtension,
    AuthExtensionRegistrationContext,
    AuthExtensionValidationContext,
)
from litestar_auth._plugin.extensions._registry import (
    apply_extension_middleware,
    build_extension_controllers,
    register_extension_exception_handlers,
    register_extension_openapi_security,
    register_extensions,
    resolve_version_gated_extensions,
    validate_extensions,
)

__all__ = (
    "EXTENSION_API_VERSION",
    "EXTENSION_ENTRY_POINT_GROUP",
    "AuthCliExtension",
    "AuthEventSubscriberExtension",
    "AuthExtension",
    "AuthExtensionRegistrationContext",
    "AuthExtensionValidationContext",
    "ExtensionDependencyContribution",
    "ExtensionDependencyKeys",
    "ExtensionExceptionHandlerContribution",
    "ExtensionOpenAPISecurityContribution",
    "ExtensionRegistrationContext",
    "ExtensionRegistrationContributions",
    "ExtensionValidationContext",
    "apply_extension_middleware",
    "build_extension_controllers",
    "build_extension_registration_context",
    "build_extension_validation_context",
    "register_extension_exception_handlers",
    "register_extension_openapi_security",
    "register_extensions",
    "resolve_version_gated_extensions",
    "validate_extensions",
)
