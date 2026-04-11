"""OpenAPI security scheme derivation and registration for the auth plugin."""

from __future__ import annotations

from copy import copy
from typing import TYPE_CHECKING, Any, cast

from litestar.openapi.spec import Components, SecurityScheme

from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport

if TYPE_CHECKING:
    from litestar.config.app import AppConfig
    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth._plugin.config import StartupBackendTemplate
    from litestar_auth.types import StrategyProtocol, TransportProtocol


def security_scheme_for_transport(
    transport: TransportProtocol,
    *,
    strategy: StrategyProtocol[Any, Any] | None = None,
) -> SecurityScheme:
    """Derive an OpenAPI ``SecurityScheme`` from a transport and optional strategy.

    Args:
        transport: The authentication transport to derive a scheme from.
        strategy: Optional strategy used to refine the scheme (e.g. JWT bearer format).

    Returns:
        A ``SecurityScheme`` matching the transport's authentication mechanism.

    Raises:
        TypeError: If the transport type is not supported for OpenAPI scheme derivation.
    """
    if isinstance(transport, BearerTransport):
        bearer_format = "JWT" if isinstance(strategy, JWTStrategy) else None
        return SecurityScheme(
            type="http",
            scheme="Bearer",
            bearer_format=bearer_format,
            description="Bearer token authentication.",
        )

    if isinstance(transport, CookieTransport):
        return SecurityScheme(
            type="apiKey",
            name=transport.cookie_name,
            security_scheme_in="cookie",
            description="Cookie-based authentication.",
        )

    msg = f"Unsupported transport type for OpenAPI security scheme: {type(transport).__name__}"
    raise TypeError(msg)


def build_openapi_security_schemes(
    backends: tuple[StartupBackendTemplate[Any, Any], ...],
) -> dict[str, SecurityScheme]:
    """Build a mapping of backend names to OpenAPI security schemes.

    Args:
        backends: Startup backend templates to derive schemes from.

    Returns:
        Dictionary keyed by backend name with corresponding security schemes.
    """
    return {
        backend.name: security_scheme_for_transport(backend.transport, strategy=backend.strategy)
        for backend in backends
    }


def build_security_requirement(
    security_schemes: dict[str, SecurityScheme],
) -> list[SecurityRequirement]:
    """Build an OpenAPI security requirement representing any-of the registered schemes.

    OpenAPI uses OR semantics across entries in the ``security`` list and AND
    semantics across keys within a single ``SecurityRequirement`` object.

    Args:
        security_schemes: The registered scheme names.

    Returns:
        A list containing one requirement per scheme so any configured backend
        can authorize the operation independently.
    """
    if not security_schemes:
        return []
    return [{name: []} for name in security_schemes]


def register_openapi_security(
    app_config: AppConfig,
    backends: tuple[StartupBackendTemplate[Any, Any], ...],
) -> dict[str, SecurityScheme]:
    """Register OpenAPI security schemes derived from auth backends.

    Merges ``Components(security_schemes=...)`` into ``app_config.openapi_config``
    following the same pattern as Litestar's ``AbstractSecurityConfig.on_app_init``.

    Does **not** set a global security requirement — security is applied per-route.

    Args:
        app_config: The Litestar application config being initialized.
        backends: Startup backend templates to derive schemes from.

    Returns:
        The registered security schemes dict (for threading to controller factories).
    """
    schemes = build_openapi_security_schemes(backends)
    if not schemes:
        return schemes

    if not app_config.openapi_config:
        return schemes

    app_config.openapi_config = copy(app_config.openapi_config)
    components = Components(security_schemes=cast("Any", schemes))

    if isinstance(app_config.openapi_config.components, list):
        cast("list[Components]", app_config.openapi_config.components).append(components)
    else:
        app_config.openapi_config.components = [components, app_config.openapi_config.components]

    return schemes
