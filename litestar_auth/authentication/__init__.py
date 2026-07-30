"""Authentication package."""

from litestar_auth.authentication.human_session import HumanSessionProvider
from litestar_auth.authentication.middleware import (
    AUTHENTICATION_PROVIDERS_KEY,
    CorrelationIdFactory,
    LitestarAuthMiddleware,
    LitestarAuthMiddlewareConfig,
    LitestarProviderBinding,
    TlsPeerEvidenceFactory,
    route_provider_policy,
)

__all__ = (
    "AUTHENTICATION_PROVIDERS_KEY",
    "CorrelationIdFactory",
    "HumanSessionProvider",
    "LitestarAuthMiddleware",
    "LitestarAuthMiddlewareConfig",
    "LitestarProviderBinding",
    "TlsPeerEvidenceFactory",
    "route_provider_policy",
)
