"""Authentication package."""

from litestar_auth.authentication.human_session import HumanSessionProvider
from litestar_auth.authentication.middleware import (
    AUTHENTICATION_PROVIDERS_KEY,
    CorrelationIdFactory,
    ExternalRequestTargetFactory,
    LitestarAuthMiddleware,
    LitestarAuthMiddlewareConfig,
    LitestarProviderBinding,
    SpiffePeerEvidenceFactory,
    TlsPeerEvidenceFactory,
    build_direct_request_target,
    route_provider_policy,
)

__all__ = (
    "AUTHENTICATION_PROVIDERS_KEY",
    "CorrelationIdFactory",
    "ExternalRequestTargetFactory",
    "HumanSessionProvider",
    "LitestarAuthMiddleware",
    "LitestarAuthMiddlewareConfig",
    "LitestarProviderBinding",
    "SpiffePeerEvidenceFactory",
    "TlsPeerEvidenceFactory",
    "build_direct_request_target",
    "route_provider_policy",
)
