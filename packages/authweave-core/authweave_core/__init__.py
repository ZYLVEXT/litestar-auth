"""Framework-neutral principal authentication contracts."""

from authweave_core.coordinator import AuthenticationCoordinator, RequestAuthenticationProvider
from authweave_core.models import (
    Authenticated,
    AuthenticationContext,
    AuthenticationDecision,
    AuthenticationEvidence,
    AuthenticationRuntime,
    CredentialMatch,
    EvidenceValue,
    FailureCode,
    Invalid,
    InvariantFailure,
    NotApplicable,
    PrincipalRef,
    RequestView,
    RouteProviderPolicy,
    TlsPeerEvidence,
    Unavailable,
)

__version__ = "7.0.0"

__all__ = (
    "Authenticated",
    "AuthenticationContext",
    "AuthenticationCoordinator",
    "AuthenticationDecision",
    "AuthenticationEvidence",
    "AuthenticationRuntime",
    "CredentialMatch",
    "EvidenceValue",
    "FailureCode",
    "Invalid",
    "InvariantFailure",
    "NotApplicable",
    "PrincipalRef",
    "RequestAuthenticationProvider",
    "RequestView",
    "RouteProviderPolicy",
    "TlsPeerEvidence",
    "Unavailable",
    "__version__",
)
