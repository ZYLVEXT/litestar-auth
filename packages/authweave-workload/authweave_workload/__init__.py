"""Framework-neutral workload authentication."""

from authweave_workload.authorization_details import (
    PAYMENT_AUTHORIZATION_TYPE,
    PaymentAction,
    PaymentAuthorizationDetail,
    PaymentAuthorizationError,
    PaymentAuthorizationPolicy,
    find_payment_authorization,
    parse_payment_authorization_details,
    validate_payment_authorization_narrowing,
)
from authweave_workload.events import SecurityEvent, SecurityEventType
from authweave_workload.lifecycle import EventRecorder, LifecycleConflictError, WorkloadLifecycleService
from authweave_workload.models import (
    CertificateMetadata,
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ResolvedMachineIdentity,
    ServiceApplication,
)
from authweave_workload.provider import DirectMTLSPolicy, DirectMTLSProvider
from authweave_workload.rate_limit import WorkloadRateLimitIdentity, rate_limit_identity
from authweave_workload.stores import (
    MachineCredentialStore,
    MachinePrincipalStore,
    ServiceApplicationStore,
    StoreConflictError,
    StoreOwnerStateConflictError,
    StoreUnavailableError,
    WorkloadStore,
)

__version__ = "7.1.2"

__all__ = (
    "PAYMENT_AUTHORIZATION_TYPE",
    "CertificateMetadata",
    "CredentialStatus",
    "DirectMTLSPolicy",
    "DirectMTLSProvider",
    "EntityStatus",
    "EventRecorder",
    "LifecycleConflictError",
    "MachineCredential",
    "MachineCredentialStore",
    "MachinePrincipal",
    "MachinePrincipalStore",
    "PaymentAction",
    "PaymentAuthorizationDetail",
    "PaymentAuthorizationError",
    "PaymentAuthorizationPolicy",
    "ResolvedMachineIdentity",
    "SecurityEvent",
    "SecurityEventType",
    "ServiceApplication",
    "ServiceApplicationStore",
    "StoreConflictError",
    "StoreOwnerStateConflictError",
    "StoreUnavailableError",
    "WorkloadLifecycleService",
    "WorkloadRateLimitIdentity",
    "WorkloadStore",
    "__version__",
    "find_payment_authorization",
    "parse_payment_authorization_details",
    "rate_limit_identity",
    "validate_payment_authorization_narrowing",
)
