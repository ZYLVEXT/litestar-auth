"""Framework-neutral workload authentication."""

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
    StoreUnavailableError,
    WorkloadStore,
)

__version__ = "7.0.0"

__all__ = (
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
    "ResolvedMachineIdentity",
    "SecurityEvent",
    "SecurityEventType",
    "ServiceApplication",
    "ServiceApplicationStore",
    "StoreConflictError",
    "StoreUnavailableError",
    "WorkloadLifecycleService",
    "WorkloadRateLimitIdentity",
    "WorkloadStore",
    "__version__",
    "rate_limit_identity",
)
