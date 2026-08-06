"""Persistence contracts for workload registrations and credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from authweave_workload.models import (
        EntityStatus,
        MachineCredential,
        MachinePrincipal,
        ResolvedMachineIdentity,
        ServiceApplication,
    )


class StoreUnavailableError(Exception):
    """Raised when persistence cannot safely complete an authentication lookup."""


class StoreConflictError(Exception):
    """Raised when a persistence uniqueness or lifecycle invariant is violated."""


class StoreOwnerStateConflictError(StoreConflictError):
    """Raised when a concurrently revalidated owner no longer permits a write."""


@runtime_checkable
class ServiceApplicationStore(Protocol):
    """Persistence operations for application registrations."""

    async def create_application(self, application: ServiceApplication) -> None: ...

    async def get_application(self, application_id: str) -> ServiceApplication | None: ...

    async def set_application_status(self, application_id: str, status: EntityStatus) -> None: ...

    async def set_application_metadata(self, application_id: str, metadata: Mapping[str, str]) -> None: ...

    async def list_applications(
        self,
        *,
        offset: int,
        limit: int,
        owner_ref: str | None = None,
        environment: str | None = None,
        status: EntityStatus | None = None,
    ) -> tuple[tuple[ServiceApplication, ...], int]:
        """Return one page of applications and the matching total count."""

@runtime_checkable
class MachinePrincipalStore(Protocol):
    """Persistence operations for machine principals."""

    async def create_principal(self, principal: MachinePrincipal) -> None:
        """Persist only when the owning application is active at write time."""
        ...

    async def get_principal(self, principal_id: str) -> MachinePrincipal | None: ...

    async def set_principal_status(self, principal_id: str, status: EntityStatus) -> None: ...

    async def set_principal_metadata(self, principal_id: str, metadata: Mapping[str, str]) -> None: ...

    async def list_principals(
        self,
        *,
        application_id: str,
        offset: int,
        limit: int,
        status: EntityStatus | None = None,
    ) -> tuple[tuple[MachinePrincipal, ...], int]:
        """Return one page of principals and the matching total count."""

@runtime_checkable
class MachineCredentialStore(Protocol):
    """Persistence operations requiring atomic credential lifecycle semantics."""

    async def register_credential(self, credential: MachineCredential, *, active_limit: int) -> None:
        """Recheck active application/principal state before enforcing the limit and inserting."""
        ...

    async def get_credential(self, credential_id: str) -> MachineCredential | None: ...

    async def revoke_credential(
        self,
        credential_id: str,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> MachineCredential: ...

    async def list_credentials(self, principal_id: str) -> tuple[MachineCredential, ...]: ...

    async def resolve_by_thumbprint(self, thumbprint: str) -> ResolvedMachineIdentity | None: ...

    async def record_last_used(self, credential_id: str, *, used_at_epoch: int, minimum_interval: int) -> None: ...

    async def complete_rotation(
        self,
        replacement_id: str,
        previous_id: str,
        *,
        completed_at: datetime,
    ) -> tuple[MachineCredential, MachineCredential]: ...


class WorkloadStore(ServiceApplicationStore, MachinePrincipalStore, MachineCredentialStore, Protocol):
    """Combined transactional store used by lifecycle services."""


__all__ = (
    "MachineCredentialStore",
    "MachinePrincipalStore",
    "ServiceApplicationStore",
    "StoreConflictError",
    "StoreUnavailableError",
    "WorkloadStore",
)
