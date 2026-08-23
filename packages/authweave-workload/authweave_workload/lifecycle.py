"""Headless workload registration and credential lifecycle service."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING
from uuid import uuid4

from authweave_core import PrincipalRef

from authweave_workload.events import SecurityEvent, SecurityEventType
from authweave_workload.models import (
    CertificateMetadata,
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ServiceApplication,
    WorkloadPage,
    freeze_metadata,
)
from authweave_workload.stores import StoreConflictError, StoreOwnerStateConflictError

_MAX_REVOCATION_REASON_LENGTH = 128
_APPLICATION_DISABLED = "application is disabled"
_CREDENTIAL_ENVIRONMENT_MISMATCH = "credential environment does not match its application"
_CREDENTIAL_OWNER_DISABLED = "credential owner is disabled"
_EMPTY_METADATA: Mapping[str, str] = MappingProxyType({})
_MAX_QUERY_PAGE_SIZE = 100

if TYPE_CHECKING:
    from authweave_workload.stores import WorkloadStore

type EventRecorder = Callable[[SecurityEvent], object]


def _validate_query_page(*, offset: int, limit: int) -> None:
    if offset < 0 or limit < 1 or limit > _MAX_QUERY_PAGE_SIZE:
        msg = f"offset must be non-negative and limit must be between 1 and {_MAX_QUERY_PAGE_SIZE}"
        raise ValueError(msg)


class LifecycleConflictError(Exception):
    """Raised when a requested lifecycle transition is invalid."""


class WorkloadLifecycleService:
    """Perform explicit application, principal, and public credential transitions."""

    def __init__(
        self,
        store: WorkloadStore,
        *,
        issuer: str,
        actor: PrincipalRef,
        correlation_id: str,
        event_recorder: EventRecorder,
        active_credential_limit: int = 4,
        maximum_rotation_lead: timedelta = timedelta(days=7),
    ) -> None:
        """Bind persistence and bounded lifecycle policy.

        Raises:
            ValueError: If the call cannot complete.
        """
        if active_credential_limit < 1:
            msg = "active_credential_limit must be positive"
            raise ValueError(msg)
        if maximum_rotation_lead <= timedelta(0):
            msg = "maximum_rotation_lead must be positive"
            raise ValueError(msg)
        self.store = store
        self.issuer = issuer
        self.actor = actor
        self.correlation_id = correlation_id
        self.event_recorder = event_recorder
        self.active_credential_limit = active_credential_limit
        self.maximum_rotation_lead = maximum_rotation_lead

    async def list_applications(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        owner_ref: str | None = None,
        environment: str | None = None,
        status: EntityStatus | None = None,
    ) -> WorkloadPage[ServiceApplication]:
        """Return a bounded deterministic application inventory page."""
        _validate_query_page(offset=offset, limit=limit)
        items, total = await self.store.list_applications(
            offset=offset,
            limit=limit,
            owner_ref=owner_ref,
            environment=environment,
            status=status,
        )
        return WorkloadPage(items=items, total=total, limit=limit, offset=offset)

    async def list_principals(
        self,
        *,
        application_id: str,
        offset: int = 0,
        limit: int = 50,
        status: EntityStatus | None = None,
    ) -> WorkloadPage[MachinePrincipal]:
        """Return a bounded deterministic principal inventory page for one application."""
        _validate_query_page(offset=offset, limit=limit)
        items, total = await self.store.list_principals(
            application_id=application_id,
            offset=offset,
            limit=limit,
            status=status,
        )
        return WorkloadPage(items=items, total=total, limit=limit, offset=offset)

    async def create_application(
        self,
        *,
        application_id: str,
        environment: str,
        owner_ref: str,
        metadata: Mapping[str, str] = _EMPTY_METADATA,
    ) -> tuple[ServiceApplication, SecurityEvent]:
        """Create an enabled service application.

        Returns:
            The created application.
        """
        application = ServiceApplication(
            id=application_id,
            status=EntityStatus.ACTIVE,
            environment=environment,
            owner_ref=owner_ref,
            metadata=metadata,
        )
        await self.store.create_application(application)
        event = SecurityEvent(
            SecurityEventType.APPLICATION_CREATED,
            target_application_id=application.id,
        )
        event = await self._record(event)
        return application, event

    async def set_application_enabled(
        self,
        application_id: str,
        *,
        enabled: bool,
    ) -> tuple[ServiceApplication, SecurityEvent]:
        """Enable or disable one application.

        Returns:
            The set application enabled.

        Raises:
            LifecycleConflictError: If the call cannot complete.
        """
        application = await self.store.get_application(application_id)
        if application is None:
            msg = "application does not exist"
            raise LifecycleConflictError(msg)
        status = EntityStatus.ACTIVE if enabled else EntityStatus.DISABLED
        updated = replace(application, status=status)
        await self.store.set_application_status(application_id, status)
        event = SecurityEvent(
            SecurityEventType.APPLICATION_ENABLED if enabled else SecurityEventType.APPLICATION_DISABLED,
            target_application_id=application_id,
        )
        event = await self._record(event)
        return updated, event

    async def create_principal(
        self,
        *,
        principal_id: str,
        application_id: str,
        subject: str,
        kind: str,
        metadata: Mapping[str, str] = _EMPTY_METADATA,
    ) -> tuple[MachinePrincipal, SecurityEvent]:
        """Create an enabled machine principal under an existing application.

        Returns:
            The created principal.

        Raises:
            LifecycleConflictError: If the call cannot complete.
        """
        application = await self.store.get_application(application_id)
        if application is None:
            msg = "application does not exist"
            raise LifecycleConflictError(msg)
        if application.status is not EntityStatus.ACTIVE:
            raise LifecycleConflictError(_APPLICATION_DISABLED)
        principal = MachinePrincipal(
            id=principal_id,
            application_id=application_id,
            ref=PrincipalRef(self.issuer, subject, kind),
            status=EntityStatus.ACTIVE,
            metadata=metadata,
        )
        try:
            await self.store.create_principal(principal)
        except StoreOwnerStateConflictError as exc:
            raise LifecycleConflictError(str(exc)) from exc
        event = SecurityEvent(
            SecurityEventType.PRINCIPAL_CREATED,
            target_application_id=application_id,
            target_principal=principal.ref,
        )
        event = await self._record(event)
        return principal, event

    async def set_principal_enabled(
        self,
        principal_id: str,
        *,
        enabled: bool,
    ) -> tuple[MachinePrincipal, SecurityEvent]:
        """Enable or disable one machine principal.

        Returns:
            The set principal enabled.

        Raises:
            LifecycleConflictError: If the call cannot complete.
        """
        principal = await self.store.get_principal(principal_id)
        if principal is None:
            msg = "principal does not exist"
            raise LifecycleConflictError(msg)
        updated = replace(principal, status=EntityStatus.ACTIVE if enabled else EntityStatus.DISABLED)
        await self.store.set_principal_status(principal_id, updated.status)
        event = SecurityEvent(
            SecurityEventType.PRINCIPAL_ENABLED if enabled else SecurityEventType.PRINCIPAL_DISABLED,
            target_application_id=principal.application_id,
            target_principal=principal.ref,
        )
        event = await self._record(event)
        return updated, event

    async def register_credential(
        self,
        *,
        principal_id: str,
        certificate: CertificateMetadata,
        scopes: tuple[str, ...],
        audiences: tuple[str, ...],
        environment: str,
        metadata: Mapping[str, str] = _EMPTY_METADATA,
        rotation_of: str | None = None,
        now: datetime | None = None,
    ) -> tuple[MachineCredential, SecurityEvent]:
        """Register validated public certificate metadata without retaining certificate bytes.

        Returns:
            The register credential.

        Raises:
            ValueError: If the call cannot complete.
            LifecycleConflictError: If the call cannot complete.
        """
        current_time = datetime.now(UTC) if now is None else now
        if current_time.utcoffset() is None:
            msg = "now must be timezone-aware"
            raise ValueError(msg)
        principal = await self.store.get_principal(principal_id)
        if principal is None:
            msg_0 = "principal does not exist"
            raise LifecycleConflictError(msg_0)
        application = await self.store.get_application(principal.application_id)
        if application is None or application.environment != environment:
            raise LifecycleConflictError(_CREDENTIAL_ENVIRONMENT_MISMATCH)
        if application.status is not EntityStatus.ACTIVE or principal.status is not EntityStatus.ACTIVE:
            raise LifecycleConflictError(_CREDENTIAL_OWNER_DISABLED)
        if certificate.not_before > current_time:
            if rotation_of is None or certificate.not_before - current_time > self.maximum_rotation_lead:
                msg_0 = "future-dated certificate is outside the rotation window"
                raise LifecycleConflictError(msg_0)
            status = CredentialStatus.PENDING
        else:
            status = CredentialStatus.ACTIVE
        if certificate.not_after <= current_time:
            msg_0 = "expired certificate cannot be registered"
            raise LifecycleConflictError(msg_0)
        if rotation_of is not None:
            previous = await self.store.get_credential(rotation_of)
            if previous is None or previous.principal_id != principal_id:
                msg_0 = "rotation source does not belong to the principal"
                raise LifecycleConflictError(msg_0)
        credential = MachineCredential(
            id=str(uuid4()),
            principal_id=principal_id,
            status=status,
            certificate_thumbprint=certificate.thumbprint,
            trust_anchor=certificate.trust_anchor,
            scopes=scopes,
            audiences=audiences,
            environment=environment,
            not_before=certificate.not_before,
            expires_at=certificate.not_after,
            subject_dn=certificate.subject_dn,
            issuer_dn=certificate.issuer_dn,
            serial_number=certificate.serial_number,
            rotation_of=rotation_of,
            metadata=freeze_metadata(metadata),
        )
        await self._register_credential(credential)
        event = SecurityEvent(
            SecurityEventType.CREDENTIAL_ROTATION_STARTED
            if rotation_of is not None
            else SecurityEventType.CREDENTIAL_REGISTERED,
            target_application_id=principal.application_id,
            target_principal=principal.ref,
            credential_id=credential.id,
        )
        event = await self._record(event)
        return credential, event

    async def _register_credential(self, credential: MachineCredential) -> None:
        """Persist one credential while preserving lifecycle conflict errors.

        Raises:
            LifecycleConflictError: If the call cannot complete.
        """
        try:
            await self.store.register_credential(credential, active_limit=self.active_credential_limit)
        except StoreOwnerStateConflictError as exc:
            raise LifecycleConflictError(str(exc)) from exc

    async def revoke_credential(
        self,
        credential_id: str,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> tuple[MachineCredential, SecurityEvent]:
        """Revoke one credential immediately.

        Returns:
            The revoke credential.

        Raises:
            ValueError: If the call cannot complete.
            LifecycleConflictError: If the call cannot complete.
        """
        if not reason or reason != reason.strip() or len(reason) > _MAX_REVOCATION_REASON_LENGTH:
            msg = f"revocation reason must be non-empty and at most {_MAX_REVOCATION_REASON_LENGTH} characters"
            raise ValueError(msg)
        revoked_at = datetime.now(UTC) if now is None else now
        if revoked_at.utcoffset() is None:
            msg = "now must be timezone-aware"
            raise ValueError(msg)
        try:
            updated = await self.store.revoke_credential(
                credential_id,
                reason=reason,
                revoked_at=revoked_at,
            )
        except StoreConflictError as exc:
            msg_0 = "credential does not exist or is already revoked"
            raise LifecycleConflictError(msg_0) from exc
        principal = await self.store.get_principal(updated.principal_id)
        event = SecurityEvent(
            SecurityEventType.CREDENTIAL_REVOKED,
            target_application_id=None if principal is None else principal.application_id,
            target_principal=None if principal is None else principal.ref,
            credential_id=updated.id,
        )
        event = await self._record(event)
        return updated, event

    async def complete_rotation(
        self,
        *,
        new_credential_id: str,
        previous_credential_id: str,
        now: datetime | None = None,
    ) -> tuple[MachineCredential, MachineCredential, SecurityEvent]:
        """Activate a valid replacement and revoke its predecessor.

        Returns:
            The complete rotation.

        Raises:
            ValueError: If the call cannot complete.
            LifecycleConflictError: If the call cannot complete.
        """
        current_time = datetime.now(UTC) if now is None else now
        if current_time.utcoffset() is None:
            msg = "now must be timezone-aware"
            raise ValueError(msg)
        try:
            activated, revoked = await self.store.complete_rotation(
                new_credential_id,
                previous_credential_id,
                completed_at=current_time,
            )
        except StoreConflictError as exc:
            raise LifecycleConflictError(str(exc)) from exc
        principal = await self.store.get_principal(activated.principal_id)
        event = SecurityEvent(
            SecurityEventType.CREDENTIAL_ROTATION_COMPLETED,
            target_application_id=None if principal is None else principal.application_id,
            target_principal=None if principal is None else principal.ref,
            credential_id=activated.id,
        )
        event = await self._record(event)
        return activated, revoked, event

    async def list_credentials(self, principal_id: str) -> tuple[MachineCredential, ...]:
        """Return safe registered metadata for one principal."""
        return await self.store.list_credentials(principal_id)

    async def update_application_metadata(
        self,
        application_id: str,
        metadata: Mapping[str, str],
    ) -> tuple[ServiceApplication, SecurityEvent]:
        """Replace bounded safe application metadata.

        Returns:
            The update application metadata.

        Raises:
            LifecycleConflictError: If the call cannot complete.
        """
        application = await self.store.get_application(application_id)
        if application is None:
            msg = "application does not exist"
            raise LifecycleConflictError(msg)
        frozen = freeze_metadata(metadata)
        updated = replace(application, metadata=frozen)
        await self.store.set_application_metadata(application_id, frozen)
        event = SecurityEvent(
            SecurityEventType.APPLICATION_METADATA_UPDATED,
            target_application_id=application_id,
        )
        event = await self._record(event)
        return updated, event

    async def update_principal_metadata(
        self,
        principal_id: str,
        metadata: Mapping[str, str],
    ) -> tuple[MachinePrincipal, SecurityEvent]:
        """Replace bounded safe principal metadata.

        Returns:
            The update principal metadata.

        Raises:
            LifecycleConflictError: If the call cannot complete.
        """
        principal = await self.store.get_principal(principal_id)
        if principal is None:
            msg = "principal does not exist"
            raise LifecycleConflictError(msg)
        frozen = freeze_metadata(metadata)
        updated = replace(principal, metadata=frozen)
        await self.store.set_principal_metadata(principal_id, frozen)
        event = SecurityEvent(
            SecurityEventType.PRINCIPAL_METADATA_UPDATED,
            target_application_id=principal.application_id,
            target_principal=principal.ref,
        )
        event = await self._record(event)
        return updated, event

    async def _record(self, event: SecurityEvent) -> SecurityEvent:
        event = replace(event, actor=self.actor, correlation_id=self.correlation_id)
        result = self.event_recorder(event)
        if inspect.isawaitable(result):
            await result
        return event


__all__ = ("EventRecorder", "LifecycleConflictError", "WorkloadLifecycleService")
