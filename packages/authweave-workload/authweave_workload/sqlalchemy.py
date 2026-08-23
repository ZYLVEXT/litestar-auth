"""SQLAlchemy 2 persistence for workload registrations."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from authweave_core import PrincipalRef
from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from authweave_workload.models import (
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ResolvedMachineIdentity,
    ServiceApplication,
)
from authweave_workload.stores import StoreConflictError, StoreOwnerStateConflictError, StoreUnavailableError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import AsyncSession


class WorkloadBase(DeclarativeBase):
    """Reference declarative base for workload tables."""


class ServiceApplicationRow(WorkloadBase):
    """Persisted service application."""

    __tablename__ = "authweave_workload_application"
    __table_args__ = (CheckConstraint("status IN ('active', 'disabled')"),)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    owner_ref: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    safe_metadata: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)


class MachinePrincipalRow(WorkloadBase):
    """Persisted machine principal."""

    __tablename__ = "authweave_workload_principal"
    __table_args__ = (
        CheckConstraint("kind <> 'human'"),
        CheckConstraint("status IN ('active', 'disabled')"),
        UniqueConstraint("issuer", "subject", name="uq_authweave_workload_principal_identity"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("authweave_workload_application.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    safe_metadata: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)


class MachineCredentialRow(WorkloadBase):
    """Persisted public X.509 credential identity."""

    __tablename__ = "authweave_workload_credential"
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'active', 'revoked')"),
        CheckConstraint("not_before < expires_at"),
        CheckConstraint("(status = 'revoked') = (revoked_at IS NOT NULL)"),
        CheckConstraint("(status = 'revoked') = (revocation_reason IS NOT NULL)"),
        Index("ix_authweave_workload_credential_principal_status", "principal_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_id: Mapped[str] = mapped_column(
        ForeignKey("authweave_workload_principal.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    certificate_thumbprint: Mapped[str] = mapped_column(String(43), nullable=False, unique=True, index=True)
    trust_anchor: Mapped[str] = mapped_column(String(128), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    audiences: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    subject_dn: Mapped[str] = mapped_column(String(2048), nullable=False)
    issuer_dn: Mapped[str] = mapped_column(String(2048), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(2048), nullable=False)
    rotation_of: Mapped[str | None] = mapped_column(
        ForeignKey("authweave_workload_credential.id", ondelete="SET NULL"),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    safe_metadata: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)


class SQLAlchemyWorkloadStore:
    """Request-scoped async SQLAlchemy implementation of the workload store."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind one application-owned transaction."""
        self.session = session

    async def create_application(self, application: ServiceApplication) -> None:
        """Insert one application."""
        self.session.add(_application_row(application))
        await self._flush_conflict("application already exists")

    async def get_application(self, application_id: str) -> ServiceApplication | None:
        """Return one application by public ID."""
        row = await self.session.get(ServiceApplicationRow, application_id)
        return None if row is None else _application(row)

    async def list_applications(
        self,
        *,
        offset: int,
        limit: int,
        owner_ref: str | None = None,
        environment: str | None = None,
        status: EntityStatus | None = None,
    ) -> tuple[tuple[ServiceApplication, ...], int]:
        """Return a deterministic filtered page and total application count.

        Raises:
            StoreUnavailableError: If the call cannot complete.
        """
        filters = []
        if owner_ref is not None:
            filters.append(ServiceApplicationRow.owner_ref == owner_ref)
        if environment is not None:
            filters.append(ServiceApplicationRow.environment == environment)
        if status is not None:
            filters.append(ServiceApplicationRow.status == status.value)
        try:
            total = await self.session.scalar(select(func.count()).select_from(ServiceApplicationRow).where(*filters))
            rows = (
                await self.session.scalars(
                    select(ServiceApplicationRow)
                    .where(*filters)
                    .order_by(ServiceApplicationRow.id)
                    .offset(offset)
                    .limit(limit),
                )
            ).all()
        except SQLAlchemyError as exc:
            msg = "workload application inventory lookup failed"
            raise StoreUnavailableError(msg) from exc
        return tuple(_application(row) for row in rows), int(total or 0)

    async def set_application_status(self, application_id: str, status: EntityStatus) -> None:
        """Update only application status, without replaying a stale aggregate.

        Raises:
            StoreConflictError: If the call cannot complete.
        """
        result = cast(
            "CursorResult[Any]",
            await self.session.execute(
                update(ServiceApplicationRow)
                .where(ServiceApplicationRow.id == application_id)
                .values(status=status.value),
            ),
        )
        if result.rowcount != 1:
            msg = "application does not exist"
            raise StoreConflictError(msg)

    async def set_application_metadata(self, application_id: str, metadata: Mapping[str, str]) -> None:
        """Update only application metadata, preserving concurrent status changes.

        Raises:
            StoreConflictError: If the call cannot complete.
        """
        result = cast(
            "CursorResult[Any]",
            await self.session.execute(
                update(ServiceApplicationRow)
                .where(ServiceApplicationRow.id == application_id)
                .values(safe_metadata=dict(metadata)),
            ),
        )
        if result.rowcount != 1:
            msg = "application does not exist"
            raise StoreConflictError(msg)

    async def create_principal(self, principal: MachinePrincipal) -> None:
        """Insert one principal while serializing against application disablement.

        Raises:
            StoreOwnerStateConflictError: If the call cannot complete.
        """
        application = await self.session.scalar(
            select(ServiceApplicationRow)
            .where(ServiceApplicationRow.id == principal.application_id)
            .with_for_update()
            .execution_options(populate_existing=True),
        )
        if application is None:
            msg = "application does not exist"
            raise StoreOwnerStateConflictError(msg)
        if application.status != EntityStatus.ACTIVE.value:
            msg = "application is disabled"
            raise StoreOwnerStateConflictError(msg)
        self.session.add(_principal_row(principal))
        await self._flush_conflict("principal already exists")

    async def get_principal(self, principal_id: str) -> MachinePrincipal | None:
        """Return one principal by public ID."""
        row = await self.session.get(MachinePrincipalRow, principal_id)
        return None if row is None else _principal(row)

    async def list_principals(
        self,
        *,
        application_id: str,
        offset: int,
        limit: int,
        status: EntityStatus | None = None,
    ) -> tuple[tuple[MachinePrincipal, ...], int]:
        """Return a deterministic filtered page and total principal count.

        Raises:
            StoreUnavailableError: If the call cannot complete.
        """
        filters = [MachinePrincipalRow.application_id == application_id]
        if status is not None:
            filters.append(MachinePrincipalRow.status == status.value)
        try:
            total = await self.session.scalar(select(func.count()).select_from(MachinePrincipalRow).where(*filters))
            rows = (
                await self.session.scalars(
                    select(MachinePrincipalRow)
                    .where(*filters)
                    .order_by(MachinePrincipalRow.id)
                    .offset(offset)
                    .limit(limit),
                )
            ).all()
        except SQLAlchemyError as exc:
            msg = "workload principal inventory lookup failed"
            raise StoreUnavailableError(msg) from exc
        return tuple(_principal(row) for row in rows), int(total or 0)

    async def set_principal_status(self, principal_id: str, status: EntityStatus) -> None:
        """Update only principal status, without replaying a stale aggregate.

        Raises:
            StoreConflictError: If the call cannot complete.
        """
        result = cast(
            "CursorResult[Any]",
            await self.session.execute(
                update(MachinePrincipalRow).where(MachinePrincipalRow.id == principal_id).values(status=status.value),
            ),
        )
        if result.rowcount != 1:
            msg = "principal does not exist"
            raise StoreConflictError(msg)

    async def set_principal_metadata(self, principal_id: str, metadata: Mapping[str, str]) -> None:
        """Update only principal metadata, preserving concurrent status changes.

        Raises:
            StoreConflictError: If the call cannot complete.
        """
        result = cast(
            "CursorResult[Any]",
            await self.session.execute(
                update(MachinePrincipalRow)
                .where(MachinePrincipalRow.id == principal_id)
                .values(safe_metadata=dict(metadata)),
            ),
        )
        if result.rowcount != 1:
            msg = "principal does not exist"
            raise StoreConflictError(msg)

    async def register_credential(self, credential: MachineCredential, *, active_limit: int) -> None:
        """Atomically validate the owner, enforce the active limit, and insert.

        Raises:
            StoreConflictError: If the call cannot complete.
            StoreOwnerStateConflictError: If the call cannot complete.
        """
        owner = (
            await self.session.execute(
                select(MachinePrincipalRow, ServiceApplicationRow)
                .join(
                    ServiceApplicationRow,
                    ServiceApplicationRow.id == MachinePrincipalRow.application_id,
                )
                .where(MachinePrincipalRow.id == credential.principal_id)
                .with_for_update()
                .execution_options(populate_existing=True),
            )
        ).one_or_none()
        if owner is None:
            msg = "principal does not exist"
            raise StoreOwnerStateConflictError(msg)
        principal, application = owner
        if application.status != EntityStatus.ACTIVE.value or principal.status != EntityStatus.ACTIVE.value:
            msg = "credential owner is disabled"
            raise StoreOwnerStateConflictError(msg)
        if application.environment != credential.environment:
            msg = "credential environment does not match its application"
            raise StoreOwnerStateConflictError(msg)
        active_count = await self.session.scalar(
            select(func.count())
            .select_from(MachineCredentialRow)
            .where(
                MachineCredentialRow.principal_id == credential.principal_id,
                MachineCredentialRow.status.in_((CredentialStatus.ACTIVE.value, CredentialStatus.PENDING.value)),
            ),
        )
        if int(active_count or 0) >= active_limit:
            msg = "active credential limit reached"
            raise StoreConflictError(msg)
        self.session.add(_credential_row(credential))
        await self._flush_conflict("credential already exists")

    async def get_credential(self, credential_id: str) -> MachineCredential | None:
        """Return one credential by public ID."""
        row = await self.session.get(MachineCredentialRow, credential_id)
        return None if row is None else _credential(row)

    async def revoke_credential(
        self,
        credential_id: str,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> MachineCredential:
        """Lock and revoke one non-revoked credential.

        Returns:
            The revoke credential.

        Raises:
            StoreConflictError: If the call cannot complete.
        """
        row = await self.session.scalar(
            select(MachineCredentialRow)
            .where(MachineCredentialRow.id == credential_id)
            .with_for_update()
            .execution_options(populate_existing=True),
        )
        if row is None or row.status == CredentialStatus.REVOKED.value:
            msg = "credential does not exist or is already revoked"
            raise StoreConflictError(msg)
        current = _credential(row)
        revoked = replace(
            current,
            status=CredentialStatus.REVOKED,
            revoked_at=revoked_at,
            revocation_reason=reason,
        )
        await self._update_credential(revoked, expected_status=current.status)
        return revoked

    async def list_credentials(self, principal_id: str) -> tuple[MachineCredential, ...]:
        """Return deterministic safe credential metadata for one principal."""
        rows = (
            await self.session.scalars(
                select(MachineCredentialRow)
                .where(MachineCredentialRow.principal_id == principal_id)
                .order_by(MachineCredentialRow.not_before, MachineCredentialRow.id),
            )
        ).all()
        return tuple(_credential(row) for row in rows)

    async def resolve_by_thumbprint(self, thumbprint: str) -> ResolvedMachineIdentity | None:
        """Atomically read credential, principal, and application status.

        Returns:
            The resolved by thumbprint.

        Raises:
            StoreUnavailableError: If the call cannot complete.
        """
        try:
            row = (
                await self.session.execute(
                    select(MachineCredentialRow, MachinePrincipalRow, ServiceApplicationRow)
                    .join(
                        MachinePrincipalRow,
                        MachinePrincipalRow.id == MachineCredentialRow.principal_id,
                    )
                    .join(
                        ServiceApplicationRow,
                        ServiceApplicationRow.id == MachinePrincipalRow.application_id,
                    )
                    .where(MachineCredentialRow.certificate_thumbprint == thumbprint),
                )
            ).one_or_none()
        except SQLAlchemyError as exc:
            msg = "workload identity lookup failed"
            raise StoreUnavailableError(msg) from exc
        if row is None:
            return None
        credential, principal, application = row
        try:
            return ResolvedMachineIdentity(
                application=_application(application),
                principal=_principal(principal),
                credential=_credential(credential),
            )
        except (TypeError, ValueError) as exc:
            msg = "workload identity data is invalid"
            raise StoreUnavailableError(msg) from exc

    async def record_last_used(self, credential_id: str, *, used_at_epoch: int, minimum_interval: int) -> None:
        """Update last-used at most once per configured interval.

        Raises:
            StoreUnavailableError: If the call cannot complete.
        """
        used_at = datetime.fromtimestamp(used_at_epoch, tz=UTC)
        threshold = datetime.fromtimestamp(used_at_epoch - minimum_interval, tz=UTC)
        try:
            await self.session.execute(
                update(MachineCredentialRow)
                .where(
                    MachineCredentialRow.id == credential_id,
                    or_(
                        MachineCredentialRow.last_used_at.is_(None),
                        MachineCredentialRow.last_used_at <= threshold,
                    ),
                )
                .values(last_used_at=used_at),
            )
        except SQLAlchemyError as exc:
            msg = "workload last-used update failed"
            raise StoreUnavailableError(msg) from exc

    async def complete_rotation(
        self,
        replacement_id: str,
        previous_id: str,
        *,
        completed_at: datetime,
    ) -> tuple[MachineCredential, MachineCredential]:
        """Validate and complete both sides of one rotation under row locks.

        Returns:
            The complete rotation.

        Raises:
            StoreConflictError: If the call cannot complete.
        """
        rows = (
            await self.session.scalars(
                select(MachineCredentialRow)
                .where(MachineCredentialRow.id.in_((replacement_id, previous_id)))
                .order_by(MachineCredentialRow.id)
                .with_for_update()
                .execution_options(populate_existing=True),
            )
        ).all()
        by_id = {row.id: row for row in rows}
        replacement_row = by_id.get(replacement_id)
        previous_row = by_id.get(previous_id)
        if replacement_row is None or previous_row is None:
            msg = "credentials do not form one rotation"
            raise StoreConflictError(msg)
        replacement = _credential(replacement_row)
        previous = _credential(previous_row)
        if (
            replacement.rotation_of != previous.id
            or replacement.principal_id != previous.principal_id
            or replacement.status not in {CredentialStatus.PENDING, CredentialStatus.ACTIVE}
            or previous.status is not CredentialStatus.ACTIVE
        ):
            msg = "credentials do not form one rotation"
            raise StoreConflictError(msg)
        if not (replacement.not_before <= completed_at < replacement.expires_at):
            msg = "replacement credential is not currently valid"
            raise StoreConflictError(msg)
        activated = replace(replacement, status=CredentialStatus.ACTIVE)
        revoked = replace(
            previous,
            status=CredentialStatus.REVOKED,
            revoked_at=completed_at,
            revocation_reason="rotation_completed",
        )
        await self._update_credential(activated, expected_status=replacement.status)
        await self._update_credential(revoked, expected_status=CredentialStatus.ACTIVE)
        return activated, revoked

    async def _update_credential(
        self,
        credential: MachineCredential,
        *,
        expected_status: CredentialStatus,
    ) -> None:
        result = cast(
            "CursorResult[Any]",
            await self.session.execute(
                update(MachineCredentialRow)
                .where(
                    MachineCredentialRow.id == credential.id,
                    MachineCredentialRow.status == expected_status.value,
                )
                .values(**_credential_values(credential)),
            ),
        )
        if result.rowcount != 1:
            msg = "credential state changed concurrently"
            raise StoreConflictError(msg)

    async def _flush_conflict(self, message: str) -> None:
        try:
            await self.session.flush()
        except IntegrityError as exc:
            raise StoreConflictError(message) from exc


def _application_row(value: ServiceApplication) -> ServiceApplicationRow:
    return ServiceApplicationRow(
        id=value.id,
        status=value.status.value,
        environment=value.environment,
        owner_ref=value.owner_ref,
        safe_metadata=dict(value.metadata),
    )


def _application(row: ServiceApplicationRow) -> ServiceApplication:
    return ServiceApplication(
        id=row.id,
        status=EntityStatus(row.status),
        environment=row.environment,
        owner_ref=row.owner_ref,
        metadata=row.safe_metadata,
    )


def _principal_row(value: MachinePrincipal) -> MachinePrincipalRow:
    return MachinePrincipalRow(
        id=value.id,
        application_id=value.application_id,
        issuer=value.ref.issuer,
        subject=value.ref.subject,
        kind=value.ref.kind,
        status=value.status.value,
        safe_metadata=dict(value.metadata),
    )


def _principal(row: MachinePrincipalRow) -> MachinePrincipal:
    return MachinePrincipal(
        id=row.id,
        application_id=row.application_id,
        ref=PrincipalRef(row.issuer, row.subject, row.kind),
        status=EntityStatus(row.status),
        metadata=row.safe_metadata,
    )


def _credential_row(value: MachineCredential) -> MachineCredentialRow:
    return MachineCredentialRow(id=value.id, principal_id=value.principal_id, **_credential_values(value))


def _credential_values(value: MachineCredential) -> dict[str, Any]:
    return {
        "audiences": list(value.audiences),
        "certificate_thumbprint": value.certificate_thumbprint,
        "environment": value.environment,
        "expires_at": value.expires_at,
        "issuer_dn": value.issuer_dn,
        "last_used_at": value.last_used_at,
        "not_before": value.not_before,
        "revocation_reason": value.revocation_reason,
        "revoked_at": value.revoked_at,
        "rotation_of": value.rotation_of,
        "safe_metadata": dict(value.metadata),
        "scopes": list(value.scopes),
        "serial_number": value.serial_number,
        "status": value.status.value,
        "subject_dn": value.subject_dn,
        "trust_anchor": value.trust_anchor,
    }


def _credential(row: MachineCredentialRow) -> MachineCredential:
    return MachineCredential(
        id=row.id,
        principal_id=row.principal_id,
        status=CredentialStatus(row.status),
        certificate_thumbprint=row.certificate_thumbprint,
        trust_anchor=row.trust_anchor,
        scopes=tuple(row.scopes),
        audiences=tuple(row.audiences),
        environment=row.environment,
        not_before=_as_utc(row.not_before),
        expires_at=_as_utc(row.expires_at),
        subject_dn=row.subject_dn,
        issuer_dn=row.issuer_dn,
        serial_number=row.serial_number,
        rotation_of=row.rotation_of,
        revoked_at=None if row.revoked_at is None else _as_utc(row.revoked_at),
        revocation_reason=row.revocation_reason,
        last_used_at=None if row.last_used_at is None else _as_utc(row.last_used_at),
        metadata=row.safe_metadata,
    )


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite's timezone-naive round-trip while preserving aware database values.

    Returns:
        The as utc.
    """
    return value.replace(tzinfo=UTC) if value.utcoffset() is None else value.astimezone(UTC)


__all__ = (
    "MachineCredentialRow",
    "MachinePrincipalRow",
    "SQLAlchemyWorkloadStore",
    "ServiceApplicationRow",
    "WorkloadBase",
)
