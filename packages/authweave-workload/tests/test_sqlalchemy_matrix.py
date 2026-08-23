"""SQLAlchemy workload store operation and failure matrix."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from authweave_core import PrincipalRef
from authweave_workload import sqlalchemy as sqlalchemy_module
from authweave_workload.models import (
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ServiceApplication,
)
from authweave_workload.sqlalchemy import MachineCredentialRow, SQLAlchemyWorkloadStore, WorkloadBase
from authweave_workload.stores import StoreConflictError, StoreUnavailableError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


def _credential(
    credential_id: str,
    thumbprint: str,
    now: datetime,
    *,
    status: CredentialStatus = CredentialStatus.ACTIVE,
    rotation_of: str | None = None,
) -> MachineCredential:
    return MachineCredential(
        credential_id,
        "principal",
        status,
        thumbprint,
        "ca",
        ("read",),
        ("api",),
        "sandbox",
        now - timedelta(minutes=1),
        now + timedelta(hours=1),
        "CN=subject",
        "CN=ca",
        credential_id,
        rotation_of=rotation_of,
    )


pytestmark = pytest.mark.integration


async def test_sqlalchemy_store_full_crud_rotation_and_last_used() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(WorkloadBase.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    application = ServiceApplication("app", EntityStatus.ACTIVE, "sandbox", "owner")
    principal = MachinePrincipal(
        "principal",
        application.id,
        PrincipalRef("issuer", "subject", "service"),
        EntityStatus.ACTIVE,
    )
    now = datetime.now(UTC)
    previous = _credential("previous", "A" * 43, now)
    replacement = _credential(
        "replacement",
        "B" * 43,
        now,
        status=CredentialStatus.PENDING,
        rotation_of=previous.id,
    )

    async with factory.begin() as session:
        store = SQLAlchemyWorkloadStore(session)
        assert await store.get_application("missing") is None
        assert await store.get_principal("missing") is None
        assert await store.get_credential("missing") is None
        assert await store.resolve_by_thumbprint("missing") is None
        with pytest.raises(StoreConflictError, match="application"):
            await store.set_application_status(application.id, EntityStatus.DISABLED)
        with pytest.raises(StoreConflictError, match="application"):
            await store.set_application_metadata(application.id, {})
        with pytest.raises(StoreConflictError, match="principal"):
            await store.set_principal_status(principal.id, EntityStatus.DISABLED)
        with pytest.raises(StoreConflictError, match="principal"):
            await store.set_principal_metadata(principal.id, {})
        with pytest.raises(StoreConflictError, match="principal"):
            await store.register_credential(previous, active_limit=4)
        with pytest.raises(StoreConflictError, match="credential"):
            await store.revoke_credential(previous.id, reason="operator_request", revoked_at=now)
        with pytest.raises(StoreConflictError, match="concurrently"):
            await store._update_credential(previous, expected_status=CredentialStatus.ACTIVE)
        with pytest.raises(StoreConflictError, match="rotation"):
            await store.complete_rotation(replacement.id, previous.id, completed_at=now)

        await store.create_application(application)
        await store.create_principal(principal)
        other_application = ServiceApplication("app-other", EntityStatus.ACTIVE, "production", "owner-other")
        other_principal = MachinePrincipal(
            "principal-other",
            other_application.id,
            PrincipalRef("issuer", "subject-other", "agent"),
            EntityStatus.ACTIVE,
        )
        await store.create_application(other_application)
        await store.create_principal(other_principal)
        await store.set_principal_status(other_principal.id, EntityStatus.DISABLED)
        await store.set_application_status(other_application.id, EntityStatus.DISABLED)
        application_page, application_total = await store.list_applications(
            offset=0,
            limit=1,
            owner_ref=application.owner_ref,
            environment="sandbox",
            status=EntityStatus.ACTIVE,
        )
        principal_page, principal_total = await store.list_principals(
            application_id=application.id,
            offset=0,
            limit=1,
            status=EntityStatus.ACTIVE,
        )
        assert application_page == (application,)
        assert application_total == 1
        assert principal_page == (principal,)
        assert principal_total == 1
        await store.register_credential(previous, active_limit=4)
        await store.register_credential(replacement, active_limit=4)
        updated_application = replace(application, metadata={"team": "payments"})
        updated_principal = replace(principal, metadata={"role": "worker"})
        await store.set_application_metadata(application.id, updated_application.metadata)
        await store.set_principal_metadata(principal.id, updated_principal.metadata)
        assert await store.get_application(application.id) == updated_application
        assert await store.get_principal(principal.id) == updated_principal
        assert await store.get_credential(previous.id) == previous
        assert await store.list_credentials(principal.id) == (previous, replacement)

        with pytest.raises(StoreConflictError, match="currently valid"):
            await store.complete_rotation(
                replacement.id,
                previous.id,
                completed_at=now - timedelta(hours=2),
            )
        activated, revoked = await store.complete_rotation(
            replacement.id,
            previous.id,
            completed_at=now,
        )
        assert await store.get_credential(activated.id) == activated
        assert await store.get_credential(revoked.id) == revoked

        revoked_replacement = await store.revoke_credential(
            activated.id,
            reason="operator_request",
            revoked_at=now + timedelta(minutes=1),
        )
        assert revoked_replacement.status is CredentialStatus.REVOKED
        with pytest.raises(StoreConflictError, match="already revoked"):
            await store.revoke_credential(
                activated.id,
                reason="again",
                revoked_at=now + timedelta(minutes=2),
            )

        await store.record_last_used(revoked_replacement.id, used_at_epoch=int(now.timestamp()), minimum_interval=300)
        row = await session.scalar(select(MachineCredentialRow).where(MachineCredentialRow.id == activated.id))
        assert row is not None
        assert row.last_used_at is not None

        await store.set_application_status(application.id, EntityStatus.DISABLED)
        await store.set_application_metadata(application.id, {"team": "security"})
        assert await store.get_application(application.id) == replace(
            updated_application,
            status=EntityStatus.DISABLED,
            metadata={"team": "security"},
        )
        await store.set_principal_status(principal.id, EntityStatus.DISABLED)
        await store.set_principal_metadata(principal.id, {"role": "disabled-worker"})
        assert await store.get_principal(principal.id) == replace(
            updated_principal,
            status=EntityStatus.DISABLED,
            metadata={"role": "disabled-worker"},
        )

    async with factory.begin() as session:
        store = SQLAlchemyWorkloadStore(session)
        with pytest.raises(StoreConflictError, match="application"):
            await store.create_application(application)
        await session.rollback()
    await engine.dispose()


async def test_sqlalchemy_store_rechecks_owner_state_before_principal_and_credential_writes() -> None:
    """Owner disablement cannot race lifecycle writes into latent active identities."""
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(WorkloadBase.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    application = ServiceApplication("app", EntityStatus.ACTIVE, "sandbox", "owner")
    principal = MachinePrincipal(
        "principal",
        application.id,
        PrincipalRef("issuer", "subject", "service"),
        EntityStatus.ACTIVE,
    )
    credential = _credential("credential", "A" * 43, now)

    async with factory.begin() as session:
        store = SQLAlchemyWorkloadStore(session)
        with pytest.raises(StoreConflictError, match="application does not exist"):
            await store.create_principal(principal)
        await store.create_application(application)
        await store.set_application_status(application.id, EntityStatus.DISABLED)
        with pytest.raises(StoreConflictError, match="application is disabled"):
            await store.create_principal(principal)

        await store.set_application_status(application.id, EntityStatus.ACTIVE)
        await store.create_principal(principal)
        await store.set_application_status(application.id, EntityStatus.DISABLED)
        with pytest.raises(StoreConflictError, match="credential owner is disabled"):
            await store.register_credential(credential, active_limit=4)

        await store.set_application_status(application.id, EntityStatus.ACTIVE)
        await store.set_principal_status(principal.id, EntityStatus.DISABLED)
        with pytest.raises(StoreConflictError, match="credential owner is disabled"):
            await store.register_credential(credential, active_limit=4)

        await store.set_principal_status(principal.id, EntityStatus.ACTIVE)
        with pytest.raises(StoreConflictError, match="environment"):
            await store.register_credential(
                replace(credential, environment="live"),
                active_limit=4,
            )

    await engine.dispose()


async def test_sqlalchemy_rotation_never_reactivates_a_revoked_replacement() -> None:
    """A revoke committed before rotation validation remains terminal."""
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(WorkloadBase.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    application = ServiceApplication("app", EntityStatus.ACTIVE, "sandbox", "owner")
    principal = MachinePrincipal(
        "principal",
        application.id,
        PrincipalRef("issuer", "subject", "service"),
        EntityStatus.ACTIVE,
    )
    previous = _credential("previous", "A" * 43, now)
    replacement = _credential(
        "replacement",
        "B" * 43,
        now,
        status=CredentialStatus.PENDING,
        rotation_of=previous.id,
    )
    async with factory.begin() as session:
        store = SQLAlchemyWorkloadStore(session)
        await store.create_application(application)
        await store.create_principal(principal)
        await store.register_credential(previous, active_limit=4)
        await store.register_credential(replacement, active_limit=4)
        revoked = await store.revoke_credential(
            replacement.id,
            reason="operator_request",
            revoked_at=now,
        )
        with pytest.raises(StoreConflictError, match="rotation"):
            await store.complete_rotation(replacement.id, previous.id, completed_at=now)
        assert await store.get_credential(replacement.id) == revoked

    await engine.dispose()


class _FailingSession:
    async def execute(self, statement: object) -> object:
        raise SQLAlchemyError

    async def scalar(self, statement: object) -> object:
        raise SQLAlchemyError


async def test_sqlalchemy_store_maps_database_outages() -> None:
    store = SQLAlchemyWorkloadStore(cast("AsyncSession", _FailingSession()))
    with pytest.raises(StoreUnavailableError, match="lookup"):
        await store.resolve_by_thumbprint("A" * 43)
    with pytest.raises(StoreUnavailableError, match="last-used"):
        await store.record_last_used("credential", used_at_epoch=0, minimum_interval=0)
    with pytest.raises(StoreUnavailableError, match="application inventory"):
        await store.list_applications(offset=0, limit=50)
    with pytest.raises(StoreUnavailableError, match="principal inventory"):
        await store.list_principals(application_id="app", offset=0, limit=50)


async def test_sqlalchemy_store_maps_corrupt_identity_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Result:
        def one_or_none(self) -> tuple[object, object, object]:
            return object(), object(), object()

    class _Session:
        async def execute(self, statement: object) -> _Result:
            return _Result()

    def invalid_application(_row: object) -> ServiceApplication:
        raise ValueError

    monkeypatch.setattr(sqlalchemy_module, "_application", invalid_application)
    store = SQLAlchemyWorkloadStore(cast("AsyncSession", _Session()))
    with pytest.raises(StoreUnavailableError, match="data is invalid"):
        await store.resolve_by_thumbprint("A" * 43)
