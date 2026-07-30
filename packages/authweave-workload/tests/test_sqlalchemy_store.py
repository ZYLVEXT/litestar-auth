"""SQLAlchemy reference store tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from authweave_core import PrincipalRef
from authweave_workload.models import (
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ServiceApplication,
)
from authweave_workload.sqlalchemy import SQLAlchemyWorkloadStore, WorkloadBase
from authweave_workload.stores import StoreConflictError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


@pytest.mark.asyncio
async def test_sqlalchemy_store_resolves_status_atomically_and_enforces_limit() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(WorkloadBase.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    application = ServiceApplication("app", EntityStatus.ACTIVE, "sandbox", "owner")
    principal = MachinePrincipal(
        "principal",
        "app",
        PrincipalRef("urn:test", "subject", "service"),
        EntityStatus.ACTIVE,
    )
    credential = MachineCredential(
        id="credential",
        principal_id="principal",
        status=CredentialStatus.ACTIVE,
        certificate_thumbprint="B" * 43,
        trust_anchor="ca",
        scopes=("read",),
        audiences=("api",),
        environment="sandbox",
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=1),
        subject_dn="CN=subject",
        issuer_dn="CN=ca",
        serial_number="01",
    )
    async with session_factory.begin() as session:
        store = SQLAlchemyWorkloadStore(session)
        await store.create_application(application)
        await store.create_principal(principal)
        await store.register_credential(credential, active_limit=1)
        resolved = await store.resolve_by_thumbprint(credential.certificate_thumbprint)
        assert resolved is not None
        assert resolved.application == application
        assert resolved.principal == principal
        assert resolved.credential == credential
        with pytest.raises(StoreConflictError):
            await store.register_credential(
                replace_credential_id(credential, "second", "C" * 43),
                active_limit=1,
            )
    await engine.dispose()


def replace_credential_id(value: MachineCredential, credential_id: str, thumbprint: str) -> MachineCredential:
    """Return a second credential sharing the same principal."""
    return MachineCredential(
        id=credential_id,
        principal_id=value.principal_id,
        status=value.status,
        certificate_thumbprint=thumbprint,
        trust_anchor=value.trust_anchor,
        scopes=value.scopes,
        audiences=value.audiences,
        environment=value.environment,
        not_before=value.not_before,
        expires_at=value.expires_at,
        subject_dn=value.subject_dn,
        issuer_dn=value.issuer_dn,
        serial_number="02",
    )
