"""Lifecycle and direct mTLS provider tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    FailureCode,
    Invalid,
    InvariantFailure,
    PrincipalRef,
    RequestView,
    TlsPeerEvidence,
    Unavailable,
)
from authweave_workload import (
    CredentialStatus,
    DirectMTLSPolicy,
    DirectMTLSProvider,
    EntityStatus,
    StoreConflictError,
    WorkloadLifecycleService,
    rate_limit_identity,
)
from authweave_workload.models import (
    MachineCredential,
    MachinePrincipal,
    ResolvedMachineIdentity,
    ServiceApplication,
    _certificate_metadata,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from authweave_workload.events import SecurityEvent
    from authweave_workload.stores import WorkloadStore

_THUMBPRINT = "A" * 43
_LIFECYCLE_ACTOR = PrincipalRef("urn:test", "operator", "human")


def _service(
    store: WorkloadStore,
    *,
    issuer: str,
    active_credential_limit: int = 4,
    maximum_rotation_lead: timedelta = timedelta(days=7),
) -> WorkloadLifecycleService:
    return WorkloadLifecycleService(
        store,
        issuer=issuer,
        actor=_LIFECYCLE_ACTOR,
        correlation_id="test-operation",
        event_recorder=lambda _event: None,
        active_credential_limit=active_credential_limit,
        maximum_rotation_lead=maximum_rotation_lead,
    )


class MemoryStore:
    """Small transactional-shape store used to verify headless behavior."""

    def __init__(self) -> None:
        self.applications: dict[str, ServiceApplication] = {}
        self.principals: dict[str, MachinePrincipal] = {}
        self.credentials: dict[str, MachineCredential] = {}
        self.last_used: list[tuple[str, int, int]] = []

    async def create_application(self, application: ServiceApplication) -> None:
        if application.id in self.applications:
            raise StoreConflictError
        self.applications[application.id] = application

    async def get_application(self, application_id: str) -> ServiceApplication | None:
        return self.applications.get(application_id)

    async def set_application_status(self, application_id: str, status: EntityStatus) -> None:
        self.applications[application_id] = replace(self.applications[application_id], status=status)

    async def set_application_metadata(self, application_id: str, metadata: Mapping[str, str]) -> None:
        self.applications[application_id] = replace(self.applications[application_id], metadata=metadata)

    async def create_principal(self, principal: MachinePrincipal) -> None:
        self.principals[principal.id] = principal

    async def get_principal(self, principal_id: str) -> MachinePrincipal | None:
        return self.principals.get(principal_id)

    async def set_principal_status(self, principal_id: str, status: EntityStatus) -> None:
        self.principals[principal_id] = replace(self.principals[principal_id], status=status)

    async def set_principal_metadata(self, principal_id: str, metadata: Mapping[str, str]) -> None:
        self.principals[principal_id] = replace(self.principals[principal_id], metadata=metadata)

    async def register_credential(self, credential: MachineCredential, *, active_limit: int) -> None:
        active = sum(
            value.principal_id == credential.principal_id
            and value.status in {CredentialStatus.ACTIVE, CredentialStatus.PENDING}
            for value in self.credentials.values()
        )
        if active >= active_limit:
            raise StoreConflictError
        self.credentials[credential.id] = credential

    async def get_credential(self, credential_id: str) -> MachineCredential | None:
        return self.credentials.get(credential_id)

    async def revoke_credential(
        self,
        credential_id: str,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> MachineCredential:
        credential = self.credentials.get(credential_id)
        if credential is None or credential.status is CredentialStatus.REVOKED:
            msg = "credential does not exist or is already revoked"
            raise StoreConflictError(msg)
        revoked = replace(
            credential,
            status=CredentialStatus.REVOKED,
            revoked_at=revoked_at,
            revocation_reason=reason,
        )
        self.credentials[credential_id] = revoked
        return revoked

    async def list_credentials(self, principal_id: str) -> tuple[MachineCredential, ...]:
        return tuple(value for value in self.credentials.values() if value.principal_id == principal_id)

    async def resolve_by_thumbprint(self, thumbprint: str) -> ResolvedMachineIdentity | None:
        credential = next(
            (value for value in self.credentials.values() if value.certificate_thumbprint == thumbprint),
            None,
        )
        if credential is None:
            return None
        principal = self.principals[credential.principal_id]
        return ResolvedMachineIdentity(
            self.applications[principal.application_id],
            principal,
            credential,
        )

    async def record_last_used(self, credential_id: str, *, used_at_epoch: int, minimum_interval: int) -> None:
        self.last_used.append((credential_id, used_at_epoch, minimum_interval))

    async def complete_rotation(
        self,
        replacement_id: str,
        previous_id: str,
        *,
        completed_at: datetime,
    ) -> tuple[MachineCredential, MachineCredential]:
        replacement = self.credentials.get(replacement_id)
        previous = self.credentials.get(previous_id)
        if replacement is None or previous is None:
            msg = "credentials do not form one rotation"
            raise StoreConflictError(msg)
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
        self.credentials[replacement.id] = activated
        self.credentials[previous.id] = revoked
        return activated, revoked


pytestmark = pytest.mark.unit


async def test_lifecycle_and_direct_mtls_are_principal_neutral() -> None:
    now = datetime.now(UTC)
    store = MemoryStore()
    lifecycle = _service(store, issuer="urn:test:workloads")
    application, _ = await lifecycle.create_application(
        application_id="payments",
        environment="sandbox",
        owner_ref="team-payments",
    )
    principal, _ = await lifecycle.create_principal(
        principal_id="payments-worker",
        application_id=application.id,
        subject="payments-worker",
        kind="workload",
    )
    credential, _ = await lifecycle.register_credential(
        principal_id=principal.id,
        certificate=_certificate_metadata(
            thumbprint=_THUMBPRINT,
            trust_anchor="sandbox-ca",
            not_before=now - timedelta(minutes=1),
            not_after=now + timedelta(hours=1),
            subject_dn="CN=payments-worker",
            issuer_dn="CN=sandbox-ca",
            serial_number="01",
        ),
        scopes=("payments:write",),
        audiences=("payments-api",),
        environment="sandbox",
        now=now,
    )
    events: list[SecurityEvent] = []

    async def record_event(event: SecurityEvent) -> None:
        await asyncio.sleep(0)
        events.append(event)

    provider = DirectMTLSProvider(
        name="workload_mtls",
        store=store,
        policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"sandbox-ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
        event_callback=record_event,
    )
    request = RequestView(
        method="POST",
        timestamp=now,
        correlation_id="request-1",
        tls_peer=TlsPeerEvidence(
            tls_version="TLSv1.3",
            certificate_thumbprint=_THUMBPRINT,
            certificate_not_before=now - timedelta(minutes=1),
            certificate_not_after=now + timedelta(hours=1),
            revocation_checked_at=now,
            trust_anchor="sandbox-ca",
            termination_boundary="envoy",
        ),
    )

    decision = await provider.authenticate(request, AuthenticationRuntime())

    assert isinstance(decision, Authenticated)
    assert decision.context.subject == principal.ref
    assert decision.context.evidence.credential_id == credential.id
    assert decision.context.evidence.extensions == {"authweave-workload:application_id": application.id}
    limit_identity = rate_limit_identity(decision.context)
    assert limit_identity.application_id == application.id
    assert limit_identity.principal == principal.ref
    assert limit_identity.credential_id == credential.id
    with pytest.raises(TypeError, match="verified workload"):
        rate_limit_identity(
            replace(
                decision.context,
                evidence=replace(decision.context.evidence, extensions={}),
            ),
        )
    assert store.last_used == [(credential.id, int(now.timestamp()), 300)]
    assert events[-1].credential_id == credential.id

    store.applications[application.id] = replace(application, status=EntityStatus.DISABLED)
    disabled = await provider.authenticate(request, AuthenticationRuntime())
    assert disabled == Invalid(FailureCode.PRINCIPAL_DISABLED)


async def test_direct_mtls_rejects_downgrade_and_mixed_credentials() -> None:
    now = datetime.now(UTC)
    store = MemoryStore()
    provider = DirectMTLSProvider(
        name="workload_mtls",
        store=store,
        policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
    )
    peer = TlsPeerEvidence(
        tls_version="TLSv1.2",
        certificate_thumbprint=_THUMBPRINT,
        certificate_not_before=now - timedelta(minutes=1),
        certificate_not_after=now + timedelta(minutes=1),
        revocation_checked_at=now,
        trust_anchor="ca",
        termination_boundary="envoy",
    )
    request = RequestView(method="GET", timestamp=now, tls_peer=peer)

    assert await provider.authenticate(request, AuthenticationRuntime()) == Invalid(
        FailureCode.SENDER_CONSTRAINT_MISMATCH,
    )
    stale = replace(
        peer,
        tls_version="TLSv1.3",
        revocation_checked_at=now - timedelta(minutes=16),
    )
    assert (
        await provider.authenticate(
            RequestView(method="GET", timestamp=now, tls_peer=stale),
            AuthenticationRuntime(),
        )
        == Unavailable()
    )
    future_check = replace(stale, revocation_checked_at=now + timedelta(seconds=1))
    assert (
        await provider.authenticate(
            RequestView(method="GET", timestamp=now, tls_peer=future_check),
            AuthenticationRuntime(),
        )
        == InvariantFailure()
    )
    assert (
        provider.match(
            RequestView(method="GET", headers=((b"authorization", b"Bearer token"),), timestamp=now, tls_peer=peer),
        ).value
        == "ambiguous"
    )
