"""Lifecycle and model invariant matrix."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from authweave_core import PrincipalRef, SecurityOperation, SecurityOutcome, TraceCorrelation, observe_security
from authweave_workload.events import SecurityEvent, SecurityEventType, deliver_security_event
from authweave_workload.lifecycle import LifecycleConflictError, WorkloadLifecycleService
from authweave_workload.models import (
    CertificateMetadata,
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ServiceApplication,
    _certificate_metadata,
    freeze_metadata,
)
from authweave_workload.stores import StoreConflictError, StoreOwnerStateConflictError

from tests.test_lifecycle_provider import MemoryStore

if TYPE_CHECKING:
    from collections.abc import Iterator

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


def _certificate(now: datetime, **changes: object) -> CertificateMetadata:
    values: dict[str, object] = {
        "issuer_dn": "CN=ca",
        "not_after": now + timedelta(hours=1),
        "not_before": now - timedelta(minutes=1),
        "serial_number": "01",
        "subject_dn": "CN=worker",
        "thumbprint": _THUMBPRINT,
        "trust_anchor": "ca",
    }
    values.update(changes)
    return _certificate_metadata(**values)


def _credential(now: datetime, **changes: object) -> MachineCredential:
    values: dict[str, object] = {
        "audiences": ("api",),
        "certificate_thumbprint": _THUMBPRINT,
        "environment": "sandbox",
        "expires_at": now + timedelta(hours=1),
        "id": "credential-1",
        "issuer_dn": "CN=ca",
        "not_before": now - timedelta(minutes=1),
        "principal_id": "principal-1",
        "scopes": ("read",),
        "serial_number": "01",
        "status": CredentialStatus.ACTIVE,
        "subject_dn": "CN=worker",
        "trust_anchor": "ca",
    }
    values.update(changes)
    return MachineCredential(**values)  # ty: ignore[invalid-argument-type]


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "metadata",
    [
        {f"k{index}": "v" for index in range(33)},
        {"Bad": "v"},
        {"key": ""},
        {"key": " padded "},
        {"key": "x" * 513},
    ],
)
def test_metadata_is_bounded_and_immutable(metadata: dict[str, str]) -> None:
    """Operator metadata cannot carry unbounded or mutable request data."""
    with pytest.raises(ValueError, match=r".+"):
        freeze_metadata(metadata)
    frozen = freeze_metadata({"team": "payments"})
    with pytest.raises(TypeError):
        frozen["team"] = "other"  # ty: ignore[invalid-assignment]


@pytest.mark.parametrize(
    "application",
    [
        {"id": "bad id"},
        {"owner_ref": "bad owner"},
        {"environment": "LIVE"},
    ],
)
def test_application_validation(application: dict[str, object]) -> None:
    values: dict[str, object] = {
        "environment": "sandbox",
        "id": "application",
        "owner_ref": "team",
        "status": EntityStatus.ACTIVE,
    }
    values.update(application)
    with pytest.raises(ValueError, match=r".+"):
        ServiceApplication(**values)  # ty: ignore[invalid-argument-type]


def test_principal_rejects_human_and_invalid_ownership() -> None:
    with pytest.raises(ValueError, match="human"):
        MachinePrincipal("principal", "application", PrincipalRef("issuer", "subject", "human"), EntityStatus.ACTIVE)
    with pytest.raises(ValueError, match="application_id"):
        MachinePrincipal("principal", "bad owner", PrincipalRef("issuer", "subject", "service"), EntityStatus.ACTIVE)


@pytest.mark.parametrize(
    "changes",
    [
        {"certificate_thumbprint": "short"},
        {"environment": "LIVE"},
        {"not_before": datetime(2026, 1, 1)},
        {"expires_at": datetime(2026, 1, 1)},
        {"expires_at": datetime(2020, 1, 1, tzinfo=UTC)},
        {"status": CredentialStatus.REVOKED},
        {"revoked_at": datetime.now(UTC), "revocation_reason": "bad"},
        {"scopes": ("read", "read")},
        {"audiences": tuple(f"a{index}" for index in range(65))},
        {"rotation_of": "bad rotation"},
    ],
)
def test_credential_validation(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r".+"):
        _credential(datetime(2026, 1, 1, tzinfo=UTC), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"thumbprint": "short"},
        {"not_before": datetime(2026, 1, 1)},
        {"not_after": datetime(2026, 1, 1)},
        {"not_after": datetime(2020, 1, 1, tzinfo=UTC)},
        {"subject_dn": ""},
        {"issuer_dn": "x" * 2049},
        {"serial_number": ""},
    ],
)
def test_certificate_metadata_validation(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r".+"):
        _certificate(datetime(2026, 1, 1, tzinfo=UTC), **changes)


def test_security_event_requires_aware_time() -> None:
    with pytest.raises(ValueError, match="timezone"):
        SecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, timestamp=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="correlation"):
        SecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, correlation_id=" ")
    with pytest.raises(ValueError, match="together"):
        SecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, trace_id="1" * 32)
    with pytest.raises(ValueError, match="trace_id"):
        SecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, trace_id="0" * 32, span_id="1" * 16)
    event = SecurityEvent(SecurityEventType.AUTHENTICATION_FAILED, trace_id="1" * 32, span_id="2" * 16)
    assert event.trace_id == "1" * 32


async def test_security_event_inherits_active_trace_correlation() -> None:
    class _Observation:
        @staticmethod
        def set_outcome(outcome: SecurityOutcome, *, reason_code: str | None = None) -> None:
            _ = outcome, reason_code

    class _Observer:
        @contextmanager
        def observe(self, operation: SecurityOperation, **_kwargs: object) -> Iterator[_Observation]:
            _ = operation
            yield _Observation()

        @staticmethod
        def current_correlation() -> TraceCorrelation:
            return TraceCorrelation("1" * 32, "2" * 16)

    events: list[SecurityEvent] = []
    with observe_security(_Observer(), SecurityOperation.AUTHENTICATE):  # type: ignore[arg-type]
        await deliver_security_event(events.append, SecurityEvent(SecurityEventType.AUTHENTICATION_FAILED))

    assert events[0].trace_id == "1" * 32
    assert events[0].span_id == "2" * 16


async def test_application_and_principal_lifecycle_transitions() -> None:
    store = MemoryStore()
    service = _service(store, issuer="urn:test")
    with pytest.raises(LifecycleConflictError, match="application"):
        await service.set_application_enabled("missing", enabled=False)
    with pytest.raises(LifecycleConflictError, match="application"):
        await service.create_principal(
            principal_id="principal",
            application_id="missing",
            subject="subject",
            kind="service",
        )
    application, _ = await service.create_application(
        application_id="application",
        environment="sandbox",
        owner_ref="team",
    )
    disabled, disabled_event = await service.set_application_enabled(application.id, enabled=False)
    assert disabled.status is EntityStatus.DISABLED
    assert disabled_event.type is SecurityEventType.APPLICATION_DISABLED
    with pytest.raises(LifecycleConflictError, match="disabled"):
        await service.create_principal(
            principal_id="principal",
            application_id=application.id,
            subject="subject",
            kind="service",
        )
    await service.set_application_enabled(application.id, enabled=True)
    principal, _ = await service.create_principal(
        principal_id="principal",
        application_id=application.id,
        subject="subject",
        kind="service",
    )
    with pytest.raises(LifecycleConflictError, match="principal"):
        await service.set_principal_enabled("missing", enabled=False)
    disabled_principal, event = await service.set_principal_enabled(principal.id, enabled=False)
    assert disabled_principal.status is EntityStatus.DISABLED
    assert event.type is SecurityEventType.PRINCIPAL_DISABLED
    enabled_principal, event = await service.set_principal_enabled(principal.id, enabled=True)
    assert enabled_principal.status is EntityStatus.ACTIVE
    assert event.type is SecurityEventType.PRINCIPAL_ENABLED


async def test_lifecycle_translates_owner_state_store_conflicts_and_preserves_other_conflicts() -> None:
    """Concurrent owner-state rejection maps to lifecycle errors without hiding capacity conflicts."""
    application = ServiceApplication("application", EntityStatus.ACTIVE, "sandbox", "team")
    principal = MachinePrincipal(
        "principal",
        application.id,
        PrincipalRef("urn:test", "subject", "service"),
        EntityStatus.ACTIVE,
    )
    application_disabled_message = "custom application owner conflict"
    credential_owner_disabled_message = "custom credential owner conflict"

    class _DisabledApplicationStore(MemoryStore):
        async def create_principal(self, principal: MachinePrincipal) -> None:
            raise StoreOwnerStateConflictError(application_disabled_message)

    disabled_application_store = _DisabledApplicationStore()
    disabled_application_store.applications[application.id] = application
    with pytest.raises(LifecycleConflictError, match=application_disabled_message):
        await _service(disabled_application_store, issuer="urn:test").create_principal(
            principal_id=principal.id,
            application_id=application.id,
            subject="subject",
            kind="service",
        )

    class _DisabledCredentialStore(MemoryStore):
        async def register_credential(self, credential: MachineCredential, *, active_limit: int) -> None:
            raise StoreOwnerStateConflictError(credential_owner_disabled_message)

    disabled_credential_store = _DisabledCredentialStore()
    disabled_credential_store.applications[application.id] = application
    disabled_credential_store.principals[principal.id] = principal
    with pytest.raises(LifecycleConflictError, match=credential_owner_disabled_message):
        await _service(disabled_credential_store, issuer="urn:test").register_credential(
            principal_id=principal.id,
            certificate=_certificate(datetime(2026, 1, 1, tzinfo=UTC)),
            scopes=("read",),
            audiences=("api",),
            environment="sandbox",
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )

    capacity_store = MemoryStore()
    capacity_store.applications[application.id] = application
    capacity_store.principals[principal.id] = principal
    capacity_service = _service(capacity_store, issuer="urn:test", active_credential_limit=1)
    await capacity_service.register_credential(
        principal_id=principal.id,
        certificate=_certificate(datetime(2026, 1, 1, tzinfo=UTC)),
        scopes=("read",),
        audiences=("api",),
        environment="sandbox",
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(StoreConflictError):
        await capacity_service.register_credential(
            principal_id=principal.id,
            certificate=_certificate(datetime(2026, 1, 1, tzinfo=UTC), thumbprint="B" * 43),
            scopes=("read",),
            audiences=("api",),
            environment="sandbox",
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


async def test_credential_registration_rotation_and_revocation_matrix() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryStore()
    service = _service(store, issuer="urn:test", maximum_rotation_lead=timedelta(days=1))
    with pytest.raises(ValueError, match="active_credential_limit"):
        _service(store, issuer="urn:test", active_credential_limit=0)
    with pytest.raises(ValueError, match="maximum_rotation_lead"):
        _service(store, issuer="urn:test", maximum_rotation_lead=timedelta(0))
    with pytest.raises(ValueError, match="timezone"):
        await service.register_credential(
            principal_id="missing",
            certificate=_certificate(now),
            scopes=(),
            audiences=(),
            environment="sandbox",
            now=datetime(2026, 1, 1),
        )
    with pytest.raises(LifecycleConflictError, match="principal"):
        await service.register_credential(
            principal_id="missing",
            certificate=_certificate(now),
            scopes=(),
            audiences=(),
            environment="sandbox",
            now=now,
        )
    application, _ = await service.create_application(
        application_id="application",
        environment="sandbox",
        owner_ref="team",
    )
    principal, _ = await service.create_principal(
        principal_id="principal",
        application_id=application.id,
        subject="subject",
        kind="workload",
    )
    with pytest.raises(LifecycleConflictError, match="environment"):
        await service.register_credential(
            principal_id=principal.id,
            certificate=_certificate(now),
            scopes=(),
            audiences=(),
            environment="live",
            now=now,
        )
    await service.set_principal_enabled(principal.id, enabled=False)
    with pytest.raises(LifecycleConflictError, match="disabled"):
        await service.register_credential(
            principal_id=principal.id,
            certificate=_certificate(now),
            scopes=(),
            audiences=(),
            environment="sandbox",
            now=now,
        )
    await service.set_principal_enabled(principal.id, enabled=True)
    with pytest.raises(LifecycleConflictError, match="future-dated"):
        await service.register_credential(
            principal_id=principal.id,
            certificate=_certificate(now, not_before=now + timedelta(minutes=30)),
            scopes=(),
            audiences=(),
            environment="sandbox",
            now=now,
        )
    with pytest.raises(LifecycleConflictError, match="expired"):
        await service.register_credential(
            principal_id=principal.id,
            certificate=_certificate(
                now,
                not_before=now - timedelta(hours=2),
                not_after=now - timedelta(hours=1),
            ),
            scopes=(),
            audiences=(),
            environment="sandbox",
            now=now,
        )
    credential, event = await service.register_credential(
        principal_id=principal.id,
        certificate=_certificate(now),
        scopes=("read",),
        audiences=("api",),
        environment="sandbox",
        now=now,
    )
    assert event.type is SecurityEventType.CREDENTIAL_REGISTERED
    with pytest.raises(LifecycleConflictError, match="rotation source"):
        await service.register_credential(
            principal_id=principal.id,
            certificate=_certificate(now, thumbprint="B" * 43, not_before=now + timedelta(minutes=30)),
            scopes=("read",),
            audiences=("api",),
            environment="sandbox",
            rotation_of="missing",
            now=now,
        )
    replacement, event = await service.register_credential(
        principal_id=principal.id,
        certificate=_certificate(now, thumbprint="B" * 43, not_before=now + timedelta(minutes=30)),
        scopes=("read",),
        audiences=("api",),
        environment="sandbox",
        rotation_of=credential.id,
        now=now,
    )
    assert replacement.status is CredentialStatus.PENDING
    assert event.type is SecurityEventType.CREDENTIAL_ROTATION_STARTED
    store.credentials[replacement.id] = replace(replacement, rotation_of=None)
    with pytest.raises(LifecycleConflictError, match="rotation"):
        await service.complete_rotation(
            new_credential_id=replacement.id,
            previous_credential_id=credential.id,
            now=now + timedelta(minutes=45),
        )
    store.credentials[replacement.id] = replacement
    with pytest.raises(LifecycleConflictError, match="currently valid"):
        await service.complete_rotation(
            new_credential_id=replacement.id,
            previous_credential_id=credential.id,
            now=now,
        )
    activated, revoked, event = await service.complete_rotation(
        new_credential_id=replacement.id,
        previous_credential_id=credential.id,
        now=now + timedelta(minutes=45),
    )
    assert activated.status is CredentialStatus.ACTIVE
    assert revoked.status is CredentialStatus.REVOKED
    assert event.type is SecurityEventType.CREDENTIAL_ROTATION_COMPLETED
    with pytest.raises(LifecycleConflictError, match="rotation"):
        await service.complete_rotation(
            new_credential_id="missing",
            previous_credential_id=credential.id,
            now=now,
        )
    with pytest.raises(ValueError, match="reason"):
        await service.revoke_credential(activated.id, reason=" ")
    with pytest.raises(ValueError, match="timezone"):
        await service.revoke_credential(activated.id, reason="operator_request", now=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="timezone"):
        await service.complete_rotation(
            new_credential_id=activated.id,
            previous_credential_id=credential.id,
            now=datetime(2026, 1, 1),
        )
    revoked_replacement, event = await service.revoke_credential(
        activated.id,
        reason="operator_request",
        now=now + timedelta(hours=2),
    )
    assert revoked_replacement.status is CredentialStatus.REVOKED
    assert event.type is SecurityEventType.CREDENTIAL_REVOKED
    with pytest.raises(LifecycleConflictError, match="already"):
        await service.revoke_credential(activated.id, reason="again")
    with pytest.raises(LifecycleConflictError, match="does not exist"):
        await service.revoke_credential("missing", reason="operator_request")


async def test_rotation_accepts_an_already_valid_replacement() -> None:
    """Normal certificate overlap completes without requiring future dating."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryStore()
    service = _service(store, issuer="urn:test")
    application, _ = await service.create_application(
        application_id="application",
        environment="sandbox",
        owner_ref="team",
    )
    principal, _ = await service.create_principal(
        principal_id="principal",
        application_id=application.id,
        subject="subject",
        kind="workload",
    )
    previous, _ = await service.register_credential(
        principal_id=principal.id,
        certificate=_certificate(now),
        scopes=("read",),
        audiences=("api",),
        environment="sandbox",
        now=now,
    )
    replacement, _ = await service.register_credential(
        principal_id=principal.id,
        certificate=_certificate(now, thumbprint="B" * 43),
        scopes=("read",),
        audiences=("api",),
        environment="sandbox",
        rotation_of=previous.id,
        now=now,
    )

    activated, revoked, event = await service.complete_rotation(
        new_credential_id=replacement.id,
        previous_credential_id=previous.id,
        now=now,
    )

    assert replacement.status is CredentialStatus.ACTIVE
    assert activated.status is CredentialStatus.ACTIVE
    assert revoked.status is CredentialStatus.REVOKED
    assert event.type is SecurityEventType.CREDENTIAL_ROTATION_COMPLETED


async def test_lifecycle_safe_metadata_and_listing() -> None:
    store = MemoryStore()
    service = _service(store, issuer="urn:test")
    with pytest.raises(LifecycleConflictError):
        await service.update_application_metadata("missing", {})
    with pytest.raises(LifecycleConflictError):
        await service.update_principal_metadata("missing", {})
    application, _ = await service.create_application(
        application_id="application",
        environment="sandbox",
        owner_ref="team",
    )
    principal, _ = await service.create_principal(
        principal_id="principal",
        application_id=application.id,
        subject="subject",
        kind="agent",
    )
    updated_application, application_event = await service.update_application_metadata(
        application.id,
        {"team": "payments"},
    )
    updated_principal, principal_event = await service.update_principal_metadata(
        principal.id,
        {"role": "worker"},
    )
    assert updated_application.metadata["team"] == "payments"
    assert updated_principal.metadata["role"] == "worker"
    assert application_event.type is SecurityEventType.APPLICATION_METADATA_UPDATED
    assert principal_event.type is SecurityEventType.PRINCIPAL_METADATA_UPDATED
    assert await service.list_credentials(principal.id) == ()


async def test_lifecycle_requires_attributed_recording_before_success() -> None:
    store = MemoryStore()
    events: list[SecurityEvent] = []

    async def record(event: SecurityEvent) -> None:
        await asyncio.sleep(0)
        events.append(event)

    service = WorkloadLifecycleService(
        store,
        issuer="urn:test",
        actor=_LIFECYCLE_ACTOR,
        correlation_id="operation-123",
        event_recorder=record,
    )

    application, event = await service.create_application(
        application_id="application",
        environment="sandbox",
        owner_ref="team",
    )

    assert events == [event]
    assert event.actor == _LIFECYCLE_ACTOR
    assert event.correlation_id == "operation-123"
    assert event.target_application_id == application.id

    def fail_recording(_event: SecurityEvent) -> None:
        msg = "audit unavailable"
        raise RuntimeError(msg)

    failing = WorkloadLifecycleService(
        store,
        issuer="urn:test",
        actor=_LIFECYCLE_ACTOR,
        correlation_id="operation-456",
        event_recorder=fail_recording,
    )
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await failing.create_application(
            application_id="other-application",
            environment="sandbox",
            owner_ref="team",
        )


async def test_revoke_and_rotation_survive_audit_recorder_outage(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A recorder outage never masks a durable revoke; the gap is logged instead."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryStore()
    credential = _credential(now)
    store.credentials[credential.id] = credential

    def fail_recording(_event: SecurityEvent) -> None:
        msg = "audit unavailable"
        raise RuntimeError(msg)

    service = WorkloadLifecycleService(
        store,
        issuer="urn:test",
        actor=_LIFECYCLE_ACTOR,
        correlation_id="audit-outage",
        event_recorder=fail_recording,
    )

    with caplog.at_level("ERROR", logger="authweave_workload.audit"):
        revoked, event = await service.revoke_credential(credential.id, reason="operator_request", now=now)

    assert revoked.status is CredentialStatus.REVOKED
    assert store.credentials[credential.id].status is CredentialStatus.REVOKED
    assert event.type is SecurityEventType.CREDENTIAL_REVOKED
    assert event.actor == _LIFECYCLE_ACTOR
    assert event.correlation_id == "audit-outage"
    assert any(getattr(record, "event", None) == "workload_audit_record_failed" for record in caplog.records)
