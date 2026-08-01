"""Framework-neutral workload provisioning and direct mTLS authentication."""

from datetime import UTC, datetime

from authweave_core import AuthenticationRuntime, PrincipalRef, RequestView, TlsPeerEvidence
from authweave_workload import (
    DirectMTLSPolicy,
    DirectMTLSProvider,
    WorkloadLifecycleService,
)
from authweave_workload.lifecycle import EventRecorder
from authweave_workload.mtls import CertificateValidationPolicy, validate_public_certificate
from authweave_workload.stores import WorkloadStore


async def provision_and_authenticate(  # ruff: ignore[too-many-arguments]
    store: WorkloadStore,
    *,
    certificate_pem: bytes,
    ca_pem: bytes,
    peer: TlsPeerEvidence,
    actor: PrincipalRef,
    correlation_id: str,
    event_recorder: EventRecorder,
) -> object:
    """Register public certificate metadata and authenticate one neutral request.

    Returns:
        The typed neutral authentication decision.
    """
    now = datetime.now(UTC)
    certificate = validate_public_certificate(
        certificate_pem,
        policy=CertificateValidationPolicy(
            trust_anchor="production-ca",
            trust_anchor_certificates=(ca_pem,),
            revocation_checked_at=now,
        ),
        verification_time=now,
    )
    lifecycle = WorkloadLifecycleService(
        store,
        issuer="urn:example",
        actor=actor,
        correlation_id=correlation_id,
        event_recorder=event_recorder,
    )
    application, _ = await lifecycle.create_application(
        application_id="payments",
        environment="production",
        owner_ref="payments-team",
    )
    principal, _ = await lifecycle.create_principal(
        principal_id="payments-worker",
        application_id=application.id,
        subject="payments-worker",
        kind="workload",
    )
    await lifecycle.register_credential(
        principal_id=principal.id,
        certificate=certificate,
        scopes=("payments:write",),
        audiences=("payments-api",),
        environment=application.environment,
        now=now,
    )
    provider = DirectMTLSProvider(
        name="direct-machine",
        store=store,
        policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"production-ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
        event_callback=event_recorder,
    )
    return await provider.authenticate(RequestView("POST", timestamp=now, tls_peer=peer), AuthenticationRuntime())
