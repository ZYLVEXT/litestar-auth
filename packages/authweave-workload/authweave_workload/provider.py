"""Direct mTLS authentication provider."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationEvidence,
    CredentialMatch,
    FailureCode,
    Invalid,
    InvariantFailure,
    NotApplicable,
    Unavailable,
)

from authweave_workload.events import (
    EventDeliveryError,
    SecurityEvent,
    SecurityEventType,
    deliver_security_event,
)
from authweave_workload.models import CredentialStatus, EntityStatus
from authweave_workload.stores import StoreUnavailableError

if TYPE_CHECKING:
    from collections.abc import Callable

    from authweave_core import AuthenticationDecision, AuthenticationRuntime, RequestView

    from authweave_workload.stores import MachineCredentialStore


@dataclass(frozen=True, slots=True)
class DirectMTLSPolicy:
    """Trusted TLS termination and certificate evidence policy."""

    trust_anchors: frozenset[str]
    termination_boundaries: frozenset[str]
    maximum_revocation_age: timedelta = timedelta(minutes=15)
    last_used_minimum_interval_seconds: int = 300

    def __post_init__(self) -> None:
        """Reject empty or unsafe policy configuration."""
        if not self.trust_anchors or not self.termination_boundaries:
            msg = "direct mTLS policy requires trust anchors and termination boundaries"
            raise ValueError(msg)
        if self.maximum_revocation_age <= timedelta(0):
            msg = "maximum_revocation_age must be positive"
            raise ValueError(msg)
        if self.last_used_minimum_interval_seconds < 0:
            msg = "last_used_minimum_interval_seconds cannot be negative"
            raise ValueError(msg)


class DirectMTLSProvider:
    """Authenticate a registered machine identity from trusted TLS evidence."""

    profile = "direct_mtls"

    def __init__(
        self,
        *,
        name: str,
        store: MachineCredentialStore,
        policy: DirectMTLSPolicy,
        event_callback: Callable[[SecurityEvent], object] | None = None,
    ) -> None:
        """Bind credential persistence and the trusted boundary policy."""
        self.name = name
        self.store = store
        self.policy = policy
        self.event_callback = event_callback

    def match(self, request: RequestView) -> CredentialMatch:
        """Own verified TLS evidence and reject mixed credential presentations."""
        if request.tls_peer is None:
            return CredentialMatch.NOT_APPLICABLE
        if request.header_values(b"authorization") or request.header_values(b"cookie"):
            return CredentialMatch.AMBIGUOUS
        return CredentialMatch.OWNED

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Authenticate and fail closed if mandatory event delivery fails (ADR 0001).

        Returns:
            A terminal typed authentication decision.
        """
        try:
            return await self._authenticate(request, runtime)
        except EventDeliveryError:
            return Unavailable()

    async def _authenticate(  # ruff: ignore[too-many-branches]
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Verify boundary facts and atomically resolve active registration state."""
        _ = runtime
        peer = request.tls_peer
        if peer is None:
            return NotApplicable()
        failure = self._validate_peer(request)
        if failure is not None:
            await self._emit_failure(request, failure)
            if failure is FailureCode.PROVIDER_UNAVAILABLE:
                return Unavailable()
            if failure is FailureCode.INTERNAL_INVARIANT:
                return InvariantFailure()
            return Invalid(failure)
        try:
            resolved = await self.store.resolve_by_thumbprint(peer.certificate_thumbprint)
        except StoreUnavailableError:
            await self._emit(
                SecurityEvent(
                    SecurityEventType.PROVIDER_UNAVAILABLE,
                    provider=self.name,
                    profile=self.profile,
                    reason=FailureCode.PROVIDER_UNAVAILABLE,
                    correlation_id=request.correlation_id,
                    timestamp=request.timestamp,
                ),
            )
            return Unavailable()
        if resolved is None:
            await self._emit_failure(request, FailureCode.INVALID)
            return Invalid(FailureCode.INVALID)
        application = resolved.application
        principal = resolved.principal
        credential = resolved.credential
        if application.status is not EntityStatus.ACTIVE or principal.status is not EntityStatus.ACTIVE:
            await self._emit_failure(request, FailureCode.PRINCIPAL_DISABLED)
            return Invalid(FailureCode.PRINCIPAL_DISABLED)
        if credential.status is CredentialStatus.REVOKED:
            await self._emit_failure(request, FailureCode.REVOKED)
            return Invalid(FailureCode.REVOKED)
        if credential.status is not CredentialStatus.ACTIVE:
            await self._emit_failure(request, FailureCode.NOT_YET_VALID)
            return Invalid(FailureCode.NOT_YET_VALID)
        if request.timestamp < credential.not_before:
            await self._emit_failure(request, FailureCode.NOT_YET_VALID)
            return Invalid(FailureCode.NOT_YET_VALID)
        if request.timestamp >= credential.expires_at:
            await self._emit_failure(request, FailureCode.EXPIRED)
            return Invalid(FailureCode.EXPIRED)
        if credential.environment != application.environment or credential.trust_anchor != peer.trust_anchor:
            await self._emit_failure(request, FailureCode.SENDER_CONSTRAINT_MISMATCH)
            return Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)

        evidence = AuthenticationEvidence(
            provider=self.name,
            profile=self.profile,
            method="mtls",
            issuer=principal.ref.issuer,
            audiences=credential.audiences,
            scopes=credential.scopes,
            not_before=credential.not_before,
            expires_at=credential.expires_at,
            credential_id=credential.id,
            confirmation_thumbprint=peer.certificate_thumbprint,
            environment=credential.environment,
            extensions={"authweave-workload:application_id": application.id},
        )
        context = AuthenticationContext(subject=principal.ref, actor=principal.ref, evidence=evidence)
        try:
            await self.store.record_last_used(
                credential.id,
                used_at_epoch=int(request.timestamp.timestamp()),
                minimum_interval=self.policy.last_used_minimum_interval_seconds,
            )
        except StoreUnavailableError:
            await self._emit_failure(request, FailureCode.PROVIDER_UNAVAILABLE)
            return Unavailable()
        await self._emit(
            SecurityEvent(
                SecurityEventType.AUTHENTICATION_SUCCEEDED,
                target_application_id=application.id,
                target_principal=principal.ref,
                credential_id=credential.id,
                actor=principal.ref,
                provider=self.name,
                profile=self.profile,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )
        return Authenticated(context)

    def _validate_peer(self, request: RequestView) -> FailureCode | None:
        peer = request.tls_peer
        if peer is None:
            return FailureCode.MISSING
        if peer.tls_version != "TLSv1.3":
            return FailureCode.SENDER_CONSTRAINT_MISMATCH
        if (
            peer.trust_anchor not in self.policy.trust_anchors
            or peer.termination_boundary not in self.policy.termination_boundaries
        ):
            return FailureCode.SENDER_CONSTRAINT_MISMATCH
        if not (peer.certificate_not_before <= request.timestamp < peer.certificate_not_after):
            return FailureCode.EXPIRED if request.timestamp >= peer.certificate_not_after else FailureCode.NOT_YET_VALID
        if request.timestamp - peer.revocation_checked_at > self.policy.maximum_revocation_age:
            return FailureCode.PROVIDER_UNAVAILABLE
        if peer.revocation_checked_at > request.timestamp:
            return FailureCode.INTERNAL_INVARIANT
        return None

    async def _emit_failure(self, request: RequestView, reason: FailureCode) -> None:
        event_type = (
            SecurityEventType.SENDER_CONSTRAINT_REJECTED
            if reason is FailureCode.SENDER_CONSTRAINT_MISMATCH
            else SecurityEventType.AUTHENTICATION_FAILED
        )
        await self._emit(
            SecurityEvent(
                event_type,
                provider=self.name,
                profile=self.profile,
                reason=reason,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )

    async def _emit(self, event: SecurityEvent) -> None:
        await deliver_security_event(self.event_callback, event)


__all__ = ("DirectMTLSPolicy", "DirectMTLSProvider")
