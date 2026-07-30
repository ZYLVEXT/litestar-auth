"""Typed secret-free workload security events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authweave_core import FailureCode, PrincipalRef

_MAX_CORRELATION_ID_LENGTH = 512


class SecurityEventType(StrEnum):
    """Stable event classes emitted by workload lifecycle and providers."""

    APPLICATION_CREATED = "application_created"
    APPLICATION_ENABLED = "application_enabled"
    APPLICATION_DISABLED = "application_disabled"
    APPLICATION_METADATA_UPDATED = "application_metadata_updated"
    PRINCIPAL_CREATED = "principal_created"
    PRINCIPAL_ENABLED = "principal_enabled"
    PRINCIPAL_DISABLED = "principal_disabled"
    PRINCIPAL_METADATA_UPDATED = "principal_metadata_updated"
    CREDENTIAL_REGISTERED = "credential_registered"
    CREDENTIAL_ROTATION_STARTED = "credential_rotation_started"
    CREDENTIAL_ROTATION_COMPLETED = "credential_rotation_completed"
    CREDENTIAL_REVOKED = "credential_revoked"
    AUTHENTICATION_SUCCEEDED = "authentication_succeeded"
    AUTHENTICATION_FAILED = "authentication_failed"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    SENDER_CONSTRAINT_REJECTED = "sender_constraint_rejected"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """One bounded event with no raw credential or certificate body."""

    type: SecurityEventType
    target_application_id: str | None = None
    target_principal: PrincipalRef | None = None
    credential_id: str | None = None
    actor: PrincipalRef | None = None
    provider: str | None = None
    profile: str | None = None
    reason: FailureCode | None = None
    correlation_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Require an aware timestamp.

        Raises:
            ValueError: If the timestamp has no timezone.
        """
        if self.timestamp.utcoffset() is None:
            msg = "event timestamp must be timezone-aware"
            raise ValueError(msg)
        if self.correlation_id is not None and (
            not self.correlation_id
            or self.correlation_id != self.correlation_id.strip()
            or len(self.correlation_id) > _MAX_CORRELATION_ID_LENGTH
        ):
            msg = "event correlation_id must be non-empty, trimmed, and at most 512 characters"
            raise ValueError(msg)


__all__ = ("SecurityEvent", "SecurityEventType")
