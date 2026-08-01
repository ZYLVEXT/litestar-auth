"""Typed secret-free workload security events."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from authweave_core import TraceCorrelation, Unavailable, ambient_trace_correlation

if TYPE_CHECKING:
    from collections.abc import Callable

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
    trace_id: str | None = None
    span_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Require an aware timestamp.

        Raises:
            ValueError: If the timestamp has no timezone.
        """
        if self.timestamp.utcoffset() is None:
            msg = "event timestamp must be timezone-aware"
            raise ValueError(msg)
        if (self.trace_id is None) is not (self.span_id is None):
            msg = "event trace_id and span_id must be supplied together"
            raise ValueError(msg)
        if self.trace_id is not None and self.span_id is not None:
            TraceCorrelation(self.trace_id, self.span_id)
        if self.correlation_id is not None and (
            not self.correlation_id
            or self.correlation_id != self.correlation_id.strip()
            or len(self.correlation_id) > _MAX_CORRELATION_ID_LENGTH
        ):
            msg = "event correlation_id must be non-empty, trimmed, and at most 512 characters"
            raise ValueError(msg)


class EventDeliveryError(Exception):
    """Internal signal that mandatory security-event delivery failed.

    Providers translate this into a fail-closed :class:`~authweave_core.Unavailable`
    authentication decision (ADR 0001). It never escapes a provider's public
    ``authenticate`` boundary and never carries credential material.
    """


async def deliver_security_event(
    callback: Callable[[SecurityEvent], object] | None,
    event: SecurityEvent,
) -> None:
    """Invoke a configured authentication event callback as a mandatory channel.

    Per ADR 0001 the callback is the durable, application-owned audit path. When a
    callback is configured, a raised exception or a returned ``Unavailable`` is a
    delivery failure that must fail the authentication decision closed. Applications
    that want absorb-and-observe semantics supply their own wrapper callback.

    Args:
        callback: Configured event callback, or ``None`` for unaudited fixtures.
        event: The bounded, secret-free security event to deliver.

    Raises:
        EventDeliveryError: If a configured callback raises or returns ``Unavailable``.
    """
    if callback is None:
        return
    correlation = ambient_trace_correlation()
    if correlation is not None and event.trace_id is None:
        event = replace(event, trace_id=correlation.trace_id, span_id=correlation.span_id)
    try:
        result = callback(event)
        if inspect.isawaitable(result):
            result = await result
    except Exception as exc:
        raise EventDeliveryError from exc
    if isinstance(result, Unavailable):
        raise EventDeliveryError


__all__ = (
    "EventDeliveryError",
    "SecurityEvent",
    "SecurityEventType",
    "deliver_security_event",
)
