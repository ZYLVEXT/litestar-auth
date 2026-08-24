"""Optional, framework-neutral security observation contracts.

Observers are operational telemetry, never an audit ledger. Helpers here isolate
observer failures from security decisions without importing an implementation.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from types import TracebackType

_LOGGER = logging.getLogger("authweave.observability")
_WARNING_INTERVAL_SECONDS = 60.0
_TRACE_ID_LENGTH = 32
_SPAN_ID_LENGTH = 16
_warning_lock = threading.Lock()
_last_warning_at = [float("-inf")]
_current_correlation: ContextVar[TraceCorrelation | None]


class SecurityOperation(StrEnum):
    """Bounded logical security operations shared by AuthWeave packages."""

    AUTHENTICATE = "authenticate"
    VERIFY_DPOP = "verify_dpop"
    VERIFY_HTTP_SIGNATURE = "verify_http_signature"
    VERIFY_WEBHOOK = "verify_webhook"
    VALIDATE_SPIFFE_SVID = "validate_spiffe_svid"
    OAUTH_INTROSPECT = "oauth.introspect"
    OAUTH_PAR = "oauth.par"
    OAUTH_VERIFY_JARM = "oauth.verify_jarm"
    OAUTH_TOKEN_EXCHANGE = "oauth.token_exchange"  # ruff: ignore[hardcoded-password-string] - Public operation label.
    KEY_REFRESH = "key.refresh"
    REPLAY_CHECK = "replay.check"
    WEBHOOK_DELIVER = "webhook.deliver"


class SecurityOutcome(StrEnum):
    """Bounded terminal outcomes safe for spans and metric dimensions."""

    AUTHENTICATED = "authenticated"
    NOT_APPLICABLE = "not_applicable"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"
    INVARIANT_FAILURE = "invariant_failure"
    VERIFIED = "verified"
    STORED = "stored"
    REPLAY = "replay"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    SUCCESS = "success"
    ERROR = "error"
    HIT = "hit"
    MISS = "miss"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class TraceCorrelation:
    """Secret-free W3C-compatible trace/span identifiers."""

    trace_id: str
    span_id: str

    def __post_init__(self) -> None:
        """Reject malformed and invalid all-zero identifiers.

        Raises:
            ValueError: If either identifier is not a valid lowercase W3C identifier.
        """
        if len(self.trace_id) != _TRACE_ID_LENGTH or not _is_lower_hex(self.trace_id) or int(self.trace_id, 16) == 0:
            msg = "trace_id must be 32 lowercase hexadecimal characters and non-zero"
            raise ValueError(msg)
        if len(self.span_id) != _SPAN_ID_LENGTH or not _is_lower_hex(self.span_id) or int(self.span_id, 16) == 0:
            msg = "span_id must be 16 lowercase hexadecimal characters and non-zero"
            raise ValueError(msg)


_current_correlation = ContextVar("authweave_trace_correlation", default=None)


class SecurityObservation(Protocol):
    """One in-flight observation returned by a security observer."""

    def set_outcome(self, outcome: SecurityOutcome, *, reason_code: str | None = None) -> None:
        """Attach the bounded terminal outcome."""
        ...


class SecurityObservationContext(Protocol):
    """Synchronous context manager spanning async-compatible security work."""

    def __enter__(self) -> SecurityObservation:
        """Start the observation."""
        ...

    def __exit__(
        self,
        typ: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Finish without suppressing application exceptions."""
        ...


class SecurityObserver(Protocol):
    """Minimal implementation seam for optional telemetry packages."""

    def observe(
        self,
        operation: SecurityOperation,
        *,
        profile: str | None = None,
        principal_kind: str | None = None,
        credential_kind: str | None = None,
        links: Sequence[TraceCorrelation] = (),
    ) -> SecurityObservationContext:
        """Create one logical security observation."""
        ...

    def current_correlation(self) -> TraceCorrelation | None:
        """Return current trace correlation when one exists."""
        ...


class _NoOpObservation:
    __slots__ = ()

    @staticmethod
    def set_outcome(outcome: SecurityOutcome, *, reason_code: str | None = None) -> None:
        _ = outcome, reason_code


class _FailureIsolatingObservation:
    __slots__ = ("_observation",)

    def __init__(self, observation: SecurityObservation) -> None:
        self._observation = observation

    def set_outcome(self, outcome: SecurityOutcome, *, reason_code: str | None = None) -> None:
        try:
            self._observation.set_outcome(outcome, reason_code=reason_code)
        except Exception as exc:
            _warn_observer_failure(exc)


_NOOP_OBSERVATION = _NoOpObservation()


@contextmanager
def observe_security(
    observer: SecurityObserver | None,
    operation: SecurityOperation,
    *,
    profile: str | None = None,
    principal_kind: str | None = None,
    credential_kind: str | None = None,
    links: Sequence[TraceCorrelation] = (),
) -> Iterator[SecurityObservation]:
    """Observe work while preserving body results, errors, and cancellation.

    Yields:
        A failure-isolating observation handle, or a no-op handle.
    """
    if observer is None:
        yield _NOOP_OBSERVATION
        return
    try:
        manager = observer.observe(
            operation,
            profile=profile,
            principal_kind=principal_kind,
            credential_kind=credential_kind,
            links=links,
        )
        observation = manager.__enter__()
    except Exception as exc:
        _warn_observer_failure(exc)
        yield _NOOP_OBSERVATION
        return

    safe_observation = _FailureIsolatingObservation(observation)
    correlation_token = _current_correlation.set(current_trace_correlation(observer))
    try:
        try:
            yield safe_observation
        except BaseException as body_exc:
            try:
                manager.__exit__(type(body_exc), body_exc, body_exc.__traceback__)
            except Exception as observer_exc:
                _warn_observer_failure(observer_exc)
            raise
        else:
            try:
                manager.__exit__(None, None, None)
            except Exception as exc:
                _warn_observer_failure(exc)
    finally:
        _current_correlation.reset(correlation_token)


def current_trace_correlation(observer: SecurityObserver | None) -> TraceCorrelation | None:
    """Read correlation without letting telemetry affect security work.

    Returns:
        Current valid correlation, or ``None`` when unavailable.
    """
    if observer is None:
        return None
    try:
        return observer.current_correlation()
    except Exception as exc:
        _warn_observer_failure(exc)
        return None


def ambient_trace_correlation() -> TraceCorrelation | None:
    """Return correlation installed by the innermost active security observation.

    Returns:
        Current correlation, or ``None`` when telemetry is disabled.
    """
    return _current_correlation.get()


def _warn_observer_failure(exc: Exception) -> None:
    now = time.monotonic()
    with _warning_lock:
        if now - _last_warning_at[0] < _WARNING_INTERVAL_SECONDS:
            return
        _last_warning_at[0] = now
    _LOGGER.warning("AuthWeave security observer failed", extra={"exception_type": type(exc).__name__})


def _is_lower_hex(value: str) -> bool:
    return all(character in "0123456789abcdef" for character in value)


__all__ = (
    "SecurityObservation",
    "SecurityObservationContext",
    "SecurityObserver",
    "SecurityOperation",
    "SecurityOutcome",
    "TraceCorrelation",
    "ambient_trace_correlation",
    "current_trace_correlation",
    "observe_security",
)
