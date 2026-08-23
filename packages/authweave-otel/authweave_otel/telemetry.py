"""OpenTelemetry API-only security observability facade.

The facade depends only on ``opentelemetry-api``. Without a configured SDK the
API returns no-op tracers, meters, and instruments, so instrumentation is safe
and free. The application owns the ``TracerProvider``/``MeterProvider``, SDK,
Collector, sampling, export, and retention; this library never installs a global
SDK, exporter, sampler, or ``service.name``.
"""

from __future__ import annotations

from contextlib import contextmanager
from time import perf_counter
from typing import TYPE_CHECKING

from authweave_core import TraceCorrelation
from opentelemetry import metrics, trace
from opentelemetry.trace import Link, SpanContext, SpanKind, TraceFlags
from opentelemetry.trace.status import Status, StatusCode

from authweave_otel.catalog import (
    ERROR_OUTCOMES,
    INSTRUMENTATION_SCOPE,
    METRIC_CATALOG,
    SEMANTIC_CONVENTIONS_SCHEMA_URL,
    AttributeKey,
    Instrument,
    Operation,
    Outcome,
    normalize_reason_code,
    span_name,
)
from authweave_otel.privacy import sanitize_attributes

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    from opentelemetry.metrics import CallbackOptions, Counter, Histogram, Meter, MeterProvider, Observation
    from opentelemetry.trace import Span, TracerProvider

__version__ = "7.3.4"

type AttributeValue = str
type Attributes = dict[str, AttributeValue]
type KeyAgeCallback = Callable[[CallbackOptions], Sequence[Observation]]


class OperationScope:
    """Handle for enriching one in-flight AuthWeave security span."""

    __slots__ = (
        "_credential_kind",
        "_operation",
        "_outcome",
        "_principal_kind",
        "_profile",
        "_reason_code",
        "_span",
        "_unexpected",
    )

    def __init__(
        self,
        span: Span,
        operation: Operation,
        *,
        profile: str | None,
        principal_kind: str | None,
        credential_kind: str | None,
    ) -> None:
        """Bind the scope to its span and low-cardinality context."""
        self._span = span
        self._operation = operation
        self._profile = profile
        self._principal_kind = principal_kind
        self._credential_kind = credential_kind
        self._outcome: Outcome | None = None
        self._reason_code: str | None = None
        self._unexpected = False

    def set_outcome(self, outcome: Outcome, *, reason_code: str | None = None) -> None:
        """Record the terminal outcome and an optional bounded reason code."""
        self._outcome = outcome
        self._reason_code = reason_code

    def record_unexpected_exception(self, exc: BaseException) -> None:
        """Record only the sanitized exception type, never its message or stack."""
        self._unexpected = True
        self._span.add_event("exception", {"exception.type": type(exc).__name__})

    def _finalize(self) -> None:
        attributes: Attributes = {AttributeKey.OPERATION.value: self._operation.value}
        for key, value in (
            (AttributeKey.PROFILE, self._profile),
            (AttributeKey.PRINCIPAL_KIND, self._principal_kind),
            (AttributeKey.CREDENTIAL_KIND, self._credential_kind),
        ):
            if value is not None:
                attributes[key.value] = value
        if self._outcome is not None:
            attributes[AttributeKey.OUTCOME.value] = self._outcome.value
        normalized = normalize_reason_code(self._reason_code)
        if normalized is not None:
            attributes[AttributeKey.REASON_CODE.value] = normalized
        for key, value in sanitize_attributes(attributes).items():
            self._span.set_attribute(key, value)
        if self._unexpected or (self._outcome is not None and self._outcome in ERROR_OUTCOMES):
            self._span.set_status(Status(StatusCode.ERROR))


class AuthWeaveTelemetry:
    """Typed telemetry facade over the pinned AuthWeave span and metric catalog."""

    __slots__ = ("_counters", "_histograms", "_meter", "_metrics_enabled", "_spans_enabled", "_tracer")

    def __init__(
        self,
        *,
        tracer_provider: TracerProvider | None = None,
        meter_provider: MeterProvider | None = None,
        spans_enabled: bool = True,
        metrics_enabled: bool = True,
    ) -> None:
        """Acquire scoped tracer/meter and eagerly build the catalog instruments."""
        self._spans_enabled = spans_enabled
        self._metrics_enabled = metrics_enabled
        self._tracer = trace.get_tracer(
            INSTRUMENTATION_SCOPE,
            __version__,
            tracer_provider,
            SEMANTIC_CONVENTIONS_SCHEMA_URL,
        )
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}
        self._meter: Meter | None = None
        if metrics_enabled:
            self._build_instruments(meter_provider)

    def _build_instruments(self, meter_provider: MeterProvider | None) -> None:
        meter = metrics.get_meter(
            INSTRUMENTATION_SCOPE,
            __version__,
            meter_provider,
            SEMANTIC_CONVENTIONS_SCHEMA_URL,
        )
        self._meter = meter
        for spec in METRIC_CATALOG:
            if spec.instrument is Instrument.COUNTER:
                self._counters[spec.name] = meter.create_counter(spec.name, spec.unit, spec.description)
            elif spec.instrument is Instrument.HISTOGRAM:
                self._histograms[spec.name] = meter.create_histogram(spec.name, spec.unit, spec.description)
            # Observable instruments (key.age) are registered with an application
            # callback in a dedicated API and are not built eagerly here.

    @contextmanager
    def operation_span(
        self,
        operation: Operation,
        *,
        profile: str | None = None,
        principal_kind: str | None = None,
        credential_kind: str | None = None,
        links: Sequence[TraceCorrelation] = (),
    ) -> Iterator[OperationScope]:
        """Run one INTERNAL security span, recording only sanitized exceptions.

        Cancellation propagates untouched; only ``Exception`` subclasses are
        recorded (by sanitized type) before being re-raised.

        Yields:
            The scope used to set the terminal outcome and reason code.
        """
        if not self._spans_enabled:
            yield OperationScope(
                trace.INVALID_SPAN,
                operation,
                profile=profile,
                principal_kind=principal_kind,
                credential_kind=credential_kind,
            )
            return
        with self._tracer.start_as_current_span(
            span_name(operation),
            kind=SpanKind.INTERNAL,
            links=[_otel_link(link) for link in links],
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            scope = OperationScope(
                span,
                operation,
                profile=profile,
                principal_kind=principal_kind,
                credential_kind=credential_kind,
            )
            try:
                yield scope
            except Exception as exc:
                scope.record_unexpected_exception(exc)
                raise
            finally:
                scope._finalize()

    @contextmanager
    def observe(
        self,
        operation: Operation,
        *,
        profile: str | None = None,
        principal_kind: str | None = None,
        credential_kind: str | None = None,
        links: Sequence[TraceCorrelation] = (),
    ) -> Iterator[OperationScope]:
        """Implement the core observer contract and emit matching metrics.

        Yields:
            The operation scope used by core/provider flow instrumentation.
        """
        started = perf_counter()
        with self.operation_span(
            operation,
            profile=profile,
            principal_kind=principal_kind,
            credential_kind=credential_kind,
            links=links,
        ) as scope:
            try:
                yield scope
            except Exception:
                scope.set_outcome(Outcome.ERROR)
                raise
            finally:
                if scope._outcome is not None:
                    self._record_observation(scope, perf_counter() - started)

    @staticmethod
    def current_correlation() -> TraceCorrelation | None:
        """Return the current valid OpenTelemetry span identifiers."""
        context = trace.get_current_span().get_span_context()
        if not context.is_valid:
            return None
        return TraceCorrelation(trace_id=f"{context.trace_id:032x}", span_id=f"{context.span_id:016x}")

    def _record_observation(self, scope: OperationScope, duration_seconds: float) -> None:
        operation = scope._operation
        outcome = scope._outcome
        if outcome is None:
            return
        if operation is Operation.AUTHENTICATE:
            self.record_authentication(
                profile=scope._profile,
                outcome=outcome,
                reason_code=scope._reason_code,
                principal_kind=scope._principal_kind,
                credential_kind=scope._credential_kind,
                duration_seconds=duration_seconds,
            )
        elif operation in {
            Operation.VERIFY_DPOP,
            Operation.VERIFY_HTTP_SIGNATURE,
            Operation.VERIFY_WEBHOOK,
            Operation.VALIDATE_SPIFFE_SVID,
        }:
            self.record_integrity(
                operation=operation,
                profile=scope._profile,
                outcome=outcome,
                reason_code=scope._reason_code,
                credential_kind=scope._credential_kind,
                duration_seconds=duration_seconds,
            )
        elif operation is Operation.REPLAY_CHECK:
            self.record_replay(profile=scope._profile, outcome=outcome)
        elif operation is Operation.WEBHOOK_DELIVER:
            self.record_webhook_delivery(
                profile=scope._profile,
                outcome=outcome,
                duration_seconds=duration_seconds,
            )
        else:
            self.record_remote_operation(
                operation=operation,
                outcome=outcome,
                profile=scope._profile,
                duration_seconds=duration_seconds,
            )

    def record_authentication(
        self,
        *,
        profile: str | None,
        outcome: Outcome,
        reason_code: str | None = None,
        principal_kind: str | None = None,
        credential_kind: str | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        """Record one authentication attempt and optional latency."""
        attributes = _build_attributes(
            profile=profile,
            operation=Operation.AUTHENTICATE,
            outcome=outcome,
            reason_code=reason_code,
            principal_kind=principal_kind,
            credential_kind=credential_kind,
        )
        self._add("authweave.authentication.attempts", attributes)
        self._record("authweave.authentication.duration", duration_seconds, attributes)

    def record_integrity(
        self,
        *,
        operation: Operation,
        profile: str | None,
        outcome: Outcome,
        reason_code: str | None = None,
        credential_kind: str | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        """Record one message-integrity verification and optional latency."""
        attributes = _build_attributes(
            profile=profile,
            operation=operation,
            outcome=outcome,
            reason_code=reason_code,
            principal_kind=None,
            credential_kind=credential_kind,
        )
        self._add("authweave.integrity.verifications", attributes)
        self._record("authweave.integrity.duration", duration_seconds, attributes)

    def record_replay(self, *, profile: str | None, outcome: Outcome) -> None:
        """Record one replay/nonce store decision."""
        attributes = _build_attributes(
            profile=profile,
            operation=Operation.REPLAY_CHECK,
            outcome=outcome,
            reason_code=None,
            principal_kind=None,
            credential_kind=None,
        )
        self._add("authweave.replay.decisions", attributes)

    def record_remote_operation(
        self,
        *,
        operation: Operation,
        outcome: Outcome,
        profile: str | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        """Record one remote dependency attempt and optional latency, never a URL."""
        attributes = _build_attributes(
            profile=profile,
            operation=operation,
            outcome=outcome,
            reason_code=None,
            principal_kind=None,
            credential_kind=None,
        )
        self._add("authweave.remote.operation.attempts", attributes)
        self._record("authweave.remote.operation.duration", duration_seconds, attributes)

    def record_cache(self, *, operation: Operation, outcome: Outcome) -> None:
        """Record one cache hit, miss, stale, or error decision."""
        attributes = _build_attributes(
            profile=None,
            operation=operation,
            outcome=outcome,
            reason_code=None,
            principal_kind=None,
            credential_kind=None,
        )
        self._add("authweave.cache.requests", attributes)

    def record_webhook_delivery(
        self,
        *,
        profile: str | None,
        outcome: Outcome,
        duration_seconds: float | None = None,
    ) -> None:
        """Record one webhook delivery attempt and optional end-to-end latency."""
        attributes = _build_attributes(
            profile=profile,
            operation=Operation.WEBHOOK_DELIVER,
            outcome=outcome,
            reason_code=None,
            principal_kind=None,
            credential_kind=None,
        )
        self._add("authweave.webhook.delivery.attempts", attributes)
        self._record("authweave.webhook.delivery.duration", duration_seconds, attributes)

    def register_key_age(self, callback: KeyAgeCallback) -> None:
        """Register the application callback backing the ``authweave.key.age`` gauge.

        The callback must return bounded, low-cardinality observations and never a
        key identifier or URL. It is a no-op when metrics are disabled.
        """
        if not self._metrics_enabled or self._meter is None:
            return
        spec = next(spec for spec in METRIC_CATALOG if spec.name == "authweave.key.age")
        self._meter.create_observable_gauge(spec.name, [callback], spec.unit, spec.description)

    def _add(self, name: str, attributes: Attributes) -> None:
        if self._metrics_enabled:
            self._counters[name].add(1, attributes)

    def _record(self, name: str, value: float | None, attributes: Attributes) -> None:
        if self._metrics_enabled and value is not None:
            self._histograms[name].record(value, attributes)


def _build_attributes(
    *,
    profile: str | None,
    operation: Operation,
    outcome: Outcome,
    reason_code: str | None,
    principal_kind: str | None,
    credential_kind: str | None,
) -> Attributes:
    attributes: Attributes = {
        AttributeKey.OPERATION.value: operation.value,
        AttributeKey.OUTCOME.value: outcome.value,
    }
    normalized = normalize_reason_code(reason_code)
    for key, value in (
        (AttributeKey.PROFILE, profile),
        (AttributeKey.REASON_CODE, normalized),
        (AttributeKey.PRINCIPAL_KIND, principal_kind),
        (AttributeKey.CREDENTIAL_KIND, credential_kind),
    ):
        if value is not None:
            attributes[key.value] = value
    return sanitize_attributes(attributes)


def _otel_link(correlation: TraceCorrelation) -> Link:
    return Link(
        SpanContext(
            trace_id=int(correlation.trace_id, 16),
            span_id=int(correlation.span_id, 16),
            is_remote=True,
            trace_flags=TraceFlags(TraceFlags.DEFAULT),
        ),
    )
