"""In-memory SDK behavior tests for the AuthWeave telemetry facade."""

from __future__ import annotations

from time import perf_counter
from typing import TYPE_CHECKING, Any

import pytest
from authweave_core import TraceCorrelation
from authweave_otel import (
    INSTRUMENTATION_SCOPE,
    SEMANTIC_CONVENTIONS_SCHEMA_URL,
    AttributeKey,
    AuthWeaveTelemetry,
    Operation,
    OperationScope,
    Outcome,
    __version__,
)
from opentelemetry import trace
from opentelemetry.metrics import CallbackOptions, Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind
from opentelemetry.trace.status import StatusCode

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan

pytestmark = pytest.mark.unit
_KEY_AGE_SECONDS = 42.0
_NOOP_ITERATIONS = 10_000
_NOOP_BUDGET_SECONDS = 1.0
_HOSTILE_REASON_COUNT = 1_000


@pytest.fixture
def spans() -> tuple[AuthWeaveTelemetry, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return AuthWeaveTelemetry(tracer_provider=provider, metrics_enabled=False), exporter


@pytest.fixture
def metrics() -> tuple[AuthWeaveTelemetry, InMemoryMetricReader]:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    return AuthWeaveTelemetry(meter_provider=provider, spans_enabled=False), reader


def _only_span(exporter: InMemorySpanExporter) -> ReadableSpan:
    finished = exporter.get_finished_spans()
    assert len(finished) == 1
    return finished[0]


def _points(reader: InMemoryMetricReader) -> dict[str, tuple[Any, list[tuple[dict[str, Any], Any]]]]:
    data = reader.get_metrics_data()
    collected: dict[str, tuple[Any, list[tuple[dict[str, Any], Any]]]] = {}
    if data is None:
        return collected
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                data_points: Any = metric.data.data_points
                points = [(dict(point.attributes), point) for point in data_points]
                collected[metric.name] = (scope_metric.scope, points)
    return collected


def test_operation_span_records_internal_kind_and_bounded_attributes(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    telemetry, exporter = spans

    with telemetry.operation_span(
        Operation.AUTHENTICATE,
        profile="direct_mtls",
        principal_kind="service",
        credential_kind="x509",
    ) as scope:
        scope.set_outcome(Outcome.AUTHENTICATED)

    span = _only_span(exporter)
    assert span.name == "authweave.authenticate"
    assert span.kind is SpanKind.INTERNAL
    assert span.attributes is not None
    assert span.attributes[AttributeKey.OPERATION.value] == "authenticate"
    assert span.attributes[AttributeKey.PROFILE.value] == "direct_mtls"
    assert span.attributes[AttributeKey.OUTCOME.value] == "authenticated"
    assert span.status.status_code is StatusCode.UNSET


def test_span_without_outcome_has_no_outcome_attribute(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    telemetry, exporter = spans

    with telemetry.operation_span(Operation.KEY_REFRESH):
        pass

    span = _only_span(exporter)
    assert span.attributes is not None
    assert AttributeKey.OUTCOME.value not in span.attributes
    assert AttributeKey.REASON_CODE.value not in span.attributes
    assert span.status.status_code is StatusCode.UNSET


def test_expected_invalid_outcome_is_not_error(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    telemetry, exporter = spans

    with telemetry.operation_span(Operation.VERIFY_DPOP, profile="dpop_jwt") as scope:
        scope.set_outcome(Outcome.INVALID, reason_code="expired")

    span = _only_span(exporter)
    assert span.status.status_code is StatusCode.UNSET
    assert span.attributes is not None
    assert span.attributes[AttributeKey.REASON_CODE.value] == "expired"


def test_unavailable_outcome_marks_error(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    telemetry, exporter = spans

    with telemetry.operation_span(Operation.REPLAY_CHECK, profile="dpop_jwt") as scope:
        scope.set_outcome(Outcome.UNAVAILABLE)

    assert _only_span(exporter).status.status_code is StatusCode.ERROR


def test_unknown_reason_code_collapses_to_other(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    telemetry, exporter = spans

    with telemetry.operation_span(Operation.VERIFY_DPOP, profile="dpop_jwt") as scope:
        scope.set_outcome(Outcome.INVALID, reason_code="attacker-supplied")

    span = _only_span(exporter)
    assert span.attributes is not None
    assert span.attributes[AttributeKey.REASON_CODE.value] == "_OTHER"


def test_exception_is_recorded_sanitized_and_reraised(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    telemetry, exporter = spans

    def leak() -> None:
        message = "secret-token-must-not-leak"
        with telemetry.operation_span(Operation.OAUTH_INTROSPECT, profile="introspection") as scope:
            scope.set_outcome(Outcome.UNAVAILABLE)
            raise ValueError(message)

    with pytest.raises(ValueError, match="secret-token"):
        leak()

    span = _only_span(exporter)
    assert span.status.status_code is StatusCode.ERROR
    assert [event.name for event in span.events] == ["exception"]
    assert span.events[0].attributes == {"exception.type": "ValueError"}
    assert "secret-token-must-not-leak" not in str(span.events[0].attributes)


def test_base_exception_is_not_captured(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    telemetry, exporter = spans

    def interrupt() -> None:
        with telemetry.operation_span(Operation.AUTHENTICATE) as scope:
            scope.set_outcome(Outcome.AUTHENTICATED)
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        interrupt()

    span = _only_span(exporter)
    assert span.events == ()
    assert span.status.status_code is StatusCode.UNSET


def test_disabled_spans_emit_nothing(
    spans: tuple[AuthWeaveTelemetry, InMemorySpanExporter],
) -> None:
    _telemetry, exporter = spans
    disabled = AuthWeaveTelemetry(spans_enabled=False, metrics_enabled=False)

    with disabled.operation_span(Operation.AUTHENTICATE) as scope:
        scope.set_outcome(Outcome.AUTHENTICATED)

    assert exporter.get_finished_spans() == ()


def test_record_authentication_emits_bounded_metric(
    metrics: tuple[AuthWeaveTelemetry, InMemoryMetricReader],
) -> None:
    telemetry, reader = metrics

    telemetry.record_authentication(
        profile="direct_mtls",
        outcome=Outcome.AUTHENTICATED,
        principal_kind="service",
        duration_seconds=0.004,
    )

    points = _points(reader)
    scope, attempts = points["authweave.authentication.attempts"]
    assert scope.name == INSTRUMENTATION_SCOPE
    assert scope.version == __version__
    assert scope.schema_url == SEMANTIC_CONVENTIONS_SCHEMA_URL
    attributes, point = attempts[0]
    assert point.value == 1
    assert attributes == {
        "authweave.operation": "authenticate",
        "authweave.outcome": "authenticated",
        "authweave.profile": "direct_mtls",
        "authweave.principal_kind": "service",
    }
    _, duration = points["authweave.authentication.duration"]
    assert duration[0][1].count == 1


def test_record_authentication_without_duration_skips_histogram(
    metrics: tuple[AuthWeaveTelemetry, InMemoryMetricReader],
) -> None:
    telemetry, reader = metrics

    telemetry.record_authentication(profile=None, outcome=Outcome.NOT_APPLICABLE)

    points = _points(reader)
    assert "authweave.authentication.attempts" in points
    assert "authweave.authentication.duration" not in points


def test_record_integrity_and_replay(
    metrics: tuple[AuthWeaveTelemetry, InMemoryMetricReader],
) -> None:
    telemetry, reader = metrics

    telemetry.record_integrity(
        operation=Operation.VERIFY_WEBHOOK,
        profile="standard_webhooks",
        outcome=Outcome.VERIFIED,
        duration_seconds=0.002,
    )
    telemetry.record_replay(profile="dpop_jwt", outcome=Outcome.REPLAY)

    points = _points(reader)
    _, verifications = points["authweave.integrity.verifications"]
    assert verifications[0][1].value == 1
    assert verifications[0][0]["authweave.operation"] == "verify_webhook"
    _, decisions = points["authweave.replay.decisions"]
    assert decisions[0][0]["authweave.outcome"] == "replay"


def test_record_remote_cache_and_webhook_metrics(
    metrics: tuple[AuthWeaveTelemetry, InMemoryMetricReader],
) -> None:
    telemetry, reader = metrics

    telemetry.record_remote_operation(
        operation=Operation.OAUTH_INTROSPECT,
        outcome=Outcome.SUCCESS,
        duration_seconds=0.05,
    )
    telemetry.record_cache(operation=Operation.OAUTH_INTROSPECT, outcome=Outcome.MISS)
    telemetry.record_webhook_delivery(profile="standard_webhooks", outcome=Outcome.SUCCESS, duration_seconds=0.2)

    points = _points(reader)
    _, remote = points["authweave.remote.operation.attempts"]
    assert remote[0][0] == {"authweave.operation": "oauth.introspect", "authweave.outcome": "success"}
    assert points["authweave.remote.operation.duration"][1][0][1].count == 1
    _, cache = points["authweave.cache.requests"]
    assert cache[0][0]["authweave.outcome"] == "miss"
    _, webhook = points["authweave.webhook.delivery.attempts"]
    assert webhook[0][0]["authweave.profile"] == "standard_webhooks"


def test_register_key_age_gauge_observes_callback(
    metrics: tuple[AuthWeaveTelemetry, InMemoryMetricReader],
) -> None:
    telemetry, reader = metrics

    def observe(_options: CallbackOptions) -> list[Observation]:
        return [Observation(_KEY_AGE_SECONDS, {"authweave.profile": "standard_webhooks"})]

    telemetry.register_key_age(observe)

    _, ages = _points(reader)["authweave.key.age"]
    assert ages[0][1].value == pytest.approx(_KEY_AGE_SECONDS)
    assert ages[0][0] == {"authweave.profile": "standard_webhooks"}


def test_register_key_age_is_noop_when_metrics_disabled() -> None:
    telemetry = AuthWeaveTelemetry(metrics_enabled=False, spans_enabled=False)

    telemetry.register_key_age(lambda _options: [Observation(1.0, {})])


def test_disabled_metrics_record_nothing() -> None:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    telemetry = AuthWeaveTelemetry(meter_provider=provider, metrics_enabled=False)

    telemetry.record_authentication(profile="direct_mtls", outcome=Outcome.AUTHENTICATED, duration_seconds=0.1)
    telemetry.record_replay(profile="dpop_jwt", outcome=Outcome.STORED)

    assert _points(reader) == {}


@pytest.mark.parametrize(
    ("operation", "outcome", "metric_name"),
    [
        (Operation.AUTHENTICATE, Outcome.AUTHENTICATED, "authweave.authentication.attempts"),
        (Operation.VERIFY_DPOP, Outcome.VERIFIED, "authweave.integrity.verifications"),
        (Operation.REPLAY_CHECK, Outcome.STORED, "authweave.replay.decisions"),
        (Operation.WEBHOOK_DELIVER, Outcome.SUCCESS, "authweave.webhook.delivery.attempts"),
        (Operation.OAUTH_INTROSPECT, Outcome.SUCCESS, "authweave.remote.operation.attempts"),
    ],
)
def test_observer_contract_emits_span_and_matching_metric(
    operation: Operation,
    outcome: Outcome,
    metric_name: str,
) -> None:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    telemetry = AuthWeaveTelemetry(tracer_provider=tracer_provider, meter_provider=meter_provider)

    with telemetry.observe(operation, profile="profile") as scope:
        scope.set_outcome(outcome)

    assert exporter.get_finished_spans()[0].name == f"authweave.{operation.value}"
    assert metric_name in _points(reader)


def test_observer_correlation_links_and_exception_outcome() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    telemetry = AuthWeaveTelemetry(tracer_provider=provider, metrics_enabled=False)
    link = TraceCorrelation("1" * 32, "2" * 16)
    assert telemetry.current_correlation() is None

    with telemetry.observe(Operation.VERIFY_WEBHOOK, links=(link,)):
        correlation = telemetry.current_correlation()
        assert correlation is not None

    span = exporter.get_finished_spans()[0]
    assert span.links[0].context.trace_id == int(link.trace_id, 16)
    assert span.links[0].context.span_id == int(link.span_id, 16)

    message = "verification failed"
    with pytest.raises(ValueError, match=message), telemetry.observe(Operation.VERIFY_WEBHOOK):
        raise ValueError(message)
    assert exporter.get_finished_spans()[-1].status.status_code is StatusCode.ERROR


def test_record_observation_without_outcome_is_a_noop() -> None:
    telemetry = AuthWeaveTelemetry(metrics_enabled=False, spans_enabled=False)
    scope = OperationScope(
        trace.INVALID_SPAN, Operation.AUTHENTICATE, profile=None, principal_kind=None, credential_kind=None
    )

    telemetry._record_observation(scope, 0.1)


def test_hostile_reason_load_has_one_bounded_metric_series() -> None:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    telemetry = AuthWeaveTelemetry(meter_provider=provider, spans_enabled=False)

    for index in range(_HOSTILE_REASON_COUNT):
        telemetry.record_authentication(
            profile="direct_mtls",
            outcome=Outcome.INVALID,
            reason_code=f"hostile-{index}",
        )

    _, attempts = _points(reader)["authweave.authentication.attempts"]
    assert len(attempts) == 1
    assert attempts[0][0]["authweave.reason_code"] == "_OTHER"
    assert attempts[0][1].value == _HOSTILE_REASON_COUNT


def test_disabled_observer_has_measurable_noop_overhead_budget() -> None:
    telemetry = AuthWeaveTelemetry(metrics_enabled=False, spans_enabled=False)
    started = perf_counter()

    for _ in range(_NOOP_ITERATIONS):
        with telemetry.observe(Operation.AUTHENTICATE) as scope:
            scope.set_outcome(Outcome.AUTHENTICATED)

    elapsed = perf_counter() - started
    assert elapsed < _NOOP_BUDGET_SECONDS
