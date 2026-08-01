"""Privacy and cardinality policy tests for authweave-otel."""

from __future__ import annotations

import pytest
from authweave_otel import (
    ALLOWED_ATTRIBUTE_KEYS,
    DEFAULT_BAGGAGE_KEYS_ALLOWLIST,
    DEFAULT_TRACE_CONTEXT_POLICY,
    MAX_ATTRIBUTE_COUNT,
    MAX_ATTRIBUTE_VALUE_LENGTH,
    REDACTED_ATTRIBUTE_VALUE,
    SECRET_CANARY_FRAGMENTS,
    AttributeKey,
    AuthWeaveTelemetry,
    Operation,
    Outcome,
    contains_secret_canary,
    sanitize_attributes,
    truncate_attribute_value,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

pytestmark = pytest.mark.unit


def test_trace_context_policy_defaults_are_fail_closed() -> None:
    assert DEFAULT_TRACE_CONTEXT_POLICY.accept_remote_parent is False
    assert DEFAULT_TRACE_CONTEXT_POLICY.extract_baggage is False
    assert DEFAULT_TRACE_CONTEXT_POLICY.forward_baggage is False
    assert frozenset() == DEFAULT_BAGGAGE_KEYS_ALLOWLIST
    assert frozenset() == DEFAULT_TRACE_CONTEXT_POLICY.baggage_keys_allowlist


def test_sanitize_attributes_drops_unknown_keys_and_truncates() -> None:
    oversized = "p" * (MAX_ATTRIBUTE_VALUE_LENGTH + 12)
    sanitized = sanitize_attributes({
        AttributeKey.PROFILE.value: oversized,
        "http.url": "https://merchant.example/payment?token=eyJhbGciOi",
        AttributeKey.OUTCOME.value: Outcome.AUTHENTICATED.value,
    })

    assert set(sanitized) <= ALLOWED_ATTRIBUTE_KEYS
    assert "http.url" not in sanitized
    assert sanitized[AttributeKey.PROFILE.value] == "p" * MAX_ATTRIBUTE_VALUE_LENGTH
    assert len(sanitized) <= MAX_ATTRIBUTE_COUNT


def test_sanitize_attributes_enforces_count_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    keys = frozenset(f"authweave.budget_{index}" for index in range(MAX_ATTRIBUTE_COUNT + 3))
    monkeypatch.setattr("authweave_otel.privacy.ALLOWED_ATTRIBUTE_KEYS", keys)
    sanitized = sanitize_attributes(dict.fromkeys(sorted(keys), "v"))

    assert len(sanitized) == MAX_ATTRIBUTE_COUNT
    assert set(sanitized) <= keys


def test_truncate_attribute_value_is_idempotent_for_short_values() -> None:
    assert truncate_attribute_value("direct_mtls") == "direct_mtls"


@pytest.mark.parametrize("fragment", sorted(SECRET_CANARY_FRAGMENTS))
def test_secret_canary_detector(fragment: str) -> None:
    assert contains_secret_canary(f"prefix-{fragment}-suffix")


def test_span_attributes_never_carry_secret_canaries() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    telemetry = AuthWeaveTelemetry(tracer_provider=provider, metrics_enabled=False)
    canary_profile = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.leak"

    with telemetry.operation_span(Operation.AUTHENTICATE, profile=canary_profile) as scope:
        scope.set_outcome(Outcome.INVALID, reason_code="password=hunter2")

    span = exporter.get_finished_spans()[0]
    assert span.attributes is not None
    rendered = " ".join(f"{key}={value}" for key, value in span.attributes.items())
    for fragment in SECRET_CANARY_FRAGMENTS:
        assert fragment.lower() not in rendered.lower()
    assert span.attributes[AttributeKey.PROFILE.value] == REDACTED_ATTRIBUTE_VALUE
    # Hostile reason codes collapse to the bounded vocabulary, never raw secrets.
    assert span.attributes[AttributeKey.REASON_CODE.value] == "_OTHER"


def test_metric_labels_never_carry_secret_canaries() -> None:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    telemetry = AuthWeaveTelemetry(meter_provider=provider, spans_enabled=False)
    canary = "cookie=session-secret; authorization_code=abc"

    telemetry.record_authentication(profile=canary, outcome=Outcome.INVALID, reason_code="client_secret")

    data = reader.get_metrics_data()
    assert data is not None
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                for point in metric.data.data_points:
                    assert point.attributes is not None
                    for key, value in point.attributes.items():
                        assert key in ALLOWED_ATTRIBUTE_KEYS
                        assert not contains_secret_canary(str(value))
