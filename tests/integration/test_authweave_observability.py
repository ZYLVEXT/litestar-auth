"""Synthetic real-provider proof for AuthWeave OpenTelemetry wiring."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import anyio.lowlevel
import pytest
from authweave_core import (
    Authenticated,
    AuthenticationCoordinator,
    AuthenticationRuntime,
    RequestView,
    RouteProviderPolicy,
    TlsPeerEvidence,
)
from authweave_otel import AuthWeaveTelemetry
from authweave_workload.introspection import (
    BoundedIntrospectionClient,
    IntrospectionEndpoint,
    IntrospectionIssuerProfile,
    MTLSBoundIntrospectionProvider,
)
from authweave_workload.provider import DirectMTLSPolicy
from litestar.connection import ASGIConnection
from litestar.datastructures.state import State
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

from litestar_auth.authentication import LitestarAuthMiddleware, LitestarProviderBinding

if TYPE_CHECKING:
    from collections.abc import Sequence

    from authweave_workload.events import SecurityEvent

pytestmark = pytest.mark.integration
_NOW = datetime.now(UTC)
_THUMBPRINT = "A" * 43


class _UnavailableExporter(SpanExporter):
    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        _ = spans
        return SpanExportResult.FAILURE


class _NoOpProcessor(SpanProcessor):
    def on_start(self, span: Span, parent_context: object | None = None) -> None:
        _ = span, parent_context

    def on_end(self, span: ReadableSpan) -> None:
        _ = span

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        _ = timeout_millis
        return True


def _provider(events: list[SecurityEvent]) -> MTLSBoundIntrospectionProvider:
    async def poster(
        _url: str,
        _headers: object,
        _request_body: bytes,
        _timeout: float,
        _maximum: int,
    ) -> tuple[int, bytes, str]:
        await anyio.lowlevel.checkpoint()
        body = json.dumps(
            {
                "active": True,
                "sub": "merchant-1",
                "client_id": "client-1",
                "aud": "payments-api",
                "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
                "iat": int((_NOW - timedelta(minutes=1)).timestamp()),
                "cnf": {"x5t#S256": _THUMBPRINT},
            },
        ).encode()
        return 200, body, "application/json"

    return MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=poster,
        ),
        profile=IntrospectionIssuerProfile(
            issuer="https://as.example/issuer",
            environment="sandbox",
            audiences=frozenset({"payments-api"}),
        ),
        tls_policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"local-ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
        event_callback=events.append,
    )


def _request() -> RequestView:
    return RequestView(
        method="POST",
        headers=((b"authorization", b"Bearer opaque-token"),),
        tls_peer=TlsPeerEvidence(
            tls_version="TLSv1.3",
            certificate_thumbprint=_THUMBPRINT,
            certificate_not_before=_NOW - timedelta(hours=1),
            certificate_not_after=_NOW + timedelta(hours=1),
            revocation_checked_at=_NOW - timedelta(minutes=1),
            trust_anchor="local-ca",
            termination_boundary="envoy",
        ),
        timestamp=_NOW,
    )


async def test_real_provider_exports_child_spans_metrics_and_event_correlation() -> None:
    """A real introspection provider emits child security spans, metrics, and correlated events."""
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    telemetry = AuthWeaveTelemetry(tracer_provider=tracer_provider, meter_provider=meter_provider)
    events: list[SecurityEvent] = []
    provider = _provider(events)
    binding = LitestarProviderBinding(provider=provider, load_principal=lambda _context: object())
    middleware = LitestarAuthMiddleware(
        cast("Any", lambda _scope, _receive, _send: None),
        get_request_session=cast("Any", lambda _state, _scope: object()),
        provider_bindings_factory=lambda _session: (binding,),
        default_policy=RouteProviderPolicy(("intro",)),
        tls_peer_evidence_factory=lambda _scope: _request().tls_peer,
        observer=telemetry,
    )
    connection = ASGIConnection(
        cast(
            "Any",
            {
                "type": "http",
                "method": "POST",
                "path": "/payments",
                "path_params": {},
                "query_string": b"",
                "scheme": "https",
                "headers": [(b"authorization", b"Bearer opaque-token")],
                "litestar_app": SimpleNamespace(state=State()),
                "route_handler": SimpleNamespace(opt={}),
            },
        ),
    )
    tracer = tracer_provider.get_tracer("synthetic-server")

    with tracer.start_as_current_span("POST /payments", kind=SpanKind.SERVER):
        result = await middleware.authenticate_request(connection)

    assert result.auth is not None
    spans = {span.name: span for span in span_exporter.get_finished_spans()}
    assert set(spans) == {"POST /payments", "authweave.authenticate", "authweave.oauth.introspect"}
    assert spans["authweave.authenticate"].parent is not None
    assert spans["authweave.authenticate"].parent.span_id == spans["POST /payments"].context.span_id
    assert spans["authweave.oauth.introspect"].parent is not None
    assert spans["authweave.oauth.introspect"].parent.span_id == spans["authweave.authenticate"].context.span_id
    assert sum(span.kind is SpanKind.SERVER for span in spans.values()) == 1
    assert events[0].trace_id == f"{spans['authweave.authenticate'].context.trace_id:032x}"
    assert events[0].span_id == f"{spans['authweave.authenticate'].context.span_id:016x}"

    metrics = metric_reader.get_metrics_data()
    assert metrics is not None
    names = {
        metric.name
        for resource in metrics.resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
    }
    assert "authweave.authentication.attempts" in names
    assert "authweave.remote.operation.attempts" in names


async def test_collector_export_failure_does_not_change_authentication_decision() -> None:
    """An unavailable Collector remains isolated from the authentication decision."""
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(_UnavailableExporter()))
    tracer_provider.add_span_processor(_NoOpProcessor())
    events: list[SecurityEvent] = []

    decision = await AuthenticationCoordinator((_provider(events),)).authenticate(
        _request(),
        AuthenticationRuntime(
            observer=AuthWeaveTelemetry(tracer_provider=tracer_provider, metrics_enabled=False),
        ),
        RouteProviderPolicy(("intro",)),
    )

    assert isinstance(decision, Authenticated)
    assert len(events) == 1
