"""Emit synthetic AuthWeave telemetry into the reference observability stack.

Application-owned Resource attributes are set explicitly. The library never
guesses ``service.name``. Run against a live Collector on localhost OTLP ports.
"""

from __future__ import annotations

import argparse
import time

from authweave_otel import AuthWeaveTelemetry, Operation, Outcome
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.metrics import Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def _build_telemetry(endpoint: str) -> AuthWeaveTelemetry:
    resource = Resource.create({
        "service.namespace": "authweave",
        "service.name": "observability-reference",
        "service.version": "7.0.0",
        "deployment.environment.name": "reference",
    })
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True)))
    trace.set_tracer_provider(tracer_provider)

    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=endpoint, insecure=True),
        export_interval_millis=1000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)
    return AuthWeaveTelemetry(tracer_provider=tracer_provider, meter_provider=meter_provider)


def emit(endpoint: str, cycles: int) -> None:
    telemetry = _build_telemetry(endpoint)
    telemetry.register_key_age(lambda _options: [Observation(120.0, {"authweave.profile": "standard_webhooks"})])

    for index in range(cycles):
        with telemetry.operation_span(
            Operation.AUTHENTICATE,
            profile="direct_mtls",
            principal_kind="service",
            credential_kind="x509",
        ) as scope:
            scope.set_outcome(Outcome.AUTHENTICATED)
        telemetry.record_authentication(
            profile="direct_mtls",
            outcome=Outcome.AUTHENTICATED,
            principal_kind="service",
            credential_kind="x509",
            duration_seconds=0.004 + (index * 0.0001),
        )
        telemetry.record_replay(profile="dpop_jwt", outcome=Outcome.STORED)
        telemetry.record_integrity(
            operation=Operation.VERIFY_WEBHOOK,
            profile="standard_webhooks",
            outcome=Outcome.VERIFIED,
            duration_seconds=0.002,
        )
        telemetry.record_remote_operation(
            operation=Operation.KEY_REFRESH,
            outcome=Outcome.SUCCESS,
            profile="standard_webhooks",
            duration_seconds=0.01,
        )
        telemetry.record_cache(operation=Operation.KEY_REFRESH, outcome=Outcome.HIT)
        telemetry.record_webhook_delivery(
            profile="standard_webhooks",
            outcome=Outcome.SUCCESS,
            duration_seconds=0.05,
        )
        time.sleep(0.2)

    # Allow final export flush.
    time.sleep(2.0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="127.0.0.1:14317")
    parser.add_argument("--cycles", type=int, default=5)
    args = parser.parse_args()
    emit(args.endpoint, args.cycles)


if __name__ == "__main__":
    main()
