# authweave-otel

OpenTelemetry API-only security observability facade for the AuthWeave
authentication stack.

`authweave-otel` depends only on `opentelemetry-api` and `authweave-core`. It
never installs an SDK, exporter, sampler, propagator, or `service.name`. Without
a configured SDK every span and metric is a no-op, so instrumentation is safe and
free by default.

The application owns the `TracerProvider`/`MeterProvider`, sampling, export, and
retention. Construct `AuthWeaveTelemetry` with global or explicit providers and
pass it into your AuthWeave adapter configuration. `LitestarAuth` creates only
`INTERNAL` child security spans inside the server span produced by normal ASGI
instrumentation; it never creates a second HTTP span:

```python
from authweave_otel import AuthWeaveTelemetry
from litestar_auth import LitestarAuthConfig

telemetry = AuthWeaveTelemetry()
config = LitestarAuthConfig(
    # normal required configuration omitted
    observer=telemetry,
)
```

The same observer can be passed to the HTTP-signature/webhook verifier and
webhook sender constructors. `verify(..., links=(TraceCorrelation(...),))` and
`send(..., links=...)` attach retry/async causal links without accepting trace
context as identity. Direct `operation_span()` and metric methods remain
available for application-owned operations.

## Privacy and abuse resistance

- Attribute keys are allowlisted (`authweave.*` catalog only).
- Values are truncated to 64 characters and redacted when they match secret
  canaries (tokens, cookies, PEM headers, payment fragments).
- Unknown reason codes collapse to `_OTHER` so hostile input cannot grow label
  cardinality.
- Baggage extraction/forwarding defaults to off
  (`DEFAULT_TRACE_CONTEXT_POLICY`); remote parents are never trusted identity.
- Telemetry never participates in authentication, authorization, replay, or
  idempotency decisions. Collector/exporter outage must not change auth results.
- Workload `SecurityEvent` values receive the active `trace_id`/`span_id` for
  lookup only. The mandatory event callback remains the durable audit channel.

## Catalog and reference stack

Span names, metric names, units, and attribute keys are a versioned catalog. See
`authweave_otel.catalog`; renames and cardinality growth are breaking changes.

A non-production Collector/Prometheus/Tempo/Grafana stack lives at
`docker/reference/observability/`. Run `sh docker/reference/observability/verify.sh`
for the synthetic smoke test and golden Prometheus name checks after the pinned
OTel→Prometheus translation.
