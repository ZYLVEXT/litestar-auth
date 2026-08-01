# AuthWeave observability reference

Non-production OpenTelemetry Collector + Prometheus + Tempo + Grafana stack for
local smoke tests of `authweave-otel`.

## Boundaries

- The library depends only on `opentelemetry-api` and never installs an SDK,
  exporter, sampler, propagator, or `service.name`.
- This compose file is owned by the deployer/reference harness.
- Resource attributes `service.namespace`, `service.name`, `service.version`,
  and `deployment.environment.name` are set by `emit_synthetic.py`, not by the
  library.
- Grafana runs with anonymous Viewer access and no hard-coded admin password.
- Retention is intentionally short (`2h` Prometheus, `1h` Tempo).

## Ports (loopback only)

| Service     | Port  |
|-------------|-------|
| OTLP gRPC   | 14317 |
| OTLP HTTP   | 14318 |
| Collector health | 23133 |
| Prometheus  | 19090 |
| Grafana     | 13000 |
| Tempo       | 13200 |

## Smoke test

```sh
sh docker/reference/observability/verify.sh
```

The script starts the stack, emits synthetic AuthWeave spans/metrics, asserts
pinned Prometheus metric names after OTel→Prometheus translation, and checks
Grafana datasource UIDs plus the `AuthWeave Overview` dashboard.

## Dashboard

`grafana/dashboards/authweave-overview.json` is provisioned with datasource
UIDs `authweave-prometheus` and `authweave-tempo`. Variables are limited to:

- `service_namespace`
- `service_name`
- `deployment_environment`
- `authweave_profile`
- `authweave_operation`

Recording rules under `prometheus/recording-rules.yml` are safe examples only.
Production SLO thresholds remain a deployment decision.
