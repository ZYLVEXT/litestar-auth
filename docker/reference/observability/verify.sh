#!/usr/bin/env sh
# Smoke-test the non-production AuthWeave observability reference stack.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${ROOT}/../../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/compose.yml"
PROM_URL="${PROM_URL:-http://127.0.0.1:19090}"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:13000}"
COLLECTOR_HEALTH_URL="${COLLECTOR_HEALTH_URL:-http://127.0.0.1:23133/}"
TEMPO_READY_URL="${TEMPO_READY_URL:-http://127.0.0.1:13200/ready}"
COLLECTOR_OTLP="${COLLECTOR_OTLP:-127.0.0.1:14317}"

# Exact Prometheus names after pinned OTel→Prometheus UnderscoreEscapingWithSuffixes.
REQUIRED_METRICS="
authweave_authentication_attempts_total
authweave_authentication_duration_seconds_bucket
authweave_integrity_verifications_total
authweave_integrity_duration_seconds_bucket
authweave_replay_decisions_total
authweave_remote_operation_attempts_total
authweave_remote_operation_duration_seconds_bucket
authweave_cache_requests_total
authweave_key_age_seconds
authweave_webhook_delivery_attempts_total
authweave_webhook_delivery_duration_seconds_bucket
"

wait_http() {
  url="$1"
  name="$2"
  for _ in $(seq 1 60); do
    if curl --silent --fail --max-time 2 "$url" >/dev/null 2>&1; then
      echo "  ready ${name}"
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${name}: ${url}" >&2
  return 1
}

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "${REPO_ROOT}"

echo "==> starting observability reference"
$COMPOSE up -d

echo "==> waiting for collector / tempo / prometheus / grafana"
wait_http "${COLLECTOR_HEALTH_URL}" collector
wait_http "${TEMPO_READY_URL}" tempo
wait_http "${PROM_URL}/-/ready" prometheus
wait_http "${GRAFANA_URL}/api/health" grafana

echo "==> validating dashboard datasource UIDs"
python3 - <<'PY'
import json
from pathlib import Path

dashboard = json.loads(
    Path("docker/reference/observability/grafana/dashboards/authweave-overview.json").read_text()
)
uids = {
    panel["datasource"]["uid"]
    for panel in dashboard["panels"]
    if isinstance(panel.get("datasource"), dict)
}
assert uids == {"authweave-prometheus", "authweave-tempo"}, uids
variables = [item["name"] for item in dashboard["templating"]["list"]]
assert variables == [
    "service_namespace",
    "service_name",
    "deployment_environment",
    "authweave_profile",
    "authweave_operation",
], variables
print("dashboard UIDs and variables ok")
PY

echo "==> emitting synthetic AuthWeave telemetry"
uv run --frozen --group reference \
  python "${ROOT}/emit_synthetic.py" --endpoint "${COLLECTOR_OTLP}" --cycles 8

echo "==> waiting for Prometheus scrape"
ready=0
for _ in $(seq 1 30); do
  if curl --silent --fail "${PROM_URL}/api/v1/query?query=authweave_authentication_attempts_total" \
    | grep -q '"result":\[{'; then
    ready=1
    break
  fi
  sleep 2
done
if [ "$ready" -ne 1 ]; then
  echo "Prometheus did not observe authweave_authentication_attempts_total" >&2
  exit 1
fi

echo "==> asserting golden Prometheus metric names"
for metric in $REQUIRED_METRICS; do
  curl --silent --fail "${PROM_URL}/api/v1/query?query=${metric}" \
    | grep -q '"result":\[{' \
    || { echo "missing metric: ${metric}" >&2; exit 1; }
  echo "  ok ${metric}"
done

echo "==> asserting Grafana health and dashboard link"
python3 - <<'PY'
import json
import urllib.request

def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.load(response)

health = get("http://127.0.0.1:13000/api/health")
assert health.get("database") == "ok", health

dashboard = get("http://127.0.0.1:13000/api/dashboards/uid/authweave-overview")
assert dashboard["dashboard"]["uid"] == "authweave-overview"

for uid in ("authweave-prometheus", "authweave-tempo"):
    payload = get(f"http://127.0.0.1:13000/api/datasources/uid/{uid}")
    assert payload["uid"] == uid, payload

print("grafana health, dashboard, and datasource UIDs ok")
PY

echo "==> observability reference smoke passed"
