#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${ROOT}/../../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/compose.yml"
CERT_DIR="$(mktemp -d)"

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
  rm -rf -- "${CERT_DIR}"
}
trap cleanup EXIT

cd "${REPO_ROOT}"
$COMPOSE up -d --wait
$COMPOSE cp token-exchange-mtls:/certs/ca.crt "${CERT_DIR}/ca.crt"
$COMPOSE cp token-exchange-mtls:/certs/client.crt "${CERT_DIR}/client.crt"
$COMPOSE cp token-exchange-mtls:/certs/client.key "${CERT_DIR}/client.key"
CA_CERT="${CERT_DIR}/ca.crt" CLIENT_CERT="${CERT_DIR}/client.crt" CLIENT_KEY="${CERT_DIR}/client.key" \
  uv run --package authweave-workload --extra token-exchange python docker/reference/token-exchange/verify_live.py

echo "==> sender-constrained token exchange reference OK"
