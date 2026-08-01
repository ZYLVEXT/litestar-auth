#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${ROOT}/../../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/compose.yml"
REFERENCE_CA="$(mktemp)"

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
  rm -f "${REFERENCE_CA}"
}
trap cleanup EXIT

cd "${REPO_ROOT}"
$COMPOSE up -d --wait
$COMPOSE cp fapi-authorization-server:/certs/server.crt "${REFERENCE_CA}" >/dev/null
SSL_CERT_FILE="${REFERENCE_CA}" uv run --extra oauth python docker/reference/fapi/verify_live.py

echo "==> FAPI Message Signing authorization-code reference OK"
