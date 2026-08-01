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
$COMPOSE cp authorization-server:/certs/server.crt "${REFERENCE_CA}" >/dev/null
SSL_CERT_FILE="${REFERENCE_CA}" uv run --package authweave-workload --extra introspection --with httpx python docker/reference/introspection/verify_live.py

echo "==> signed sender-constrained introspection reference OK"
