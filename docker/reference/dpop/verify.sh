#!/usr/bin/env sh
# Test independent vectors, external AS/JWKS, Redis races, and multi-worker RS.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${ROOT}/../../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/compose.yml"

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "${REPO_ROOT}"

echo "==> starting DPoP Redis + live RS reference"
$COMPOSE up -d --wait

echo "==> verifying language-neutral DPoP vectors"
uv run --package authweave-workload --extra dpop python docs/vectors/dpop/rfc9449/verify_vectors.py
node docs/vectors/dpop/rfc9449/verify_vectors.mjs

echo "==> verifying Redis replay store outcomes"
uv run --package authweave-workload --extra dpop --extra redis python docker/reference/dpop/verify_redis.py

echo "==> flushing Redis before external-AS live HTTP checks"
$COMPOSE exec -T redis redis-cli FLUSHDB >/dev/null

echo "==> verifying external test AS/JWKS + multi-worker DPoP resource server"
uv run --package authweave-workload --extra dpop --with httpx python docker/reference/dpop/verify_live.py

echo "==> DPoP reference OK"
