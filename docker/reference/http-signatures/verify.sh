#!/usr/bin/env sh
# Smoke-test AuthWeave HTTP signature vectors, Redis nonce replay, and Envoy rewrite.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${ROOT}/../../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/compose.yml"
RUNTIME="$(mktemp -d "${TMPDIR:-/tmp}/authweave-http-signatures.XXXXXX")"
export HTTP_SIGNATURE_RUNTIME="${RUNTIME}"

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
  rm -rf -- "${RUNTIME}"
}
trap cleanup EXIT

cd "${REPO_ROOT}"

echo "==> preparing Envoy rewrite key material"
uv run --frozen --group reference python "${ROOT}/prepare_keys.py" "${RUNTIME}"

echo "==> starting test AS + DPoP + Redis + Envoy signature reference"
$COMPOSE up -d --wait

echo "==> verifying language-neutral HTTP signature vectors"
uv run --frozen --group reference python docs/vectors/http-signatures/payment-v1/verify_vectors.py
node docs/vectors/http-signatures/payment-v1/verify_vectors.mjs

echo "==> verifying trusted-target vs spoofed authority"
uv run --frozen --group reference python docker/reference/http-signatures/verify_proxy_target.py

echo "==> verifying Redis nonce replay store outcomes"
uv run --frozen --group reference python docker/reference/http-signatures/verify_redis.py

echo "==> verifying Envoy path rewrite + body integrity"
uv run --frozen --group reference python docker/reference/http-signatures/verify_envoy_rewrite.py "${RUNTIME}"

echo "==> HTTP signature reference OK"
