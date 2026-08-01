#!/usr/bin/env sh
# Verify Standard Webhooks vectors, environment packs, and real-Redis races.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${ROOT}/../../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/compose.yml"

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "${REPO_ROOT}"

echo "==> starting Standard Webhooks Redis reference"
$COMPOSE up -d --wait

echo "==> verifying vectors with authweave-webhooks"
uv run --package authweave-webhooks python docs/vectors/webhooks/v1a/verify_vectors.py

echo "==> verifying vectors with independent Node.js Ed25519"
node docs/vectors/webhooks/v1a/verify_vectors.mjs

echo "==> validating sandbox/live merchant environment packs"
python3 docs/merchant/environment-packs/webhooks/verify_packs.py

echo "==> exercising concurrent Redis refresh, rotation, and duplicate claims"
uv run --package authweave-webhooks --extra redis python "${ROOT}/verify_redis.py"

echo "==> Standard Webhooks reference OK"
