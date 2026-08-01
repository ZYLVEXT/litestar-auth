#!/usr/bin/env sh
# Smoke-test SPIFFE vectors and the py-spiffe adapter against SPIRE.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${ROOT}/../../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/compose.yml"

cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cd "${REPO_ROOT}"

echo "==> verifying language-neutral SPIFFE ID vectors"
uv run --package authweave-workload --extra spiffe python docs/vectors/spiffe/x509-svid/verify_vectors.py

echo "==> starting SPIRE server"
$COMPOSE up -d server
for _ in $(seq 1 60); do
  if $COMPOSE exec -T server /opt/spire/bin/spire-server healthcheck \
    -socketPath /run/spire/sockets/server.sock >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
$COMPOSE exec -T server /opt/spire/bin/spire-server healthcheck \
  -socketPath /run/spire/sockets/server.sock >/dev/null

token_output="$($COMPOSE exec -T server /opt/spire/bin/spire-server token generate \
  -socketPath /run/spire/sockets/server.sock \
  -spiffeID spiffe://example.org/agent/authweave)"
SPIRE_JOIN_TOKEN="$(printf '%s\n' "$token_output" | sed -n 's/^Token: //p')"
test -n "$SPIRE_JOIN_TOKEN"
export SPIRE_JOIN_TOKEN

echo "==> starting SPIRE agent and registering workload"
$COMPOSE up -d agent
for _ in $(seq 1 60); do
  if $COMPOSE exec -T agent /opt/spire/bin/spire-agent healthcheck -socketPath /run/spire/sockets/agent.sock >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
$COMPOSE exec -T agent /opt/spire/bin/spire-agent healthcheck -socketPath /run/spire/sockets/agent.sock >/dev/null
$COMPOSE exec -T server /opt/spire/bin/spire-server entry create \
  -socketPath /run/spire/sockets/server.sock \
  -parentID spiffe://example.org/agent/authweave \
  -spiffeID spiffe://example.org/workload/authweave \
  -selector unix:uid:0 >/dev/null

echo "==> verifying Workload API adapter"
$COMPOSE run --rm verifier

echo "==> SPIFFE reference OK"
