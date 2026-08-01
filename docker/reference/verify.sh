#!/bin/sh
set -eu

compose="docker compose -f docker/reference/compose.yml"
cleanup() {
  $compose down -v
}
trap cleanup EXIT

$compose up -d --wait
uv run --frozen --group reference python docker/reference/verify.py

$compose run --rm --no-deps --entrypoint /bin/sh pki -c '
  set -eu
  openssl verify -CAfile /public/ca.crt -crl_check -CRLfile /public/ca.crl /clients/client.crt
  ! openssl verify -CAfile /public/ca.crt -crl_check -CRLfile /public/ca.crl /clients/revoked-client.crt
'

$compose run --rm --no-deps --entrypoint /bin/sh curl -c '
  set -eu
  response=$(curl --silent --show-error --fail --cacert /public/ca.crt \
    --cert /clients/client.crt --key /clients/client.key \
    -H "x-auth-tls-verified: FORGED" \
    -H "x-auth-client-cert-sha256: FORGED" \
    -H "x-auth-client-cert-not-before: 2099-01-01T00:00:00Z" \
    https://envoy:8443/reference)
  echo "$response" | grep -q "\"profile\":\"direct_mtls\""
  echo "$response" | grep -q "\"subject\":\"reference-client\""
  echo "$response" | grep -q "\"audience\":\"reference\""
  ! echo "$response" | grep -q FORGED
  ! curl --silent --fail --cacert /public/ca.crt https://envoy:8443/reference
  ! curl --silent --fail --cacert /public/ca.crt --cert /clients/revoked-client.crt \
    --key /clients/revoked-client.key https://envoy:8443/reference
  ! curl --silent --fail --tls-max 1.2 --cacert /public/ca.crt --cert /clients/client.crt \
    --key /clients/client.key https://envoy:8443/reference
'
