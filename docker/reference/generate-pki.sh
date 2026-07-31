#!/bin/sh
set -eu

pki=/state
mkdir -p "$pki/newcerts"
: > "$pki/index.txt"
printf '1000\n' > "$pki/serial"
printf '1000\n' > "$pki/crlnumber"

openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -days 30 -subj /CN=auth-reference-root -keyout "$pki/ca.key" -out "$pki/ca.crt"

for identity in envoy client revoked-client; do
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$identity" -keyout "$pki/$identity.key" -out "$pki/$identity.csr"
done

openssl ca -batch -config /config/openssl.cnf -extensions server_cert \
  -in "$pki/envoy.csr" -out "$pki/envoy.crt"
openssl ca -batch -config /config/openssl.cnf -extensions client_cert \
  -in "$pki/client.csr" -out "$pki/client.crt"
openssl ca -batch -config /config/openssl.cnf -extensions client_cert \
  -in "$pki/revoked-client.csr" -out "$pki/revoked-client.crt"
openssl ca -batch -config /config/openssl.cnf -revoke "$pki/revoked-client.crt"
openssl ca -batch -config /config/openssl.cnf -gencrl -out "$pki/ca.crl"
mkdir -p /public /envoy /clients
cp "$pki/ca.crt" "$pki/ca.crl" "$pki/client.crt" /public/
cp "$pki/envoy.crt" "$pki/envoy.key" /envoy/
cp "$pki/client.crt" "$pki/client.key" "$pki/revoked-client.crt" "$pki/revoked-client.key" /clients/
chmod 644 /public/* /envoy/*.crt /clients/*.crt
chmod 600 /envoy/*.key /clients/*.key
chown 101:101 /envoy/*
