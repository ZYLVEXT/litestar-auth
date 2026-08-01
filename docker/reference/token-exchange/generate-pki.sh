#!/usr/bin/env sh
set -eu

openssl ecparam -name prime256v1 -genkey -noout -out /certs/ca.key
openssl req -x509 -new -key /certs/ca.key -days 1 -subj /CN=reference-ca \
  -addext keyUsage=critical,keyCertSign,cRLSign -out /certs/ca.crt

openssl ecparam -name prime256v1 -genkey -noout -out /certs/server.key
openssl req -new -key /certs/server.key -subj /CN=token-exchange -out /certs/server.csr
openssl x509 -req -in /certs/server.csr -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial -days 1 \
  -extfile /app/server.ext -out /certs/server.crt

openssl ecparam -name prime256v1 -genkey -noout -out /certs/client.key
openssl req -new -key /certs/client.key -subj /CN=exchange-client -out /certs/client.csr
openssl x509 -req -in /certs/client.csr -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial -days 1 \
  -extfile /app/client.ext -out /certs/client.crt
