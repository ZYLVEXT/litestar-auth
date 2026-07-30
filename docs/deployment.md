# Deployment

Human sessions require HTTPS, secure cookies, CSRF protection, one database or Redis session
provider, and worker-shared persistence. Use distinct high-entropy secrets for token digests,
account artifacts, OAuth flow cookies, encrypted provider tokens, and encrypted TOTP material.

Machine routes require TLS 1.3 mutual authentication. The reference Envoy boundary:

- validates the client chain and CRL;
- removes caller-supplied TLS evidence headers;
- projects verified facts;
- connects to the application through a Unix domain socket.

If the application receives projected evidence, allowlist the proxy connection and reject
incomplete, duplicated, malformed, or untrusted headers. Never trust client-facing forwarded
headers directly.

`EnvoyTLSHeaderEvidence` normalizes Envoy's hex DER SHA-256 fingerprint to the package's canonical
unpadded base64url form. For an application reachable only through a permission-restricted Unix
domain socket, allowlist `UNIX_SOCKET_PROXY`; do not use that sentinel on a TCP listener. Supply
`revocation_checked_at` from trusted local CRL/control-plane freshness metadata, such as the
timestamp of the locally mounted CRL. Never derive it from a caller header or the current request
time.

PostgreSQL is the guaranteed workload persistence target. The application owns migrations,
transaction boundaries, row-level security, tenant mapping, business authorization, and durable
event delivery. The lifecycle event recorder must use the same SQLAlchemy session/transaction as
the mutation and fail closed; publish from an outbox after commit. Redis is the reference shared
human-session store.

In Kubernetes, issue dedicated workload-auth certificates from a dedicated issuer and mount the
minimum material per container. Do not reuse Kafka, database, ingress-server, or service-account
credentials. Keep private keys out of application containers unless that workload is the TLS
client, disable unnecessary service-account token automounting, use default-deny network policy,
run as non-root with dropped capabilities and seccomp, and pin deployed images by digest. The
bundled Envoy evidence adapter is optional: Traefik or another ingress needs an independently
reviewed adapter that proves the immediate proxy boundary and never trusts public forwarded
headers.

External issuer configuration uses an explicit HTTPS JWKS URL, bounded network/cache/key limits,
an asymmetric algorithm allowlist, issuer and audience allowlists, and mandatory TLS certificate
binding. Outage is unavailable, never anonymous.

Run `sh docker/reference/verify.sh` before deployment. Production rollout additionally requires an
independent review of proxy/TLS/JWKS trust boundaries and an explicit rollout approval.
