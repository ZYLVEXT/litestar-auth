# Webhook sender SSRF and egress threat model

## Scope and trust boundary

`HttpxWebhookSender` sends one already-signed delivery attempt. It is not an
endpoint-registration service, retry scheduler, DNS firewall, or delivery
queue. The endpoint is configuration supplied by an approved merchant
environment pack; it must never come directly from a webhook body, request
header, token claim, redirect, or unreviewed tenant field.

Protected assets include cloud metadata and control-plane endpoints, loopback
and private services, Unix-socket/admin interfaces, credentials available to
the worker, merchant payload confidentiality, network availability, and the
integrity of delivery audit records.

An attacker may control a merchant account or endpoint DNS, compromise an
allowlisted host after onboarding, return redirects or an unbounded response,
rebind DNS between validation and connection, supply IPv4/IPv6 textual
variants, or influence ambient proxy variables.

## Library controls

- The sender accepts only an explicit, non-empty exact endpoint allowlist at
  construction. A delivery URL must match one entry byte-for-byte.
- Endpoint syntax is HTTPS-only and rejects missing hosts, userinfo, and
  fragments.
- Redirects are disabled on every attempt.
- Each attempt has a bounded timeout and no hidden retry.
- Response bytes are streamed and consumption stops at 65,536 bytes; the
  response is closed without buffering the remainder.
- Payloads, signatures, response bytes, and key material are excluded from
  sender result representations and bounded telemetry.

These controls prevent arbitrary URL substitution and response-memory
amplification. They do not establish that an allowlisted hostname resolves to a
safe address at connect time.

## Required deployment controls

1. Route webhook workers through a dedicated egress proxy or isolated subnet
   that denies loopback, link-local, private, carrier-grade NAT, multicast,
   documentation, benchmark, and cloud-metadata ranges for both IPv4 and IPv6.
2. Resolve and filter every address at connection time in that controlled
   layer. Apply the rule to all A/AAAA answers and every reconnect; a one-time
   application DNS lookup is vulnerable to rebinding and TOCTOU races.
3. Allow only TCP 443 to approved merchant destinations. Deny alternate ports,
   internal DNS zones, service-discovery suffixes, and direct access to the
   control plane.
4. Build the application-owned `httpx.AsyncClient` with certificate and
   hostname verification enabled. Use `trust_env=False` unless an explicitly
   approved proxy is configured; do not inherit ambient `HTTP_PROXY`,
   `HTTPS_PROXY`, or `NO_PROXY` policy accidentally.
5. Keep the exact endpoint and its egress rule in the same reviewed merchant
   change. Re-run approval when scheme, host, port, path, DNS ownership, or
   certificate ownership changes.
6. Run workers without cloud instance credentials or unrelated service
   credentials. Apply request rate, concurrency, queue, and total delivery
   budgets per merchant.
7. Log only merchant/environment identifiers, bounded outcome codes, attempt
   number, and timing. Never log signed payloads, signatures, response bodies,
   proxy credentials, or DNS answers containing sensitive internal names.

## Failure and downgrade policy

DNS rejection, proxy denial, TLS failure, timeout, and every non-2xx response are
failed attempts. Response bodies are retained only up to 65,536 bytes; a 2xx
response remains successful when its body is truncated. The adapter never follows
a redirect or falls back to HTTP/direct egress. Retry decisions belong to the
application scheduler and must preserve the webhook ID while creating a fresh
timestamp and signature for each attempt.

If the controlled egress layer is unavailable, delivery stops. Direct outbound
access is not an availability fallback.

## Verification checklist

- An unlisted public HTTPS URL is rejected before the client is called.
- Userinfo, fragments, HTTP, redirects, and responses beyond 65,536 bytes are
  rejected or bounded by tests.
- The environment pack requires one exact endpoint, no redirects, and a
  controlled proxy.
- Deployment tests cover IPv4 and IPv6 loopback/private/link-local/metadata,
  multiple DNS answers, DNS rebinding, proxy outage, and TLS hostname failure.

The final deployment checks require the merchant/infra egress environment and
remain an external production gate.
