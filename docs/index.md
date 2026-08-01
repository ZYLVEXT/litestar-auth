# Authentication stack version 7

Six coordinated distributions separate verified identity contracts, human/workload authentication,
observability, and message-integrity tooling:

- **authweave-core** routes one owned credential presentation to one provider and returns typed principal,
  evidence, and decision contracts.
- **litestar-auth** supplies Litestar's supported modern human flows through one opaque,
  server-side cookie-session pipeline.
- **authweave-workload** supplies X.509 service application, principal, and credential lifecycle plus
  direct mTLS, mTLS/DPoP-bound access-token and introspection profiles, SPIFFE X.509-SVID, and strict
  outbound token exchange.
- **authweave-otel** supplies non-authoritative OpenTelemetry security observation.
- **authweave-webhooks** supplies Ed25519 Standard Webhooks signing and verification.
- **authweave-http-signatures** supplies the RFC 9530/RFC 9421 payment-message profile after machine
  authentication.

Start with the [quickstart](quickstart.md), review the [architecture](architecture.md) and
[security posture](security.md), and use the [6.x → 7.0 migration guide](migration.md) before
upgrading an existing deployment. Optional profile readiness is tracked on the
[roadmap](roadmap.md). Merchant onboarding notes for webhooks, DPoP, HTTP Message
Signatures, SPIFFE, and introspection live under [merchant/webhooks](merchant/webhooks.md),
[merchant/dpop](merchant/dpop.md),
[merchant/http-signatures](merchant/http-signatures.md),
[merchant/spiffe](merchant/spiffe.md), and
[merchant/introspection](merchant/introspection.md).

| Need | Distribution |
| --- | --- |
| Human registration, login, OAuth + PKCE, TOTP, roles, organizations, and opaque sessions in Litestar | `litestar-auth` |
| Framework-neutral authentication contracts and coordination | `authweave-core` |
| Workload lifecycle and sender-constrained Resource Server profiles | `authweave-workload` |
| Security telemetry facade | `authweave-otel` |
| Standard Webhooks signing and verification | `authweave-webhooks` |
| Payment HTTP Message Signatures | `authweave-http-signatures` |

All distributions require Python 3.12–3.14 and use coordinated `7.x` versions.
