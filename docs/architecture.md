# Version 7 architecture contract

## Package topology

The dependency direction is intentionally one-way:

```text
authweave-core
├── litestar-auth
├── authweave-workload
│   └── authweave-workload[litestar] → litestar-auth Extension SDK v2
├── authweave-otel
├── authweave-webhooks
└── authweave-http-signatures
```

`authweave-core` contains principal, evidence, context, request, decision, replay,
observation, and coordinator contracts. It imports no framework, storage, or cryptographic
implementation. `litestar-auth` owns supported human authentication and the single Litestar
middleware. `authweave-workload` owns service application, service/workload/agent principal,
public X.509 credential lifecycle, and sender-constrained Resource Server integrations.
`authweave-otel` implements the optional observer seam. `authweave-webhooks` and
`authweave-http-signatures` are message-integrity packages, not authentication providers.

All distributions use coordinated `7.x` versions, require Python
`>=3.12,<3.15`, and reject cross-major integration. Optional workload
implementations remain behind `sqlalchemy`, `mtls`, `jwt`, `dpop`, `spiffe`,
`introspection`, `token-exchange`, `redis`, and `litestar` extras; a base import does not load
them.

## Request vocabulary and routing

A `PrincipalRef` identifies the verified human, service, workload, or agent.
`AuthenticationEvidence` records the verified method and bounded properties.
`AuthenticationContext` separates subject, actor, delegation, and request
projection. It never contains a raw credential, access token, or private key.

Every route resolves exactly one provider profile before verification. Credential ownership is
`NOT_APPLICABLE`, `OWNED`, or `AMBIGUOUS`; ambiguity fails closed. Providers return `Authenticated`,
`NotApplicable`, `Invalid`, `Unavailable`, or `InvariantFailure`. Invalid, unavailable, and
invariant results are terminal and never trigger a fallback provider.

Authentication establishes identity and verified constraints. Tenant mapping,
RLS, resource ownership, and business authorization remain application-owned.

## Human and machine boundary

Human routes use opaque server-side database or Redis sessions in secure cookies. Machine routes
use exactly one configured profile: direct mTLS, mTLS-bound JWT, DPoP-bound JWT, SPIFFE X.509-SVID,
or mTLS/DPoP-bound opaque-token introspection. Sender constraints and replay policy are profile
specific. Principal-kind guards are invariant checks, so similar attributes cannot make a human
credential satisfy a machine route or vice versa.

## Observation and message-integrity boundaries

`authweave-otel` implements `SecurityObserver`; observer failures never change authentication,
authorization, replay, or event-delivery decisions. Applications own the OpenTelemetry SDK,
exporters, sampling, and retention.

Standard Webhooks and payment HTTP Message Signatures verify bounded raw messages after the caller
trust boundary is selected. They do not establish a human/workload principal, replace business
idempotency, or own key custody and outbound network policy.

## ADR: external Authorization Server

Version 7 is an OAuth relying party and Resource Server, not an Authorization
Server. Human OAuth uses Authorization Code with PKCE. mTLS-bound workload access tokens come from
an explicitly trusted external issuer and are verified against the documented RFC 9068/RFC 8705
profile; DPoP-bound access tokens use the separate RFC 9449 profile.

`authweave-workload` also provides bounded Resource Server integrations for opaque-token
introspection, DPoP, SPIFFE identity, and certificate-bound access tokens. Its RFC 8693 token
exchange is a strict outbound client, not a Resource Server provider. The optional FAPI message-
signing client belongs to `litestar-auth` human OAuth. None of these integrations issues credentials
or implements an Authorization Server. Replay stores, issuer/key policy, outbound egress, and
application authorization hooks remain mandatory deployment configuration.

This decision keeps key issuance, federation, consent, and token-service
operations at a dedicated trust service while the packages remain focused on
authentication, certificate lifecycle, and verified request context.

## Removed profiles

Version 7 deliberately has no deprecated aliases, request-authentication
bearer strategy, user-owned API key, proprietary HMAC request signing, ordered
compatibility authenticator, or `None`-based failure path. The migration guide
and read-only removal audit are the only compatibility aids; runtime adapters
for removed profiles do not exist.
