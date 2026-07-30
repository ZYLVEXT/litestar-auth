# Version 7 architecture contract

## Package topology

The dependency direction is intentionally one-way:

```text
authweave-core
├── litestar-auth
└── authweave-workload
    └── authweave-workload[litestar] → litestar-auth Extension SDK v2
```

`authweave-core` contains identity, evidence, context, request, decision, error, and
coordinator contracts. It imports no framework, storage, or cryptographic
implementation. `litestar-auth` owns supported human authentication and the
single Litestar middleware. `authweave-workload` owns service application,
service/workload/agent principal, public X.509 credential lifecycle, direct
mTLS, and external certificate-bound JWT verification.

All distributions use coordinated `7.x` versions, require Python
`>=3.12,<3.15`, and reject cross-major integration. Optional workload
implementations remain behind `sqlalchemy`, `mtls`, `jwt`, and `litestar`
extras; a base import does not load them.

## Request vocabulary and routing

A `Principal` identifies the verified human, service, workload, or agent.
`AuthenticationEvidence` records the verified method and bounded properties.
`AuthenticationContext` separates subject, actor, delegation, and request
projection. It never contains a raw credential, access token, or private key.

Every route resolves exactly one provider profile before verification.
Credential ownership has three outcomes: absent, owned, or ambiguous.
Ambiguity fails closed. A provider returns a typed success, anonymous result,
invalid result, or unavailable result; invalid, unavailable, and invariant
failure are terminal and never trigger a fallback provider.

Authentication establishes identity and verified constraints. Tenant mapping,
RLS, resource ownership, and business authorization remain application-owned.

## Human and machine boundary

Human routes use opaque server-side database or Redis sessions in secure
cookies. Machine routes require verified client-certificate possession and use
either direct mTLS or an external asymmetric access token bound to that
certificate. Principal-kind guards are invariant checks, so similar attributes
cannot make a human credential satisfy a machine route or vice versa.

## ADR: external Authorization Server

Version 7 is an OAuth relying party and Resource Server, not an Authorization
Server. Human OAuth uses Authorization Code with PKCE. Workload access tokens
come from an explicitly trusted external issuer and are verified against the
documented RFC 9068/RFC 8705 profile. Building an issuer, discovery system,
opaque-token introspection, DPoP, or generic IAM surface is outside this
release.

This decision keeps key issuance, federation, consent, and token-service
operations at a dedicated trust service while the packages remain focused on
authentication, certificate lifecycle, and verified request context.

## Removed profiles

Version 7 deliberately has no deprecated aliases, request-authentication
bearer strategy, user-owned API key, proprietary HMAC request signing, ordered
compatibility authenticator, or `None`-based failure path. The migration guide
and read-only removal audit are the only compatibility aids; runtime adapters
for removed profiles do not exist.
