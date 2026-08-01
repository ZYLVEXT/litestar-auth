# ADR 0004: Payment HTTP Message Signature profile v1

- **Status:** accepted
- **Date:** 2026-07-31
- **Packages:** `authweave-http-signatures`

## Context

Payment mutations need message integrity separate from authentication.
FAPI 2.0 Message Signing Final covers JAR/JARM/introspection, not a ready RS HTTP
signature profile. OIDF HTTP Signatures drafts are informative only until Final.

## Decision

Ship an immutable profile identifier:

```text
authweave-payment-http-sig-v1
```

as the RFC 9421 `tag` parameter. Algorithm is `ed25519` only for v1.

Covered components in exact order:

1. `@method`
2. `@target-uri`
3. `content-digest`
4. `content-type`
5. `idempotency-key`
6. `authorization` — only when the route uses DPoP authentication

Signature parameters (not covered components): `created`, `expires`, `keyid`,
`nonce`, `tag`.

Additional v1 fixed policy:

- `Content-Digest` uses `sha-256` (RFC 9530)
- reject non-identity `Content-Encoding` / compressed bodies
- JSON media-type allowlist
- bounded raw body size, clock skew, signature lifetime, and nonce TTL
- high-risk mutation routes reject query unless a route profile explicitly allows it
- Structured Fields parsing via a maintained RFC 8941 implementation
  (`http-message-signatures`), not an ad-hoc parser
- `keyid` must bind to the already-authenticated machine principal/application/
  environment; a globally trusted key alone is insufficient
- signature nonce replay is separate from business `idempotency-key` semantics

## Consequences

- New distribution `authweave-http-signatures` owns integrity contracts and raw-body
  lifecycle; it depends on `authweave-core` only for binding seams.
- Profile version bumps require a new ADR; v1 remains immutable.
- Interoperability-ready still needs independent crypto review and cross-impl vectors.

## Alternatives considered

- **Workload extra instead of new package:** rejected — integrity has distinct
  contracts and consumers outside workload auth.
- **HMAC shared secrets:** rejected for payment mutations.
- **Ad-hoc Structured Fields parser:** rejected without separate security review.

## Evidence

- RFC 9421, RFC 9530, and RFC 8941.
