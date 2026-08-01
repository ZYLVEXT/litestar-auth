# ADR 0010: Outbound sender-constrained token exchange

- **Status:** accepted
- **Date:** 2026-08-01
- **Package:** `authweave-workload`

## Context

RFC 8693 deliberately leaves token trust, proof of possession, and delegation
policy to deployment profiles. A generic exchange helper could turn a stolen
credential into a broader or unconstrained downstream token.

## Decision

1. AuthWeave is only an RFC 8693 client. The configured HTTPS Authorization
   Server remains the STS and validates all input tokens.
2. Client authentication is RFC 7523 `private_key_jwt` through the existing
   external signer seam. Private key bytes never enter AuthWeave.
3. Every profile configures exactly one output sender constraint:
   - DPoP with an external signer and public JWK; or
   - mTLS through an injected certificate-owning transport.
4. Resource, audience, source audience, requested access-token type, issuer,
   algorithms, scopes, lifetimes, response size, and timeouts are exact profile
   policy. Callers cannot override the target.
5. Requested scopes must be a non-empty subset of both verified subject scopes
   and profile scopes. Payment authorization details must be narrower than the
   verified subject authority and restricted to the configured resource.
6. An optional actor token may add one direct actor ahead of the existing
   delegation chain. The actor credential must itself be direct, identities may
   not repeat, and the resulting chain is bounded.
7. A mandatory deployment-supplied verifier validates the issued token. The
   client checks its issuer, audience, scopes, payment details, lifetime,
   sender-binding thumbprint, subject, actor, and delegation chain before
   returning it.
8. The response parser accepts one access token, requires a bounded lifetime,
   rejects refresh tokens and unknown fields, and performs no general retry. A
   DPoP profile may make exactly one RFC 9449 nonce continuation with fresh
   proofs and rejects a `Bearer` downgrade.

## Consequences

- Opaque issued tokens require an introspection-backed verifier; JWTs may use a
  local exact-issuer verifier.
- mTLS profiles require an injected transport that owns the client certificate
  and key. AuthWeave cannot prove transport possession by accepting a header.
- The caller must pair each raw input token with the `AuthenticationContext`
  produced when that same token was verified.
- Injected transports must preserve a single `DPoP-Nonce` response header and
  reject duplicates. The built-in HTTPX transport does both.
- Token caching, refresh, general retries, STS policy, and token issuance remain
  outside AuthWeave.

## Evidence

- RFC 8693 Sections 1.1, 2.1, 2.1.1, 2.2, 4.1, and 5.
- RFC 7523 Sections 2.2 and 3.
- RFC 9449 Sections 5, 7, 8, and 11.
- RFC 9396 Sections 6, 7, 9, and 12.
- The live Docker reference exercises both an AS-provided DPoP nonce and a TLS
  endpoint that requires a trusted client certificate.
