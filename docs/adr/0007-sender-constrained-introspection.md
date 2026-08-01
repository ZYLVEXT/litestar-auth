# ADR 0007: Sender-constrained OAuth token introspection

- **Status:** accepted
- **Date:** 2026-07-31
- **Packages:** `authweave-workload[introspection]`

## Context

Opaque access tokens are validated at the resource server via RFC 7662.
Outbound authentication to the introspection endpoint (mTLS or
`private_key_jwt`) is a different trust relationship from the inbound sender
constraint that binds the merchant token to the calling client
(`cnf.x5t#S256` or `cnf.jkt`). Mixing those keys or allowing plain-JSON
fallback when signed mode is configured creates downgrade paths.

## Decision

1. **Two trust planes stay separate:**
   - **Outbound RS→AS** — explicit HTTPS introspection URL, no redirects,
     bounded timeouts/body; client authentication is profile-exact.
   - **Inbound sender constraint** — after active introspection, exactly one
     confirmation method from the issuer profile must match trusted request
     evidence (`TlsPeerEvidence` thumbprint or verified DPoP proof jkt).
2. **Plain RFC 7662** is allowed only when the issuer profile selects it.
   Inactive responses must not carry extra token metadata. Endpoint
   configuration supplies issuer trust even when the JSON body omits `iss`.
3. **RFC 9701 signed introspection** rejects plain JSON with no downgrade and
   verifies exact media type, JWT `typ`, issuer, audience, algorithm, key, and
   response age.
4. **Cache** keys on issuer-namespaced SHA-256 of the
   token, never the raw token; money-movement routes default to no positive
   active cache. Active TTL is capped by token expiry and an explicit
   revocation-risk ceiling. Cache failure falls through to the AS.
5. Introspection produces `AuthenticationEvidence` only — payment
   authorization remains application-owned.

## Consequences

- `authweave-workload[introspection]` owns the bounded client, plain and signed
  parsers, external-signer client authentication, and mTLS/DPoP-bound opaque
  token providers.
- Private signing keys remain behind the application-owned async signer seam.
- Litestar wiring follows the existing `WorkloadAuthExtension` provider seam.

## Alternatives considered

- **Reuse JWT access-token providers for opaque tokens:** rejected — opaque
  tokens have no local signature; introspection is mandatory.
- **Shared outbound/inbound certificate comparison:** rejected — RS client
  auth to the AS must never be confused with merchant client confirmation.

## Evidence

- RFC 7662; RFC 9701; RFC 8705 `cnf`; RFC 9449 `cnf.jkt`.
