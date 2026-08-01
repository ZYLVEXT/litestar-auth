# ADR 0008: Exact FAPI 2.0 Message Signing client profile

- **Status:** accepted
- **Date:** 2026-08-01
- **Package:** `litestar-auth[oauth]`

## Context

An OIDC authorization-code client handling financial data must not accept
unsigned front-channel parameters, dynamically discovered request-time trust,
or JWTs valid under a different protocol schema. The Authorization Server,
client registration, signing key and verification keys are deployment-owned.

## Decision

1. Each client instance binds one exact HTTPS issuer, authorization endpoint,
   PAR endpoint, redirect URI, client ID, asymmetric signing key ID and
   allowlisted response algorithms. Redirects and request-time discovery are
   not supported.
2. Authorization uses `response_type=code`, PKCE `S256`, OIDC `nonce`,
   `response_mode=jwt`, and a signed JAR with audience equal to the exact
   issuer. PAR contains only the request object and RFC 7523
   `private_key_jwt` client-authentication fields.
3. Private keys stay behind an async signer. Verification keys come from an
   issuer-bound resolver; the library never selects an issuer or JWKS URI from
   unverified claims.
4. JARM requires the selected `oauth-authz-resp+jwt` type, exact issuer and
   audience, bounded lifetime, `state`, `jti`, and exactly one of `code` or
   `error`. A verified state is atomically consumed only after the complete
   response is valid.
5. ID tokens use a distinct `JWT` schema and nonce namespace. Claims belonging
   to JARM or signed introspection are rejected before nonce consumption.
6. Token exchange and Resource Server sender-constraint verification remain
   separate profiles. The caller persists the returned state, nonce and PKCE
   verifier and supplies them back as exact expected values.

## Consequences

- AS metadata and client registration are provisioned out of band and reviewed
  as one issuer profile.
- Replay-store and signer outages fail closed with typed unavailable errors.
- The profile is integration-ready after local negative tests; official FAPI
  conformance, partner registration and production key operations remain
  external readiness gates.

## Alternatives considered

- **Generic OAuth/JWT framework:** rejected; it broadens accepted message
  shapes and algorithm policy.
- **Front-channel request parameters:** rejected; all authorization parameters
  are integrity-protected inside the PAR request object.
- **Consume state before full validation:** rejected; a malformed signed message
  must not burn a legitimate protocol run.

## Evidence

- FAPI 2.0 Message Signing Final; FAPI 2.0 Security Profile Final; RFC 9101;
  RFC 9126; OpenID JARM Final.
- `tests/unit/test_fapi.py` covers the positive flow, negative JWT/schema/time
  matrix, replay/outage paths and bounded HTTPS transport.
