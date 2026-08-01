# ADR 0005: External request-target trust boundary

- **Status:** accepted
- **Date:** 2026-07-31
- **Packages:** `authweave-core`, `litestar-auth`, `authweave-http-signatures`,
  `authweave-workload[dpop]`

## Context

Sender-constrained profiles (DPoP `htu`, HTTP Message Signature `@target-uri`) need the
absolute external HTTPS request target. Client-controlled `Host` / `Forwarded` /
`X-Forwarded-*` headers are not a trust source. `RequestView.target_uri` and the
Litestar `external_request_target_factory` provide the explicit projection seam.

## Decision

1. `RequestView.target_uri` is a bounded absolute `https://` URI projected by the
   adapter, never reconstructed ad hoc inside providers from inbound forwarding headers.
2. Direct TLS termination may use
   `litestar_auth.authentication.build_direct_request_target`, which takes scheme and
   authority from the ASGI `server` tuple and preserves raw path/query encoding.
3. Proxy / mesh deployments **must** supply an explicit
   `ExternalRequestTargetFactory` built from an allowlisted proxy trust boundary.
   Incomplete, ambiguous, or untrusted forwarding metadata yields `None` (no target) and
   fail-closed authentication/integrity checks.
4. Applications must not treat `Host` or client-supplied `Forwarded` as the request
   target for DPoP or payment HTTP Message Signatures.

## Consequences

- Library seam is stable; each deployment owns proxy allowlists and header policy.
- Docker/reference evidence for reverse-proxy rewrite lives under
  `docker/reference/http-signatures/` (Envoy strips/re-injects the trusted
  target; spoofed internal URIs fail signature/`htu`).
- SPIFFE mesh termination follows the same rule: verified identity headers are
  boundary-projected, never client-writable.

## Alternatives considered

- **Always trust `X-Forwarded-Proto` / `X-Forwarded-Host`:** rejected — spoofable without
  an allowlisted hop.
- **Normalize/decode paths before binding:** rejected — breaks signature/`htu` equality
  with the bytes the client signed.

## Evidence

- `build_direct_request_target`; ADR 0003 / ADR 0004 consumers.
- `AllowlistedProxyExternalTarget` + Envoy rewrite smoke under
  `docker/reference/http-signatures/` (`verify.sh`).
