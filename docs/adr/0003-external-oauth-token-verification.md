# ADR 0003: External OAuth access tokens are verified, never issued

- **Status:** accepted
- **Date:** 2026-07-31
- **Packages:** `authweave-workload[dpop]`, `authweave-workload[jwt]`

## Context

FAPI-facing resource servers must authenticate machine clients with
sender-constrained access tokens from an external Authorization Server. AuthWeave
is a library, not an AS: issuing tokens would expand product scope and key-ceremony
burden beyond the stated non-goals.

## Decision

AuthWeave verifies external access tokens only. For DPoP:

- composite ownership is exactly one `Authorization: DPoP` and one `DPoP` proof;
- mixed Bearer/Cookie/client-certificate presentations are ambiguous;
- proof replay keys are namespaced per resource-server id + `jkt` + `jti`;
- Redis-backed replay/nonce adapters are optional via `[redis]`;
- high-risk mutations may require an RS-issued opaque nonce with secret-free
  `WWW-Authenticate: DPoP error="use_dpop_nonce"` challenges.

## Consequences

- Library behavior: `DPoPBoundJWTProvider` fail-closes on JWKS/replay/nonce outages.
- Application ownership: AS trust policy, JWKS URLs, Redis durability, nonce threat model.
- Explicit non-goals: token minting, refresh, and Authorization Server endpoints.
  Outbound OAuth clients remain separate profiles.

## Alternatives considered

- **Mint DPoP-bound tokens in AuthWeave:** rejected — violates library boundary.
- **Bearer fallback when proof missing:** rejected — silent downgrade.

## Evidence

- RFC 9449 resource-server profile and its replay/nonce vectors.
