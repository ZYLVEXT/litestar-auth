# Merchant DPoP resource-server notes

AuthWeave verifies **external** OAuth access tokens bound with RFC 9449 DPoP
proofs. It does not mint tokens or operate an Authorization Server
([ADR 0003](../adr/0003-external-oauth-token-verification.md)).

## Presentation

Exactly:

- one `Authorization: DPoP <access-token>`
- one `DPoP: <proof-jwt>`

No Cookie, Bearer, or client-certificate presentation on the same route.
Trusted `target_uri` must come from an application-approved external request
target factory (never client `Host` / `Forwarded`). See
[ADR 0005](../adr/0005-external-request-target-trust-boundary.md).

Use one of the explicit [proxy target and clock profiles](dpop-deployment-profiles.md).
An unclassified deployment is not ready for DPoP enforcement.

## High-risk mutations

Money-movement routes should set `DPoPPolicy.require_nonce=True` with a durable
nonce store (Redis in multi-worker deployments). Challenge responses use:

- `WWW-Authenticate: DPoP error="use_dpop_nonce"`
- `DPoP-Nonce: <opaque>`
- `Cache-Control: no-store`

## FAPI posture

Passing AuthWeave unit/vector checks is **not** FAPI 2.0 certification.
Document issuer/audience/algorithm policy per deployment. Official FAPI
conformance remains an external readiness requirement.

## Language-neutral vectors

See the [RFC 9449 vector manifest](../vectors/dpop/rfc9449/manifest.json). Run:

```bash
uv run --package authweave-workload --extra dpop python docs/vectors/dpop/rfc9449/verify_vectors.py
```

Docker Redis + live HTTP RS smoke (no client certificate; application-owned
`EXTERNAL_TARGET`):

```bash
sh docker/reference/dpop/verify.sh
```

Direct mTLS live harness: `sh docker/reference/verify.sh`.

The DPoP reference starts a separately deployed test Authorization Server, obtains
a `token_type=DPoP` token bound through `cnf.jkt`, retrieves its JWKS over the
Compose network, and presents fresh proofs to a four-worker RS. The fixture is not
a supported AuthWeave AS product.
