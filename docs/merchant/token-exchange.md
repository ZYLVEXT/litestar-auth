# Outbound token exchange

`authweave-workload[token-exchange]` is a strict client for one configured
external RFC 8693 security token service. AuthWeave does not issue tokens or
discover exchange targets.

## Required profile

- exact HTTPS endpoint, issuer, source issuer/audience, resource, and audience;
- RFC 7523 `private_key_jwt` through an external asymmetric signer;
- exactly one sender constraint: DPoP, or mTLS with a certificate-owning
  injected transport;
- deployment-supplied `IssuedTokenVerifier` that verifies the returned token;
- finite scope allowlist, lifetime, delegation depth, response size, and
  timeout;
- optional strict payment `authorization_details` policy.

`TokenExchangeCredential` pairs a raw source token with the already verified
`AuthenticationContext` for that token. Callers must never construct that pair
from unverified claims.

## Fail-closed behavior

The client rejects caller-selected targets, scope or payment-authority
widening, delegation cycles, nested actor credentials, unknown response
members, refresh tokens, unbounded responses, sender-constraint downgrade,
and any mismatch between the token response and the locally verified issued
token. It has no general or hidden retry.

For DPoP only, an RFC 9449 `use_dpop_nonce` response permits one immediate
continuation with fresh client and DPoP proofs. The client retains a valid
server nonce for the next exchange; a repeated challenge fails instead of
looping. mTLS and transport failures are never retried.

See [ADR 0010](../adr/0010-outbound-token-exchange.md) and the
[live HTTPS STS reference](../../docker/reference/token-exchange/).
