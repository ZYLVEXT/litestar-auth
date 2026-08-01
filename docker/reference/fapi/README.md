# FAPI Message Signing Docker reference

This reference runs an HTTPS authorization server, the strict AuthWeave FAPI
client, and a four-worker Redis-backed DPoP resource server.

```sh
sh docker/reference/fapi/verify.sh
```

The flow covers signed JAR through PAR, `private_key_jwt`, PKCE S256, JARM,
ID-token nonce binding, an authorization-code exchange, and a `cnf.jkt`-bound
access token. Negative checks cover state/JARM replay, cross-JWT confusion,
authorization-code replay, DPoP replay/key mismatch, and AS outage.

The signed request also carries the exact payment authorization-details v1
profile. The authorization server preserves it in the access token, the DPoP
provider validates it against issuer scope/location/currency ceilings, and the
resource endpoint applies a separate concrete-operation guard.

This is local integration evidence, not an official FAPI conformance result.
