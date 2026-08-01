# Merchant introspection notes

AuthWeave validates **opaque** access tokens at the resource server via
RFC 7662 introspection
([ADR 0007](../adr/0007-sender-constrained-introspection.md)).

Outbound RS→AS authentication and inbound merchant sender constraint are
separate trust planes.

## Library-ready surface (`authweave-workload[introspection]`)

1. `BoundedIntrospectionClient` — exact HTTPS endpoint, no redirects, bounded
   response, RFC 7523 `private_key_jwt`, and optional short Redis cache keyed
   only by issuer-scoped token digest. Positive caching is disabled by default.
2. `parse_plain_introspection` and `parse_signed_introspection` — strict RFC
   7662 JSON or RFC 9701 JWT. Signed mode requires
   `application/token-introspection+jwt` and never falls back to JSON.
3. `MTLSBoundIntrospectionProvider` — Bearer opaque token whose
   `cnf.x5t#S256` matches trusted `TlsPeerEvidence`.
4. `DPoPBoundIntrospectionProvider` — opaque DPoP token whose `token_type` and
   `cnf.jkt` match the locally verified proof; proof replay is rejected.

## Vectors

See [`../vectors/introspection/rfc7662/`](../vectors/introspection/rfc7662/).
The live HTTPS AS/RS/Redis matrix is
[`../../docker/reference/introspection/`](../../docker/reference/introspection/).
