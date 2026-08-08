# authweave-workload

Framework-neutral authentication for registered service applications and
service, workload, or agent principals. Version 7 supports registered X.509
credentials, direct mTLS, mTLS-bound access tokens, DPoP-bound access tokens
issued by an external OAuth Authorization Server, SPIFFE X.509-SVID
resource-server verification, RFC 7662 mTLS- or DPoP-bound opaque-token introspection,
and sender-constrained outbound RFC 8693 token exchange.
Issuer-specific payment authority is available through the strict RFC 9396
payment authorization-details profile.

```bash
uv add 'authweave-workload[mtls,jwt,dpop,spiffe,introspection,token-exchange]'
```

The base package never accepts or stores private keys and imports no web
framework, ORM, or cryptography implementation. Optional DPoP verification lives
behind `authweave-workload[dpop]` and never mints tokens. Optional SPIFFE
verification lives behind `authweave-workload[spiffe]` and never registers
short-lived SVIDs by thumbprint (see ADR 0006). Optional introspection lives
behind `authweave-workload[introspection]` (see ADR 0007). Merchant notes:
`docs/merchant/dpop.md`, `docs/merchant/spiffe.md`, `docs/merchant/introspection.md`,
`docs/merchant/token-exchange.md`.
The payment profile and application guard are documented in
`docs/merchant/authorization-details.md`.

Lifecycle mutations require a verified actor, a correlation ID, and an application recorder that
writes the security event in the same transaction. X.509 registration accepts only opaque
`CertificateMetadata` returned by an AuthWeave validator; it cannot be built from unchecked fields.
Use `validate_public_certificate` when the application owns the PKIX trust anchors. For a managed CA
that intentionally does not export its root, use `validate_attested_certificate` with a fresh
`ProviderCertificateAttestation` constructed only from the pinned provider's authenticated control
plane response. That path binds the leaf profile, fingerprint, dates, active status, provider, and
application trust-anchor identity without claiming local PKIX validation.
Custom stores raise `StoreOwnerStateConflictError` when concurrent owner revalidation rejects a
principal or credential write; the lifecycle service maps that typed conflict to `LifecycleConflictError`.

The optional Litestar adapter accepts Envoy evidence only over an explicitly
trusted TCP peer or permission-restricted Unix socket. Envoy's hex certificate
fingerprint is normalized to canonical base64url, while revocation freshness
comes from application-trusted CRL/control-plane metadata rather than an
inbound request header.
