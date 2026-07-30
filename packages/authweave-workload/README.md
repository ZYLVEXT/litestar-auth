# authweave-workload

Framework-neutral authentication for registered service applications and
service, workload, or agent principals. Version 7 supports registered X.509
credentials, direct mTLS, and mTLS-bound access tokens issued by an external
OAuth Authorization Server.

```bash
uv add 'authweave-workload[mtls,jwt]'
```

The base package never accepts or stores private keys and imports no web
framework, ORM, or cryptography implementation.

Lifecycle mutations require a verified actor, a correlation ID, and an application recorder that
writes the security event in the same transaction. X.509 registration accepts only opaque
`CertificateMetadata` returned by `validate_public_certificate`; it cannot be built from unchecked
fields.

The optional Litestar adapter accepts Envoy evidence only over an explicitly
trusted TCP peer or permission-restricted Unix socket. Envoy's hex certificate
fingerprint is normalized to canonical base64url, while revocation freshness
comes from application-trusted CRL/control-plane metadata rather than an
inbound request header.
