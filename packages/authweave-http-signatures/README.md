# authweave-http-signatures

Payment HTTP Message Signatures profile (`authweave-payment-http-sig-v1`)
for AuthWeave. Verifies RFC 9530 `Content-Digest` and RFC 9421 signatures after
machine authentication (mTLS or DPoP), then binds `keyid` to the authenticated
principal and consumes a signature nonce.

This package does **not** authenticate callers and does **not** implement business
idempotency. Structured Fields parsing uses the maintained
`http-message-signatures` library (RFC 8941 / RFC 9421).

`PaymentHttpSignatureVerifier(..., observer=...)` emits logical integrity and
nonce-replay observations through the neutral `authweave-core` observer seam.
`verify(..., links=(TraceCorrelation(...),))` supports async/retry causality;
linked trace context never participates in authentication or key binding.

Frozen/custom verifier clocks are request-local; the package does not mutate the
process-global clock of the Structured Fields/signature implementation.

```bash
uv add authweave-http-signatures
```

See ADR 0004 and `docs/roadmap.md`. Optional extras: `[redis]`, `[litestar]`.
