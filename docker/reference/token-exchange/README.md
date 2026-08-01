# Sender-constrained token exchange reference

This fixture starts an independent HTTPS RFC 8693 security token service and
exercises the real outbound client. It verifies `private_key_jwt`, an
Authorization Server DPoP nonce, exact targeting, direct actor delegation,
payment-authority narrowing, and the signed issued token before AuthWeave
returns it. A second endpoint requires a trusted TLS client certificate and
returns a certificate-bound token; an unauthenticated TLS client is rejected.

Run from the repository root:

```bash
sh docker/reference/token-exchange/verify.sh
```
