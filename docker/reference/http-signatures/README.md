# HTTP Message Signatures reference (DPoP + Redis + Envoy)

Smoke stack for `authweave-http-signatures`:

- language-neutral AuthWeave profile vectors
- trusted-target vs spoofed-authority checks
  ([ADR 0005](../../../docs/adr/0005-external-request-target-trust-boundary.md))
- separately deployed test Authorization Server issuing a DPoP-bound JWT
- four-worker upstream that authenticates a fresh DPoP proof before verifying the
  HTTP signature and binding `keyid` to the authenticated subject/application/environment
- Redis-backed DPoP replay and HTTP-signature nonce replay
- Envoy path rewrite (`/v1/payments` → `/internal/payments`) with
  strip/re-inject of `x-auth-external-target` and buffered raw body for
  `Content-Digest`
- fail-closed identity mismatch, missing proof, body mutation, and signature replay

Trusted `target_uri` is projected by the allowlisted proxy factory — never raw
`Host` / `Forwarded`.

```bash
sh docker/reference/http-signatures/verify.sh
```

See also `docs/merchant/http-signatures.md` and
`docs/vectors/http-signatures/payment-v1/`.

The Authorization Server is a reference fixture, not a supported AuthWeave AS.
