# Merchant payment HTTP Message Signature notes

AuthWeave verifies **AuthWeave payment profile v1** integrity for high-risk
mutations ([ADR 0004](../adr/0004-payment-http-message-signature-v1.md)).
Authentication (mTLS or DPoP) happens first; HTTP Message Signatures are not a
second login mechanism.

The signing `keyid` is accepted only when its configured subject, application,
and environment match the fully authenticated machine context. There is no
fallback from a failed binding to another authentication or signature profile.

## Profile

- `tag`: `authweave-payment-http-sig-v1`
- algorithm: Ed25519
- covered components (exact order): `@method`, `@target-uri`, `content-digest`,
  `content-type`, `idempotency-key` (+ `authorization` for DPoP routes)
- `Content-Digest`: `sha-256` over the exact raw body

## Trusted target URI

Applications must resolve the external absolute `https://` request target from
an approved proxy/trust boundary ([ADR 0005](../adr/0005-external-request-target-trust-boundary.md)).
Never sign or verify against client-controlled `Host` / `Forwarded` alone. A
wrong `target_uri` fails signature verification.

## Replay vs idempotency

- Signature `nonce` prevents the same integrity envelope from being accepted twice.
- Business `idempotency-key` is owned by the payment domain inbox.

## Language-neutral vectors

See the [payment-profile vector manifest](../vectors/http-signatures/payment-v1/manifest.json).
Run:

```bash
uv run --package authweave-http-signatures python docs/vectors/http-signatures/payment-v1/verify_vectors.py
node docs/vectors/http-signatures/payment-v1/verify_vectors.mjs
```

Docker Redis + Envoy path-rewrite smoke (trusted `x-auth-external-target`
injection over a Unix-socket hop):

```bash
sh docker/reference/http-signatures/verify.sh
```

The Docker flow obtains a DPoP-bound token from a separate test AS, authenticates
the request in a four-worker upstream, verifies the exact authorization component,
signature base and raw-body digest, and then enforces the signing-key identity
binding. It also checks a validly signed request made by the wrong authenticated
application.

## Rotation and compromise

Follow the [merchant signing-key rotation and compromise runbook](http-signature-key-runbook.md).
Normal rotation may overlap old/new public keys for a bounded window. A compromised
key is removed immediately and is never retained as a fallback.
