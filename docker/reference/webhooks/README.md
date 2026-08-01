# Standard Webhooks reference

This reference exercises the `authweave-standard-webhooks-v1a` profile against:

- exact-byte, rotation-overlap, and negative vectors in both Python and an
  independent dependency-free Node.js Ed25519 verifier;
- checked sandbox/live merchant environment packs;
- 32 simultaneous cold key snapshots converging on one atomically published
  Redis rotation document;
- 32 simultaneous duplicate claims producing exactly one winner; and
- rejection of a Redis-published key-document rollback.

Run:

```bash
sh docker/reference/webhooks/verify.sh
```

This is integration/interoperability evidence, not production approval. The
external cryptographic review, real KMS ceremony, merchant/infra-owner
key-compromise exercise, and deployment egress tests remain external gates.
