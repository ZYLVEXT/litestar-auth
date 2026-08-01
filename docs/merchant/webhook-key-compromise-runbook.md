# Standard Webhooks key-compromise runbook

This runbook covers compromise or suspected compromise of an AuthWeave `v1a`
Ed25519 private signing key. The producer application owns private-key custody and
signing behind the AuthWeave signer protocol; merchants own their trusted public-key
documents, refresh path, replay store, and business inbox. The security incident
commander owns the decision to revoke.

## Preconditions

- Separate sandbox/live and per-endpoint or per-merchant keys.
- An approved active/next/retiring environment pack and out-of-band contacts.
- KMS/HSM audit access, a bounded key-set publishing path, and merchant refresh
  telemetry.
- A durable list of affected owner/environment/endpoint bindings and the first
  suspected-compromise time.
- A tested emergency communication path that does not depend on the compromised
  signing key.

## Immediate response

1. Open an incident, freeze unrelated key changes, preserve KMS/HSM and delivery
   audit evidence, and identify the exact key reference and blast radius.
2. Stop new signing with the suspected key. Do not delete it before evidence and
   already-enqueued delivery impact are accounted for.
3. Promote a previously distributed `next` key, or create a new external KMS/HSM
   key reference if `next` may also be exposed. Never export private bytes.
4. Publish a monotonically newer key document. Remove the compromised public key
   immediately; do not retain it as `retiring` for availability.
5. Force controlled merchant refresh and monitor bounded version/outcome
   telemetry. Fail closed where the new document cannot be obtained; do not
   restore the compromised key as a fallback.
6. Pause delivery to merchants that cannot confirm the new document. Resume only
   after exact environment/owner/endpoint binding and a signed canary verify.
7. Search the durable business inbox and delivery audit for affected webhook IDs
   from the first suspected-compromise time. Signature validity alone cannot
   distinguish attacker messages signed by the compromised key.

## Recovery and validation

- Verify an exact-byte canary signed only by the promoted key.
- Verify the old key is rejected after refresh in sandbox and live independently.
- Run concurrent refresh and duplicate-claim checks against the production-like
  Redis topology; one webhook ID must have exactly one immediate claim.
- Reconcile deliveries with the source-of-truth payment ledger before replay.
  Preserve original webhook IDs for business idempotency and use fresh attempt
  timestamps/signatures.
- Rotate any credentials, proxy policy, or KMS grants implicated in the cause.
- Obtain incident commander, merchant operations, KMS owner, and infra egress
  owner approval before closing containment.

## Rollback rule

Rollback may restore a known-good uncompromised document version only. It may
never re-authorize the compromised key. If the new key or distribution path is
unavailable, deliveries remain paused and verification remains fail closed.

## Exercise record

For each exercise, attach an evidence record containing date, participants,
scenario/key reference, exact commands and environment, document versions,
merchant refresh acknowledgements, Redis concurrency result, old-key rejection,
recovery time, unexpected findings, owners, and due dates. A repository-local
simulation does not replace an external cryptographic review, KMS/infra-owner
exercise, or deployment approval.
