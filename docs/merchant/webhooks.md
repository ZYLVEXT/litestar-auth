# Merchant webhook onboarding (AuthWeave asymmetric Standard Webhooks)

AuthWeave verifies deliveries; it does not own merchant inbox or business
idempotency. Private signing keys stay with the webhook sender. Consumers only
receive public keys.

## Onboarding binding

Each binding is exact:

- `environment` (`sandbox` | `live`)
- `owner` / merchant id
- HTTPS `endpoint` URL
- public key document (≤3 Ed25519 keys: active / next / retiring)
- optional key-set URL for one controlled refresh

Sandbox and live never share keys. Independent merchants never share keys
([ADR 0002](../adr/0002-webhook-key-tenancy.md)).

Checked `sandbox` and `live` templates with explicit active/next/retiring roles
live under
[`environment-packs/webhooks/`](environment-packs/webhooks/README.md). They
contain disposable example public keys only; production packs and private keys
must stay in the approved configuration/KMS systems.

## Consumer checklist

1. Read the **raw body bytes** before JSON parsing.
2. Verify `webhook-id`, `webhook-timestamp`, and `webhook-signature` with
   `StandardWebhooksVerifier`. Its mandatory shared replay store atomically
   claims the delivery only after a valid signature, namespaced by environment,
   owner, endpoint, and `webhook-id`; outage and capacity pressure fail closed.
   A repeated valid delivery returns a verified envelope with
   `replay_detected=True`.
3. After **every** successful verification, atomically insert the complete raw
   body and verified metadata into a durable inbox under a unique
   environment/owner/endpoint/`webhook-id` key. Use insert-if-absent semantics;
   never overwrite the first committed item. A retry therefore repairs the
   claim-before-inbox crash window instead of losing the event.
4. Return `2xx` only after the inbox transaction commits. Process and retry
   business work from the inbox; `replay_detected` is telemetry and must not
   replace durable idempotency.
5. On sender retry, keep the same `webhook-id` and create a delivery with a fresh
   timestamp + signature; do not treat a new timestamp as a new business event.

The verifier owns the complete timestamp-window replay TTL. Consumers cannot
shorten it. `InMemoryReplayStore` is only for tests or a documented single-worker
process; production consumers use a worker-shared implementation such as
`RedisReplayStore`. The durable inbox remains the authoritative delivery record.

## Key compromise / rotation

- Rotate by publishing `next`, then retiring the old key inside the ≤3-key
  window.
- If a sender private key is compromised, revoke/retire the matching
  public key immediately in a monotonically newer merchant document and force
  refresh. A compromised key is not retained for overlap.
- Consumers never store sender private or shared HMAC secrets for this profile.

Use the full
[`webhook-key-compromise runbook`](webhook-key-compromise-runbook.md). Its
KMS/merchant/infra-owner exercise and external cryptographic review remain
production gates until their evidence is attached.

## Sender SSRF / egress boundary

`HttpxWebhookSender` requires a non-empty exact endpoint allowlist, never
follows redirects, and streams at most 65,536 response bytes. URL checks do not
defeat DNS rebinding or a compromised allowlisted host. A controlled egress
proxy or isolated subnet is mandatory; direct egress is not a fallback. See the
[`sender threat model`](webhook-sender-threat-model.md) for deployment controls
and negative checks.

## Language-neutral vectors

See the [Standard Webhooks vector manifest](../vectors/webhooks/v1a/manifest.json). Run:

```bash
uv run --package authweave-webhooks python docs/vectors/webhooks/v1a/verify_vectors.py
node docs/vectors/webhooks/v1a/verify_vectors.mjs
```

Both commands consume the same exact signed bytes, active/next/retiring overlap,
and negative cases. The Node.js verifier uses only the independent built-in
Ed25519 implementation. The manifest pins Standard Webhooks upstream tag
`v1.0.2`.
