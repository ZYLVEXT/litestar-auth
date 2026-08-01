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
2. Verify `webhook-id`, `webhook-timestamp`, `webhook-signature` with
   `StandardWebhooksVerifier`.
3. Claim immediate duplicate delivery (`environment` + endpoint/merchant +
   `webhook-id`) via `DuplicateDeliveryGuard` / Redis helper.
4. Enqueue an application inbox item for **business** idempotency (separate
   from delivery duplicate claims).
5. On retry, the application or scheduler must keep the same `webhook-id` and ask
   AuthWeave to create a delivery with a fresh timestamp + signature; do not treat
   a new timestamp as a new business event if the id already completed.

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
