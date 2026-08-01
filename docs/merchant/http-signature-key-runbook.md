# HTTP Message Signature key rotation and compromise runbook

This runbook covers merchant-held Ed25519 keys for
`authweave-payment-http-sig-v1`. Private keys remain in the merchant KMS/HSM or
approved non-exportable keystore. AuthWeave stores public keys and their exact
subject/application/environment bindings only.

The bundled `sign_payment_message` function is limited to local reference tests because
it accepts an in-process `Ed25519PrivateKey`. Production producers implement the same
profile in their KMS/HSM signing boundary; AuthWeave does not wrap or retain that key.

## Ownership and prerequisites

- Merchant security owns private-key generation, access policy and destruction.
- AuthWeave identity/platform owners approve the public-key binding and environment.
- Payment operations owns reconciliation of accepted idempotency keys and outcomes.
- Every change records ticket, merchant, environment, old/new `keyid`, KMS reference,
  approvers, timestamps, affected routes and rollback decision. Never record private
  key bytes, Authorization, DPoP proof, signature, or nonce values.
- Sandbox and live use disjoint keys and `keyid` values.

## Planned rotation

1. Generate a new Ed25519 key in the approved merchant KMS/HSM. Use a new immutable
   `keyid`; never overwrite key material behind an existing identifier.
2. Exchange and verify the public key out of band. Confirm the exact authenticated
   subject, application and environment binding with two-person approval.
3. Deploy the new public key and binding alongside the old key. Do not change the
   required algorithm, tag, signature label or covered-component order.
4. Send a canary signed with the new key through the real DPoP/mTLS authentication
   path. Verify raw-body digest, trusted external target, identity binding and Redis
   nonce consumption.
5. Switch the merchant signer to the new KMS reference. Monitor acceptance/rejection
   reason codes without logging request credentials or payment body.
6. After all in-flight requests plus the maximum signature lifetime, clock skew and
   nonce TTL have elapsed, remove the old public key/binding and revoke private-key
   use in KMS. Retain only approved audit metadata.

Rollback before compromise may temporarily switch signing back to the old active
key while its approved binding and KMS policy remain valid. Rollback must not relax
covered components, nonce enforcement, identity binding or Redis fail-closed behavior.

## Suspected or confirmed compromise

1. Open the security incident and record the earliest suspected compromise time.
2. Disable the compromised private key in KMS and immediately remove its public-key
   binding from every environment. Do not keep it as a retiring overlap key.
3. Block or quarantine affected merchant credentials if the authentication key/token
   may also be compromised. HTTP signatures do not replace DPoP/mTLS authentication.
4. Provision a new key and `keyid` through the normal out-of-band approval path.
   Never reuse the compromised identifier or restore it during rollback.
5. Search security events by bounded metadata (merchant/application, environment,
   route, outcome, time range). Do not copy raw Authorization, DPoP, Signature,
   nonce, body, account or payment values into tickets.
6. Reconcile payment-domain idempotency records and immutable transaction outcomes
   from the earliest suspected time. A cryptographically valid signature cannot
   distinguish the legitimate signer from an attacker holding the same private key.
7. Rotate adjacent credentials when scope is uncertain: DPoP/mTLS key, API access,
   KMS grants and operator credentials. Preserve evidence under the approved
   retention and access-control policy.

## Verification and closure

- Compromised `keyid` fails even with a cryptographically correct signature.
- New key succeeds only with the exact authenticated identity/environment binding.
- Old/new nonce namespaces cannot bypass replay protection; Redis outage/capacity
  returns unavailable and never falls back to process-local memory.
- Envoy strips client forwarding/target headers and preserves the exact raw body.
- Incident closure records reconciliation results, key destruction evidence,
  monitoring window and lessons learned.

The runbook is production evidence only after a merchant, security and infrastructure
owner execute it against production-like KMS, Redis and proxy topology.
