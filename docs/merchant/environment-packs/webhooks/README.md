# Standard Webhooks merchant environment packs

These two checked examples make the onboarding boundary explicit for `sandbox`
and `live`. They are templates, not production credentials: every file carries
`status: example-do-not-deploy`, and all public keys correspond to disposable
deterministic test keys.

Copy one pack into the merchant's approved configuration system, replace the
owner, endpoint, key-set URL, validity window, and all three keys through the
key ceremony, then remove the example status only in that external system. Do
not add production packs or private key material to this repository.

The roles describe an overlap snapshot:

- `active` signs current deliveries;
- `next` is distributed before activation and may co-sign during cutover;
- `retiring` remains accepted only for the bounded rollback/overlap window.

Sandbox and live endpoints, key-set URLs, and keys must remain disjoint. The
exact endpoint allowlist is an application control; the required controlled
egress proxy/subnet remains a deployment control. See
[`../../webhook-sender-threat-model.md`](../../webhook-sender-threat-model.md).

Validate the examples with:

```bash
uv run python docs/merchant/environment-packs/webhooks/verify_packs.py
```
