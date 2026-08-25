# TOTP and step-up

Install `litestar-auth[totp]` and configure `TotpConfig` with encrypted-at-rest secrets
(`totp_secret_key` or `totp_secret_keyring`). Production enrollment fails closed without encryption.

## Flows

| Flow | Credential | Notes |
| --- | --- | --- |
| Enrollment | Challenge JWT `litestar-auth:2fa-enroll` | Secret stored server-side, encrypted |
| Pending login | Challenge JWT `litestar-auth:2fa-pending` | Single-attempt: JTI claimed before OTP/recovery verify |
| Step-up | Inline TOTP code + `UsedTotpCodeStore` | Replay-protected within the TOTP window |

Pending-login and enrollment tokens are **not** opaque sessions. See
[credentials and tokens](../credentials.md).

## Hardening (8.0.1+)

- Pending JTI is claimed atomically before TOTP or recovery verification.
- Step-up uses `UsedTotpCodeStore`; with replay protection required (default) and no store,
  inline codes fail closed.
- `always_required` step-up fails closed for user models that cannot present TOTP.
- Codes must be ASCII digits (`[0-9]{6}`), not Unicode digit classes.

Multi-worker deployments need shared pending-JTI and used-code stores. See
[multi-worker stores](multi-worker-stores.md).

## Related

- [Secrets and stores](../secrets.md)
- [Security posture](../security.md)
- [Migrate 7.x → 8](../migration-v8.md)
