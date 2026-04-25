# TOTP (two-factor authentication)

TOTP is enabled by setting `totp_config: TotpConfig` on `LitestarAuthConfig`. Routes are mounted under the auth prefix, e.g. `/auth/2fa/...`.

## Enrollment (two-step)

1. **`POST .../2fa/enable`** — returns a secret, otpauth URI, and short-lived `enrollment_token` (JWT). The secret is **not** stored until confirmation.
2. **`POST .../2fa/enable/confirm`** — sends `enrollment_token` + TOTP code; on success the secret is persisted and the response returns one-time recovery codes.

By default **`totp_enable_requires_password=True`**, so step 1 also requires the current password (step-up).
Because the `/2fa/enable` response necessarily includes the plaintext TOTP secret and otpauth URI
for QR-code rendering, production deployments must serve this route only over HTTPS.

### Enrollment-token confidentiality

The `enrollment_token` does **not** carry the freshly generated TOTP secret.
It carries only short-lived lookup claims (`sub`, `jti`, and an encoding marker).
The secret is stored server-side in `totp_enrollment_store`, encrypted first with
`user_manager_security.totp_secret_keyring` — the same keyring used to encrypt
the persisted secret. The one-key `totp_secret_key` shortcut remains available
for deployments with a single active Fernet key. In production,
`totp_secret_keyring` or `totp_secret_key` is required together with
`totp_enrollment_store`; plaintext, process-local enrollment state is only
created automatically when the owning config/controller explicitly sets
`unsafe_testing=True`.

Each `/2fa/enable` call replaces any previous pending enrollment for that user,
and `/2fa/enable/confirm` atomically consumes the matching `jti`. A stale token,
reused token, token from an older `/enable`, or token consumed by an invalid code
cannot be confirmed later.

Successful confirmation returns `TotpConfirmEnableResponse` with `enabled: true`
and `recovery_codes`. The plaintext recovery codes are issued only in that
response; the user model stores only Argon2 hashes in `recovery_codes_hashes`.
Generated recovery codes are 28 lowercase hex characters (112 bits).

## Recovery-code rotation

- **`POST .../2fa/recovery-codes/regenerate`** — authenticated users can replace the active recovery-code set. The response returns the new plaintext `recovery_codes` once; old recovery codes stop working immediately.

By default this route follows the same password step-up policy as enrollment:
when **`totp_enable_requires_password=True`**, send
`TotpRegenerateRecoveryCodesRequest` with `current_password`. A wrong password
returns the same `LOGIN_BAD_CREDENTIALS` failure shape as login. When the flag is
disabled, the route accepts no request body.

## Login completion

When a login requires a second factor, the client finishes with:

- **`POST .../2fa/verify`** — pending token + TOTP code, or pending token + an unused recovery code in the same `code` field. A recovery code is consumed on successful login and cannot be reused.

Pending login JWTs use a JTI denylist internally. In production, configure **`TotpConfig.totp_pending_jti_store`** on the plugin-managed path or pass **`pending_jti_store`** to **`create_totp_controller`** manually. Missing pending-token replay storage now fails closed unless the owning config/controller explicitly sets **`unsafe_testing=True`**.

Pending login JWTs are client-bound by default. With
**`TotpConfig.totp_pending_require_client_binding=True`**, `/login` adds SHA-256
fingerprint claims for the trusted-proxy-aware client IP (`cip`) and
User-Agent (`uaf`), and `/2fa/verify` recomputes them before accepting either a
TOTP code or recovery code. A mismatch returns the same 400
`TOTP_PENDING_BAD_TOKEN` shape as an expired or malformed pending token. Set
the flag to **`False`** only when your deployment accepts cross-client
pending-token replay; the controller logs that weaker posture at factory time.

## Disable

- **`POST .../2fa/disable`** — requires a valid current TOTP code or an unused recovery code. A recovery-code disable consumes the matching code, clears the TOTP secret, and clears any remaining recovery-code hashes.

## Replay protection

Production deployments should configure **`totp_used_tokens_store`** so codes cannot be reused. Without it, the library fails fast unless the owning config/controller explicitly opts into `unsafe_testing=True`.

When the same async Redis client should back auth rate limiting plus the TOTP Redis stores, use
the shared-client recipe in
[Configuration](../configuration.md#redis-backed-auth-surface). That is the maintained
`RedisAuthPreset` flow for `build_rate_limit_config()`,
`build_totp_enrollment_store()`, `build_totp_pending_jti_store()`, and
`build_totp_used_tokens_store()` together. Keep manual `totp_enrollment_store` /
`pending_jti_store` / `totp_used_tokens_store` wiring as the direct path when
you intentionally use separate backends or bespoke key prefixes.

The three production stores are still distinct even in the shared-client recipe:

- **`totp_enrollment_store`** stores pending enrollment secrets and enforces latest-only, single-use confirmation.
- **`totp_pending_jti_store`** prevents pending-login JWT replay.
- **`totp_used_tokens_store`** prevents consumed TOTP-code replay.

For pytest-driven plugin tests, see the [testing guide](testing.md). Under **`unsafe_testing=True`**, the plugin can run without **`totp_used_tokens_store`**, but that is a single-process testing convenience rather than a production-safe replay-protection setup.

Algorithm defaults to **SHA256** (`totp_algorithm`). Supported algorithms are **SHA256** and **SHA512**.

## Related

- [Configuration](../configuration.md#redis-backed-auth-surface) — Redis-backed
  production recipe for rate limiting plus the TOTP Redis stores.
- [Configuration](../configuration.md) — `TotpConfig`.
- [TOTP API](../api/totp.md) — helpers and types.
- [Manager API](../api/manager.md) — manager hooks for secrets and lifecycle.
- [Testing plugin-backed apps](testing.md) — explicit `unsafe_testing`, request-scoped sessions, and store-isolation boundaries.
