# TOTP (two-factor authentication)

TOTP is enabled by setting `totp_config: TotpConfig` on `LitestarAuthConfig`. Routes are mounted under the auth prefix, e.g. `/auth/2fa/...`.

## Enrollment (two-step)

1. **`POST .../2fa/enable`** — returns a secret, otpauth URI, and short-lived `enrollment_token` (JWT). The secret is **not** stored until confirmation.
2. **`POST .../2fa/enable/confirm`** — sends `enrollment_token` + TOTP code; on success the secret is persisted.

By default **`totp_enable_requires_password=True`**, so step 1 also requires the current password (step-up).

## Login completion

When a login requires a second factor, the client finishes with:

- **`POST .../2fa/verify`** — pending token + TOTP code.

Pending login JWTs use a JTI denylist internally. The plugin-built TOTP controller does not expose a Redis `pending_jti_store`; it resolves an in-process fallback with **warnings** when not in testing mode. For strict multi-worker deduplication of pending JTIs, mount **`create_totp_controller`** yourself and pass **`pending_jti_store`** (e.g. `RedisJWTDenylistStore`).

## Disable

- **`POST .../2fa/disable`** — requires a valid current TOTP `code`.

## Replay protection

Production deployments should configure **`totp_used_tokens_store`** so codes cannot be reused. Without it, the library fails fast outside testing mode.

For pytest-driven plugin tests, see the [testing guide](testing.md). Under **`LITESTAR_AUTH_TESTING=1`**, the plugin can run without **`totp_used_tokens_store`**, but that is a single-process testing convenience rather than a production-safe replay-protection setup.

Algorithm defaults to **SHA256** (`totp_algorithm`).

## Related

- [Configuration](../configuration.md) — `TotpConfig`.
- [TOTP API](../api/totp.md) — helpers and types.
- [Manager API](../api/manager.md) — manager hooks for secrets and lifecycle.
- [Testing plugin-backed apps](testing.md) — pytest-only testing mode, request-scoped sessions, and store-isolation boundaries.
