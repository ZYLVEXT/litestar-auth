# TOTP

Use this page for `TotpConfig` fields and the plugin-owned TOTP route contract.

## TOTP — `totp_config: TotpConfig | None`

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `totp_pending_secret` | (required) | Secret for pending-2FA JWTs; must align with auth controller. |
| `totp_backend_name` | `None` | Which named `AuthenticationBackend` issues tokens after 2FA. |
| `totp_issuer` | `"litestar-auth"` | Issuer in otpauth URI. |
| `totp_algorithm` | `"SHA256"` | TOTP hash algorithm; supported values are `"SHA256"` and `"SHA512"`. |
| `totp_pending_jti_store` | `None` | JWT JTI denylist for pending login tokens. Required unless the owning config/controller explicitly sets `unsafe_testing=True`. Use a shared store such as `RedisJWTDenylistStore` for multi-worker deployments. |
| `totp_enrollment_store` | `None` | Server-side pending-enrollment store. Required unless the owning config/controller explicitly sets `unsafe_testing=True`. Use a shared store such as `RedisTotpEnrollmentStore` for multi-worker deployments. |
| `totp_used_tokens_store` | `None` | Replay store for consumed TOTP codes (required unless the owning config/controller explicitly sets `unsafe_testing=True`). See [Redis-backed auth surface](redis.md#redis-backed-auth-surface) for the Redis setup and import paths. |
| `totp_require_replay_protection` | `True` | Fail startup without a store unless `unsafe_testing=True`. |
| `totp_enable_requires_password` | `True` | Step-up password for `/2fa/enable`. |

Routes: `{auth_path}/2fa/...`. See [TOTP guide](../guides/totp.md).

The plugin-owned TOTP flow follows `LitestarAuthConfig.requires_verification`, which now defaults
to `True`. Manual `create_totp_controller(...)` wiring should keep that flag aligned with the auth
controller so unverified accounts cannot complete the second authentication step. When both checks
fail, the shared account-state policy reports inactive users before unverified users.

`totp_pending_secret` signs pending-2FA JWTs for the controller flow. It is separate from
`user_manager_security.totp_secret_key`, which encrypts the TOTP secret at rest on the user
record **and** before writing the short-lived pending-enrollment secret to
`totp_enrollment_store`. The enrollment JWT returned by `/2fa/enable` carries only lookup claims,
not the secret. The plugin forwards the configured `totp_secret_key` into
`create_totp_controller(..., totp_secret_key=...)` automatically. In production,
`totp_secret_key` is required — `create_totp_controller` fails closed with `ConfigurationError`
when it is omitted and `unsafe_testing=False`.

If `totp_backend_name` is omitted, the plugin uses the primary startup backend. Set a backend name
only when a secondary startup backend should issue post-2FA tokens.

!!! note "Pending-token JTI store"
    The plugin-owned controller forwards `TotpConfig.totp_pending_jti_store` into `create_totp_controller(..., pending_jti_store=...)`. In production, missing pending-token replay storage now fails closed unless `unsafe_testing=True`.

!!! note "Pending-enrollment store"
    The plugin-owned controller forwards `TotpConfig.totp_enrollment_store` into `create_totp_controller(..., enrollment_store=...)`. In production, missing enrollment storage now fails closed unless `unsafe_testing=True`; each `/2fa/enable` replaces the previous pending enrollment for that user, and `/2fa/enable/confirm` consumes the matching `jti` once.
