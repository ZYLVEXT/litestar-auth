# TOTP

Use this page for `TotpConfig` fields and the plugin-owned TOTP route contract.

## TOTP — `totp_config: TotpConfig | None`

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `totp_pending_secret` | (required) | Secret for pending-2FA JWTs; must align with auth controller. |
| `totp_backend_name` | `None` | Which named `AuthenticationBackend` issues tokens after 2FA. |
| `totp_issuer` | `"litestar-auth"` | Issuer in otpauth URI. |
| `totp_algorithm` | `"SHA256"` | TOTP hash algorithm. |
| `totp_pending_jti_store` | `None` | JWT JTI denylist for pending login tokens. Required unless the owning config/controller explicitly sets `unsafe_testing=True`. Use a shared store such as `RedisJWTDenylistStore` for multi-worker deployments. |
| `totp_used_tokens_store` | `None` | Replay store for consumed TOTP codes (required unless the owning config/controller explicitly sets `unsafe_testing=True`). See [Redis-backed auth surface](redis.md#redis-backed-auth-surface) for the Redis setup and import paths. |
| `totp_require_replay_protection` | `True` | Fail startup without a store unless `unsafe_testing=True`. |
| `totp_enable_requires_password` | `True` | Step-up password for `/2fa/enable`. |

Routes: `{auth_path}/2fa/...`. See [TOTP guide](../guides/totp.md).

`totp_pending_secret` signs pending-2FA JWTs for the controller flow. It is separate from
`user_manager_security.totp_secret_key`, which only encrypts the persisted TOTP secret stored on
the user record.

If `totp_backend_name` is omitted, the plugin uses the primary startup backend. Set a backend name
only when a secondary startup backend should issue post-2FA tokens.

!!! note "Pending-token JTI store"
    The plugin-owned controller forwards `TotpConfig.totp_pending_jti_store` into `create_totp_controller(..., pending_jti_store=...)`. In production, missing pending-token replay storage now fails closed unless `unsafe_testing=True`.
