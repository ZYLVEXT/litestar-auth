# TOTP

Use this page for `TotpConfig` fields and the plugin-owned TOTP route contract.

## TOTP — `totp_config: TotpConfig | None` {#totp--totp_config-totpconfig--none}

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
| `totp_pending_require_client_binding` | `True` | Bind pending-login JWTs to hashed client IP and User-Agent fingerprints and reject mismatches at `/2fa/verify`. |

Routes: `{auth_path}/2fa/...`. See [TOTP guide](../guides/totp.md).

When `LitestarAuthConfig.totp_config` is set, the plugin derives an internal TOTP extension and
mounts the bundled TOTP controller through the same extension contribution mechanism used by other
optional route surfaces. This is an internal wiring detail: applications enable plugin-owned TOTP
with `totp_config`, not by instantiating a public TOTP extension. The extension contributes the
same `/2fa` controller and keeps controller-build validation in the factory path, so missing replay
stores or production TOTP secret encryption still fail when the controller is built during plugin
startup.

The plugin-owned TOTP flow follows `LitestarAuthConfig.requires_verification`, which defaults
to `True`. Manual `create_totp_controller(...)` wiring should keep that flag aligned with the auth
controller so unverified accounts cannot complete the second authentication step. When both checks
fail, the shared account-state policy reports inactive users before unverified users.

`totp_pending_secret` signs pending-2FA JWTs for the controller flow. It is separate from
`user_manager_security.totp_secret_keyring`, which encrypts the TOTP secret at rest on the user
record **and** before writing the short-lived pending-enrollment secret to
`totp_enrollment_store`. The enrollment JWT returned by `/2fa/enable` carries only lookup claims,
not the secret. The plugin forwards the configured keyring into
`create_totp_controller(..., totp_secret_keyring=...)` automatically. Manual controller wiring keeps
the same keyword names, typed by `TotpControllerOptions`. In production,
`totp_secret_keyring` or the one-key `totp_secret_key` shortcut is required —
`create_totp_controller` fails closed with `ConfigurationError` when both are omitted and
`unsafe_testing=False`. Persisted user-row TOTP secrets are stored as
`fernet:v1:<key_id>:<ciphertext>` values and unprefixed plaintext rows are rejected fail-closed.
Use `BaseUserManager.totp_secret_requires_reencrypt(...)` and
`BaseUserManager.reencrypt_totp_secret_for_storage(...)` from migration code that rewrites stored
values under the active configured key.

Startup validation for plugin-owned TOTP store requirements fails with `ConfigurationError`.
This includes missing `totp_pending_jti_store`, `totp_enrollment_store`, and
`totp_used_tokens_store` when `unsafe_testing=False`. This is an intentional breaking change from
the earlier `ValueError` raised for missing pending-token and enrollment stores; catch
`ConfigurationError` around plugin configuration validation if the application handles startup
misconfiguration explicitly.

For rotation, add a new Fernet key id to `user_manager_security.totp_secret_keyring.keys`, deploy the
expanded keyring first, then switch `active_key_id` to the new id. New pending-enrollment and
persisted TOTP writes use the new key id while old versioned rows remain readable. An
application-owned migration can scan persisted TOTP secret values, call
`BaseUserManager.totp_secret_requires_reencrypt(value)`, and rewrite only values that return `True`
through `BaseUserManager.reencrypt_totp_secret_for_storage(value)`. Verify a final scan before
removing the retired key id. The full staged checklist is in
[Deployment](../deployment.md#versioned-fernet-key-rotation).

Legacy unversioned Fernet values are migration input only because they do not carry a key id. They
must be decrypted with explicit old key material and rewritten to `fernet:v1:<key_id>:<ciphertext>`.
Plaintext persisted TOTP rows remain unsupported and fail closed; clear or encrypt them before
production use.

If `totp_backend_name` is omitted, the plugin uses the primary startup backend. Set a backend name
only when a secondary startup backend should issue post-2FA tokens.

!!! note "Pending-token JTI store"
    The plugin-owned controller forwards `TotpConfig.totp_pending_jti_store` into `create_totp_controller(..., pending_jti_store=...)`. In production, missing pending-token replay storage fails closed unless `unsafe_testing=True`.

!!! note "Pending-token client binding"
    The plugin-owned auth and TOTP controllers both forward `TotpConfig.totp_pending_require_client_binding`. Keep the default `True` unless your proxy topology cannot provide stable client metadata and you accept pending-token replay from a different client. The fingerprints are SHA-256 hex values, not raw IP or User-Agent strings.

    The client-IP fingerprint resolves through the same `trusted_proxy`, `trusted_headers`, and `trusted_proxy_hops` settings as the `/2fa/verify` rate limiter — these are mirrored from `totp_verify` so the binding keys on the same `X-Forwarded-For` hop the limiter does. In a multi-proxy deployment set `totp_verify.trusted_proxy_hops=N` (see [rate limiting](../guides/rate_limiting.md)); otherwise the binding would fingerprint the inner-proxy address shared by every client behind it and the IP component would no longer distinguish callers.

!!! note "Pending-enrollment store"
    The plugin-owned controller forwards `TotpConfig.totp_enrollment_store` into `create_totp_controller(..., enrollment_store=...)`. In production, missing enrollment storage fails closed unless `unsafe_testing=True`; each `/2fa/enable` replaces the previous pending enrollment for that user, and `/2fa/enable/confirm` consumes the matching `jti` once.

## TOTP step-up for sensitive operations {#totp-step-up-for-sensitive-operations}

TOTP step-up is the server-side proof that an authenticated user recently completed an app-code
TOTP verification. The marker is session-scoped, stored by the configured token strategy, and
expires server-side. Sensitive controller operations check that marker before mutating state, or
verify an inline `totp_code` when the request body supports one.

The relevant `LitestarAuthConfig` fields are:

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `totp_stepup_ttl_seconds` | `300` | Lifetime, in seconds, for a recent-TOTP marker. The value must be a non-negative integer. |
| `totp_stepup_policy` | `{}` | Per-endpoint overrides. Valid modes are `required_when_enrolled`, `always_required`, and `off`. Unknown endpoint keys fail startup validation. |
| `totp_stepup_allow_recovery` | `False` | Controls whether successful recovery-code verification at `{auth_path}/2fa/verify` may issue the recent-TOTP marker. Keep the default when recovery codes should only complete login. |

Default endpoint policy:

| `totp_stepup_policy` key | Built-in route surface | Default mode | Inline proof field |
| ------------------------ | ---------------------- | ------------ | ------------------ |
| `users.update_self` | `PATCH {users_path}/me` email changes | `required_when_enrolled` | `totp_code` |
| `api_keys.create` | `POST /api-keys` and `POST {users_path}/{user_id}/api-keys` | `required_when_enrolled` | `totp_code` on create bodies |
| `api_keys.update` | `PATCH /api-keys/{key_id}` | `required_when_enrolled` | `totp_code` |
| `api_keys.revoke` | `DELETE /api-keys/{key_id}` and `DELETE {users_path}/{user_id}/api-keys/{key_id}` | `required_when_enrolled` | None; use a recent marker |
| `oauth.associate` | `GET {auth_path}/associate/{provider}/callback` | `required_when_enrolled` | None; use a recent marker |
| `totp.disable` | `POST {auth_path}/2fa/disable` | `required_when_enrolled` | `code` |
| `totp.regenerate_recovery_codes` | `POST {auth_path}/2fa/recovery-codes/regenerate` | `required_when_enrolled` | `totp_code` |

`required_when_enrolled` preserves existing behavior for users without TOTP. If the user has an
active TOTP secret, the operation requires either a recent marker for the same authenticated session
or a valid inline TOTP code. `always_required` also blocks users without an active readable TOTP
secret, which is useful only when enrollment is mandatory before the protected operation can be used.
`off` disables the built-in gate for that endpoint.

When the gate fails, bundled controllers return HTTP 403 with `ErrorCode.TOTP_STEPUP_REQUIRED`
(`TOTP_STEPUP_REQUIRED`) in the response `extra.code`. Clients should prompt for a fresh TOTP code,
submit it inline when the endpoint accepts the field, or complete `{auth_path}/2fa/verify` and retry
from the same session.

Recovery codes are intentionally narrower than app-code verification. With the default
`totp_stepup_allow_recovery=False`, a recovery code can complete the pending login flow but does not
create a marker that unlocks other sensitive operations. `POST {auth_path}/2fa/disable` still accepts
a recovery code as its own unlock factor so users can disable MFA when the authenticator app is
unavailable.

API-key authenticated requests cannot complete an interactive TOTP challenge. API-key management
routes also require `requires_password_session`, so API-key callers are rejected before the step-up
gate instead of being allowed to satisfy it with the same delegated credential they are trying to
manage. Use a bearer or cookie login session for API-key create/update/revoke flows.
