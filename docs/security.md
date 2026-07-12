# Security model

This page summarizes protections and practical security trade-offs shipped by the library.

## Operator checklist {#operator-checklist}

Before production rollout, verify the deployment-owned security contract in
[Deployment](deployment.md#deployment-security-contract):
[reverse-proxy and trust boundaries](deployment.md#reverse-proxy-and-trust-boundaries),
[cookie transport security requirements](deployment.md#cookie-transport-security-requirements), and
[secrets at rest and key rotation](deployment.md#secrets-at-rest-and-key-rotation).

## Implemented controls

- **Passwords** — hashing via `pwdlib`; hash upgrade on login when parameters change.
- **Credential rotation** — self-service password changes use `POST /users/me/change-password`
  with current-password re-verification. Self-service profile updates do not accept password
  changes, so stale profile-edit clients cannot rotate credentials without proving the current
  password; admin-initiated rotation remains privileged through `AdminUserUpdate`.
- **Reset & verify tokens** — signed JWT-style tokens with a password fingerprint so reset tokens die after password change (de-facto single-use). Library-issued verify and reset tokens include JOSE `typ=JWT`; missing or unexpected `typ` headers are rejected before the normal signed decode. For explicit server-side single-use, configure `account_token_denylist_store` (a shared `JWTDenylistStore` such as `RedisJWTDenylistStore`) on `LitestarAuthConfig` or `BaseUserManager`: the token's `jti` is checked on entry and consumed on a successful verify/reset, so the same token cannot be replayed even before the underlying state rotates. When unset (default), single-use rests on fingerprint/verification-state rotation only.
- **JWT** — library-issued access tokens include JOSE `typ=JWT`, and access-token decode rejects missing or unexpected `typ` headers before signature, audience, issuer, algorithm, and required-claim validation. This is defense-in-depth against token-class confusion, not a substitute for those primary controls. Access-token validation also enforces `exp` / `iat` / `aud`; optional `iss`; a small `exp` / `nbf` leeway for ordinary clock skew; and `jti` denylist support (`InMemoryJWTDenylistStore`, `RedisJWTDenylistStore`) with an explicit `JWTStrategy.revocation_posture` contract. The in-memory denylist prunes expired JTIs on each revoke and **fails closed** when `max_entries` is reached with no reclaimable slots: it does not insert the new revocation and does not drop active revocations (use `RedisJWTDenylistStore` or raise the cap for high revoke volume). Callers are not misled into thinking logout succeeded: `JWTStrategy.destroy_token` raises `TokenError`, and `AuthenticationBackend.logout` maps that to HTTP **503** with `TOKEN_PROCESSING_FAILED` for API routes using the bundled exception handler.
- **Session fingerprint** — optional claim on JWT tying tokens to current password/email state. The default fingerprint HMAC key is HKDF-SHA256-derived from the JWT signing secret with a `litestar-auth` JWT fingerprint domain; outstanding tokens minted with the older raw-secret fingerprint are intentionally invalidated and require one re-login after upgrade.
- **Cookie auth** — secure defaults (`HttpOnly`, `Secure`, `SameSite`); CSRF for unsafe methods when wired (see [Guides — Security](guides/security.md)).
- **TOTP** — pending enrollment secrets stay server-side in `totp_enrollment_store`; replay protection is enforced when `totp_used_tokens_store` is configured; production fails fast without required stores; persisted TOTP secrets require encrypted-at-rest storage through `BaseUserManager.totp_secret_storage_posture` plus `UserManagerSecurity.totp_secret_keyring` or the one-key `totp_secret_key`; recovery codes are 112-bit lowercase hex values stored as HMAC lookup digests mapped to Argon2 hashes; pending-login tokens are bound to hashed client IP and User-Agent fingerprints by default; successful app-code verification can record a short-lived server-side step-up marker for downstream sensitive operations.
- **OAuth** — state and PKCE verifier evidence in a short-lived `HttpOnly` flow cookie encrypted/authenticated with a Fernet key HKDF-derived from `oauth_flow_cookie_secret`; strict state validation; optional encryption at rest for provider tokens (`oauth_token_encryption_keyring` or one-key `oauth_token_encryption_key`); OAuth token persistence accepts only current-module `OAuthTokenEncryption` policies; write-time plaintext snapshots are restored after successful writes and cleared on rollback; guarded associate-by-email rules (`oauth_trust_provider_email_verified` on plugin-owned routes, `trust_provider_email_verified` on manual controllers, and `oauth_associate_by_email`); redirect-host validation rejects non-public and SSRF-adjacent hosts and, with the fail-closed default `oauth_redirect_dns_strict=True`, also turns DNS resolver failures or empty/unusable answers into `ConfigurationError` (set it to `False` to restore fail-open DNS behavior for offline or sandboxed startup); **the associate authorize route is POST + CSRF-protected** so a victim's `SameSite=Lax` session cookie cannot be abused by a cross-site top-level navigation to attach an attacker-controlled provider account to the victim's local user. Login authorize stays GET because anonymous OAuth login has no victim session to abuse.
- **Opaque DB tokens** — keyed digest at rest; plugin-managed DB-token wiring uses `DatabaseTokenAuthConfig` plus `LitestarAuthConfig(..., database_token_auth=...)`.
- **API keys** — opt-in user-owned credentials with digest-only bearer storage, one-time raw-secret
  create responses, soft revocation, expiry, active-key caps, allowed-scope validation, and
  route-time downscoping by current user roles when `scope_subset_check=True`. Self-service
  list/read/create/update/revoke routes and superuser admin mint/list/revoke routes require
  `requires_password_session`, so API-key callers cannot enumerate or maintain API-key inventory
  or cross the password-session boundary. Optional
  `LSA1-HMAC-SHA256` request signing adds timestamp skew and
  nonce replay checks and caps pre-auth body buffering with `api_keys.signed_body_max_bytes`, but
  signing-required keys store an encrypted copy of the raw secret via `api_keys.secret_encryption_keyring`;
  this is a deliberate reversible-storage trade-off compared with bearer keys' digest-only storage.
- **Failed-login telemetry** — failed-login logs never include the submitted email/username. Configure
  `UserManagerSecurity.login_identifier_telemetry_secret` when you want a stable, non-reversible
  `identifier_digest`; the digest is omitted when that dedicated secret is unset.
- **Per-account lockout** — optional password-login brute-force protection through
  `AccountLockoutConfig`. It is disabled by default; when enabled, login identifiers are normalized
  and stored only as keyed digests, repeated failed password checks lock that account key for the
  configured window, and a successful password login before lockout resets the counter. Locked
  accounts deliberately return the same `LOGIN_BAD_CREDENTIALS` response as wrong credentials or a
  missing user, without a distinct lockout code, status, or `Retry-After` header. Lockout keys are
  derived from `login_identifier_telemetry_secret` under a dedicated domain-separation context;
  rotating that secret changes every account key and therefore clears all active lockout counters.
- **Rate limiting** — optional per-endpoint limits; in-memory backend is single-process only and fails closed for new keys when its capacity cap is reached.
- **Route-level role checks** — `is_superuser`, `has_any_role(...)`, and `has_all_roles(...)` reuse the same normalized flat-role semantics as persistence and manager writes, and they fail closed if the authenticated user does not expose the documented role-capable contract. Role guard matching uses fixed-work internal comparisons over normalized role strings to avoid role-membership short-circuit predicates; this is a defense-in-depth posture, not a claim of cryptographic constant-time behavior across Python or the network.

## Plugin-managed security posture paths

The plugin keeps these security-sensitive paths aligned with the same runtime posture contracts used by startup warnings and fail-closed validation where applicable:

--8<-- "docs/snippets/plugin_security_tradeoffs.md"

## Direct/manual posture contracts

When you assemble `JWTStrategy` or `BaseUserManager` yourself, inspect the runtime posture objects directly instead of inferring security behavior from constructor kwargs later:

- `JWTStrategy(secret=..., denylist_store=RedisJWTDenylistStore(...))` reports the durable `shared_store` posture.
- `JWTStrategy(secret=..., allow_inmemory_denylist=True)` reports the process-local `in_memory` posture. `revocation_is_durable` stays `False` and logout / revoke remains single-process.
- Plugin-managed JWT revocation notices consume the live `JWTRevocationPosture` exported from
  `litestar_auth.authentication.strategy.jwt` and returned by `JWTStrategy.revocation_posture`;
  posture-shaped wrappers or objects retained from earlier module identities are ignored.
- `BaseUserManager.totp_secret_storage_posture` reports the `fernet_encrypted` persisted-secret contract. Supplying `totp_secret_keyring=FernetKeyringConfig(...)` on `UserManagerSecurity(...)` lets direct/custom integrations store and read encrypted TOTP secrets with an active key id and configured old keys. The one-key `totp_secret_key` field remains an ergonomic shortcut and is encoded under the `default` key id.
- New persisted TOTP secret writes use `fernet:v1:<key_id>:<ciphertext>` values. `BaseUserManager.totp_secret_requires_reencrypt(...)` and `BaseUserManager.reencrypt_totp_secret_for_storage(...)` are the manager helpers for at-rest rotation jobs.
- With `totp_secret_keyring` and `totp_secret_key` omitted, `None` still represents disabled 2FA, but non-null TOTP secret writes and unprefixed legacy plaintext reads fail closed. Encrypt, rotate, or clear existing plaintext TOTP secret rows before upgrading.
- TOTP step-up for sensitive operations is documented in
  [TOTP step-up for sensitive operations](configuration/totp.md#totp-step-up-for-sensitive-operations),
  including `totp_stepup_ttl_seconds`, `totp_stepup_policy`, `totp_stepup_allow_recovery`, the
  `TOTP_STEPUP_REQUIRED` 403 contract, default endpoint policies, recovery-code behavior, and the
  API-key transport rationale.
- `BaseUserManager` uses `UserManagerSecurity.login_identifier_telemetry_secret` only for
  failed-login identifier digests and plugin-managed account-lockout key derivation. It is optional
  while lockout is disabled; enabling `AccountLockoutConfig` without this secret is rejected. Omit it
  only when you do not need correlated failed-login telemetry and do not enable account lockout.

## OAuth redirect-host DNS validation

Plugin-owned `OAuthConfig.oauth_redirect_dns_strict` and manual OAuth controller
`oauth_redirect_dns_strict` both default to `True` (fail closed). Redirect-host validation
rejects loopback, RFC 1918 private, RFC 3927 link-local including `169.254.169.254`, multicast,
reserved, and unspecified IP literals or DNS answers, and — with the fail-closed default — DNS
resolver failures, empty answers, and answers without any usable public address also become
`ConfigurationError` at plugin startup or manual controller construction.

Set `oauth_redirect_dns_strict=False` to restore the fail-open behavior for offline or sandboxed
startup environments where DNS is unavailable; with that override, only resolvable internal-only
answers are rejected and resolver failures are accepted. This check resolves DNS once at validation
time only in either mode. It does not defend
against DNS rebinding or any later runtime DNS change, so production deployments must also enforce
network egress controls that block app-to-RFC1918, app-to-link-local, metadata-service, and other
internal destinations.

## Secret-at-rest rotation

OAuth token encryption and TOTP secret encryption share the same versioned Fernet storage format:
`fernet:v1:<key_id>:<ciphertext>`. The key id is operational metadata, not secret material; the
ciphertext remains sensitive.

Use `FernetKeyringConfig(active_key_id=..., keys=...)` for production. During rotation, deploy a
keyring that contains both the old and new ids, switch `active_key_id` to the new id for writes, run
row-level re-encryption with `OAuthTokenEncryption.requires_reencrypt(...)` /
`OAuthTokenEncryption.reencrypt(...)` and `BaseUserManager.totp_secret_requires_reencrypt(...)` /
`BaseUserManager.reencrypt_totp_secret_for_storage(...)`.

API-key signing secrets use the same Fernet envelope through
`api_keys.secret_encryption_keyring`, but only signing-required keys have reversible storage. Bearer
API keys remain digest-only, cannot be upgraded to signing mode, and are not rotation candidates.
For signing rows, scan rows where `signing_required` is true and `encrypted_secret` is non-null, call
`BaseUserManager.api_key_signing_secret_requires_reencrypt(row)`, and rewrite one row at a time with
`BaseUserManager.reencrypt_api_key_signing_secret(row_or_key_id)`. The helper returns the updated row
metadata, never the plaintext signing secret, and it does not invoke API-key create/revoke/use
lifecycle hooks. Verify no rows still require rotation, and only then remove the retired key id. The
full operator checklist lives in [Deployment](deployment.md#versioned-fernet-key-rotation).

Unknown key ids, malformed Fernet envelopes, missing `encrypted_secret` values on signing rows, and
bearer rows must be treated as migration errors or explicit data-cleanup cases. Do not catch and
ignore those failures while removing an old key id.

Legacy unversioned Fernet values must be handled as migration input because they do not
identify the decrypting key. They are not a general runtime compatibility mode. Plaintext persisted
TOTP secrets remain fail-closed and must be cleared or encrypted before production use.

Additional opt-ins to weaker behavior:

| Surface | Risk |
| ---- | ---- |
| `totp_enable_requires_password=False` | Weakens step-up for TOTP enrollment. |
| `csrf_secret` unset with plugin-owned cookie auth | Plugin validation fails closed unless cookie auth explicitly opts out. |
| `csrf_protection_managed_externally=True` on manual cookie auth | You are asserting that app-owned CSRF middleware or an equivalent framework-level control protects the manual route table. |
| `CookieTransport(allow_insecure_cookie_auth=True)` | Allows cookie auth without CSRF for controlled non-browser scenarios only. |
| `ApiKeyConfig(signing_enabled=True, secret_encryption_keyring=...)` | Enables request signing, but stores an encrypted copy of signing-required key secrets so signatures can be verified. |
| `InMemoryApiKeyNonceStore` | Process-local API-key signing replay cache; use `RedisApiKeyNonceStore` for multi-worker deployments. |
| `AccountLockoutConfig(enabled=True)` with the default in-memory store | Process-local per-account lockout counters; use `RedisAccountLockoutStore` for multi-worker deployments. |

## Bearer failure-code taxonomy

Bearer API-key authentication returns the same outer response shape for unknown, revoked, and expired keys:
HTTP **401** with a JSON `code` value. The distinct `API_KEY_INVALID`, `API_KEY_REVOKED`, and
`API_KEY_EXPIRED` codes are a deliberate client-semantics trade-off, not an accidental disclosure
channel.

The bearer credential embeds a generated `key_id` with at least 128 bits of entropy before the raw
secret is verified against the stored HMAC digest. Blind enumeration of real `key_id` values is
therefore impractical under ordinary online attack constraints. Once a request names a valid
high-entropy `key_id`, separate codes let clients choose the correct remediation:

- `API_KEY_INVALID` — the key id is unknown or the presented raw secret does not match; rotate or
  report the credential rather than retrying indefinitely.
- `API_KEY_REVOKED` — the key row is known but was intentionally disabled; stop using the credential
  and create a replacement through a password-backed session.
- `API_KEY_EXPIRED` — the key row is known but past its configured expiry; refresh the credential
  through normal key-management flows.

Do not depend on the specific code to grant access. All three outcomes are authentication failures
and must remain non-authorizing.

When `AuthRateLimitConfig.api_key_use` is configured, malformed and unknown API-key credentials are
classified without consuming the API-key-use limiter. Resolved unusable key rows, such as revoked,
expired, timestamp-skewed, or nonce-replayed keys, still consume the limiter before the structured
401 response is returned.

## Limitations (by design)

- No built-in **email** sending — you must implement hooks.
- No **RBAC** or **WebAuthn** in core — the built-in role guards are flat membership checks only; extend in your application for permission matrices or object-level policy.
- **Durable JWT revocation** requires a shared store — `JWTStrategy(secret=...)` without `denylist_store` or `allow_inmemory_denylist=True` fails closed at construction time. Use Redis (or equivalent) denylist for multi-worker production if you rely on revoke; reserve `allow_inmemory_denylist=True` for single-process development or tests.
- **Per-account lockout** requires a shared store in multi-worker deployments. The default
  `InMemoryAccountLockoutStore` is single-process only and is a development/single-worker tool; use
  `RedisAccountLockoutStore` or a custom shared `AccountLockoutStore` when multiple workers can
  receive login attempts for the same account. Lockout counters are TTL-bound state, not durable
  records: a Redis restart without persistence (or a worker restart with the in-memory store) clears
  active lockouts, so keep `rate_limit_config.login` configured as the primary brute-force brake and
  treat lockout as a complementary per-account layer.
- **API keys** are user-owned delegated credentials only. Service-account-only keys, HKDF child keys,
  IP allowlists, per-key audit tables, and mTLS binding are outside this release.
- API-key signing-secret rotation is operator-owned row processing. The library does not provide
  built-in batching, locking, audit-log storage, per-key audit tables, or an automatic database
  migration service for this workflow.

## Further reading

- [Guides — Security](guides/security.md) — CSRF, cookies, headers.
- [Deployment](deployment.md) — production checklist.
- [Security and DI](configuration/security.md#security-and-token-policy) — CSRF, JWT/TOTP policy, dependency keys; OAuth token encryption is configured on [OAuth](configuration/oauth.md#oauth--oauth_config-oauthconfig--none).
