# Security model

This page summarizes protections and **conscious trade-offs** shipped by the library.

## Implemented controls

- **Passwords** — hashing via `pwdlib`; hash upgrade on login when parameters change.
- **Reset tokens** — signed JWT-style reset tokens with password fingerprint so tokens die after password change.
- **JWT** — enforced `exp` / `iat` / `aud`; optional `iss`; a small `exp` / `nbf` leeway for ordinary clock skew on access-token validation; `jti` denylist support (`InMemoryJWTDenylistStore`, `RedisJWTDenylistStore`) with an explicit `JWTStrategy.revocation_posture` contract. The in-memory denylist prunes expired JTIs on each revoke and **fails closed** when `max_entries` is reached with no reclaimable slots: it does not insert the new revocation and does not drop active revocations (use `RedisJWTDenylistStore` or raise the cap for high revoke volume). Callers are not misled into thinking logout succeeded: `JWTStrategy.destroy_token` raises `TokenError`, and `AuthenticationBackend.logout` maps that to HTTP **503** with `TOKEN_PROCESSING_FAILED` for API routes using the bundled exception handler.
- **Session fingerprint** — optional claim on JWT tying tokens to current password/email state.
- **Cookie auth** — secure defaults (`HttpOnly`, `Secure`, `SameSite`); CSRF for unsafe methods when wired (see [Guides — Security](guides/security.md)).
- **TOTP** — pending enrollment secrets stay server-side in `totp_enrollment_store`; replay protection is enforced when `totp_used_tokens_store` is configured; production fails fast without required stores; persisted TOTP secrets require encrypted-at-rest storage through `BaseUserManager.totp_secret_storage_posture` / `totp_secret_key`.
- **OAuth** — state in `HttpOnly` cookie; strict validation; optional encryption at rest for provider tokens (`oauth_token_encryption_key`); OAuth token persistence accepts only current-module `OAuthTokenEncryption` policies; write-time plaintext snapshots are restored after successful writes and cleared on rollback; guarded associate-by-email rules (`oauth_trust_provider_email_verified` on plugin-owned routes, `trust_provider_email_verified` on manual controllers, and `oauth_associate_by_email`).
- **Opaque DB tokens** — keyed digest at rest; plugin-managed DB-token wiring uses `DatabaseTokenAuthConfig` plus `LitestarAuthConfig(..., database_token_auth=...)`.
- **Rate limiting** — optional per-endpoint limits; in-memory backend is single-process only and fails closed for new keys when its capacity cap is reached.
- **Route-level role checks** — `is_superuser`, `has_any_role(...)`, and `has_all_roles(...)` reuse the same normalized flat-role semantics as persistence and manager writes, and they fail closed if the authenticated user does not expose the documented role-capable contract.

## Plugin-managed security posture paths

The plugin keeps these security-sensitive paths explicit and ties them to the same runtime posture contracts used by startup warnings and fail-closed validation where applicable:

--8<-- "docs/snippets/plugin_security_tradeoffs.md"

## Direct/manual posture contracts

When you assemble `JWTStrategy` or `BaseUserManager` yourself, inspect the runtime posture objects directly instead of inferring security behavior from constructor kwargs later:

- `JWTStrategy(secret=..., denylist_store=RedisJWTDenylistStore(...))` reports the durable `shared_store` posture.
- `JWTStrategy(secret=..., allow_inmemory_denylist=True)` reports the explicit process-local `in_memory` posture. `revocation_is_durable` stays `False` and logout / revoke remains single-process.
- Plugin-managed JWT revocation notices consume the concrete current-module `JWTRevocationPosture`
  returned by `JWTStrategy.revocation_posture`; posture-shaped wrappers or objects retained from
  earlier module identities are ignored.
- `BaseUserManager.totp_secret_storage_posture` reports the `fernet_encrypted` persisted-secret contract. Supplying `totp_secret_key` on `UserManagerSecurity(...)` lets direct/custom integrations store and read encrypted TOTP secrets.
- With `totp_secret_key` omitted or explicitly `None`, `None` still represents disabled 2FA, but non-null TOTP secret writes and unprefixed legacy plaintext reads fail closed. Encrypt, rotate, or clear existing plaintext TOTP secret rows before upgrading.

Additional explicit opt-ins to weaker behavior:

| Surface | Risk |
| ---- | ---- |
| `totp_enable_requires_password=False` | Weakens step-up for TOTP enrollment. |
| `csrf_secret` unset with plugin-owned cookie auth | Plugin validation fails closed unless cookie auth explicitly opts out. |
| `csrf_protection_managed_externally=True` on manual cookie auth | You are asserting that app-owned CSRF middleware or an equivalent framework-level control protects the manual route table. |
| `CookieTransport(allow_insecure_cookie_auth=True)` | Allows cookie auth without CSRF for controlled non-browser scenarios only. |

## Limitations (by design)

- No built-in **email** sending — you must implement hooks.
- No **RBAC** or **WebAuthn** in core — the built-in role guards are flat membership checks only; extend in your application for permission matrices or object-level policy.
- **Durable JWT revocation** requires an explicit shared store — `JWTStrategy(secret=...)` without `denylist_store` or `allow_inmemory_denylist=True` fails closed at construction time. Use Redis (or equivalent) denylist for multi-worker production if you rely on revoke; reserve `allow_inmemory_denylist=True` for single-process development or tests.

## Further reading

- [Guides — Security](guides/security.md) — CSRF, cookies, headers.
- [Deployment](deployment.md) — production checklist.
- [Configuration](configuration.md) — all security-related config fields.
