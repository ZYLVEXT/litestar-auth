# Security model

This page summarizes protections and **conscious trade-offs** shipped by the library.

## Implemented controls

- **Passwords** — hashing via `pwdlib`; hash upgrade on login when parameters change.
- **Reset tokens** — signed JWT-style reset tokens with password fingerprint so tokens die after password change.
- **JWT** — enforced `exp` / `iat` / `aud`; optional `iss`; `jti` denylist support (`InMemoryJWTDenylistStore`, `RedisJWTDenylistStore`) with an explicit `JWTStrategy.revocation_posture` contract. The in-memory denylist prunes expired JTIs on each revoke and **fails closed** when `max_entries` is reached with no reclaimable slots: it does not insert the new revocation and does not drop active revocations (use `RedisJWTDenylistStore` or raise the cap for high revoke volume). Callers are not misled into thinking logout succeeded: `JWTStrategy.destroy_token` raises `TokenError`, and `AuthenticationBackend.logout` maps that to HTTP **503** with `TOKEN_PROCESSING_FAILED` for API routes using the bundled exception handler.
- **Session fingerprint** — optional claim on JWT tying tokens to current password/email state.
- **Cookie auth** — secure defaults (`HttpOnly`, `Secure`, `SameSite`); CSRF for unsafe methods when wired (see [Guides — Security](guides/security.md)).
- **TOTP** — replay protection when a `totp_used_tokens_store` is configured; fail-fast in production without a store when replay protection is required; persisted secrets use the explicit `BaseUserManager.totp_secret_storage_posture` contract.
- **OAuth** — state in `HttpOnly` cookie; strict validation; optional encryption at rest for provider tokens (`oauth_token_encryption_key`); guarded associate-by-email rules (`oauth_trust_provider_email_verified` on plugin-owned routes, `trust_provider_email_verified` on manual controllers, and `oauth_associate_by_email`).
- **Opaque DB tokens** — keyed digest at rest; plugin-managed DB-token wiring uses `DatabaseTokenAuthConfig` plus `LitestarAuthConfig(..., database_token_auth=...)`, and legacy plaintext acceptance is migration-only and unsafe for production.
- **Rate limiting** — optional per-endpoint limits; in-memory backend is single-process only.
- **Route-level role checks** — `has_any_role(...)` and `has_all_roles(...)` reuse the same normalized flat-role semantics as persistence and manager writes, and they fail closed if the authenticated user does not expose the documented role-capable contract.

## Plugin-managed downgrade paths

The plugin keeps these downgrade paths explicit and ties them to the same runtime posture contracts used by startup warnings and production validation:

--8<-- "docs/snippets/plugin_security_tradeoffs.md"

## Direct/manual posture contracts

When you assemble `JWTStrategy` or `BaseUserManager` yourself, inspect the runtime posture objects directly instead of inferring security behavior from constructor kwargs later:

- `JWTStrategy(secret=...)` keeps the compatibility-grade `compatibility_in_memory` revocation posture by default. `revocation_is_durable` stays `False` and logout / revoke remains single-process until you provide a shared denylist store.
- `JWTStrategy(..., denylist_store=RedisJWTDenylistStore(...))` reports the durable `shared_store` posture and clears the compatibility-only warning / validation branch.
- `BaseUserManager(..., security=UserManagerSecurity(...))` with `totp_secret_key` omitted or explicitly `None` keeps the compatibility-grade `compatibility_plaintext` storage posture so existing plaintext TOTP secrets still round-trip for direct/custom integrations.
- Supplying a non-`None` `totp_secret_key` on that `UserManagerSecurity(...)` bundle flips `BaseUserManager.totp_secret_storage_posture` to `fernet_encrypted`, so newly persisted TOTP secrets are encrypted at rest.

Additional explicit opt-ins to weaker behavior:

| Surface | Risk |
| ---- | ---- |
| `allow_legacy_plaintext_tokens=True` | Accepts legacy plaintext opaque tokens in DB for manual `DatabaseTokenStrategy` setups. For the plugin-managed DB-token preset, set `DatabaseTokenAuthConfig.accept_legacy_plaintext_tokens=True` instead. |
| `totp_enable_requires_password=False` | Weakens step-up for TOTP enrollment. |
| `csrf_secret` unset with cookie auth | CSRF middleware may not protect unsafe methods — see validation warnings at startup. |

If you are migrating from a hand-assembled DB bearer backend, move that setup to `LitestarAuthConfig(..., database_token_auth=DatabaseTokenAuthConfig(...))` and keep plaintext compatibility enabled only for the shortest migration window possible.

## Limitations (by design)

- No built-in **email** sending — you must implement hooks.
- No **RBAC** or **WebAuthn** in core — the built-in role guards are flat membership checks only; extend in your application for permission matrices or object-level policy.
- **Durable JWT revocation** is not automatic for every deployment mode — the default `JWTStrategy(secret=...)` posture remains compatibility-grade and process-local. Use Redis (or equivalent) denylist for multi-worker production if you rely on revoke.

## Further reading

- [Guides — Security](guides/security.md) — CSRF, cookies, headers.
- [Deployment](deployment.md) — production checklist.
- [Configuration](configuration.md) — all security-related config fields.
