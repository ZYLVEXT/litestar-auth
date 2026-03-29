# Security model

This page summarizes protections and **conscious trade-offs** shipped by the library.

## Implemented controls

- **Passwords** — hashing via `pwdlib`; hash upgrade on login when parameters change.
- **Reset tokens** — signed JWT-style reset tokens with password fingerprint so tokens die after password change.
- **JWT** — enforced `exp` / `iat` / `aud`; optional `iss`; `jti` denylist support (`InMemoryJWTDenylistStore`, `RedisJWTDenylistStore`).
- **Session fingerprint** — optional claim on JWT tying tokens to current password/email state.
- **Cookie auth** — secure defaults (`HttpOnly`, `Secure`, `SameSite`); CSRF for unsafe methods when wired (see [Guides — Security](guides/security.md)).
- **TOTP** — replay protection when a `totp_used_tokens_store` is configured; fail-fast in production without a store when replay protection is required.
- **OAuth** — state in `HttpOnly` cookie; strict validation; optional encryption at rest for provider tokens (`oauth_token_encryption_key`); guarded associate-by-email rules (`trust_provider_email_verified`, `oauth_associate_by_email`).
- **Opaque DB tokens** — keyed digest at rest; **`allow_legacy_plaintext_tokens`** is migration-only and unsafe for production.
- **Rate limiting** — optional per-endpoint limits; in-memory backend is single-process only.

## Configuration flags (downgrade / compatibility)

Treat these as **explicit opt-in** to weaker behavior:

| Flag | Risk |
| ---- | ---- |
| `allow_nondurable_jwt_revocation=True` | In-memory JWT denylist does not survive restarts or scale horizontally. |
| `allow_legacy_plaintext_tokens=True` | Accepts legacy plaintext opaque tokens in DB. |
| `totp_enable_requires_password=False` | Weakens step-up for TOTP enrollment. |
| `csrf_secret` unset with cookie auth | CSRF middleware may not protect unsafe methods — see validation warnings at startup. |

## Limitations (by design)

- No built-in **email** sending — you must implement hooks.
- No **RBAC** or **WebAuthn** in core — extend in your application.
- **Durable JWT revocation** is not automatic for every deployment mode — use Redis (or equivalent) denylist for multi-worker production if you rely on revoke.

## Further reading

- [Guides — Security](guides/security.md) — CSRF, cookies, headers.
- [Deployment](deployment.md) — production checklist.
- [Configuration](configuration.md) — all security-related config fields.
