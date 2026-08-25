# Secrets and stores

Production AuthWeave deployments need distinct secrets and, for multi-worker processes, shared
durable stores. Process-local defaults are for single-worker development only.

## Secret roles

Keep one high-entropy secret per trust domain. Do not reuse the session digest secret for CSRF,
challenge JWTs, OAuth cookies, or TOTP encryption.

| Setting | Protects |
| --- | --- |
| `token_hash_secret` / session digest | Opaque session lookup digests |
| `csrf_secret` | CSRF tokens |
| `verification_token_secret` | Email-verification JWT (`litestar-auth:verify`) |
| `reset_password_token_secret` | Password-reset JWT and password fingerprints |
| `organization_invitation_token_secret` | Invitation JWT and lookup HMAC |
| `totp_pending_secret` | Pending-login and enrollment JWTs |
| `totp_secret_key` / `totp_secret_keyring` | TOTP secrets at rest (Fernet) |
| `totp_recovery_code_lookup_secret` | Recovery-code lookup HMAC |
| `oauth_flow_cookie_secret` | OAuth state and PKCE cookie encryption |
| OAuth provider token encryption key | Stored provider tokens at rest |
| `login_identifier_telemetry_secret` | Lockout keys and failed-login digests |

`validate_secret_distinctness` rejects overlapping secret material unless `unsafe_testing=True`.

## Encryption at rest

Production TOTP enrollment and OAuth provider-token persistence require a configured Fernet key or
keyring. Without a key, those paths fail closed.

`FernetKeyring(nullable=True)` may store plaintext when no keys are configured. That mode exists
for explicit `unsafe_testing` and low-level tests. Do not enable nullable/plaintext storage for
reusable secrets in production.

## Shared stores (multi-worker)

When more than one worker serves authentication traffic, these stores must be shared (for example
Redis) or the corresponding guarantee is per-process only:

| Store | Guarantee |
| --- | --- |
| Session store (DB or Redis) | Session lookup and revocation |
| Refresh / consumed-refresh digests | Refresh rotation and replay revocation |
| Challenge JWT replay / denylist | Consume-once verification and reset tokens |
| TOTP pending JTI and used-code stores | MFA single-attempt and step-up replay |
| Account lockout | Brute-force threshold across workers |
| Rate-limit backends | Admission limits across workers |
| Workload / webhook / HTTP-signature nonces | Replay protection for machine and message paths |

In-memory implementations must be labelled test-only or local development. Do not silence
worker-shared warnings outside controlled tests.

## `unsafe_testing`

`unsafe_testing=True` relaxes secret distinctness and some replay requirements for fixtures. It is
never a production posture. Prefer dedicated test secrets and shared fakes such as `fakeredis`
instead of disabling protections permanently.

## Related

- [Credentials and tokens](credentials.md)
- [Multi-worker stores](how-to/multi-worker-stores.md)
- [Deployment](deployment.md)
- [Security posture](security.md)
