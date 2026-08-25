# Migration from 7.x to 8

Version 8 keeps the AuthWeave 7 security boundary (opaque human sessions, separate workload
profiles, no unrestricted bearer/API-key human login) and tightens concurrency, invitation, and
documentation contracts. Upgrade every installed AuthWeave distribution to the **same exact**
lockstep version.

## Upgrade invariants

- Keep `authweave-core`, `litestar-auth`, `authweave-workload`, `authweave-otel`,
  `authweave-webhooks`, and `authweave-http-signatures` on one published version.
- Do not mix Extension SDK majors.
- Prefer **8.0.1+** for new production integrations (MFA, lockout, and replay hardening).
- If you are already on 7.x, do not stay below **7.3.4** (request-scoped dependency caching fix).

## Breaking: organization invitations (8.0.0)

Custom organization stores must implement `finalize_invitation_acceptance(...)` before enabling
invitation-acceptance routes. The previous split consume/membership fallback was removed. See
[organizations](how-to/organizations.md).

## Security hardening (8.0.1)

Notable fixes you inherit by upgrading:

- Atomic TOTP pending-JTI claim before OTP/recovery verification
- Step-up TOTP replay store with fail-closed default
- `always_required` step-up for non-TOTP user models
- Atomic account-lockout admission and optional rate-limit `reserve_attempts`
- Password material removed from `after_update` hook payloads
- FAPI `nbf` enforcement; HTTP-signature nonce key length-prefixing

Read the full list in `CHANGELOG.md` under `8.0.1`.

## Documentation and import boundaries (8.0.2)

- User-facing docs and the documentation site describe **AuthWeave 8** (no remaining “current
  product is v7” drift).
- Import direction is enforced with import-linter (`uv run lint-imports`, part of `just check`).
  See [architecture](architecture.md).

## Checklist

1. Pin all AuthWeave distributions to the same `8.0.x` release.
2. Implement `finalize_invitation_acceptance` if you use custom organization stores.
3. Confirm shared Redis/DB stores for multi-worker replay, lockout, and sessions.
4. Re-read [credentials and tokens](credentials.md) and [secrets and stores](secrets.md).
5. Run your own negative tests for concurrent login/TOTP, refresh replay, and DI isolation.

Historical **6.x → 7** boundary migration remains in [migration.md](migration.md).
