# Migration from 6.x to 7.0

Version 7 is a security-boundary release. Upgrade all three coordinated distributions together and
test in a copy of production data. There is no automatic conversion of removed credentials.

## 1. Inventory before upgrading

Run the removal audit against application source, configuration exports, and database dumps:

```bash
uv run python scripts/audit_v7_removals.py src config exported-data.sql
```

The command is read-only. Resolve every finding manually and retain an operator-approved migration
record.

## 2. Replace the human backend

Configure exactly one `CookieTransport` with `DatabaseTokenStrategy` or `RedisTokenStrategy`.
Remove custom provider ordering and fallback logic. Existing 6.x login credentials and sessions
must be invalidated; do not reinterpret signed or shared-secret values as v7 session tokens.

Preserved modern human flows are registration, verification, password reset, login/logout,
rotating refresh, TOTP/step-up, OAuth Authorization Code + PKCE, roles, permissions,
organizations, and session/device management. Re-run the full application regression corpus.

Stored passwords outside the Argon2id baseline require a reset or a separately reviewed,
one-time authenticated rehash process. Do not add a runtime legacy-hash fallback.

## 3. Migrate non-human callers

Create a service application and a service, workload, or agent principal with
`WorkloadLifecycleService`. Issue a short-lived client certificate from an application-approved
CA and validate it with `validate_public_certificate`. `CertificateMetadata` is an opaque result
type and cannot be assembled from caller-supplied fields.

Construct each lifecycle service with the verified operator `actor`, an application-generated
`correlation_id`, and an `event_recorder`. The recorder must insert the event into the same
application-owned database transaction as the workload mutation (an audit table or transactional
outbox is appropriate); do not make a remote broker call from it. Recorder failure is terminal, so
the outer unit of work must roll back. A lifecycle mutation is not complete until both writes
commit.

Choose one profile per route:

- direct mTLS through trusted `TlsPeerEvidence`; or
- an external modern asymmetric access token bound to the same client certificate.

Do not translate an old shared secret into certificate metadata. Revoke and delete old credential
rows only after every caller has moved and rollback policy has expired. That data change is
operator-owned and intentionally outside this package.

## 4. Persistence

Apply `authweave_workload/migrations/0001_postgresql.sql` in an application-owned migration after review.
The reference tables store only public certificate identity and bounded metadata. The application
owns tenant mapping, row-level security, business authorization, and the same-transaction
implementation of `event_recorder`.

Human database-session schema remains owned by `litestar-auth`; Redis sessions use isolated key
prefixes and a distinct high-entropy digest secret.

## 5. Litestar integration

Install `authweave-workload[litestar]` and register `WorkloadAuthExtension` through Extension SDK v2.
Do not create a second middleware. Route provider policy must select exactly one human or machine
profile. Update guards to test verified principal kind, audience, scope, environment, and
delegation depth. Configure `correlation_id_factory` from trusted application scope/state; inbound
request IDs are not trusted automatically.

## 6. Verification

Before rollout, require:

- Python 3.12, 3.13, and 3.14 install-and-test results;
- clean wheel and sdist installation for every distribution and optional extra;
- the complete human regression and machine negative matrices;
- `sh docker/reference/verify.sh`;
- source/config/data removal-audit results;
- an independent production proxy, trust-anchor, issuer, and migration review.

Package publication and production rollout require separate approval.
