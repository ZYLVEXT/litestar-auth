# Migration from 6.x to 7.0

Version 7 is a security-boundary release, not an in-place credential-format upgrade. Upgrade the
three coordinated distributions together, rehearse against a copy of production data, and require
an explicit operator decision before cutover. There is no automatic conversion of removed
credentials.

## Upgrade invariants

- Keep `authweave-core`, `litestar-auth`, and `authweave-workload` on the same `7.x` release line.
- Do not run a v7 Litestar extension inside a v6 host or mix Extension SDK major versions.
- Do not accept an old credential and reinterpret it as a v7 session or certificate identity.
- Keep human and machine routes on separate provider profiles.
- Keep old data available for rollback until the approved rollback window closes; do not keep old
  runtime authentication enabled inside the v7 process.

## 1. Inventory before upgrading

Run the removal audit against application source, configuration exports, and database dumps:

```bash
uv run python scripts/audit_v7_removals.py src config exported-data.sql
```

The command is read-only. Resolve every finding manually and retain an operator-approved migration
record.

The audit detects known removed names and records, but it cannot understand dynamic imports,
generated configuration, secret-manager entries, proxy rules, mobile clients, or third-party
integrations. Inventory those separately.

| 6.x construct | 7.0 replacement |
| --- | --- |
| `BearerTransport` + `JWTStrategy` for users | `CookieTransport` + `DatabaseTokenStrategy` or `RedisTokenStrategy` |
| User-owned API key or signed API-key request | Registered workload principal with direct mTLS or an external certificate-bound JWT |
| Ordered `Authenticator` fallback | One `RouteProviderPolicy` profile selected before verification |
| Extension SDK v1 integration | Extension SDK v2 with `requires_api = (2, 0)` |
| Shared-secret machine record | Public `CertificateMetadata` returned by `validate_public_certificate` |

## 2. Prepare the deployment

1. Back up the human-session database and any application-owned credential tables.
2. Generate and review the application migration that incorporates
   [`0001_postgresql.sql`](https://github.com/ZYLVEXT/litestar-auth/blob/main/packages/authweave-workload/authweave_workload/migrations/0001_postgresql.sql).
3. Establish the workload CA, trust-anchor identifiers, revocation distribution, TLS termination
   boundary, and external issuer/JWKS policy before provisioning callers.
4. Create distinct high-entropy secrets and key prefixes for human session digests. Do not reuse
   v6 JWT, API-key, OAuth-cookie, or encryption secrets.
5. Confirm HTTPS, CSRF protection, cookie scope, proxy allowlists, worker-shared storage, and
   rollback ownership in staging.

The workload SQL is a reference schema, not a migration runner. The application owns its Alembic
or equivalent migration and transaction boundary.

## 3. Replace the human backend

Configure exactly one `CookieTransport` with `DatabaseTokenStrategy` or `RedisTokenStrategy`.
Remove custom provider ordering and fallback logic. Existing 6.x login credentials and sessions
must be invalidated; do not reinterpret signed or shared-secret values as v7 session tokens.

Preserved modern human flows are registration, verification, password reset, login/logout,
rotating refresh, TOTP/step-up, OAuth Authorization Code + PKCE, roles, permissions,
organizations, and session/device management. Re-run the full application regression corpus.

Stored passwords outside the Argon2id baseline require a reset or a separately reviewed,
one-time authenticated rehash process. Do not add a runtime legacy-hash fallback.

Before opening traffic:

- use a host-only, `Secure`, `HttpOnly` cookie with the narrowest viable path and SameSite policy;
- enable CSRF protection for every unsafe cookie-authenticated request;
- invalidate existing bearer JWTs, API keys, and refresh sessions at the old authority;
- verify login, refresh rotation, logout, replay revocation, OAuth + PKCE, TOTP/step-up, and
  session-device revocation through the new cookie path.

## 4. Upgrade extensions

Version 7 exposes Extension SDK `2.0`. Update external extensions to import only from
`litestar_auth.extensions`, declare `requires_api = (2, 0)`, and use the v2 validation and
registration contexts.

`WorkloadAuthExtension` contributes providers to the middleware installed by `LitestarAuth`.
Register it through `LitestarAuthConfig.extensions`; do not add a second authentication
middleware. Keep provider names and contributed OpenAPI security scheme names globally unique.

## 5. Migrate non-human callers

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

Move callers one at a time at the routing or infrastructure boundary:

1. Provision and validate a new certificate.
2. Register its public metadata in `pending` state.
3. Activate it and confirm the target route's direct-mTLS or bound-JWT profile.
4. Shift that caller to the v7 route without enabling fallback in the v7 process.
5. Observe authentication, revocation freshness, rate-limit identity, and security events.
6. Revoke the old credential after the caller-specific rollback window.

## 6. Persistence

Apply the bundled
[`0001_postgresql.sql`](https://github.com/ZYLVEXT/litestar-auth/blob/main/packages/authweave-workload/authweave_workload/migrations/0001_postgresql.sql)
in an application-owned migration after review. The reference tables store only public certificate
identity and bounded metadata. The application owns tenant mapping, row-level security, business
authorization, and the same-transaction implementation of `event_recorder`.

Human database-session schema remains owned by `litestar-auth`; Redis sessions use isolated key
prefixes and a distinct high-entropy digest secret.

Do not drop old API-key or token tables during the first v7 deployment. Remove them in a separate,
approved migration only after rollback expires and the inventory confirms that no caller,
operator tool, export, or recovery procedure still depends on them.

## 7. Litestar integration

Install `authweave-workload[litestar]` and register `WorkloadAuthExtension` through Extension SDK v2.
Do not create a second middleware. Route provider policy must select exactly one human or machine
profile. Update guards to test verified principal kind, audience, scope, environment, and
delegation depth. Configure `correlation_id_factory` from trusted application scope/state; inbound
request IDs are not trusted automatically.

The bundled examples show the supported boundaries:

- [`examples/workload_headless.py`](https://github.com/ZYLVEXT/litestar-auth/blob/main/examples/workload_headless.py)
  for framework-neutral
  provisioning and direct mTLS;
- [`examples/workload_litestar.py`](https://github.com/ZYLVEXT/litestar-auth/blob/main/examples/workload_litestar.py)
  for the Litestar extension;
- [`examples/workload_asgi.py`](https://github.com/ZYLVEXT/litestar-auth/blob/main/examples/workload_asgi.py)
  for a minimal neutral ASGI adapter.

## 8. Cutover verification

Before rollout, require:

- Python 3.12, 3.13, and 3.14 install-and-test results;
- clean wheel and sdist installation for every distribution and optional extra;
- the complete human regression and machine negative matrices;
- `sh docker/reference/verify.sh`;
- source/config/data removal-audit results;
- an independent production proxy, trust-anchor, issuer, and migration review.

Record the exact package hashes, schema revision, trust-anchor set, issuer/JWKS configuration,
proxy configuration, and removal-audit output used for approval.

## 9. Rollback

Rollback means routing affected traffic back to the separately deployable v6 application while
the old schema and credentials are still retained. Do not make the v7 process accept v6
credentials as a shortcut.

- Newly issued v7 human sessions are not rollback credentials; require users to authenticate
  again on v6.
- A workload caller moved to a v7 certificate profile must return to its retained v6 credential
  only if the approved rollback plan allows it.
- The additive workload tables may remain during rollback. Do not delete public certificate or
  security-event records needed for incident review.
- Never restore a revoked or exposed private key. Issue a new credential instead.
- After rollback, reconcile security events and explicitly revoke credentials created only for the
  failed rollout before attempting another cutover.

Package publication and production rollout require separate approval.
