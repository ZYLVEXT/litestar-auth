# Authentication stack version 7

Three coordinated distributions separate verified identity contracts from human and workload
implementations:

- **authweave-core** routes one owned credential presentation to one provider and returns typed principal,
  evidence, and decision contracts.
- **litestar-auth** supplies Litestar's supported modern human flows through one opaque,
  server-side cookie-session pipeline.
- **authweave-workload** supplies X.509 service application, principal, and credential lifecycle plus
  direct mTLS and external certificate-bound access-token profiles.

Start with the [quickstart](quickstart.md), review the [architecture](architecture.md) and
[security posture](security.md), and use the [6.x → 7.0 migration guide](migration.md) before
upgrading an existing deployment.

| Need | Distribution |
| --- | --- |
| Human registration, login, OAuth + PKCE, TOTP, roles, organizations, and opaque sessions in Litestar | `litestar-auth` |
| Framework-neutral authentication contracts and coordination | `authweave-core` |
| X.509 workload lifecycle, direct mTLS, or externally issued certificate-bound JWTs | `authweave-workload` |

All distributions require Python 3.12–3.14 and use coordinated `7.x` versions.
