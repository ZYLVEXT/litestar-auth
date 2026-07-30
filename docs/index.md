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
[security posture](security.md), and use the [6.x migration guide](migration.md) before upgrading
an existing deployment.
