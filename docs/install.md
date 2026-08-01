# Installation

All distributions require Python 3.12–3.14.

```bash
uv add litestar-auth
uv add authweave-core
uv add authweave-workload
uv add authweave-otel
uv add authweave-webhooks
uv add authweave-http-signatures
```

`litestar-auth` includes its required Litestar and SQLAlchemy integration. Its public extras are
`redis`, `oauth`, `totp`, `jwt`, and the aggregate `all`; install only the features used by the
application.

`authweave-workload` has a dependency-light base import. Add:

- `authweave-workload[sqlalchemy]` for persistence;
- `authweave-workload[mtls]` for public X.509 validation;
- `authweave-workload[jwt]` for external asymmetric access-token and bounded JWKS validation;
- `authweave-workload[dpop]` for DPoP-bound JWT Resource Server verification;
- `authweave-workload[spiffe]` for SPIFFE X.509-SVID validation and snapshots;
- `authweave-workload[introspection]` for sender-constrained opaque-token introspection;
- `authweave-workload[token-exchange]` for strict outbound RFC 8693 token exchange;
- `authweave-workload[redis]` for shared replay/nonce stores;
- `authweave-workload[litestar]` for Extension SDK v2 integration;
- `authweave-workload[all]` for the complete reference feature set.

`authweave-webhooks` exposes `redis`, `httpx`, and `litestar` extras.
`authweave-http-signatures` exposes `redis` and `litestar` extras. `authweave-otel` deliberately
depends on the OpenTelemetry API only; applications install and configure their chosen SDK/exporter.

The six distributions release in lockstep. Keep integrations on the same `7.x` major line and do
not combine a v7 extension with a v6 host. Optional-feature imports fail with an actionable extra
name rather than silently degrading.
