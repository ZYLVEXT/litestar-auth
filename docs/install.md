# Installation

All distributions require Python 3.12–3.14.

```bash
uv add litestar-auth
uv add authweave-core
uv add authweave-workload
```

`litestar-auth` includes its required Litestar and SQLAlchemy integration. Add its `redis`, `oauth`,
or `totp` extras only for the corresponding supported human flow.

`authweave-workload` has a dependency-light base import. Add:

- `authweave-workload[sqlalchemy]` for persistence;
- `authweave-workload[mtls]` for public X.509 validation;
- `authweave-workload[jwt]` for external asymmetric access-token and bounded JWKS validation;
- `authweave-workload[litestar]` for Extension SDK v2 integration;
- `authweave-workload[all]` for the complete reference feature set.

Install all three at the same `7.x` minor line. Do not combine a v7 extension with a v6 host.
Optional-feature imports fail with an actionable extra name rather than silently degrading.
