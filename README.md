<p align="center">
  <img src="https://raw.githubusercontent.com/ZYLVEXT/litestar-auth/main/assets/readme/hero.svg" width="100%" alt="litestar-auth keeps opaque human sessions and sender-constrained workload identity on separate fail-closed trust paths">
</p>

<p align="center">
  <a href="https://github.com/ZYLVEXT/litestar-auth/actions/workflows/1_test.yml">
    <img src="https://github.com/ZYLVEXT/litestar-auth/actions/workflows/1_test.yml/badge.svg?branch=main" alt="Tests">
  </a>
  <a href="https://app.codecov.io/gh/ZYLVEXT/litestar-auth">
    <img src="https://codecov.io/gh/ZYLVEXT/litestar-auth/branch/main/graph/badge.svg" alt="Codecov coverage">
  </a>
  <a href="https://pypi.org/project/litestar-auth/">
    <img src="https://img.shields.io/pypi/v/litestar-auth.svg?label=PyPI%20stable" alt="Latest stable release on PyPI">
  </a>
  <a href="https://pypi.org/project/litestar-auth/">
    <img src="https://img.shields.io/pypi/pyversions/litestar-auth.svg" alt="Supported Python versions">
  </a>
  <a href="https://github.com/ZYLVEXT/litestar-auth/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/ZYLVEXT/litestar-auth.svg" alt="MIT license">
  </a>
</p>

`litestar-auth` 7 is the human-authentication layer in the six-distribution AuthWeave workspace for
Python 3.12–3.14. Browser sessions and machine credentials stay on separate trust paths while
sharing typed, fail-closed AuthWeave decisions.

```bash
uv add litestar-auth
```

## Six packages, one version

- **`litestar-auth`** — Litestar registration, login, OAuth + PKCE, TOTP, roles,
  organizations, and opaque database or Redis sessions. `uv add litestar-auth`
- **`authweave-core`** — Typed principals, evidence, decisions, route policies, and fail-closed
  provider coordination. `uv add authweave-core`
- **`authweave-workload`** — X.509 lifecycle plus mTLS, DPoP, SPIFFE, bound JWT, and
  introspection profiles. `uv add 'authweave-workload[all]'`
- **`authweave-otel`** — API-only security spans and metrics without an SDK or exporter.
  `uv add authweave-otel`
- **`authweave-webhooks`** — Ed25519 Standard Webhooks integrity, replay control, and bounded
  delivery. `uv add 'authweave-webhooks[redis,httpx]'`
- **`authweave-http-signatures`** — RFC 9530/RFC 9421 payment-message integrity after machine
  authentication. `uv add authweave-http-signatures`

Install only the layer you need; optional integrations stay lazy. All six distributions use one
exact lockstep version, and the dependency direction stays one-way:

```text
authweave-core
├── litestar-auth
├── authweave-workload
│   └── authweave-workload[litestar] → litestar-auth Extension SDK v2
├── authweave-otel
├── authweave-webhooks
└── authweave-http-signatures
```

## Start with a secure human session

```bash
uv add litestar-auth aiosqlite
```

```python
from litestar import Litestar
from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig

config = LitestarAuthConfig(
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret=session_digest_secret,
    ),
    csrf_secret=csrf_secret,
    session_maker=session_maker,
    user_model=User,
    user_manager_class=UserManager,
    user_db_factory=user_db_factory,
    user_manager_security=user_manager_security,
)

app = Litestar(plugins=[LitestarAuth(config)])
```

The [quickstart](https://zylvext.github.io/litestar-auth/quickstart/) covers schema requirements and links the runnable
registration/login flow. Use `RedisTokenStrategy` with `litestar-auth[redis]` when sessions belong
in Redis. Both implementations issue opaque server-side access tokens. With
`LitestarAuthConfig.enable_refresh=True`, they also rotate refresh tokens, revoke replayed chains,
and expose safe session metadata.

## Keep machine identity on its own path

```bash
uv add 'authweave-workload[mtls,jwt,sqlalchemy]'
# Add [litestar] only for the Extension SDK v2 integration.
```

`WorkloadLifecycleService` manages service applications, principals, public certificate metadata,
overlapping rotation, revocation, and same-transaction security events. Private keys are rejected
at the package boundary and are never stored.

At request time:

- `DirectMTLSProvider` consumes trusted TLS peer evidence.
- `MTLSBoundJWTProvider` verifies an asymmetric access token from a configured external issuer.
- DPoP, SPIFFE, and sender-constrained introspection profiles remain behind explicit extras and
  route policy.
- Bound tokens or proofs must match the same verified certificate or DPoP key.
- Ambiguous credential ownership and provider failures stop authentication; they never fall
  through to another provider.

`authweave-workload` also provides strict outbound RFC 8693 token exchange and typed payment
authorization details. `authweave-webhooks` and `authweave-http-signatures` verify message
integrity after authentication; `authweave-otel` observes outcomes without changing them.

The repository includes an Envoy-based reference stack with negative-path verification:

```bash
sh docker/reference/verify.sh
```

## Security boundary

> [!IMPORTANT]
> Authentication establishes a verified principal and constraints. Your application still owns
> tenant mapping, row-level security, resource ownership, and business authorization.

Version 7 intentionally does **not** provide unconstrained bearer login, user-owned API keys,
shared-secret machine or request-signing credentials, an OAuth Authorization Server or STS,
generic IAM, or production rollout automation. Token exchange is a strict client for an external
STS; it does not operate one.

## Release evidence

CI exercises Python 3.12–3.14 on Linux, macOS, and Windows. Every distribution has an independent
100% branch-coverage gate, and the repository runs CodeQL, dependency review, pinned-action checks,
reproducible builds, per-distribution CycloneDX 1.7 SBOMs and build-provenance attestations, isolated
wheel imports, and live PostgreSQL/Redis/proxy reference stacks.

That evidence establishes library readiness, not certification of a particular deployment. The
[readiness roadmap](https://github.com/ZYLVEXT/litestar-auth/blob/main/docs/roadmap.md) lists the independent
conformance, security-review, KMS, capacity, and operational gates required for production profiles.

## Documentation

- [Quickstart](https://zylvext.github.io/litestar-auth/quickstart/)
- [Installation and extras](https://zylvext.github.io/litestar-auth/install/)
- [Architecture contract](https://zylvext.github.io/litestar-auth/architecture/)
- [Security posture](https://zylvext.github.io/litestar-auth/security/)
- [Vulnerability reporting](https://github.com/ZYLVEXT/litestar-auth/blob/main/SECURITY.md)
- [Version 7 migration](https://zylvext.github.io/litestar-auth/migration/)
- [Changelog](https://github.com/ZYLVEXT/litestar-auth/blob/main/CHANGELOG.md)
- [Deployment reference](https://zylvext.github.io/litestar-auth/deployment/)
- [Contributing](https://zylvext.github.io/litestar-auth/contributing/)

## License

[MIT](https://github.com/ZYLVEXT/litestar-auth/blob/main/LICENSE)
