<p align="center">
  <img src="https://raw.githubusercontent.com/ZYLVEXT/litestar-auth/main/assets/readme/hero.svg" width="100%" alt="litestar-auth 7 separates opaque human sessions from sender-constrained workload identity on a shared AuthWeave core">
</p>

<p align="center">
  <strong>One Python authentication stack. Separate trust paths for people and machines.</strong>
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
Python 3.12–3.14. Browser sessions, workload credentials, framework-neutral coordination,
observability, webhooks, and payment-message integrity remain explicit package boundaries instead
of one credential parser.

## Choose the layer you need

| Package | Use it for | Install |
| --- | --- | --- |
| [`litestar-auth`](https://pypi.org/project/litestar-auth/) | Registration, login, OAuth + PKCE, TOTP, roles, organizations, and opaque database or Redis sessions in Litestar | `uv add litestar-auth` |
| `authweave-core` | Typed principals, evidence, decisions, route policies, and fail-closed provider coordination | `uv add authweave-core` |
| `authweave-workload` | X.509 workload lifecycle plus mTLS-, DPoP-, SPIFFE-, JWT-, and introspection-based Resource Server profiles | `uv add 'authweave-workload[all]'` |
| `authweave-otel` | API-only security spans and metrics without installing an SDK or exporter | `uv add authweave-otel` |
| `authweave-webhooks` | Ed25519 Standard Webhooks signing, verification, replay control, and bounded delivery | `uv add 'authweave-webhooks[httpx]'` |
| `authweave-http-signatures` | RFC 9530/RFC 9421 payment-message integrity after machine authentication | `uv add authweave-http-signatures` |

All six distributions use one exact lockstep version. The dependency direction stays one-way:

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
from uuid import UUID

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

Authentication establishes a verified principal and constraints. Your application still owns
tenant mapping, row-level security, resource ownership, and business authorization.

Version 7 intentionally does **not** provide unconstrained bearer login, user-owned API keys,
shared-secret machine or request-signing credentials, an OAuth Authorization Server or STS,
generic IAM, or production rollout automation. Token exchange is a strict client for an external
STS; it does not operate one.

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
