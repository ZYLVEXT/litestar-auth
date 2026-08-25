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

`litestar-auth` 8 is the human-authentication layer in the six-distribution AuthWeave workspace for
Python 3.12–3.14. Browser sessions and machine credentials stay on separate trust paths while
sharing typed, fail-closed AuthWeave decisions.

```bash
uv add litestar-auth
```

## Six packages, one version

- **`litestar-auth`** — Litestar registration, login, OAuth + PKCE, TOTP, roles,
  organizations, and opaque database or Redis sessions
- **`authweave-core`** — Typed principals, evidence, decisions, route policies, and fail-closed
  provider coordination
- **`authweave-workload`** — X.509 lifecycle plus mTLS, DPoP, SPIFFE, bound JWT, and
  introspection profiles
- **`authweave-otel`** — API-only security spans and metrics without an SDK or exporter
- **`authweave-webhooks`** — Ed25519 Standard Webhooks integrity, replay control, and bounded
  delivery
- **`authweave-http-signatures`** — RFC 9530/RFC 9421 payment-message integrity after machine
  authentication

Install only the layer you need. All six distributions use one exact lockstep version; dependency
direction stays one-way (`authweave-core` at the root). Details:
[architecture](https://zylvext.github.io/litestar-auth/architecture/).

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

Opaque sessions are not challenge JWTs and not workload credentials. Read
[credentials and tokens](https://zylvext.github.io/litestar-auth/credentials/) and the
[quickstart](https://zylvext.github.io/litestar-auth/quickstart/).

## Keep machine identity on its own path

```bash
uv add 'authweave-workload[mtls,jwt,sqlalchemy]'
# Add [litestar] only for the Extension SDK v2 integration.
```

Bound tokens or proofs must match the verified certificate or DPoP key. Ambiguous credential
ownership fails closed. See the [security posture](https://zylvext.github.io/litestar-auth/security/).

## Security boundary

> [!IMPORTANT]
> Authentication establishes a verified principal and constraints. Your application still owns
> tenant mapping, row-level security, resource ownership, and business authorization.

AuthWeave intentionally does **not** provide unconstrained bearer login, user-owned API keys,
shared-secret machine credentials, an OAuth Authorization Server or STS, or generic IAM.

## Release evidence

CI exercises Python 3.12–3.14 on Linux, macOS, and Windows with a 100% branch-coverage gate per
distribution, CodeQL, dependency review, pinned actions, CycloneDX 1.7 SBOMs, and reference stacks.
That evidence is library readiness, not certification of a deployment.

## Documentation

- [Quickstart](https://zylvext.github.io/litestar-auth/quickstart/)
- [Credentials and tokens](https://zylvext.github.io/litestar-auth/credentials/)
- [Architecture](https://zylvext.github.io/litestar-auth/architecture/)
- [Security posture](https://zylvext.github.io/litestar-auth/security/)
- [Migrate 7.x → 8](https://zylvext.github.io/litestar-auth/migration-v8/)
- [Changelog](https://github.com/ZYLVEXT/litestar-auth/blob/main/CHANGELOG.md)
- [Vulnerability reporting](https://github.com/ZYLVEXT/litestar-auth/blob/main/SECURITY.md)

## License

[MIT](https://github.com/ZYLVEXT/litestar-auth/blob/main/LICENSE)
