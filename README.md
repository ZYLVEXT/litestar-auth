# litestar-auth 7

Version 7 is a coordinated authentication stack for Python 3.12–3.14:

- `authweave-core`: dependency-light principal, evidence, decision, routing, and coordinator contracts.
- `litestar-auth`: modern human authentication for Litestar through one typed, cookie-based
  server-side session pipeline.
- `authweave-workload`: framework-neutral X.509 workload lifecycle, direct mTLS, and external
  certificate-bound JWT resource-server profiles.

The human product supports registration, verification, password reset, login/logout, rotating
database or Redis sessions, CSRF-safe cookies, TOTP, OAuth Authorization Code + PKCE, roles,
permissions, organizations, and session/device management. Version 7 deliberately has no bearer
login profile, user-owned shared-secret credentials, proprietary request signing, deprecated
aliases, or compatibility execution paths.

## Minimal human configuration

```python
from uuid import UUID

from litestar import Litestar
from litestar_auth import AuthenticationBackend, LitestarAuth, LitestarAuthConfig
from litestar_auth.authentication.strategy import RedisTokenStrategy
from litestar_auth.authentication.transport import CookieTransport

backend = AuthenticationBackend(
    name="human-session",
    transport=CookieTransport(),
    strategy=RedisTokenStrategy(
        redis=redis_client,
        token_hash_secret=session_digest_secret,
        subject_decoder=UUID,
    ),
)

app = Litestar(
    plugins=[
        LitestarAuth(
            LitestarAuthConfig(
                backends=(backend,),
                session_maker=session_maker,
                user_model=User,
                user_manager_class=UserManager,
                user_db_factory=user_db_factory,
                user_manager_security=user_manager_security,
            ),
        ),
    ],
)
```

Database sessions use `DatabaseTokenStrategy` instead. Both implementations issue opaque access
and refresh tokens, rotate refresh tokens, revoke replayed chains, and expose safe session metadata.

## Workload authentication

Install only the extras used by the application:

```bash
uv add 'authweave-workload[mtls,jwt,sqlalchemy]'
# add [litestar] only for the optional Litestar Extension SDK v2 integration
```

`WorkloadLifecycleService` creates and disables service applications and principals, registers
validator-produced opaque public certificate metadata, performs overlapping rotation, and revokes
credentials. Every mutation requires attributed, correlated same-transaction event recording.
Private keys are rejected at the package boundary and are never stored. `DirectMTLSProvider` consumes trusted
TLS peer evidence; `MTLSBoundJWTProvider` accepts only a configured modern asymmetric JWT profile
whose RFC 8705 thumbprint matches that same peer certificate.

See [the migration guide](docs/migration.md), [security posture](docs/security.md),
[architecture](docs/architecture.md), and the
[Docker reference stack](docker/reference/compose.yml). Run the complete reference verification
with:

```bash
sh docker/reference/verify.sh
```

This repository does not implement an OAuth Authorization Server, generic IAM, business
authorization, DPoP, SPIFFE, opaque-token introspection, or production rollout.
