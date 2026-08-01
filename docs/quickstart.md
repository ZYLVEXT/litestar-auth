# Quickstart

`litestar-auth` 7 has one human authentication shape: a secure cookie carrying an opaque
server-side session token. The database preset is the shortest supported starting point.

```bash
uv add litestar-auth aiosqlite
```

Set four independent, high-entropy secrets:

```bash
export LITESTAR_AUTH_SESSION_HASH_SECRET='replace-with-a-random-session-digest-secret'
export LITESTAR_AUTH_CSRF_SECRET='replace-with-a-random-csrf-secret'
export LITESTAR_AUTH_VERIFY_TOKEN_SECRET='replace-with-a-random-verification-secret'
export LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET='replace-with-a-random-reset-secret'
```

Configure the database-backed cookie session preset:

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

`session_maker`, `User`, `UserManager`, `user_db_factory`, and `user_manager_security` are the
application's normal database and account-lifecycle objects.

This minimal configuration warns that the default rate-limit and account-token replay state is
process-local. Configure worker-shared backends for multi-worker production; do not silence those
warnings outside controlled tests or local development.

Create the user and access-token tables through the application's normal migration system before
serving requests. If refresh is explicitly enabled, also create the refresh-token and
consumed-refresh-digest tables. The runnable
[`demo_db_token_refresh`](https://github.com/ZYLVEXT/litestar-auth/tree/main/examples/demo_db_token_refresh)
shows model import, SQLite table bootstrap, registration, login, refresh, and cleanup.

Use HTTPS in production. Keep the default `Secure`, `HttpOnly`, and narrow SameSite cookie
attributes, and protect every unsafe cookie-authenticated request with CSRF validation. Database
and Redis deployments must use worker-shared, durable services.

For Redis sessions, install `litestar-auth[redis]` and configure exactly one
`CookieTransport` + `RedisTokenStrategy` backend. Do not combine database and Redis session
providers or add credential fallback.

Workload identities are not users. Install `authweave-workload`, configure direct mTLS or a
trusted external certificate-bound JWT issuer, and optionally contribute that provider through
`WorkloadAuthExtension`. A route policy selects exactly one human or machine provider profile.
DPoP, SPIFFE, introspection, and token-exchange integrations are optional advanced profiles; use
the [architecture](architecture.md), [security posture](security.md), and linked merchant runbooks
before enabling them.
