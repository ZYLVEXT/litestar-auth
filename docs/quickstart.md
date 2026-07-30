# Quickstart

`litestar-auth` 7 has one human authentication shape: a secure cookie carrying an opaque
server-side session token. Configure exactly one database or Redis session strategy.

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

config = LitestarAuthConfig(
    backends=(backend,),
    session_maker=session_maker,
    user_model=User,
    user_manager_class=UserManager,
    user_db_factory=user_db_factory,
    user_manager_security=user_manager_security,
    enable_refresh=True,
)

app = Litestar(plugins=[LitestarAuth(config)])
```

Use HTTPS. Keep the default `Secure`, `HttpOnly`, and safe SameSite cookie attributes. Litestar's
CSRF middleware must protect unsafe cookie-authenticated requests. Production Redis and database
deployments must use shared, durable services.

For SQL-backed sessions, substitute `DatabaseTokenStrategy` and bind it through the normal plugin
session factory. See the runnable `examples/demo_db_token_refresh` application.

Workload identities are not users. Install `authweave-workload`, configure direct mTLS or a trusted
external certificate-bound JWT issuer, and optionally contribute that provider through
`WorkloadAuthExtension`. A route policy selects exactly one human or machine provider profile.
