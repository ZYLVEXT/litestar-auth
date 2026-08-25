# Quickstart

`litestar-auth` 8 has one human authentication shape: a secure cookie carrying an opaque
server-side session token. The database preset is the shortest supported starting point.

Before you continue, skim [credentials and tokens](credentials.md) so opaque sessions are not
confused with challenge JWTs or workload credentials.

```bash
uv add litestar-auth aiosqlite
```

Set independent, high-entropy secrets (see [secrets and stores](secrets.md)):

```bash
export LITESTAR_AUTH_SESSION_HASH_SECRET='replace-with-a-random-session-digest-secret'
export LITESTAR_AUTH_CSRF_SECRET='replace-with-a-random-csrf-secret'
export LITESTAR_AUTH_VERIFY_TOKEN_SECRET='replace-with-a-random-verification-secret'
export LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET='replace-with-a-random-reset-secret'
```

Configure the database-backed cookie session preset:

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

`session_maker`, `User`, `UserManager`, `user_db_factory`, and `user_manager_security` are the
application's normal database and account-lifecycle objects.

Create the user and access-token tables through the application's normal migration system before
serving requests. The runnable
[`demo_db_token_refresh`](https://github.com/ZYLVEXT/litestar-auth/tree/main/examples/demo_db_token_refresh)
shows model import, SQLite table bootstrap, registration, login, refresh, and cleanup.

This minimal configuration warns that the default rate-limit and account-token replay state is
process-local. Configure worker-shared backends for multi-worker production; see
[multi-worker stores](how-to/multi-worker-stores.md).

Use HTTPS in production. Keep the default `Secure`, `HttpOnly`, and narrow SameSite cookie
attributes, and protect every unsafe cookie-authenticated request with CSRF validation.

## Next steps

- Borrow an existing request session: [Borrowed request session](how-to/borrowed-session.md)
- Redis sessions and refresh rotation: [Redis sessions](how-to/redis-sessions.md)
- OAuth, TOTP, organizations: Human how-to in the sidebar
- Workload identity: [architecture](architecture.md) and Workload how-to
