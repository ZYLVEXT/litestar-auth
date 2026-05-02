# Quickstart

This walkthrough gives you one working flow on local SQLite: register a user, verify the email, log in with Bearer + JWT, and call a protected route.

## 1. Install

```bash
uv add litestar-auth aiosqlite
```

Add extras only when you need them later: `litestar-auth[redis]` for shared Redis-backed features, `litestar-auth[oauth]` for OAuth, and `litestar-auth[totp]` for built-in TOTP flows.

## 2. Create the SQLite tables

Save this as `create_tables.py`:

```python
import asyncio

from sqlalchemy.ext.asyncio import create_async_engine

from litestar_auth.models import User

DATABASE_URL = "sqlite+aiosqlite:///./quickstart.db"


async def main() -> None:
    engine = create_async_engine(DATABASE_URL, echo=False)
    async with engine.begin() as connection:
        await connection.run_sync(User.metadata.create_all)
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
```

## 3. Save the application as `app.py`

This local example keeps logout revocation state in-process with `allow_inmemory_denylist=True` so it works without Redis. Use a shared `denylist_store` such as `RedisJWTDenylistStore` for multi-worker production. The `UserManager` hook prints the verification token to the server console so you can finish the flow without wiring email first.

```python
"""Minimal Litestar auth quickstart app mirrored in docs/quickstart.md."""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Any
from uuid import UUID

from litestar import Litestar, Request, get
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from litestar_auth import (
    AuthenticationBackend,
    BaseUserManager,
    BearerTransport,
    LitestarAuth,
    LitestarAuthConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.authentication.strategy import JWTStrategy
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import User

DATABASE_URL = "sqlite+aiosqlite:///./quickstart.db"
JWT_SECRET = os.environ["LITESTAR_AUTH_JWT_SECRET"]
RESET_PASSWORD_TOKEN_SECRET = os.environ["LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET"]
VERIFY_TOKEN_SECRET = os.environ["LITESTAR_AUTH_VERIFY_TOKEN_SECRET"]

engine = create_async_engine(DATABASE_URL, echo=False)
session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class UserManager(BaseUserManager[User, UUID]):
    """Print verification tokens so the quickstart can finish without email infrastructure."""

    verification_tokens: dict[str, str] = {}

    async def on_after_register(self, user: User, token: str) -> None:
        self.verification_tokens[user.email] = token
        print(f"verification token for {user.email}: {token}")  # noqa: T201


@get("/protected", guards=[is_authenticated])
async def protected(request: Request[User, Any, Any]) -> dict[str, str]:
    user = request.user
    assert user is not None
    return {"email": user.email}


backend = AuthenticationBackend[User, UUID](
    name="bearer",
    transport=BearerTransport(),
    strategy=JWTStrategy[User, UUID](
        secret=JWT_SECRET,
        lifetime=timedelta(minutes=15),
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    ),
)

config = LitestarAuthConfig[User, UUID](
    backends=(backend,),
    session_maker=session_maker,
    user_model=User,
    user_manager_class=UserManager,
    user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
    user_manager_security=UserManagerSecurity(
        verification_token_secret=VERIFY_TOKEN_SECRET,
        reset_password_token_secret=RESET_PASSWORD_TOKEN_SECRET,
    ),
    include_users=False,
)

app = Litestar(route_handlers=[protected], plugins=[LitestarAuth(config)])
```

## 4. Run the app

```bash
export LITESTAR_AUTH_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export LITESTAR_AUTH_VERIFY_TOKEN_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run python create_tables.py
uv run litestar run --debug
```

## 5. Register, verify, log in, and call a protected route

After the register call, copy the verification token printed by `app.py` and paste it into `VERIFY_TOKEN`.

```bash
EMAIL="demo@example.com"
PASSWORD="correct horse battery staple"

curl -s http://127.0.0.1:8000/auth/register \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

VERIFY_TOKEN="<paste the token from the server log>"
curl -s http://127.0.0.1:8000/auth/verify \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$VERIFY_TOKEN\"}"

curl -s http://127.0.0.1:8000/auth/login \
  -H 'content-type: application/json' \
  -d "{\"identifier\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

curl -s http://127.0.0.1:8000/protected \
  -H "Authorization: Bearer <access_token from /auth/login>"
```

Next, harden the starter app with [Security](security.md), choose a production auth surface in [Backends](configuration/backends.md), and align your user model with [Types and protocols](api/types.md).
