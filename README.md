# litestar-auth

`litestar-auth` is a production-focused authentication and authorization library for
[Litestar](https://litestar.dev/). It gives Litestar apps a native plugin for
registration, login, email verification, password reset, route guards, and optional
OAuth, Redis-backed features, and TOTP without forcing you to rebuild security-critical
flows from scratch.

[![Tests](https://github.com/ZYLVEXT/litestar-auth/actions/workflows/1_test.yml/badge.svg?branch=main)](https://github.com/ZYLVEXT/litestar-auth/actions/workflows/1_test.yml)
[![Coverage](https://codecov.io/gh/ZYLVEXT/litestar-auth/branch/main/graph/badge.svg)](https://codecov.io/gh/ZYLVEXT/litestar-auth)
[![Downloads](https://static.pepy.tech/personalized-badge/litestar-auth?period=month&units=international_system&left_color=grey&right_color=green&left_text=downloads/month)](https://www.pepy.tech/projects/litestar-auth)
[![PyPI](https://img.shields.io/pypi/v/litestar-auth.svg?label=PyPI)](https://pypi.org/project/litestar-auth)
[![Python versions](https://img.shields.io/pypi/pyversions/litestar-auth.svg)](https://pypi.org/project/litestar-auth)
[![License](https://img.shields.io/github/license/ZYLVEXT/litestar-auth.svg)](https://github.com/ZYLVEXT/litestar-auth/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-online-green.svg)](https://zylvext.github.io/litestar-auth/)

Documentation: <https://zylvext.github.io/litestar-auth/>

## Quick peek

This is the same `app.py` used in the
[Quickstart](https://zylvext.github.io/litestar-auth/quickstart/). The quickstart page adds
the SQLite table bootstrap and the register/verify/login request flow. To run this exact
SQLite demo locally, install `aiosqlite` alongside `litestar-auth`.

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

## Features

- Litestar-native plugin setup through `LitestarAuthConfig(...)` and `LitestarAuth(config)`.
- Registration, login, email verification, password reset, and protected-route guards out of the box.
- Transport + strategy auth backends, including Bearer or Cookie transports and JWT, database, or Redis token strategies.
- Opt-in DB-backed session/device routes for listing active refresh sessions and revoking one session
  or all other sessions without exposing raw tokens or token digests.
- `BaseUserManager` hooks for integrating email delivery, background jobs, and app-specific lifecycle logic.
- Bundled SQLAlchemy user model plus `SQLAlchemyUserDatabase` for the default persistence path.
- Normalized flat-role contract for responses and guards, with a matching `litestar roles` CLI for operator workflows.
- Optional Redis denylist, rate limiting, OAuth login/account linking, and built-in TOTP support.
- Typed public APIs and docs aimed at application developers rather than framework internals.

## Install

```bash
uv add litestar-auth
# or
pip install litestar-auth
```

For the SQLite quick peek and quickstart example, also add `aiosqlite`:

```bash
uv add litestar-auth aiosqlite
```

Install extras only when you need those features:

- `litestar-auth[redis]` for Redis-backed token storage, JWT denylist support, and auth rate limiting.
- `litestar-auth[oauth]` for OAuth flows via `httpx-oauth` and encrypted provider tokens.
- `litestar-auth[totp]` for built-in TOTP helpers.
- `litestar-auth[all]` for `redis`, `oauth`, and `totp` together.

Password hashing defaults are now Argon2-only. Unsupported stored password hashes fail closed
under the library default, so rotate or reset those credentials before upgrading; see the
[Migration Guide](https://zylvext.github.io/litestar-auth/migration/).

## Runnable examples

This repository ships small Litestar apps under [`examples/`](examples/__init__.py) (not published on PyPI).
Each package documents its own environment variables; local demos typically set `..._INSECURE=1` as noted there.

Install an ASGI server (for example `uvicorn`), then pick a scenario from the table in [`examples/__init__.py`](examples/__init__.py).

Bearer JWT + TOTP sketch (`demo_totp`):

```bash
export LITESTAR_AUTH_DEMO_TOTP_INSECURE=1
uv run uvicorn examples.demo_totp.app:app --host 127.0.0.1 --port 8000
# curl http://127.0.0.1:8000/health
# curl -sS -X POST http://127.0.0.1:8000/auth/register \
#   -H 'Content-Type: application/json' \
#   -d '{"email":"you@example.com","password":"choose-a-strong-password"}'
```

Cookie + CSRF flows (`demo_cookie_jwt`, `demo_cookie_jwt_totp`) need a client that keeps cookies and sends `X-CSRF-Token` on unsafe methods after loading `/health`.

## Read more

- [Quickstart](https://zylvext.github.io/litestar-auth/quickstart/): bootstrap SQLite, run the app, and walk through register/verify/login.
- [Installation](https://zylvext.github.io/litestar-auth/install/): requirements, extras, and typical deployment stacks.
- [Configuration](https://zylvext.github.io/litestar-auth/configuration/): user model, manager, backends, Redis, OAuth, TOTP, and security knobs.
- [HTTP API](https://zylvext.github.io/litestar-auth/http_api/): generated routes, including the opt-in DB refresh-session/device management surface.
- [Security](https://zylvext.github.io/litestar-auth/security/): secure defaults, migration-only flags, and production hardening notes.
- [Role management CLI](https://zylvext.github.io/litestar-auth/guides/roles_cli/): operator commands for bundled relational roles.
- [Testing plugin-backed apps](https://zylvext.github.io/litestar-auth/guides/testing/): AsyncTestClient patterns and repo-aligned test advice.
- [Python API overview](https://zylvext.github.io/litestar-auth/api/package/): stable imports and where advanced submodules live.

## Repository

Contributor setup, verification commands, and docs tooling live in
[Contributing](https://zylvext.github.io/litestar-auth/contributing/).
