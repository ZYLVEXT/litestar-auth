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
        """Store and print a verification token for the registered user."""
        self.verification_tokens[user.email] = token
        print(f"verification token for {user.email}: {token}")  # noqa: T201


@get("/protected", guards=[is_authenticated])
async def protected(request: Request[User, Any, Any]) -> dict[str, str]:
    """Return the authenticated user's email address."""
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
