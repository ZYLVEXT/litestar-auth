"""Executable Litestar auth quickstart app."""

from __future__ import annotations

import os
from typing import Any, ClassVar, cast
from uuid import UUID

from litestar import Litestar, Request, get
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from litestar_auth import (
    BaseUserManager,
    DatabaseTokenAuthConfig,
    LitestarAuth,
    LitestarAuthConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.models import User

DATABASE_URL = "sqlite+aiosqlite:///./quickstart.db"
SESSION_HASH_SECRET = os.environ["LITESTAR_AUTH_SESSION_HASH_SECRET"]
CSRF_SECRET = os.environ["LITESTAR_AUTH_CSRF_SECRET"]
RESET_PASSWORD_TOKEN_SECRET = os.environ["LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET"]
VERIFY_TOKEN_SECRET = os.environ["LITESTAR_AUTH_VERIFY_TOKEN_SECRET"]

engine = create_async_engine(DATABASE_URL, echo=False)
session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class UserManager(BaseUserManager[User, UUID]):
    """Print verification tokens so the quickstart can finish without email infrastructure."""

    verification_tokens: ClassVar[dict[str, str]] = {}

    async def on_after_register(self, user: User, token: str) -> None:
        """Store and print a verification token for the registered user."""
        self.verification_tokens[user.email] = token
        print(f"verification token for {user.email}: {token}")  # ruff: ignore[print]


@get("/protected", guards=[is_authenticated], sync_to_thread=False)
def protected(request: Request[User, Any, Any]) -> dict[str, str]:
    """Return the authenticated user's email address."""
    user = cast("User", request.user)
    return {"email": user.email}


config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(token_hash_secret=SESSION_HASH_SECRET),
    session_maker=session_maker,
    user_model=User,
    user_manager_class=UserManager,
    user_manager_security=UserManagerSecurity(
        verification_token_secret=VERIFY_TOKEN_SECRET,
        reset_password_token_secret=RESET_PASSWORD_TOKEN_SECRET,
    ),
    csrf_secret=CSRF_SECRET,
    include_users=False,
)

app = Litestar(route_handlers=[protected], plugins=[LitestarAuth(config)])
