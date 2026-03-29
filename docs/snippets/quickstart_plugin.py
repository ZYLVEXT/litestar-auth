"""Minimal wiring pattern: JWT + Bearer backend and LitestarAuth plugin.

Replace secrets and database URL. For SQLite async you need `aiosqlite`.
This file is included in docs via pymdownx.snippets; it is not part of the installed package.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

from litestar import Litestar
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from litestar_auth import (
    BaseUserManager,
    LitestarAuth,
    LitestarAuthConfig,
    PasswordHelper,
    SQLAlchemyUserDatabase,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy import JWTStrategy
from litestar_auth.authentication.transport import BearerTransport
from litestar_auth.models import User


DATABASE_URL = "sqlite+aiosqlite:///./auth.db"
engine = create_async_engine(DATABASE_URL, echo=False)
session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class UserManager(BaseUserManager[User, UUID]):
    """Override hooks (on_after_register, etc.) as needed."""


def build_app() -> Litestar:
    jwt_strategy = JWTStrategy[User, UUID](
        secret="replace-with-32+-char-jwt-secret",
        lifetime=timedelta(minutes=15),
        subject_decoder=UUID,
    )
    backend = AuthenticationBackend[User, UUID](
        name="jwt",
        transport=BearerTransport(),
        strategy=jwt_strategy,
    )
    config = LitestarAuthConfig(
        backends=(backend,),
        session_maker=session_maker,
        user_model=User,
        user_manager_class=UserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_kwargs={
            "password_helper": PasswordHelper(),
            "verification_token_secret": "replace-with-32+-char-secret-for-verify",
            "reset_password_token_secret": "replace-with-32+-char-secret-for-reset",
        },
        include_users=False,
    )
    return Litestar(plugins=[LitestarAuth(config)])
