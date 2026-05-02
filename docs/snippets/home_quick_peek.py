"""Home-page quick peek: plugin wiring. Included via pymdownx.snippets."""

from __future__ import annotations

import os
from uuid import UUID

from litestar import Litestar
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from litestar_auth import (
    BaseUserManager,
    DatabaseTokenAuthConfig,
    LitestarAuth,
    LitestarAuthConfig,
    UserManagerSecurity,
)
from litestar_auth.models import User

DATABASE_TOKEN_HASH_SECRET = os.environ["LITESTAR_AUTH_DATABASE_TOKEN_HASH_SECRET"]
RESET_PASSWORD_TOKEN_SECRET = os.environ["LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET"]
VERIFY_TOKEN_SECRET = os.environ["LITESTAR_AUTH_VERIFY_TOKEN_SECRET"]

session_maker = async_sessionmaker[AsyncSession](
    class_=AsyncSession,
    expire_on_commit=False,
)


class UserManager(BaseUserManager[User, UUID]):
    """Customize hooks such as on_after_register as needed."""


config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret=DATABASE_TOKEN_HASH_SECRET,
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret=VERIFY_TOKEN_SECRET,
        reset_password_token_secret=RESET_PASSWORD_TOKEN_SECRET,
    ),
)
app = Litestar(plugins=[LitestarAuth(config)])
