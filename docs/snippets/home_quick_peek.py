"""Home-page quick peek: plugin wiring. Included via pymdownx.snippets."""

from __future__ import annotations

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


session_maker = async_sessionmaker[AsyncSession](
    class_=AsyncSession,
    expire_on_commit=False,
)


class UserManager(BaseUserManager[User, UUID]):
    """Customize hooks such as on_after_register as needed."""


config = LitestarAuthConfig[User, UUID](
    database_token_auth=DatabaseTokenAuthConfig(
        token_hash_secret="replace-with-32+-char-db-token-secret",
    ),
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    user_manager_security=UserManagerSecurity(
        verification_token_secret="replace-with-32+-char-secret-for-verify",
        reset_password_token_secret="replace-with-32+-char-secret-for-reset",
    ),
)
app = Litestar(plugins=[LitestarAuth(config)])
