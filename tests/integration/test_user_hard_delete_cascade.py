"""Integration coverage for hard-delete cleanup of user-owned auth state."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import OAuthAccount, User
from litestar_auth.oauth_encryption import OAuthTokenEncryption
from tests.integration.conftest import enable_aiosqlite_foreign_keys

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


pytestmark = pytest.mark.integration

TOKEN_HASH_SECRET = "hard-delete-token-secret-0123456789abcdef"


@dataclass(slots=True)
class _Backend:
    strategy: object


@pytest.fixture
async def hard_delete_session_maker(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Create an aiosqlite session maker with SQLite FK enforcement enabled.

    Yields:
        Async session maker bound to an isolated SQLite database.
    """
    database_path = tmp_path / "hard-delete-cascade.sqlite"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    enable_aiosqlite_foreign_keys(engine)
    async with engine.begin() as connection:
        await connection.run_sync(User.metadata.create_all)

    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


def _user_database(session: AsyncSession) -> SQLAlchemyUserDatabase[User]:
    """Return a SQLAlchemy user database bound to the bundled OAuth model."""
    oauth_token_encryption = OAuthTokenEncryption(base64.urlsafe_b64encode(b"0" * 32).decode())
    return SQLAlchemyUserDatabase(
        session,
        user_model=User,
        oauth_account_model=OAuthAccount,
        oauth_token_encryption=oauth_token_encryption,
    )


async def _row_count(session: AsyncSession, model: type[Any]) -> int:
    """Return row count for ``model``."""
    result = await session.execute(select(func.count()).select_from(model))
    return result.scalar_one()
