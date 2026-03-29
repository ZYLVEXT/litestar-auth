"""Shared pytest fixtures for Litestar auth tests."""

from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import pytest
from litestar import Litestar
from litestar.testing import AsyncTestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session as SASession
from sqlalchemy.pool import StaticPool

from litestar_auth.models import User

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from sqlalchemy.schema import MetaData

type AppFixtureValue = Litestar | tuple[Litestar, *tuple[object, ...]]


@asynccontextmanager
async def _async_client_context(
    app_value: AppFixtureValue,
    *,
    base_url: str | None,
) -> AsyncIterator[Any]:
    if isinstance(app_value, tuple):
        app, *extras = app_value
    else:
        app = app_value
        extras = []

    if base_url is None:
        async with AsyncTestClient(app=app) as test_client:
            if extras:
                yield (test_client, *extras)
                return

            yield test_client
            return

    async with AsyncTestClient(app=app, base_url=base_url) as test_client:
        if extras:
            yield (test_client, *extras)
            return

        yield test_client


@pytest.fixture
def test_client_base_url() -> str | None:
    """Allow modules to override the AsyncTestClient base URL when needed.

    Returns:
        Optional base URL passed to ``AsyncTestClient``.
    """
    return None


@pytest.fixture
def async_test_client_factory(test_client_base_url: str | None) -> Callable[[AppFixtureValue], Any]:
    """Build AsyncTestClient contexts from app fixtures that may carry extras.

    Returns:
        Factory that opens an ``AsyncTestClient`` for the provided app fixture value.
    """
    return lambda app_value: _async_client_context(app_value, base_url=test_client_base_url)


@pytest.fixture
async def client(
    app: AppFixtureValue,
    async_test_client_factory: Callable[[AppFixtureValue], Any],
) -> AsyncIterator[Any]:
    """Create a shared async test client from the local ``app`` fixture.

    Yields:
        Async test client, optionally bundled with extra collaborators.
    """
    async with async_test_client_factory(app) as test_client:
        yield test_client


@pytest.fixture
async def hard_delete_client(
    hard_delete_app: AppFixtureValue,
    async_test_client_factory: Callable[[AppFixtureValue], Any],
) -> AsyncIterator[Any]:
    """Create a shared async test client from the local ``hard_delete_app`` fixture.

    Yields:
        Async test client, optionally bundled with extra collaborators.
    """
    async with async_test_client_factory(hard_delete_app) as test_client:
        yield test_client


@pytest.fixture
async def client_and_db(
    app: AppFixtureValue,
    async_test_client_factory: Callable[[AppFixtureValue], Any],
) -> AsyncIterator[Any]:
    """Backwards-compatible client fixture for tests that also return collaborators.

    Yields:
        Async test client, optionally bundled with extra collaborators.
    """
    async with async_test_client_factory(app) as test_client:
        yield test_client


@pytest.fixture
def sqlalchemy_metadata() -> tuple[MetaData, ...]:
    """Expose the metadata that should be created for SQLite session tests.

    Returns:
        Metadata collections that should be created before yielding the session.
    """
    return (User.metadata,)


@pytest.fixture
def session(sqlalchemy_metadata: tuple[MetaData, ...]) -> Iterator[SASession]:
    """Create a SQLite in-memory session with foreign keys enabled.

    Yields:
        Synchronous SQLAlchemy session bound to the in-memory SQLite engine.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection: sqlite3.Connection, _: object) -> None:
        if not isinstance(dbapi_connection, sqlite3.Connection):
            return

        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    for metadata in sqlalchemy_metadata:
        metadata.create_all(engine)

    with SASession(engine) as db_session:
        yield db_session

    engine.dispose()
