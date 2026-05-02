"""Shared test-only helper models and Redis test utilities."""

from __future__ import annotations

import asyncio
import importlib
import sqlite3
from dataclasses import dataclass, field
from functools import partial
from types import ModuleType
from typing import TYPE_CHECKING, Any, Literal, Protocol, Self, cast

from litestar import Litestar
from litestar.di import Provide

from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterable, Sequence
    from uuid import UUID

    import fakeredis
    from fakeredis import FakeAsyncRedis as AsyncFakeRedis
    from litestar.datastructures.state import State
    from litestar.types import ControllerRouterHandler, Middleware, Scope
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.scoped_session import SessionFactory

type FakeRedisVersion = tuple[int, ...]
type FakeRedisServerType = Literal["redis", "dragonfly", "valkey"]

DEFAULT_FAKEREDIS_VERSION: FakeRedisVersion = (7,)


class AsyncFakeRedisFactory(Protocol):
    """Typed callable for building async fakeredis clients in tests."""

    def __call__(
        self,
        *,
        server: fakeredis.FakeServer | None = None,
        version: FakeRedisVersion = DEFAULT_FAKEREDIS_VERSION,
        server_type: FakeRedisServerType = "redis",
        decode_responses: bool = False,
    ) -> AsyncFakeRedis:
        """Create an async fakeredis client."""


class FakeRedisServerFactory(Protocol):
    """Typed callable for building isolated fakeredis servers in tests."""

    def __call__(
        self,
        *,
        version: FakeRedisVersion = DEFAULT_FAKEREDIS_VERSION,
        server_type: FakeRedisServerType = "redis",
    ) -> fakeredis.FakeServer:
        """Create a fakeredis server instance."""


class _ImmediateAioSQLiteQueue:
    """Run SQLAlchemy's internal aiosqlite work items inline for tests."""

    def put_nowait(self, item: tuple[asyncio.Future[None], Callable[[], None]]) -> None:
        """Execute one queued callback immediately and resolve its future."""
        future, function = item
        function()
        future.set_result(None)


class FakeAioSQLiteCursor:
    """Minimal async cursor surface for SQLAlchemy's aiosqlite dialect."""

    def __init__(self, cursor: sqlite3.Cursor) -> None:
        """Store the wrapped SQLite cursor."""
        self._cursor = cursor

    @property
    def description(self) -> object | None:
        """Expose the wrapped cursor description."""
        return self._cursor.description

    @property
    def lastrowid(self) -> int | None:
        """Expose the wrapped cursor last inserted row id."""
        return self._cursor.lastrowid

    @property
    def rowcount(self) -> int:
        """Expose the wrapped cursor rowcount."""
        return self._cursor.rowcount

    async def close(self) -> None:
        """Close the wrapped cursor."""
        self._cursor.close()

    async def execute(self, operation: object, parameters: object | None = None) -> Self:
        """Execute one SQL statement through the wrapped cursor.

        Returns:
            This cursor instance.
        """
        if parameters is None:
            self._cursor.execute(cast("str", operation))
        else:
            self._cursor.execute(cast("str", operation), cast("Any", parameters))
        return self

    async def executemany(self, operation: object, parameters: object) -> Self:
        """Execute one SQL statement against many parameter rows.

        Returns:
            This cursor instance.
        """
        self._cursor.executemany(cast("str", operation), cast("Any", parameters))
        return self

    async def fetchall(self) -> list[object]:
        """Return all remaining rows."""
        return cast("list[object]", self._cursor.fetchall())

    async def fetchmany(self, size: int | None = None) -> list[object]:
        """Return the next batch of rows."""
        return cast(
            "list[object]",
            self._cursor.fetchmany() if size is None else self._cursor.fetchmany(size),
        )

    async def fetchone(self) -> object | None:
        """Return the next available row or ``None``."""
        return self._cursor.fetchone()


class FakeAioSQLiteConnection:
    """Minimal driver-level async SQLite connection for AsyncSession tests."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        """Store the wrapped SQLite connection."""
        self._conn: sqlite3.Connection = connection
        self._tx = _ImmediateAioSQLiteQueue()

    @property
    def isolation_level(self) -> Literal["DEFERRED", "EXCLUSIVE", "IMMEDIATE"] | None:
        """Expose the wrapped connection isolation level."""
        return self._conn.isolation_level

    @isolation_level.setter
    def isolation_level(self, value: Literal["DEFERRED", "EXCLUSIVE", "IMMEDIATE"] | None) -> None:
        """Set the wrapped connection isolation level."""
        self._conn.isolation_level = value

    async def close(self) -> None:
        """Close the wrapped SQLite connection."""
        self._conn.close()

    async def commit(self) -> None:
        """Commit the current transaction."""
        self._conn.commit()

    async def create_function(
        self,
        name: str,
        narg: int,
        func: Callable[..., str | bytes | int | float | None] | None,
        *,
        deterministic: bool = False,
    ) -> None:
        """Create one SQLite user-defined function on the wrapped connection."""
        self._conn.create_function(name, narg, func, deterministic=deterministic)

    async def cursor(self) -> FakeAioSQLiteCursor:
        """Return a wrapped SQLite cursor."""
        return FakeAioSQLiteCursor(self._conn.cursor())

    async def execute(
        self,
        statement: str,
        parameters: object | None = None,
    ) -> FakeAioSQLiteCursor:
        """Execute one SQL statement and return a wrapped cursor.

        Returns:
            Wrapped cursor exposing the async DB-API surface SQLAlchemy expects.
        """
        if parameters is None:
            return FakeAioSQLiteCursor(self._conn.execute(statement))
        return FakeAioSQLiteCursor(self._conn.execute(statement, cast("Any", parameters)))

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        self._conn.rollback()

    def stop(self) -> None:
        """Terminate the wrapped connection for SQLAlchemy shutdown semantics."""
        self._conn.close()


def build_fake_aiosqlite_module() -> ModuleType:
    """Return a minimal ``aiosqlite`` module for SQLAlchemy AsyncSession tests."""
    module = cast("Any", ModuleType("aiosqlite"))
    module.Connection = FakeAioSQLiteConnection
    module.connect = _unexpected_aiosqlite_connect
    module.sqlite_version = sqlite3.sqlite_version
    module.sqlite_version_info = sqlite3.sqlite_version_info
    for name in (
        "DatabaseError",
        "Error",
        "IntegrityError",
        "NotSupportedError",
        "OperationalError",
        "ProgrammingError",
    ):
        setattr(module, name, getattr(sqlite3, name))
    return module


def _unexpected_aiosqlite_connect(*args: object, **kwargs: object) -> None:
    """Fail fast if the fake driver is used without ``async_creator``.

    Raises:
        AssertionError: Always, because these test helpers require ``async_creator``.
    """
    del args, kwargs
    msg = "Tests using the fake aiosqlite module must provide create_async_engine(..., async_creator=...)."
    raise AssertionError(msg)


async def open_fake_aiosqlite_connection(database: str, *_: object, **__: object) -> FakeAioSQLiteConnection:
    """Open one SQLite connection wrapped in the fake async driver surface.

    Returns:
        Wrapped SQLite connection exposing the async driver surface SQLAlchemy expects.
    """
    connection = await asyncio.to_thread(sqlite3.connect, database, check_same_thread=False)
    await asyncio.to_thread(connection.execute, "PRAGMA foreign_keys=ON")
    return FakeAioSQLiteConnection(connection)


def _load_fakeredis() -> ModuleType:
    """Import the ``fakeredis`` package lazily for test helpers.

    Returns:
        Imported ``fakeredis`` module.
    """
    return importlib.import_module("fakeredis")


def make_fakeredis_server(
    *,
    version: FakeRedisVersion = DEFAULT_FAKEREDIS_VERSION,
    server_type: FakeRedisServerType = "redis",
) -> fakeredis.FakeServer:
    """Build an isolated fakeredis server for a test case.

    Args:
        version: Redis server version emulated by fakeredis.
        server_type: Redis-family server type emulated by fakeredis.

    Returns:
        Fake Redis server backing one or more async fakeredis clients.
    """
    return _load_fakeredis().FakeServer(version=version, server_type=server_type)


def make_async_fakeredis(
    *,
    server: fakeredis.FakeServer | None = None,
    version: FakeRedisVersion = DEFAULT_FAKEREDIS_VERSION,
    server_type: FakeRedisServerType = "redis",
    decode_responses: bool = False,
) -> AsyncFakeRedis:
    """Build an async fakeredis client compatible with ``redis.asyncio.Redis``.

    Args:
        server: Shared fake server. Omit to create a client backed by a fresh server.
        version: Redis server version emulated by fakeredis.
        server_type: Redis-family server type emulated by fakeredis.
        decode_responses: Whether fakeredis should decode responses to strings.

    Returns:
        Async fakeredis client for repository tests.
    """
    fake_redis_class = _load_fakeredis().FakeAsyncRedis

    return fake_redis_class(
        server=server,
        version=version,
        server_type=server_type,
        decode_responses=decode_responses,
    )


async def aclose_fakeredis_clients(clients: Iterable[AsyncFakeRedis]) -> None:
    """Close async fakeredis clients created during a test.

    Args:
        clients: Async fakeredis clients that should be closed.
    """
    for client in clients:
        await client.aclose()


def cast_fakeredis[T](redis: AsyncFakeRedis, protocol: type[T]) -> T:
    """Cast an async fakeredis client to a narrow Redis protocol type.

    Args:
        redis: Async fakeredis client to cast.
        protocol: Target protocol type (used only for type narrowing).

    Returns:
        The same client instance typed as the target protocol.
    """
    del protocol
    return cast("T", redis)


def auth_middleware_get_request_session(session_maker: SessionFactory) -> Callable[[State, Scope], AsyncSession]:
    """Build ``get_request_session`` for :class:`LitestarAuthMiddleware` in tests.

    Returns:
        Partial of :func:`~litestar_auth._plugin.scoped_session.get_or_create_scoped_session`
        with ``session_maker`` bound.
    """
    return partial(get_or_create_scoped_session, session_maker=session_maker)


def litestar_app_with_user_manager(
    user_manager: object,
    *route_handlers: object,
    middleware: list[object] | None = None,
) -> Litestar:
    """Build a Litestar app registering ``user_manager`` under the default DI key.

    Returns:
        Configured :class:`~litestar.Litestar` instance.
    """

    async def _provide_user_manager() -> AsyncIterator[object]:  # noqa: RUF029
        yield user_manager

    return Litestar(
        route_handlers=cast("Sequence[ControllerRouterHandler]", list(route_handlers)),
        dependencies={DEFAULT_USER_MANAGER_DEPENDENCY_KEY: Provide(_provide_user_manager)},
        middleware=cast("Sequence[Middleware]", middleware or []),
    )


@dataclass(slots=True)
class ExampleUser:
    """Shared minimal user model for tests."""

    id: UUID
    email: str = ""
    username: str = ""
    hashed_password: str = "hashed"
    is_active: bool = True
    is_verified: bool = False
    roles: list[str] = field(default_factory=list)
    totp_secret: str | None = None
    recovery_codes_hashes: list[str] | None = None
    login_hint: str = ""
    bio: str = ""
