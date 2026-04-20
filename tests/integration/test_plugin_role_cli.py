"""Integration tests for the plugin-managed roles CLI."""

from __future__ import annotations

import asyncio
import sqlite3
import sys
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from types import ModuleType
from typing import TYPE_CHECKING, Any, Literal, Self, cast
from uuid import UUID

import pytest
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from click.testing import CliRunner
from litestar.cli._utils import LitestarGroup
from sqlalchemy import create_engine, event, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, selectinload
from sqlalchemy.orm import Session as SASession
from sqlalchemy.pool import StaticPool

try:
    import rich_click as click
except ImportError:
    import click  # type: ignore[no-redef]

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase, SQLAlchemyUserModelProtocol
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import (
    Role,
    RoleMixin,
    User,
    UserModelMixin,
    UserRoleAssociationMixin,
    UserRoleRelationshipMixin,
)
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import assert_structural_session_factory

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator, Mapping, Sequence
    from pathlib import Path
    from types import TracebackType

    from click import Group
    from sqlalchemy.engine import Engine, Result
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
    from sqlalchemy.sql.base import Executable

    from litestar_auth._plugin.config import UserManagerFactory
    from litestar_auth.db.base import BaseUserStore
    from litestar_auth.types import StrategyProtocol

pytestmark = [pytest.mark.integration]


class _RoleCLIUserManager[UP: SQLAlchemyUserModelProtocol](BaseUserManager[UP, UUID]):
    """Minimal manager implementation for role CLI integration tests."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return an empty page; list-users behavior is irrelevant to these tests."""
        del offset, limit
        return [], 0


@dataclass(frozen=True, slots=True)
class _RoleLifecycleEvent:
    """Captured manager lifecycle payload for one CLI-driven role mutation."""

    email: str
    roles: list[str]


class _ImmediateAioSQLiteQueue:
    """Run SQLAlchemy's internal driver work items inline for fake async SQLite."""

    def put_nowait(self, item: tuple[asyncio.Future[None], Callable[[], None]]) -> None:
        """Execute one queued callback immediately and resolve its future."""
        future, function = item
        function()
        future.set_result(None)


class _FakeAioSQLiteCursor:
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


class _FakeAioSQLiteConnection:
    """Minimal driver-level async SQLite connection for real AsyncSession tests."""

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

    async def cursor(self) -> _FakeAioSQLiteCursor:
        """Return a wrapped SQLite cursor."""
        return _FakeAioSQLiteCursor(self._conn.cursor())

    async def execute(
        self,
        statement: str,
        parameters: object | None = None,
    ) -> _FakeAioSQLiteCursor:
        """Execute one SQL statement and return a wrapped cursor.

        Returns:
            Wrapped cursor exposing the async DB-API surface SQLAlchemy expects.
        """
        if parameters is None:
            return _FakeAioSQLiteCursor(self._conn.execute(statement))
        return _FakeAioSQLiteCursor(self._conn.execute(statement, cast("Any", parameters)))

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        self._conn.rollback()

    def stop(self) -> None:
        """Terminate the wrapped connection for SQLAlchemy shutdown semantics."""
        self._conn.close()


@dataclass(frozen=True, slots=True)
class _AsyncRoleCLIDatabase:
    """Real AsyncSession-backed SQLite resources for CLI regression coverage."""

    engine: AsyncEngine
    session_maker: async_sessionmaker[AsyncSession]


class _TrackingRoleCLIUserManager[UP: SQLAlchemyUserModelProtocol](_RoleCLIUserManager[UP]):
    """Role CLI test manager that records lifecycle hook payloads."""

    def __init__(
        self,
        user_db: BaseUserStore[UP, UUID],
        *,
        update_events: list[_RoleLifecycleEvent],
        **kwargs: object,
    ) -> None:
        """Store the shared lifecycle event log."""
        super().__init__(user_db, **kwargs)
        self._update_events = update_events

    async def on_after_update(self, user: UP, update_dict: dict[str, Any]) -> None:
        """Record the normalized role payload surfaced through the manager lifecycle."""
        self._update_events.append(
            _RoleLifecycleEvent(
                email=cast("str", cast("Any", user).email),
                roles=list(cast("list[str]", update_dict["roles"])),
            ),
        )


class _ImplicitAsyncIOSession(SASession):
    """Sync session variant that rejects implicit ORM IO outside explicit adapter calls."""

    def __init__(self, bind: Engine) -> None:
        """Initialize the guarded session bound to ``bind``."""
        super().__init__(bind, expire_on_commit=False)
        self._explicit_sql_depth = 0

    @contextmanager
    def allow_sql(self) -> Iterator[None]:
        """Temporarily allow SQL execution through explicit async-adapter methods."""
        self._explicit_sql_depth += 1
        try:
            yield
        finally:
            self._explicit_sql_depth -= 1

    def execute(
        self,
        statement: Executable,
        params: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
        *,
        execution_options: Mapping[str, object] | None = None,
        bind_arguments: dict[str, Any] | None = None,
        _parent_execute_state: object | None = None,
        _add_event: object | None = None,
    ) -> Result[Any]:
        """Reject lazy-load SQL that bypasses the async adapter guard.

        Returns:
            The proxied SQLAlchemy execution result.

        Raises:
            AssertionError: If SQL is attempted outside an explicit adapter call.
        """
        if self._explicit_sql_depth == 0:
            msg = "Implicit ORM IO escaped the async adapter guard."
            raise AssertionError(msg)
        return super().execute(
            statement,
            params=params,
            execution_options=execution_options or {},
            bind_arguments=bind_arguments,
            _parent_execute_state=_parent_execute_state,
            _add_event=_add_event,
        )


class _ExplicitSQLResult:
    """Proxy result access through the same explicit-SQL guard as the async adapter."""

    def __init__(self, result: object, session: SASession) -> None:
        """Store the wrapped SQLAlchemy result and its guarded sync session."""
        self._result = result
        self._session = session

    def _explicit_sql(self) -> AbstractContextManager[None]:
        """Return the explicit-SQL guard required by the wrapped sync session."""
        allow_sql = getattr(self._session, "allow_sql", None)
        if allow_sql is None:
            return nullcontext()
        return cast("AbstractContextManager[None]", allow_sql())

    def _wrap(self, value: object) -> object:
        """Re-wrap SQLAlchemy result objects so chained access stays guarded.

        Returns:
            A guarded result proxy when ``value`` is another SQLAlchemy result
            object, otherwise ``value`` unchanged.
        """
        if value.__class__.__module__.startswith("sqlalchemy.") and (
            hasattr(value, "scalar_one_or_none") or hasattr(value, "unique")
        ):
            return _ExplicitSQLResult(value, self._session)
        return value

    def __iter__(self) -> Iterator[object]:
        """Iterate under the explicit-SQL guard.

        Yields:
            Items from the wrapped SQLAlchemy result.
        """
        with self._explicit_sql():
            yield from cast("Any", self._result)

    def __getattr__(self, name: str) -> object:
        """Proxy result methods while preserving the explicit-SQL guard.

        Returns:
            The proxied attribute or a wrapped callable that re-enters the
            explicit-SQL guard before delegating.
        """
        attribute = getattr(self._result, name)
        if not callable(attribute):
            return attribute

        def _wrapped(*args: object, **kwargs: object) -> object:
            with self._explicit_sql():
                return self._wrap(attribute(*args, **kwargs))

        return _wrapped


class _RoleCLITokenStrategy[UP: SQLAlchemyUserModelProtocol](Strategy[UP, UUID]):
    """Minimal token strategy for CLI-only plugin construction."""

    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, UUID],
    ) -> UP | None:
        """Return no user; the CLI never authenticates requests."""
        del token, user_manager
        return None

    async def write_token(self, user: UP) -> str:
        """Return a deterministic placeholder token."""
        del user
        return "role-cli-token"

    async def destroy_token(self, token: str, user: UP) -> None:
        """Discard token-destruction inputs for CLI coverage."""
        del token, user


def _build_fake_aiosqlite_module() -> ModuleType:
    """Return a minimal ``aiosqlite`` module for SQLAlchemy AsyncSession tests."""
    module = cast("Any", ModuleType("aiosqlite"))
    module.Connection = _FakeAioSQLiteConnection
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
        AssertionError: Always, because these tests require ``async_creator``.
    """
    del args, kwargs
    msg = "Role CLI async regression tests must provide an explicit async_creator."
    raise AssertionError(msg)


class _RoleCLIAsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session for CLI tests."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped sync session."""
        self._session = session

    async def __aenter__(self) -> Self:
        """Return the adapter itself for ``async with`` compatibility."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Mirror SQLAlchemy session cleanup semantics for the test adapter."""
        del exc, traceback
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        await self.close()

    def add(self, instance: object) -> None:
        """Add one instance to the wrapped sync session."""
        self._session.add(instance)

    def _explicit_sql(self) -> AbstractContextManager[None]:
        """Return the explicit-SQL guard required by the wrapped sync session."""
        allow_sql = getattr(self._session, "allow_sql", None)
        if allow_sql is None:
            return nullcontext()
        return cast("AbstractContextManager[None]", allow_sql())

    def __getattr__(self, name: str) -> object:
        """Delegate unsupported attributes to the wrapped sync session.

        Returns:
            The proxied sync-session attribute.
        """
        return getattr(self._session, name)

    async def close(self) -> None:
        """Close the wrapped sync session."""
        self._session.close()

    async def commit(self) -> None:
        """Commit the current transaction."""
        with self._explicit_sql():
            self._session.commit()

    async def execute(
        self,
        statement: object,
        params: object | None = None,
        *,
        execution_options: object | None = None,
    ) -> object:
        """Execute one SQLAlchemy statement and return the result.

        Returns:
            SQLAlchemy execution result from the wrapped sync session.
        """
        sync_session = cast("Any", self._session)
        with self._explicit_sql():
            return _ExplicitSQLResult(
                cast("object", sync_session.execute(statement, params=params, execution_options=execution_options)),
                self._session,
            )

    async def flush(self) -> None:
        """Flush pending ORM changes."""
        with self._explicit_sql():
            self._session.flush()

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Merge one instance into the wrapped session.

        Returns:
            The merged SQLAlchemy instance.
        """
        with self._explicit_sql():
            return self._session.merge(instance, load=load)

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        with self._explicit_sql():
            self._session.rollback()

    async def refresh(
        self,
        instance: object,
        *,
        attribute_names: object | None = None,
        with_for_update: object | None = None,
    ) -> None:
        """Refresh one instance from the wrapped session."""
        with self._explicit_sql():
            self._session.refresh(
                instance,
                attribute_names=cast("Any", attribute_names),
                with_for_update=cast("Any", with_for_update),
            )

    async def scalar(self, statement: object) -> object:
        """Return the first scalar result for a statement."""
        with self._explicit_sql():
            return self._session.scalar(cast("Any", statement))

    async def scalars(self, statement: object) -> object:
        """Return the scalar result collection for a statement."""
        with self._explicit_sql():
            return _ExplicitSQLResult(self._session.scalars(cast("Any", statement)), self._session)

    @property
    def no_autoflush(self) -> object:
        """Expose the wrapped session's no-autoflush context manager."""
        return self._session.no_autoflush


class _RoleCLISessionMaker:
    """Session factory exposing the AsyncSession surface required by role-admin tests."""

    def __init__(self, engine: Engine, *, session_class: type[SASession] = SASession) -> None:
        """Store the shared SQLite engine and sync session implementation."""
        self._engine = engine
        self._session_class = session_class

    def __call__(self) -> AsyncSession:
        """Return a new adapter-backed session."""
        sync_session = (
            SASession(self._engine, expire_on_commit=False)
            if self._session_class is SASession
            else self._session_class(self._engine)
        )
        return cast(
            "AsyncSession",
            _RoleCLIAsyncSessionAdapter(sync_session),
        )


def _build_adapter_session_maker(
    engine: Engine,
    *,
    session_class: type[SASession] = SASession,
) -> async_sessionmaker[AsyncSession]:
    """Return the adapter-backed session maker used by sync CLI integration tests."""
    return cast(
        "async_sessionmaker[AsyncSession]",
        assert_structural_session_factory(_RoleCLISessionMaker(engine, session_class=session_class)),
    )


def _build_root_cli() -> Group:
    """Return a Litestar-like root CLI group for integration tests."""

    @click.group(cls=LitestarGroup)
    def root() -> None:
        """Root CLI group used in integration tests."""

    return root


def _build_config[UP: SQLAlchemyUserModelProtocol](  # noqa: PLR0913
    engine: Engine | None,
    *,
    user_model: type[UP],
    user_manager_class: type[BaseUserManager[UP, UUID]] | None = None,
    extra_security_overrides: dict[str, Any] | None = None,
    user_manager_factory: UserManagerFactory[UP, UUID] | None = None,
    session_maker: async_sessionmaker[AsyncSession] | None = None,
) -> LitestarAuthConfig[UP, UUID]:
    """Return a plugin config backed by a plugin-compatible SQLAlchemy session factory.

    Raises:
        AssertionError: If neither ``engine`` nor ``session_maker`` is supplied.
    """
    backend = AuthenticationBackend[UP, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("StrategyProtocol[UP, UUID]", _RoleCLITokenStrategy[UP]()),
    )
    if session_maker is None:
        if engine is None:
            msg = "Role CLI test helpers require an engine when session_maker is omitted."
            raise AssertionError(msg)
        session_maker = _build_adapter_session_maker(engine)

    def user_db_factory(session: AsyncSession) -> SQLAlchemyUserDatabase[UP]:
        """Build the SQLAlchemy-backed user store for one request session.

        Returns:
            SQLAlchemy user store bound to ``session``.
        """
        return SQLAlchemyUserDatabase(session, user_model=user_model)

    user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="verify-secret-12345678901234567890",
        reset_password_token_secret="reset-secret-123456789012345678901",
        id_parser=UUID,
        **dict(extra_security_overrides or {}),
    )
    if user_manager_factory is not None:
        return LitestarAuthConfig[UP, UUID](
            backends=[backend],
            session_maker=session_maker,
            user_model=user_model,
            user_manager_factory=user_manager_factory,
            user_db_factory=user_db_factory,
            user_manager_security=user_manager_security,
            include_register=False,
            include_verify=False,
            include_reset_password=False,
            include_users=False,
        )
    return LitestarAuthConfig[UP, UUID](
        backends=[backend],
        session_maker=session_maker,
        user_model=user_model,
        user_manager_class=user_manager_class or _RoleCLIUserManager,
        user_db_factory=user_db_factory,
        user_manager_security=user_manager_security,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        include_users=False,
    )


def _build_roles_cli[UP: SQLAlchemyUserModelProtocol](  # noqa: PLR0913
    engine: Engine | None,
    *,
    user_model: type[UP],
    user_manager_class: type[BaseUserManager[UP, UUID]] | None = None,
    extra_security_overrides: dict[str, Any] | None = None,
    user_manager_factory: UserManagerFactory[UP, UUID] | None = None,
    session_maker: async_sessionmaker[AsyncSession] | None = None,
) -> Group:
    """Create the plugin-owned roles CLI group for one configured user model.

    Returns:
        Root CLI group with the plugin-owned ``roles`` commands registered.
    """
    root_cli = _build_root_cli()
    plugin = LitestarAuth(
        _build_config(
            engine,
            user_model=user_model,
            user_manager_class=user_manager_class,
            extra_security_overrides=extra_security_overrides,
            user_manager_factory=user_manager_factory,
            session_maker=session_maker,
        ),
    )
    plugin.on_cli_init(root_cli)
    return root_cli


def _build_tracking_roles_cli[UP: SQLAlchemyUserModelProtocol](
    engine: Engine | None,
    *,
    user_model: type[UP],
    session_maker: async_sessionmaker[AsyncSession] | None = None,
) -> tuple[Group, list[_RoleLifecycleEvent]]:
    """Create the roles CLI with a tracking manager that records lifecycle hook payloads.

    Returns:
        The CLI group plus the shared lifecycle event log.
    """
    update_events: list[_RoleLifecycleEvent] = []

    def _build_tracking_user_manager(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[UP, UUID],
        config: LitestarAuthConfig[UP, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[UP, UUID]:
        del session
        security = config.user_manager_security
        assert security is not None
        return _TrackingRoleCLIUserManager(
            user_db,
            update_events=update_events,
            password_helper=config.resolve_password_helper(),
            security=security,
            backends=backends,
            login_identifier=config.login_identifier,
            skip_reuse_warning=skip_reuse_warning,
            unsafe_testing=config.unsafe_testing,
        )

    return (
        _build_roles_cli(
            engine,
            user_model=user_model,
            user_manager_factory=_build_tracking_user_manager,
            session_maker=session_maker,
        ),
        update_events,
    )


def _create_user[UP: SQLAlchemyUserModelProtocol](
    engine: Engine,
    *,
    user_model: type[UP],
    email: str,
    roles: list[str],
) -> None:
    """Insert one user with the requested relational role membership."""
    with SASession(engine, expire_on_commit=False) as session:
        session.add(cast("Any", user_model)(email=email, hashed_password="hashed-password", roles=roles))
        session.commit()


def _load_user_roles[UP: SQLAlchemyUserModelProtocol](engine: Engine, *, user_model: type[UP], email: str) -> list[str]:
    """Return one user's persisted normalized roles."""
    with SASession(engine, expire_on_commit=False) as session:
        user = session.scalar(select(user_model).where(cast("Any", user_model).email == email))
        assert user is not None
        return list(cast("Any", user).roles)


def _load_role_catalog(engine: Engine, *, role_model: type[Any]) -> list[str]:
    """Return the persisted normalized role catalog for one model family."""
    with SASession(engine, expire_on_commit=False) as session:
        return list(
            session.execute(select(cast("Any", role_model).name).order_by(cast("Any", role_model).name)).scalars(),
        )


def _run_async[T](awaitable: Coroutine[Any, Any, T]) -> T:
    """Drive one async helper from a sync CLI integration test.

    Returns:
        The result produced by ``awaitable``.
    """
    return asyncio.run(awaitable)


def _open_fake_aiosqlite_connection(database_path: str) -> _FakeAioSQLiteConnection:
    """Open one SQLite connection wrapped in the fake async driver surface.

    Returns:
        Wrapped SQLite connection exposing the async driver surface SQLAlchemy expects.
    """
    connection = sqlite3.connect(database_path, check_same_thread=False)
    connection.execute("PRAGMA foreign_keys=ON")
    return _FakeAioSQLiteConnection(connection)


async def _async_create_tables(
    database: _AsyncRoleCLIDatabase,
    *,
    user_model: type[Any],
) -> None:
    """Create the mapped tables for one custom model family."""
    async with database.engine.begin() as connection:
        await connection.run_sync(cast("Any", user_model).metadata.create_all)


async def _async_create_user[UP: SQLAlchemyUserModelProtocol](
    session_maker: async_sessionmaker[AsyncSession],
    *,
    user_model: type[UP],
    email: str,
    roles: list[str],
) -> None:
    """Insert one user into a real AsyncSession-backed test database."""
    async with session_maker() as session:
        session.add(cast("Any", user_model)(email=email, hashed_password="hashed-password", roles=roles))
        await session.commit()


async def _async_load_user_roles[UP: SQLAlchemyUserModelProtocol](
    session_maker: async_sessionmaker[AsyncSession],
    *,
    user_model: type[UP],
    email: str,
) -> list[str]:
    """Return one user's persisted normalized roles from a real AsyncSession path."""
    async with session_maker() as session:
        statement = (
            select(user_model)
            .options(selectinload(cast("Any", user_model).role_assignments))
            .where(cast("Any", user_model).email == email)
        )
        user = await session.scalar(statement)
        assert user is not None
        return list(cast("Any", user).roles)


async def _async_load_role_catalog(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    role_model: type[Any],
) -> list[str]:
    """Return the persisted normalized role catalog from a real AsyncSession path."""
    async with session_maker() as session:
        statement = select(cast("Any", role_model).name).order_by(cast("Any", role_model).name)
        return list(cast("Any", await session.scalars(statement)))


def _build_custom_role_models(
    *,
    user_role_relationship_lazy: str = "selectin",
) -> tuple[type[Any], type[Any], type[Any]]:
    """Create one custom SQLAlchemy role-capable model family for CLI coverage.

    Returns:
        The custom user, role, and user-role association models.
    """

    class CustomRolesBase(DeclarativeBase):
        """Dedicated registry for custom role-cli integration tests."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class CustomRolesUUIDBase(UUIDPrimaryKey, CustomRolesBase):
        """UUID base for custom role-cli integration tests."""

        __abstract__ = True

    class CustomRolesUser(UserModelMixin, UserRoleRelationshipMixin, CustomRolesUUIDBase):
        """Custom user model using the shared relational role contract."""

        __tablename__ = "custom_cli_user"
        auth_user_role_model = "CustomRolesUserRole"
        auth_user_role_relationship_lazy = user_role_relationship_lazy

    class CustomRole(RoleMixin, CustomRolesBase):
        """Custom global role catalog row."""

        __tablename__ = "custom_cli_role"
        auth_user_role_model = "CustomRolesUserRole"

    class CustomRolesUserRole(UserRoleAssociationMixin, CustomRolesBase):
        """Custom user-role association row."""

        __tablename__ = "custom_cli_user_role"
        auth_user_model = "CustomRolesUser"
        auth_user_table = "custom_cli_user"
        auth_role_model = "CustomRole"
        auth_role_table = "custom_cli_role"

    return CustomRolesUser, CustomRole, CustomRolesUserRole


@pytest.fixture
def engine() -> Iterator[Engine]:
    """Create a SQLite engine suitable for repeated CLI-managed sessions.

    Yields:
        SQLite engine with foreign keys enabled.
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

    yield engine
    engine.dispose()


@pytest.fixture
def roles_cli(engine: Engine) -> Group:
    """Create the plugin-owned roles CLI group bound to the SQLite test engine.

    Returns:
        Root CLI group with the plugin-owned ``roles`` commands registered.
    """
    User.metadata.create_all(engine)
    return _build_roles_cli(engine, user_model=User)


@pytest.fixture
def async_role_cli_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_AsyncRoleCLIDatabase]:
    """Create a real AsyncSession-backed SQLite database for CLI regression coverage.

    Yields:
        Async engine and session maker backed by SQLAlchemy's real AsyncSession.
    """
    monkeypatch.setitem(sys.modules, "aiosqlite", _build_fake_aiosqlite_module())
    database_path = tmp_path / "role-cli-async.sqlite"

    async def _create_connection() -> _FakeAioSQLiteConnection:
        return await asyncio.to_thread(_open_fake_aiosqlite_connection, str(database_path))

    async_engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path}",
        async_creator=_create_connection,
    )
    yield _AsyncRoleCLIDatabase(
        engine=async_engine,
        session_maker=async_sessionmaker(async_engine, expire_on_commit=False),
    )
    _run_async(async_engine.dispose())


def test_role_catalog_commands_list_create_duplicate_and_delete_unassigned_role(
    roles_cli: Group,
    engine: Engine,
) -> None:
    """Catalog commands normalize role names, avoid duplicates, and delete unassigned roles."""
    runner = CliRunner()

    initial_list_result = runner.invoke(roles_cli, ["roles", "list"])
    create_result = runner.invoke(roles_cli, ["roles", "create", " Billing "])
    duplicate_create_result = runner.invoke(roles_cli, ["roles", "create", "billing"])

    assert initial_list_result.exit_code == 0
    assert initial_list_result.output == "[]\n"
    assert create_result.exit_code == 0
    assert create_result.output == "['billing']\n"
    assert duplicate_create_result.exit_code == 0
    assert duplicate_create_result.output == "['billing']\n"
    assert _load_role_catalog(engine, role_model=Role) == ["billing"]

    delete_result = runner.invoke(roles_cli, ["roles", "delete", "BILLING"])
    final_list_result = runner.invoke(roles_cli, ["roles", "list"])
    missing_delete_result = runner.invoke(roles_cli, ["roles", "delete", "billing"])

    assert delete_result.exit_code == 0
    assert delete_result.output == "[]\n"
    assert final_list_result.exit_code == 0
    assert final_list_result.output == "[]\n"
    assert _load_role_catalog(engine, role_model=Role) == []
    assert missing_delete_result.exit_code == 1
    assert "Role admin could not find role 'billing' in the configured catalog." in missing_delete_result.output
    assert "Traceback" not in missing_delete_result.output


def test_role_catalog_delete_without_force_fails_when_assignments_exist(roles_cli: Group, engine: Engine) -> None:
    """Deleting an assigned role fails closed unless ``--force`` removes the dependent assignments."""
    _create_user(engine, user_model=User, email="member@example.com", roles=["admin", "billing"])
    _create_user(engine, user_model=User, email="auditor@example.com", roles=["admin"])
    runner = CliRunner()

    refused_result = runner.invoke(roles_cli, ["roles", "delete", " Admin "])

    # Normalize rich panel output: strip ANSI codes and collapse whitespace so
    # assertions are not sensitive to terminal-width-dependent line wrapping.
    refused_output_normalized = " ".join(click.unstyle(refused_result.output).split())
    assert refused_result.exit_code == 1
    assert "Role admin will not delete role 'admin' while assignments still exist." in refused_output_normalized
    assert "Re-run with --force to remove dependent user-role assignments." in refused_output_normalized
    assert "Traceback" not in refused_result.output
    assert _load_role_catalog(engine, role_model=Role) == ["admin", "billing"]
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["admin", "billing"]
    assert _load_user_roles(engine, user_model=User, email="auditor@example.com") == ["admin"]

    forced_result = runner.invoke(roles_cli, ["roles", "delete", "--force", "admin"])

    assert forced_result.exit_code == 0
    assert forced_result.output == "['billing']\n"
    assert _load_role_catalog(engine, role_model=Role) == ["billing"]
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["billing"]
    assert _load_user_roles(engine, user_model=User, email="auditor@example.com") == []


def test_role_catalog_commands_support_custom_role_tables(engine: Engine) -> None:
    """Catalog commands resolve custom role-table names instead of assuming bundled tables."""
    custom_user_model, custom_role_model, _custom_user_role_model = _build_custom_role_models()
    custom_user_model.metadata.create_all(engine)
    custom_roles_cli = _build_roles_cli(engine, user_model=custom_user_model)
    _create_user(engine, user_model=custom_user_model, email="custom@example.com", roles=[" Support "])
    runner = CliRunner()

    initial_list_result = runner.invoke(custom_roles_cli, ["roles", "list"])
    create_result = runner.invoke(custom_roles_cli, ["roles", "create", " Admin "])

    assert initial_list_result.exit_code == 0
    assert initial_list_result.output == "['support']\n"
    assert create_result.exit_code == 0
    assert create_result.output == "['admin', 'support']\n"
    assert _load_role_catalog(engine, role_model=custom_role_model) == ["admin", "support"]

    delete_result = runner.invoke(custom_roles_cli, ["roles", "delete", "admin"])

    assert delete_result.exit_code == 0
    assert delete_result.output == "['support']\n"
    assert _load_role_catalog(engine, role_model=custom_role_model) == ["support"]


def test_role_user_commands_support_custom_role_tables(engine: Engine) -> None:
    """User-role commands resolve custom relational role tables for mutation and reads."""
    custom_user_model, custom_role_model, _custom_user_role_model = _build_custom_role_models()
    custom_user_model.metadata.create_all(engine)
    custom_roles_cli = _build_roles_cli(engine, user_model=custom_user_model)
    _create_user(engine, user_model=custom_user_model, email="custom-member@example.com", roles=[" Support "])
    runner = CliRunner()

    assign_result = runner.invoke(
        custom_roles_cli,
        ["roles", "assign", "--email", "custom-member@example.com", " Billing ", "admin", "ADMIN"],
    )

    assert assign_result.exit_code == 0
    assert assign_result.output == "custom-member@example.com: ['admin', 'billing', 'support']\n"
    assert _load_user_roles(engine, user_model=custom_user_model, email="custom-member@example.com") == [
        "admin",
        "billing",
        "support",
    ]
    assert _load_role_catalog(engine, role_model=custom_role_model) == ["admin", "billing", "support"]

    show_result = runner.invoke(custom_roles_cli, ["roles", "show-user", "--email", "custom-member@example.com"])

    assert show_result.exit_code == 0
    assert show_result.output == "custom-member@example.com: ['admin', 'billing', 'support']\n"

    unassign_result = runner.invoke(
        custom_roles_cli,
        ["roles", "unassign", "--email", "custom-member@example.com", " Billing ", "support", "SUPPORT"],
    )

    assert unassign_result.exit_code == 0
    assert unassign_result.output == "custom-member@example.com: ['admin']\n"
    assert _load_user_roles(engine, user_model=custom_user_model, email="custom-member@example.com") == ["admin"]
    assert _load_role_catalog(engine, role_model=custom_role_model) == ["admin", "billing", "support"]


def test_custom_lazy_role_assign_show_and_unassign_commands_avoid_implicit_loads(engine: Engine) -> None:
    """Custom lazy-select role models keep CLI membership reads on explicit SQL paths."""
    custom_user_model, custom_role_model, _custom_user_role_model = _build_custom_role_models(
        user_role_relationship_lazy="",
    )
    custom_user_model.metadata.create_all(engine)
    custom_roles_cli = _build_roles_cli(
        engine,
        user_model=custom_user_model,
        session_maker=_build_adapter_session_maker(engine, session_class=_ImplicitAsyncIOSession),
    )
    _create_user(engine, user_model=custom_user_model, email="custom-member@example.com", roles=[" Support "])
    runner = CliRunner()

    assign_result = runner.invoke(
        custom_roles_cli,
        ["roles", "assign", "--email", "custom-member@example.com", " Billing ", "admin", "ADMIN"],
    )

    assert assign_result.exit_code == 0
    assert assign_result.output == "custom-member@example.com: ['admin', 'billing', 'support']\n"

    show_result = runner.invoke(custom_roles_cli, ["roles", "show-user", "--email", "custom-member@example.com"])

    assert show_result.exit_code == 0
    assert show_result.output == "custom-member@example.com: ['admin', 'billing', 'support']\n"

    unassign_result = runner.invoke(
        custom_roles_cli,
        ["roles", "unassign", "--email", "custom-member@example.com", " Billing ", "support", "SUPPORT"],
    )

    assert unassign_result.exit_code == 0
    assert unassign_result.output == "custom-member@example.com: ['admin']\n"
    assert _load_user_roles(engine, user_model=custom_user_model, email="custom-member@example.com") == ["admin"]
    assert _load_role_catalog(engine, role_model=custom_role_model) == ["admin", "billing", "support"]


def test_custom_lazy_role_delete_force_avoids_implicit_loads_and_preserves_hooks(engine: Engine) -> None:
    """Forced delete stays CLI-safe for custom lazy-select role models and keeps lifecycle hooks."""
    custom_user_model, custom_role_model, _custom_user_role_model = _build_custom_role_models(
        user_role_relationship_lazy="",
    )
    custom_user_model.metadata.create_all(engine)
    custom_roles_cli, update_events = _build_tracking_roles_cli(
        engine,
        user_model=custom_user_model,
        session_maker=_build_adapter_session_maker(engine, session_class=_ImplicitAsyncIOSession),
    )
    _create_user(engine, user_model=custom_user_model, email="member@example.com", roles=["admin", "billing"])
    _create_user(engine, user_model=custom_user_model, email="auditor@example.com", roles=["admin"])
    runner = CliRunner()

    result = runner.invoke(custom_roles_cli, ["roles", "delete", "--force", "admin"])

    assert result.exit_code == 0
    assert result.output == "['billing']\n"
    assert update_events == [
        _RoleLifecycleEvent(email="auditor@example.com", roles=[]),
        _RoleLifecycleEvent(email="member@example.com", roles=["billing"]),
    ]
    assert _load_role_catalog(engine, role_model=custom_role_model) == ["billing"]
    assert _load_user_roles(engine, user_model=custom_user_model, email="auditor@example.com") == []
    assert _load_user_roles(engine, user_model=custom_user_model, email="member@example.com") == ["billing"]


def test_custom_async_role_assign_show_and_unassign_commands_avoid_implicit_loads(
    async_role_cli_database: _AsyncRoleCLIDatabase,
) -> None:
    """Custom lazy-select role models stay CLI-safe on a real AsyncSession path."""
    custom_user_model, custom_role_model, _custom_user_role_model = _build_custom_role_models(
        user_role_relationship_lazy="",
    )
    _run_async(_async_create_tables(async_role_cli_database, user_model=custom_user_model))
    custom_roles_cli = _build_roles_cli(
        engine=None,
        user_model=custom_user_model,
        session_maker=async_role_cli_database.session_maker,
    )
    _run_async(
        _async_create_user(
            async_role_cli_database.session_maker,
            user_model=custom_user_model,
            email="custom-member@example.com",
            roles=[" Support "],
        ),
    )
    runner = CliRunner()

    assign_result = runner.invoke(
        custom_roles_cli,
        ["roles", "assign", "--email", "custom-member@example.com", " Billing ", "admin", "ADMIN"],
    )

    assert assign_result.exit_code == 0
    assert assign_result.output == "custom-member@example.com: ['admin', 'billing', 'support']\n"

    show_result = runner.invoke(custom_roles_cli, ["roles", "show-user", "--email", "custom-member@example.com"])

    assert show_result.exit_code == 0
    assert show_result.output == "custom-member@example.com: ['admin', 'billing', 'support']\n"

    unassign_result = runner.invoke(
        custom_roles_cli,
        ["roles", "unassign", "--email", "custom-member@example.com", " Billing ", "support", "SUPPORT"],
    )

    assert unassign_result.exit_code == 0
    assert unassign_result.output == "custom-member@example.com: ['admin']\n"
    assert _run_async(
        _async_load_user_roles(
            async_role_cli_database.session_maker,
            user_model=custom_user_model,
            email="custom-member@example.com",
        ),
    ) == ["admin"]
    assert _run_async(
        _async_load_role_catalog(async_role_cli_database.session_maker, role_model=custom_role_model),
    ) == ["admin", "billing", "support"]


def test_custom_async_role_delete_force_avoids_implicit_loads_and_preserves_hooks(
    async_role_cli_database: _AsyncRoleCLIDatabase,
) -> None:
    """Forced delete stays CLI-safe for custom lazy-select models on a real AsyncSession path."""
    custom_user_model, custom_role_model, _custom_user_role_model = _build_custom_role_models(
        user_role_relationship_lazy="",
    )
    _run_async(_async_create_tables(async_role_cli_database, user_model=custom_user_model))
    custom_roles_cli, update_events = _build_tracking_roles_cli(
        engine=None,
        user_model=custom_user_model,
        session_maker=async_role_cli_database.session_maker,
    )
    _run_async(
        _async_create_user(
            async_role_cli_database.session_maker,
            user_model=custom_user_model,
            email="member@example.com",
            roles=["admin", "billing"],
        ),
    )
    _run_async(
        _async_create_user(
            async_role_cli_database.session_maker,
            user_model=custom_user_model,
            email="auditor@example.com",
            roles=["admin"],
        ),
    )
    runner = CliRunner()

    result = runner.invoke(custom_roles_cli, ["roles", "delete", "--force", "admin"])

    assert result.exit_code == 0
    assert result.output == "['billing']\n"
    assert update_events == [
        _RoleLifecycleEvent(email="auditor@example.com", roles=[]),
        _RoleLifecycleEvent(email="member@example.com", roles=["billing"]),
    ]
    assert _run_async(
        _async_load_role_catalog(async_role_cli_database.session_maker, role_model=custom_role_model),
    ) == ["billing"]
    assert (
        _run_async(
            _async_load_user_roles(
                async_role_cli_database.session_maker,
                user_model=custom_user_model,
                email="auditor@example.com",
            ),
        )
        == []
    )
    assert _run_async(
        _async_load_user_roles(
            async_role_cli_database.session_maker,
            user_model=custom_user_model,
            email="member@example.com",
        ),
    ) == ["billing"]


def test_roles_assign_command_adds_new_and_existing_normalized_roles(roles_cli: Group, engine: Engine) -> None:
    """Assigning roles normalizes input, adds missing roles, and is idempotent."""
    _create_user(engine, user_model=User, email="member@example.com", roles=["member"])
    runner = CliRunner()

    first_result = runner.invoke(
        roles_cli,
        ["roles", "assign", "--email", "member@example.com", " Billing ", "admin", "ADMIN"],
    )

    assert first_result.exit_code == 0
    assert first_result.output == "member@example.com: ['admin', 'billing', 'member']\n"
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["admin", "billing", "member"]

    second_result = runner.invoke(
        roles_cli,
        ["roles", "assign", "--email", "member@example.com", "member", "ADMIN"],
    )

    assert second_result.exit_code == 0
    assert second_result.output == "member@example.com: ['admin', 'billing', 'member']\n"
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["admin", "billing", "member"]


def test_roles_unassign_command_removes_only_requested_roles_and_is_idempotent(
    roles_cli: Group,
    engine: Engine,
) -> None:
    """Unassigning roles leaves unrelated membership unchanged and tolerates repeats."""
    _create_user(engine, user_model=User, email="member@example.com", roles=["member", "admin", "billing"])
    runner = CliRunner()

    first_result = runner.invoke(
        roles_cli,
        ["roles", "unassign", "--email", "member@example.com", " Billing ", "support"],
    )

    assert first_result.exit_code == 0
    assert first_result.output == "member@example.com: ['admin', 'member']\n"
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["admin", "member"]

    second_result = runner.invoke(
        roles_cli,
        ["roles", "unassign", "--email", "member@example.com", "billing", "support"],
    )

    assert second_result.exit_code == 0
    assert second_result.output == "member@example.com: ['admin', 'member']\n"
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["admin", "member"]


def test_roles_show_user_command_reports_normalized_roles_and_missing_emails_fail(
    roles_cli: Group,
    engine: Engine,
) -> None:
    """The read command reports persisted normalized roles and missing users fail clearly."""
    _create_user(engine, user_model=User, email="viewer@example.com", roles=[" Billing ", "admin", "ADMIN"])
    runner = CliRunner()

    show_result = runner.invoke(roles_cli, ["roles", "show-user", "--email", "viewer@example.com"])

    assert show_result.exit_code == 0
    assert show_result.output == "viewer@example.com: ['admin', 'billing']\n"

    missing_result = runner.invoke(roles_cli, ["roles", "show-user", "--email", "missing@example.com"])

    assert missing_result.exit_code == 1
    assert "Role admin could not find a user with email 'missing@example.com'." in missing_result.output
    assert "Traceback" not in missing_result.output


def test_roles_assign_command_dispatches_manager_hook_with_normalized_roles(engine: Engine) -> None:
    """Assigning roles emits the normalized lifecycle payload through ``on_after_update()``."""
    User.metadata.create_all(engine)
    roles_cli, update_events = _build_tracking_roles_cli(engine, user_model=User)
    _create_user(engine, user_model=User, email="member@example.com", roles=["member"])
    runner = CliRunner()

    result = runner.invoke(
        roles_cli,
        ["roles", "assign", "--email", "member@example.com", " Billing ", "admin", "ADMIN"],
    )

    assert result.exit_code == 0
    assert result.output == "member@example.com: ['admin', 'billing', 'member']\n"
    assert update_events == [
        _RoleLifecycleEvent(email="member@example.com", roles=["admin", "billing", "member"]),
    ]
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["admin", "billing", "member"]
    assert _load_role_catalog(engine, role_model=Role) == ["admin", "billing", "member"]


def test_roles_unassign_command_dispatches_manager_hook_with_normalized_roles(engine: Engine) -> None:
    """Unassigning roles emits the remaining normalized membership through ``on_after_update()``."""
    User.metadata.create_all(engine)
    roles_cli, update_events = _build_tracking_roles_cli(engine, user_model=User)
    _create_user(engine, user_model=User, email="member@example.com", roles=["member", "admin", "billing"])
    runner = CliRunner()

    result = runner.invoke(
        roles_cli,
        ["roles", "unassign", "--email", "member@example.com", " Billing ", "support"],
    )

    assert result.exit_code == 0
    assert result.output == "member@example.com: ['admin', 'member']\n"
    assert update_events == [
        _RoleLifecycleEvent(email="member@example.com", roles=["admin", "member"]),
    ]
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["admin", "member"]
    assert _load_role_catalog(engine, role_model=Role) == ["admin", "billing", "member"]


def test_forced_role_delete_dispatches_manager_hooks_for_each_affected_user(engine: Engine) -> None:
    """Forced catalog deletion updates every affected user through the manager lifecycle."""
    User.metadata.create_all(engine)
    roles_cli, update_events = _build_tracking_roles_cli(engine, user_model=User)
    _create_user(engine, user_model=User, email="member@example.com", roles=["admin", "billing"])
    _create_user(engine, user_model=User, email="auditor@example.com", roles=["admin"])
    runner = CliRunner()

    result = runner.invoke(roles_cli, ["roles", "delete", "--force", "admin"])

    assert result.exit_code == 0
    assert result.output == "['billing']\n"
    assert update_events == [
        _RoleLifecycleEvent(email="auditor@example.com", roles=[]),
        _RoleLifecycleEvent(email="member@example.com", roles=["billing"]),
    ]
    assert _load_role_catalog(engine, role_model=Role) == ["billing"]
    assert _load_user_roles(engine, user_model=User, email="auditor@example.com") == []
    assert _load_user_roles(engine, user_model=User, email="member@example.com") == ["billing"]
