"""Shared helpers for end-to-end tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, Self, cast

from sqlalchemy.orm import Session as SASession

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
    from types import TracebackType

    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.sql.base import Executable


class SupportsRequestSessionLifecycle(Protocol):
    """Structural contract for request-managed session objects used by the plugin."""

    async def commit(self) -> None:
        """Commit the current request-scoped unit of work."""

    async def rollback(self) -> None:
        """Roll back the current request-scoped unit of work."""

    async def close(self) -> None:
        """Release request-scoped session resources."""


class SupportsRequestSessionFactory(Protocol):
    """Structural contract for plugin-compatible request session factories."""

    def __call__(self) -> SupportsRequestSessionLifecycle:
        """Return a request-scoped session object."""


def assert_structural_session_factory[T: SupportsRequestSessionFactory](factory: T) -> T:
    """Preserve a concrete factory type while asserting the plugin's runtime contract.

    Returns:
        The same factory, narrowed only by the structural compatibility check.
    """
    return factory


class AsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped sync session."""
        self._session = session
        self.info: dict[str, Any] = {}

    async def __aenter__(self) -> Self:
        """Match :class:`AsyncSession` (``async with session_maker()``).

        Returns:
            This adapter instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close when leaving ``async with`` (mirrors SQLAlchemy ``AsyncSession``).

        The in-process test stack does not use Advanced Alchemy's request lifecycle hooks, so
        commit/rollback is handled here to keep transaction boundaries aligned with a typical
        Unit-of-Work pattern.
        """
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        del exc_type, exc, traceback
        await self.close()

    @property
    def bind(self) -> Engine | Connection | None:
        """Expose the wrapped session bind."""
        return self._session.bind

    def get_bind(self) -> Engine | Connection:
        """Expose the wrapped session bind via SQLAlchemy's API.

        Returns:
            The bound connectable.
        """
        return self._session.get_bind()

    @property
    def no_autoflush(self) -> object:
        """Expose the wrapped session no-autoflush context manager."""
        return self._session.no_autoflush

    def add(self, instance: object) -> None:
        """Add an instance to the session."""
        self._session.add(instance)

    def add_all(self, instances: Sequence[object]) -> None:
        """Add multiple instances to the session."""
        self._session.add_all(instances)

    def expunge(self, instance: object) -> None:
        """Expunge an instance from the session."""
        self._session.expunge(instance)

    async def commit(self) -> None:
        """Commit the current transaction."""
        self._session.commit()

    async def delete(self, instance: object) -> None:
        """Delete an instance from the session."""
        self._session.delete(instance)

    async def execute(
        self,
        statement: Executable,
        params: Mapping[str, object] | Sequence[Mapping[str, object]] | None = None,
        *,
        execution_options: Mapping[str, object] | None = None,
    ) -> object:
        """Execute a SQL statement.

        Returns:
            SQLAlchemy execution result.
        """
        sync_session = cast("Any", self._session)
        return cast("object", sync_session.execute(statement, params=params, execution_options=execution_options))

    async def flush(self) -> None:
        """Flush pending changes."""
        self._session.flush()

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Merge an instance into the session.

        Returns:
            The merged instance.
        """
        return self._session.merge(instance, load=load)

    async def refresh(
        self,
        instance: object,
        *,
        attribute_names: Iterable[str] | None = None,
        with_for_update: ForUpdateParameter = None,
    ) -> None:
        """Refresh an instance from the database."""
        self._session.refresh(instance, attribute_names=attribute_names, with_for_update=with_for_update)

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        self._session.rollback()

    async def close(self) -> None:
        """Close the underlying sync session (``before_send`` / AA lifecycle)."""
        self._session.close()


class SessionMaker:
    """Callable session factory compatible with the auth plugin."""

    def __init__(self, engine: Engine) -> None:
        """Store the shared engine."""
        self._engine = engine

    def __call__(self) -> AsyncSession:
        """Return a new session (same contract as :class:`async_sessionmaker`)."""
        return cast(
            "AsyncSession",
            AsyncSessionAdapter(SASession(self._engine, expire_on_commit=False)),
        )
