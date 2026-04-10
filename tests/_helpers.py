"""Shared test-only helper models and Redis test utilities."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Literal, Protocol, cast

from litestar import Litestar
from litestar.di import Provide

from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterable, Sequence
    from types import ModuleType
    from uuid import UUID

    import fakeredis
    from fakeredis import FakeAsyncRedis as AsyncFakeRedis
    from litestar.datastructures.state import State
    from litestar.types import ControllerRouterHandler, Middleware, Scope
    from sqlalchemy.ext.asyncio import AsyncSession

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


def auth_middleware_get_request_session(session_maker: object) -> Callable[[State, Scope], AsyncSession]:
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
    is_superuser: bool = False
    totp_secret: str | None = None
    login_hint: str = ""
    bio: str = ""
