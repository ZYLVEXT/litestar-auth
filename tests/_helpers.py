"""Shared test-only helper models."""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, cast

from litestar import Litestar
from litestar.di import Provide

from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Sequence
    from uuid import UUID

    from litestar.datastructures.state import State
    from litestar.types import ControllerRouterHandler, Middleware, Scope
    from sqlalchemy.ext.asyncio import AsyncSession


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
