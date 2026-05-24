"""Integration tests for Advanced Alchemy and LitestarAuth request session sharing."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest
from advanced_alchemy.config import AsyncSessionConfig
from advanced_alchemy.extensions.litestar import SQLAlchemyAsyncConfig, SQLAlchemyPlugin
from advanced_alchemy.extensions.litestar._utils import get_aa_scope_state
from litestar import Litestar, Request, get
from litestar.testing import AsyncTestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from litestar_auth._plugin.advanced_alchemy import bind_auth_session_to_alchemy
from litestar_auth._plugin.config import DatabaseTokenAuthConfig
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import SessionMaker as E2ESessionMaker
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.conftest import enable_aiosqlite_foreign_keys
from tests.integration.test_orchestrator import ExampleUser, InMemoryUserDatabase, PluginUserManager

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator
    from pathlib import Path

    from litestar.handlers import HTTPRouteHandler
    from sqlalchemy.engine import Engine

    from litestar_auth._plugin.scoped_session import SessionFactory

pytestmark = pytest.mark.integration

HTTP_OK = 200


@contextmanager
def _disposing_engine(engine: Engine) -> Iterator[Engine]:
    """Yield ``engine`` and dispose it on exit."""
    try:
        yield engine
    finally:
        engine.dispose()


def _aa_auth_session_probe(session_scope_key: str) -> HTTPRouteHandler:
    """Build a route that compares handler DI with AA scope session identity.

    Returns:
        Litestar route handler registered at ``/aa-auth-session-probe``.
    """

    @get("/aa-auth-session-probe", sync_to_thread=False)
    def probe(
        request: Request[Any, Any, Any],
        db_session: object,
    ) -> dict[str, bool]:
        """Expose whether handler DI and AA scope state reference the same session.

        Returns:
            Flags comparing the injected session with the AA scope namespace entry.
        """
        scope_session = get_aa_scope_state(request.scope, session_scope_key)
        return {"scope_matches_handler": scope_session is db_session}

    return probe


def _build_coexistence_app(
    *,
    session_maker: SessionFactory,
    connection_string: str = "sqlite+aiosqlite:///:memory:",
) -> Litestar:
    alchemy_config = SQLAlchemyAsyncConfig(
        connection_string=connection_string,
        session_config=AsyncSessionConfig(expire_on_commit=False),
        before_send_handler="autocommit",
        session_maker=session_maker,
    )
    auth_session = bind_auth_session_to_alchemy(alchemy_config, session_maker=session_maker)
    auth_config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="0123456789abcdef" * 4,
            backend_name="opaque-db",
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=auth_session.session_maker,
        session_scope_key=auth_session.session_scope_key,
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
        enable_refresh=False,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
    )
    return Litestar(
        route_handlers=[_aa_auth_session_probe(alchemy_config.session_scope_key)],
        plugins=[SQLAlchemyPlugin(config=alchemy_config), LitestarAuth(auth_config)],
    )


async def test_litestar_auth_shares_request_session_with_sqlalchemy_plugin() -> None:
    """``LitestarAuth`` and ``SQLAlchemyPlugin`` reuse one session per request via AA scope state."""
    with _disposing_engine(
        create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        ),
    ) as engine:
        session_maker = assert_structural_session_factory(E2ESessionMaker(engine))
        app = _build_coexistence_app(session_maker=session_maker)
        async with AsyncTestClient(app=app) as client:
            response = await client.get("/aa-auth-session-probe")

    assert response.status_code == HTTP_OK
    assert response.json() == {"scope_matches_handler": True}


@pytest.fixture
async def aa_async_session_maker(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Provide a real ``async_sessionmaker`` backed by ``aiosqlite``.

    Yields:
        Async session maker using SQLAlchemy's native ``AsyncSession`` implementation.
    """
    database_path = tmp_path / "aa-coexistence.sqlite"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    enable_aiosqlite_foreign_keys(engine)
    try:
        yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    finally:
        await engine.dispose()


async def test_litestar_auth_shares_request_session_with_sqlalchemy_plugin_via_async_sessionmaker(
    aa_async_session_maker: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Production-style ``async_sessionmaker`` wiring shares one scoped session per request."""
    connection_string = f"sqlite+aiosqlite:///{tmp_path / 'aa-coexistence.sqlite'}"
    app = _build_coexistence_app(
        session_maker=aa_async_session_maker,
        connection_string=connection_string,
    )
    async with AsyncTestClient(app=app) as client:
        response = await client.get("/aa-auth-session-probe")

    assert response.status_code == HTTP_OK
    assert response.json() == {"scope_matches_handler": True}
