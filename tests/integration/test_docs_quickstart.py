"""Integration coverage for the docs quickstart example."""

from __future__ import annotations

import importlib
import sys
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from litestar_auth.totp import SecurityWarning
from tests._helpers import FakeAioSQLiteConnection, build_fake_aiosqlite_module, open_fake_aiosqlite_connection

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from contextlib import AbstractAsyncContextManager
    from pathlib import Path
    from types import ModuleType

    from litestar import Litestar
    from litestar.testing import AsyncTestClient

MODULE_NAME = "docs.snippets.quickstart_plugin"
HTTP_CREATED = 201
HTTP_OK = 200

pytestmark = [pytest.mark.integration]


@pytest.fixture
async def quickstart_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[ModuleType, Litestar]]:
    """Import the quickstart module against an isolated SQLite working directory.

    Yields:
        The imported quickstart module and a Litestar app rebound to the isolated test database.
    """
    monkeypatch.chdir(tmp_path)
    sys.modules.pop(MODULE_NAME, None)
    monkeypatch.setitem(sys.modules, "aiosqlite", build_fake_aiosqlite_module())

    with pytest.warns(SecurityWarning, match="process-local in-memory denylist"):
        module = importlib.import_module(MODULE_NAME)

    database_path = tmp_path / "quickstart.db"

    async def _create_connection() -> FakeAioSQLiteConnection:
        return await open_fake_aiosqlite_connection(str(database_path))

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path}",
        async_creator=_create_connection,
    )
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    config = replace(module.config, session_maker=session_maker)
    with pytest.warns(SecurityWarning, match="process-local in-memory denylist"):
        app = module.Litestar(route_handlers=[module.protected], plugins=[module.LitestarAuth(config)])

    module.UserManager.verification_tokens.clear()
    async with engine.begin() as connection:
        await connection.run_sync(module.User.metadata.create_all)

    try:
        yield module, app
    finally:
        module.UserManager.verification_tokens.clear()
        await engine.dispose()
        sys.modules.pop(MODULE_NAME, None)


async def test_quickstart_example_register_verify_login_and_hits_protected_route(
    quickstart_module: tuple[ModuleType, Litestar],
    async_test_client_factory: Callable[[Litestar], AbstractAsyncContextManager[AsyncTestClient[Litestar]]],
) -> None:
    """The documented quickstart app supports the full register/verify/login flow."""
    module, app = quickstart_module

    async with async_test_client_factory(app) as client:
        test_client = client
        email = "quickstart@example.com"
        password = "correct horse battery staple"

        register_response = await test_client.post(
            "/auth/register",
            json={"email": email, "password": password},
        )
        assert register_response.status_code == HTTP_CREATED
        assert register_response.json()["email"] == email
        assert register_response.json()["is_verified"] is False

        verify_response = await test_client.post(
            "/auth/verify",
            json={"token": module.UserManager.verification_tokens[email]},
        )
        assert verify_response.status_code == HTTP_OK
        assert verify_response.json()["is_verified"] is True

        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": email, "password": password},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        protected_response = await test_client.get(
            "/protected",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert protected_response.status_code == HTTP_OK
        assert protected_response.json() == {"email": email}
