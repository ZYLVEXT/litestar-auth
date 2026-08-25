"""Integration coverage for the docs quickstart example."""

from __future__ import annotations

import importlib
import sys
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from tests._helpers import FakeAioSQLiteConnection, build_fake_aiosqlite_module, open_fake_aiosqlite_connection

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from contextlib import AbstractAsyncContextManager
    from types import ModuleType

    from litestar import Litestar
    from litestar.testing import AsyncTestClient

MODULE_NAME = "docs.snippets.quickstart_plugin"
HTTP_CREATED = 201
HTTP_OK = 200
REPO_ROOT = Path(__file__).resolve().parents[2]

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
    monkeypatch.setenv("LITESTAR_AUTH_SESSION_HASH_SECRET", "test-session-secret-1234567890-1234567890")
    monkeypatch.setenv("LITESTAR_AUTH_CSRF_SECRET", "test_CSRF-9fG2!xQ7#nM4$vB8@kL6%pR3&wT5")
    monkeypatch.setenv(
        "LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET", "6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8"
    )
    monkeypatch.setenv(
        "LITESTAR_AUTH_VERIFY_TOKEN_SECRET", "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe"
    )
    sys.modules.pop(MODULE_NAME, None)
    monkeypatch.setitem(sys.modules, "aiosqlite", build_fake_aiosqlite_module())

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
        csrf_response = await test_client.get("/protected")
        csrf_token = csrf_response.cookies.get("litestar_auth_csrf")
        assert csrf_token is not None
        csrf_headers = {"X-CSRF-Token": csrf_token}

        register_response = await test_client.post(
            "/auth/register",
            json={"email": email, "password": password},
            headers=csrf_headers,
        )
        assert register_response.status_code == HTTP_CREATED
        assert register_response.json()["email"] == email
        assert register_response.json()["is_verified"] is False

        verify_response = await test_client.post(
            "/auth/verify",
            json={"token": module.UserManager.verification_tokens[email]},
            headers=csrf_headers,
        )
        assert verify_response.status_code == HTTP_OK
        assert verify_response.json()["is_verified"] is True

        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": email, "password": password},
            headers=csrf_headers,
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.cookies.get("litestar_auth")

        protected_response = await test_client.get(
            "/protected",
            headers={"Cookie": f"litestar_auth={access_token}"},
        )
        assert protected_response.status_code == HTTP_OK
        assert protected_response.json() == {"email": email}


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so the documented secure session cookie is exercised.

    Returns:
        HTTPS test origin.
    """
    return "https://testserver.local"
