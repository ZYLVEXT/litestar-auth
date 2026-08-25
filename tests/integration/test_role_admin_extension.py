"""End-to-end coverage for mounting role-admin through the first-party extension."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Litestar
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session as SASession
from sqlalchemy.pool import StaticPool

from litestar_auth.authentication.transport.cookie import CookieTransportConfig
from litestar_auth.contrib.role_admin import RoleAdminExtension
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from tests.integration.test_contrib_role_admin import RoleAdminTestUserManager, SessionMaker, _login_headers

if TYPE_CHECKING:
    from collections.abc import Iterator

    from litestar.testing import AsyncTestClient


pytestmark = pytest.mark.integration

HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_OK = 200
ROLE_ROUTE_PREFIX = "/roles"


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so bearer auth matches the role-admin integration tests.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


@pytest.fixture
def app() -> Iterator[Litestar]:
    """Create an app whose role-admin routes are mounted only by RoleAdminExtension.

    Yields:
        Litestar app under test.
    """
    RoleAdminTestUserManager.update_events = []
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

    User.metadata.create_all(engine)
    password_helper = PasswordHelper()

    with SASession(engine, expire_on_commit=False) as session:
        session.add_all(
            [
                User(
                    email="admin@example.com",
                    hashed_password=password_helper.hash("admin-password"),
                    is_verified=True,
                    roles=["admin"],
                ),
                User(
                    email="member@example.com",
                    hashed_password=password_helper.hash("member-password"),
                    is_verified=True,
                    roles=[],
                ),
            ],
        )
        session.commit()

    config = LitestarAuthConfig[User, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="role-admin-extension-session-secret-1234567890",
            cookie=CookieTransportConfig(allow_insecure_cookie_auth=True),
        ),
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=User,
        user_manager_class=RoleAdminTestUserManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            reset_password_token_secret="6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8",
            id_parser=UUID,
            password_helper=password_helper,
        ),
        superuser_role_name="admin",
        include_users=False,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        extensions=(RoleAdminExtension(),),
    )

    yield Litestar(plugins=[LitestarAuth(config)])
    RoleAdminTestUserManager.update_events = []
    engine.dispose()


async def test_role_admin_extension_mounts_functional_guarded_auth_owned_routes(
    client: AsyncTestClient[Litestar],
) -> None:
    """Extension-contributed role-admin routes work, enforce guards, and use auth-owned errors."""
    admin_headers = await _login_headers(client, email="admin@example.com", password="admin-password")
    member_headers = await _login_headers(client, email="member@example.com", password="member-password")

    create_response = await client.post(
        ROLE_ROUTE_PREFIX,
        headers=admin_headers,
        json={"name": " Support ", "description": "Support access"},
    )
    list_response = await client.get(ROLE_ROUTE_PREFIX, headers=admin_headers)
    denied_response = await client.get(ROLE_ROUTE_PREFIX, headers=member_headers)
    missing_response = await client.get(f"{ROLE_ROUTE_PREFIX}/missing", headers=admin_headers)

    assert create_response.status_code == HTTP_CREATED
    assert create_response.json() == {"name": "support", "description": "Support access"}
    assert list_response.status_code == HTTP_OK
    assert list_response.json() == {
        "items": [
            {"name": "admin", "description": None},
            {"name": "support", "description": "Support access"},
        ],
        "total": 2,
        "limit": 50,
        "offset": 0,
    }
    assert denied_response.status_code == HTTP_FORBIDDEN
    assert missing_response.status_code == HTTP_NOT_FOUND
    assert missing_response.json() == {
        "detail": "Role 'missing' not found.",
        "code": ErrorCode.ROLE_NOT_FOUND,
    }
