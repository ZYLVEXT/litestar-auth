"""End-to-end registration and opaque cookie-session flows."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Litestar, Request, get
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool

from litestar_auth.authentication.transport.cookie import CookieTransportConfig
from litestar_auth.guards import is_authenticated
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import SessionMaker

if TYPE_CHECKING:
    from collections.abc import Iterator

    from litestar.testing import AsyncTestClient

pytestmark = [pytest.mark.e2e]

AUTH_COOKIE_NAME = "auth-cookie"
HTTP_CREATED = 201
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_UNAUTHORIZED = 401


@dataclass(slots=True)
class VerificationTracker:
    """Shared storage for verification tokens generated during registration."""

    tokens_by_email: dict[str, str] = field(default_factory=dict)


class E2EUserManager(BaseUserManager[User, UUID]):
    """Concrete manager that records verification tokens for tests."""

    def __init__(  # ruff: ignore[too-many-arguments]
        self,
        user_db: object,
        *,
        verification_tracker: VerificationTracker,
        password_helper: PasswordHelper,
        verification_token_secret: str,
        reset_password_token_secret: str,
        backends: tuple[object, ...] = (),
    ) -> None:
        """Initialize the manager with the shared verification tracker."""
        super().__init__(
            user_db=cast("Any", user_db),
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                id_parser=UUID,
            ),
            backends=backends,
        )
        self._verification_tracker = verification_tracker

    async def on_after_register(self, user: User, token: str) -> None:
        """Store the verification token that would normally be emailed."""
        self._verification_tracker.tokens_by_email[user.email] = token


@get("/protected", guards=[is_authenticated], sync_to_thread=False)
def protected_route(request: Request[Any, Any, Any]) -> dict[str, str]:
    """Expose the authenticated user's email for end-to-end checks.

    Returns:
        The authenticated email.
    """
    user = cast("User", request.user)
    return {"email": user.email}


@pytest.fixture
def app() -> Iterator[tuple[Litestar, VerificationTracker]]:
    """Create a Litestar app wired with a database-backed cookie session.

    Yields:
        App under test and the shared verification-token tracker.
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

    User.metadata.create_all(engine)

    verification_tracker = VerificationTracker()
    password_helper = PasswordHelper()

    def _build_user_manager(
        *,
        session: object,
        user_db: object,
        config: LitestarAuthConfig[User, UUID],
        backends: tuple[object, ...] = (),
    ) -> E2EUserManager:
        security = config.user_manager_security
        assert security is not None
        return E2EUserManager(
            user_db=user_db,
            verification_tracker=verification_tracker,
            password_helper=config.resolve_password_helper(),
            verification_token_secret=cast("str", security.verification_token_secret),
            reset_password_token_secret=cast("str", security.reset_password_token_secret),
            backends=backends,
        )

    config = LitestarAuthConfig[User, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="database-session-token-hash-secret-1234567890",
            cookie=CookieTransportConfig(cookie_name=AUTH_COOKIE_NAME),
        ),
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=User,
        user_manager_factory=_build_user_manager,
        csrf_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            reset_password_token_secret="6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8",
            password_helper=password_helper,
        ),
    )
    yield Litestar(route_handlers=[protected_route], plugins=[LitestarAuth(config)]), verification_tracker
    engine.dispose()


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so cookie and redirect behavior matches production wiring.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


async def test_register_verify_login_logout_flow(
    client: tuple[AsyncTestClient[Litestar], VerificationTracker],
) -> None:
    """A full register-to-logout flow works with a server-side cookie session."""
    test_client, verification_tracker = client
    email = "cookie-session@example.com"
    password = "correct horse battery staple"

    unauthorized_response = await test_client.get("/protected")
    assert unauthorized_response.status_code == HTTP_UNAUTHORIZED
    csrf_token = unauthorized_response.cookies.get("litestar_auth_csrf")
    assert csrf_token is not None
    csrf_headers = {"X-CSRF-Token": csrf_token}

    register_response = await test_client.post(
        "/auth/register",
        json={"email": email, "password": password},
        headers=csrf_headers,
    )

    assert register_response.status_code == HTTP_CREATED
    assert register_response.json() == {
        "id": register_response.json()["id"],
        "email": email,
        "is_active": True,
        "is_verified": False,
        "roles": [],
    }
    assert email in verification_tracker.tokens_by_email

    verify_response = await test_client.post(
        "/auth/verify",
        json={"token": verification_tracker.tokens_by_email[email]},
        headers=csrf_headers,
    )

    assert verify_response.status_code == HTTP_OK
    assert verify_response.json() == {
        "id": register_response.json()["id"],
        "email": email,
        "is_active": True,
        "is_verified": True,
        "roles": [],
    }

    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": email, "password": password},
        headers=csrf_headers,
    )
    assert login_response.status_code == HTTP_CREATED

    request_headers: dict[str, str] = dict(csrf_headers)
    assert test_client.cookies.get(AUTH_COOKIE_NAME) is not None
    assert AUTH_COOKIE_NAME in login_response.headers["set-cookie"]

    protected_response = await test_client.get("/protected", headers=request_headers)
    assert protected_response.status_code == HTTP_OK
    assert protected_response.json() == {"email": email}

    logout_response = await test_client.post("/auth/logout", headers=request_headers)
    assert logout_response.status_code == HTTP_CREATED

    assert test_client.cookies.get(AUTH_COOKIE_NAME) is None

    post_logout_response = await test_client.get("/protected")
    assert post_logout_response.status_code == HTTP_UNAUTHORIZED


async def test_register_and_verify_keep_email_and_token_payload_boundaries(
    client: tuple[AsyncTestClient[Litestar], VerificationTracker],
) -> None:
    """Registration stays email-based and verification stays token-based."""
    test_client, verification_tracker = client
    unauthorized_response = await test_client.get("/protected")
    csrf_token = unauthorized_response.cookies.get("litestar_auth_csrf")
    assert csrf_token is not None
    csrf_headers = {"X-CSRF-Token": csrf_token}

    register_invalid = await test_client.post(
        "/auth/register",
        json={"identifier": "boundary@example.com", "password": "correct horse battery staple"},
        headers=csrf_headers,
    )
    assert register_invalid.status_code == HTTP_UNPROCESSABLE_ENTITY

    email = "boundary@example.com"
    password = "correct horse battery staple"
    register_response = await test_client.post(
        "/auth/register",
        json={"email": email, "password": password},
        headers=csrf_headers,
    )
    assert register_response.status_code == HTTP_CREATED
    assert email in verification_tracker.tokens_by_email

    verify_invalid = await test_client.post(
        "/auth/verify",
        json={"email": email},
        headers=csrf_headers,
    )
    assert verify_invalid.status_code == HTTP_BAD_REQUEST

    verify_response = await test_client.post(
        "/auth/verify",
        json={"token": verification_tracker.tokens_by_email[email]},
        headers=csrf_headers,
    )
    assert verify_response.status_code == HTTP_OK
    assert verify_response.json()["email"] == email
    assert verify_response.json()["is_verified"] is True
