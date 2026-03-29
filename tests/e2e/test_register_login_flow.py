"""End-to-end register/login flows across bearer and cookie JWT backends."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Litestar, Request, get
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.guards import is_authenticated
from litestar_auth.manager import BaseUserManager
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import SessionMaker

if TYPE_CHECKING:
    from collections.abc import Iterator

    from litestar.testing import AsyncTestClient

pytestmark = pytest.mark.e2e

AUTH_COOKIE_NAME = "auth-cookie"
HTTP_CREATED = 201
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401


@dataclass(slots=True)
class VerificationTracker:
    """Shared storage for verification tokens generated during registration."""

    tokens_by_email: dict[str, str] = field(default_factory=dict)


class E2EUserManager(BaseUserManager[User, UUID]):
    """Concrete manager that records verification tokens for tests."""

    def __init__(  # noqa: PLR0913
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
            verification_token_secret=verification_token_secret,
            reset_password_token_secret=reset_password_token_secret,
            id_parser=UUID,
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
    """Create a Litestar app wired with bearer and cookie JWT auth backends.

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
    bearer_backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](secret="jwt-bearer-secret-1234567890-extra", subject_decoder=UUID),
        ),
    )
    cookie_backend = AuthenticationBackend[User, UUID](
        name="cookie",
        transport=CookieTransport(cookie_name=AUTH_COOKIE_NAME),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](secret="jwt-cookie-secret-1234567890-extra", subject_decoder=UUID),
        ),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[bearer_backend, cookie_backend],
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=User,
        user_manager_class=E2EUserManager,
        csrf_secret="c" * 32,
        allow_nondurable_jwt_revocation=True,
        user_manager_kwargs={
            "verification_tracker": verification_tracker,
            "password_helper": password_helper,
            "verification_token_secret": "verify-secret-1234567890-1234567890",
            "reset_password_token_secret": "reset-secret-1234567890-1234567890",
        },
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


@pytest.mark.parametrize(
    ("login_path", "logout_path", "transport_name"),
    [
        ("/auth/login", "/auth/logout", "bearer"),
        ("/auth/cookie/login", "/auth/cookie/logout", "cookie"),
    ],
)
async def test_register_verify_login_logout_flow(
    client: tuple[AsyncTestClient[Litestar], VerificationTracker],
    login_path: str,
    logout_path: str,
    transport_name: str,
) -> None:
    """A full register-to-logout flow works for bearer and cookie JWT auth."""
    test_client, verification_tracker = client
    email = f"{transport_name}@example.com"
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
        "is_superuser": False,
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
        "is_superuser": False,
    }

    login_response = await test_client.post(
        login_path,
        json={"identifier": email, "password": password},
        headers=csrf_headers,
    )
    assert login_response.status_code == HTTP_CREATED

    request_headers: dict[str, str] = dict(csrf_headers)
    if transport_name == "bearer":
        token = login_response.json()["access_token"]
        request_headers["Authorization"] = f"Bearer {token}"
    else:
        assert test_client.cookies.get(AUTH_COOKIE_NAME) is not None
        assert AUTH_COOKIE_NAME in login_response.headers["set-cookie"]

    protected_response = await test_client.get("/protected", headers=request_headers)
    assert protected_response.status_code == HTTP_OK
    assert protected_response.json() == {"email": email}

    logout_response = await test_client.post(logout_path, headers=request_headers)
    assert logout_response.status_code == HTTP_CREATED

    if transport_name == "cookie":
        assert test_client.cookies.get(AUTH_COOKIE_NAME) is None

    post_logout_response = await test_client.get("/protected")
    assert post_logout_response.status_code == HTTP_UNAUTHORIZED
