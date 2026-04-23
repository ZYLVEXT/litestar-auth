"""Integration tests for refresh-token rotation with CookieTransport."""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from litestar.testing import AsyncTestClient
from sqlalchemy import select

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers import create_auth_controller
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from tests._helpers import litestar_app_with_user_manager
from tests.integration.conftest import InMemoryUserDatabase

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar import Litestar
    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import Session
    from sqlalchemy.orm import Session as SASession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.sql.base import Executable

pytestmark = pytest.mark.integration

HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
_TOKEN_HASH_SECRET = "test-token-hash-secret-1234567890-1234567890"


class AsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session for repository tests."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped session."""
        self._session = session
        self.info: dict[str, Any] = {}

    @property
    def bind(self) -> Engine | Connection | None:
        """Expose the wrapped session bind."""
        return self._session.bind

    def get_bind(self) -> Engine | Connection:
        """Expose the wrapped session bind via SQLAlchemy's API.

        Returns:
            Bound SQLAlchemy connectable.
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
        if execution_options is None:
            return self._session.execute(statement, params=params)
        return self._session.execute(statement, params=params, execution_options=execution_options)

    async def flush(self) -> None:
        """Flush pending changes."""
        self._session.flush()

    async def refresh(
        self,
        instance: object,
        *,
        attribute_names: Sequence[str] | None = None,
        with_for_update: ForUpdateParameter = None,
    ) -> None:
        """Refresh an instance from the database."""
        self._session.refresh(instance, attribute_names=attribute_names, with_for_update=with_for_update)


def _create_user(session: Session) -> User:
    """Persist and return a user for refresh-cookie tests.

    Returns:
        Stored user instance with a verified password.
    """
    password_helper = PasswordHelper()
    user = User(
        email="user@example.com",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _strategy_session(session: Session) -> AsyncSession:
    """Return an async-compatible adapter for the sync test session."""
    return AsyncSessionAdapter(session)  # ty: ignore[invalid-return-type]


def build_app(
    session: Session,
    *,
    cookie_name: str = "litestar_auth",
    cookie_path: str = "/",
) -> tuple[Litestar, Any, User]:
    """Create a Litestar app wired with refresh-token-enabled cookie auth.

    Returns:
        Litestar application exposing login and refresh endpoints.
    """
    user = _create_user(session)
    user_db = InMemoryUserDatabase([user])
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    backend = AuthenticationBackend[User, UUID](
        name="db-cookie",
        transport=CookieTransport(cookie_name=cookie_name, path=cookie_path),
        strategy=cast("Any", strategy),
    )
    user_manager = BaseUserManager[User, UUID](
        user_db,
        password_helper=PasswordHelper(),
        security=UserManagerSecurity[UUID](
            verification_token_secret="test-secret-verification-secret-1234567890",
            reset_password_token_secret="test-secret-reset-password-secret-12345",
        ),
    )
    controller = create_auth_controller(
        backend=backend,
        enable_refresh=True,
        csrf_protection_managed_externally=True,
    )
    app = litestar_app_with_user_manager(user_manager, controller)
    return app, controller, user


def _set_cookie_headers(response: object) -> list[str]:
    """Return all Set-Cookie header values for an httpx response."""
    headers = getattr(response, "headers", None)
    if headers is None:
        return []
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        return list(get_list("set-cookie"))
    return []


def _find_set_cookie(headers: list[str], cookie_name: str) -> str:
    """Return the Set-Cookie header starting with ``cookie_name=``.

    Returns:
        The matching Set-Cookie header value.

    Raises:
        AssertionError: If the cookie is not present in the response headers.
    """
    needle = f"{cookie_name}="
    for header in headers:
        if header.lower().startswith(needle.lower()):
            return header
    msg = f"Missing Set-Cookie header for {cookie_name!r}"
    raise AssertionError(msg)


@pytest.fixture
def app(session: Session) -> tuple[Litestar, Session, Any, User]:
    """Create the shared refresh-cookie app and backing session.

    Returns:
        App plus the shared SQLAlchemy session used for refresh-cookie assertions.
    """
    litestar_app, controller, user = build_app(session)
    return litestar_app, session, controller, user


async def test_cookie_transport_sets_refresh_token_cookie(
    client: tuple[AsyncTestClient[Litestar], Session, Any, User],
) -> None:
    """CookieTransport should store the rotated refresh token in an HttpOnly cookie."""
    test_client, session, _controller_class, _user = client

    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )

    assert login_response.status_code == HTTP_CREATED
    assert login_response.json() is None

    access_cookie = login_response.cookies.get("litestar_auth")
    assert isinstance(access_cookie, str)
    refresh_cookie = login_response.cookies.get("litestar_auth_refresh")
    assert isinstance(refresh_cookie, str)

    refresh_row = session.scalar(select(RefreshToken).order_by(RefreshToken.created_at.desc()))
    assert refresh_row is not None

    set_cookie_headers = _set_cookie_headers(login_response)
    refresh_set_cookie = _find_set_cookie(set_cookie_headers, "litestar_auth_refresh").lower()
    assert "httponly" in refresh_set_cookie
    assert "samesite=" in refresh_set_cookie

    access_digest = hmac.new(_TOKEN_HASH_SECRET.encode(), access_cookie.encode(), hashlib.sha256).hexdigest()
    assert session.scalar(select(AccessToken).where(AccessToken.token == access_digest)) is not None

    refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_cookie})

    assert refresh_response.status_code == HTTP_CREATED
    assert refresh_response.json() is None

    refreshed_access_cookie = refresh_response.cookies.get("litestar_auth")
    assert isinstance(refreshed_access_cookie, str)
    assert refreshed_access_cookie != access_cookie

    refresh_set_cookie = _find_set_cookie(_set_cookie_headers(refresh_response), "litestar_auth_refresh").lower()
    assert "httponly" in refresh_set_cookie


async def test_logout_clears_cookie_auth_and_refresh_cookies(
    client: tuple[AsyncTestClient[Litestar], Session, Any, User],
) -> None:
    """Logout clears auth and refresh cookies while removing access-token state."""
    test_client, session, controller_class, user = client

    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )

    assert login_response.status_code == HTTP_CREATED
    assert login_response.json() is None

    access_cookie = login_response.cookies.get("litestar_auth")
    assert isinstance(access_cookie, str)
    refresh_cookie = login_response.cookies.get("litestar_auth_refresh")
    assert isinstance(refresh_cookie, str)

    access_digest = hmac.new(_TOKEN_HASH_SECRET.encode(), access_cookie.encode(), hashlib.sha256).hexdigest()
    assert session.scalar(select(AccessToken).where(AccessToken.token == access_digest)) is not None

    controller = controller_class(owner=MagicMock())
    request = MagicMock()
    request.user = user
    request.cookies = {"litestar_auth": access_cookie}

    logout_handler = controller.logout.fn
    logout_response = await logout_handler(controller, request)

    auth_cookie = next(cookie for cookie in logout_response.cookies if cookie.key == "litestar_auth")
    assert auth_cookie.key == "litestar_auth"
    assert auth_cookie.max_age == 0
    assert not auth_cookie.value
    assert auth_cookie.httponly is True

    refresh_logout_cookie = next(cookie for cookie in logout_response.cookies if cookie.key == "litestar_auth_refresh")
    assert refresh_logout_cookie.key == "litestar_auth_refresh"
    assert refresh_logout_cookie.max_age == 0
    assert not refresh_logout_cookie.value
    assert refresh_logout_cookie.httponly is True

    assert session.scalar(select(AccessToken).where(AccessToken.token == access_digest)) is None


async def test_logout_cookie_cleanup_is_deterministic_for_custom_cookie_names_and_path(session: Session) -> None:
    """Logout clears configured cookie artifacts using their configured names and path."""
    app, controller_class, user = build_app(
        session,
        cookie_name="custom_auth",
        cookie_path="/auth",
    )

    async with AsyncTestClient(app=app) as test_client:
        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )

        assert login_response.status_code == HTTP_CREATED
        access_cookie = login_response.cookies.get("custom_auth")
        assert isinstance(access_cookie, str)

        controller = controller_class(owner=MagicMock())
        request = MagicMock()
        request.user = user
        request.cookies = {"custom_auth": access_cookie}
        logout_handler = controller.logout.fn
        logout_response = await logout_handler(controller, request)

    cookie_by_key = {cookie.key: cookie for cookie in logout_response.cookies}
    for key, httponly in (("custom_auth", True), ("custom_auth_refresh", True)):
        cookie = cookie_by_key[key]
        assert cookie.max_age == 0
        assert not cookie.value
        assert cookie.path == "/auth"
        assert cookie.httponly is httponly


async def test_refresh_is_rejected_after_logout(
    client: tuple[AsyncTestClient[Litestar], Session, Any, User],
) -> None:
    """After logout, the pre-logout refresh token is rejected immediately."""
    test_client, _session, controller_class, user = client

    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )

    assert login_response.status_code == HTTP_CREATED
    refresh_cookie = login_response.cookies.get("litestar_auth_refresh")
    assert isinstance(refresh_cookie, str)

    access_cookie = login_response.cookies.get("litestar_auth")
    assert isinstance(access_cookie, str)
    controller = controller_class(owner=MagicMock())
    request = MagicMock()
    request.user = user
    request.cookies = {"litestar_auth": access_cookie}
    logout_handler = controller.logout.fn
    await logout_handler(controller, request)

    refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_cookie})

    assert refresh_response.status_code == HTTP_BAD_REQUEST
    assert refresh_response.json()["detail"] == "The refresh token is invalid."
