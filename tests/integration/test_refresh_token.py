"""Integration tests for refresh-token rotation and controller wiring."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar.testing import AsyncTestClient
from sqlalchemy import select

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import create_auth_controller
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter
from tests._helpers import litestar_app_with_user_manager
from tests.integration.conftest import InMemoryUserDatabase

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

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
HTTP_TOO_MANY_REQUESTS = 429
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

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Merge an instance into the session.

        Returns:
            The merged mapped instance.
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


def _create_user(session: Session) -> User:
    """Persist and return a user for refresh-flow tests.

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
    refresh_max_age: timedelta = timedelta(days=30),
    requires_verification: bool = False,
    rate_limit_config: AuthRateLimitConfig | None = None,
) -> Litestar:
    """Create a Litestar app wired with refresh-token-enabled auth.

    Returns:
        Litestar application exposing login and refresh endpoints.
    """
    user = _create_user(session)
    user_db = InMemoryUserDatabase([user])
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        refresh_max_age=refresh_max_age,
    )
    backend = AuthenticationBackend[User, UUID](
        name="db-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    user_manager = BaseUserManager[User, UUID](
        user_db,
        password_helper=PasswordHelper(),
        verification_token_secret="test-secret-verification-secret-1234567890",
        reset_password_token_secret="test-secret-reset-password-secret-12345",
    )
    controller = create_auth_controller(
        backend=backend,
        rate_limit_config=rate_limit_config,
        enable_refresh=True,
        requires_verification=requires_verification,
    )
    return litestar_app_with_user_manager(user_manager, controller)


@pytest.fixture
def app(session: Session) -> tuple[Litestar, Session]:
    """Create the shared refresh-token app and backing session.

    Returns:
        App plus the shared SQLAlchemy session used for refresh-token assertions.
    """
    return build_app(session), session


async def test_login_and_refresh_rotate_refresh_tokens(
    client: tuple[AsyncTestClient[Litestar], Session],
) -> None:
    """Login issues refresh tokens and refresh rotates them with replay rejection."""
    test_client, session = client

    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )

    assert login_response.status_code == HTTP_CREATED
    login_payload = login_response.json()
    assert login_payload["token_type"] == "bearer"
    assert isinstance(login_payload["access_token"], str)
    assert isinstance(login_payload["refresh_token"], str)

    first_refresh_token = login_payload["refresh_token"]
    first_refresh_digest = hmac.new(
        _TOKEN_HASH_SECRET.encode(),
        first_refresh_token.encode(),
        hashlib.sha256,
    ).hexdigest()
    access_digest = hmac.new(
        _TOKEN_HASH_SECRET.encode(),
        login_payload["access_token"].encode(),
        hashlib.sha256,
    ).hexdigest()
    assert session.scalar(select(RefreshToken).where(RefreshToken.token == first_refresh_digest)) is not None
    assert session.scalar(select(AccessToken).where(AccessToken.token == access_digest)) is not None
    session.expire_all()
    user_after_login = session.scalar(select(User).where(User.email == "user@example.com"))
    assert user_after_login is not None
    assert [token.token for token in user_after_login.access_tokens] == [access_digest]
    assert [token.token for token in user_after_login.refresh_tokens] == [first_refresh_digest]

    refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": first_refresh_token})

    assert refresh_response.status_code == HTTP_CREATED
    refresh_payload = refresh_response.json()
    assert refresh_payload["token_type"] == "bearer"
    assert isinstance(refresh_payload["access_token"], str)
    assert isinstance(refresh_payload["refresh_token"], str)
    assert refresh_payload["refresh_token"] != first_refresh_token

    assert session.scalar(select(RefreshToken).where(RefreshToken.token == first_refresh_digest)) is None
    assert (
        session.scalar(
            select(RefreshToken).where(
                RefreshToken.token
                == hmac.new(
                    _TOKEN_HASH_SECRET.encode(),
                    refresh_payload["refresh_token"].encode(),
                    hashlib.sha256,
                ).hexdigest(),
            ),
        )
        is not None
    )
    session.expire_all()
    user_after_refresh = session.scalar(select(User).where(User.email == "user@example.com"))
    assert user_after_refresh is not None
    assert first_refresh_digest not in {token.token for token in user_after_refresh.refresh_tokens}

    replay_response = await test_client.post("/auth/refresh", json={"refresh_token": first_refresh_token})

    assert replay_response.status_code == HTTP_BAD_REQUEST
    replay_payload = replay_response.json()
    assert replay_payload["detail"] == "The refresh token is invalid."
    replay_code = replay_payload.get("code") or (replay_payload.get("extra") or {}).get("code")
    assert replay_code == ErrorCode.REFRESH_TOKEN_INVALID


async def test_refresh_rejects_expired_refresh_tokens(session: Session) -> None:
    """Expired refresh tokens are rejected according to the configured TTL."""
    app = build_app(session, refresh_max_age=timedelta(seconds=1))
    async with AsyncTestClient(app=app) as test_client:
        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )

        refresh_token = login_response.json()["refresh_token"]
        persisted_refresh_token = session.scalar(
            select(RefreshToken).where(
                RefreshToken.token
                == hmac.new(_TOKEN_HASH_SECRET.encode(), refresh_token.encode(), hashlib.sha256).hexdigest(),
            ),
        )
        assert persisted_refresh_token is not None
        persisted_refresh_token.created_at = datetime.now(tz=UTC) - timedelta(seconds=5)
        session.commit()

        refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert refresh_response.status_code == HTTP_BAD_REQUEST
    payload = refresh_response.json()
    assert payload["detail"] == "The refresh token is invalid."
    code = payload.get("code") or (payload.get("extra") or {}).get("code")
    assert code == ErrorCode.REFRESH_TOKEN_INVALID


async def test_refresh_enforces_inactive_user_policy(client: tuple[AsyncTestClient[Litestar], Session]) -> None:
    """Refresh denies issuing new tokens for inactive users."""
    test_client, session = client

    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert login_response.status_code == HTTP_CREATED
    refresh_token = login_response.json()["refresh_token"]

    user = session.scalar(select(User).where(User.email == "user@example.com"))
    assert user is not None
    user.is_active = False
    session.commit()

    refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert refresh_response.status_code == HTTP_BAD_REQUEST
    payload = refresh_response.json()
    code = payload.get("code") or (payload.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_INACTIVE


async def test_refresh_enforces_verified_user_policy(session: Session) -> None:
    """When requires_verification=True, refresh denies unverified users even with a refresh token."""
    app = build_app(session, requires_verification=True)
    async with AsyncTestClient(app=app) as test_client:
        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        refresh_token = login_response.json()["refresh_token"]

        user = session.scalar(select(User).where(User.email == "user@example.com"))
        assert user is not None
        user.is_verified = False
        session.commit()

        refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert refresh_response.status_code == HTTP_BAD_REQUEST
    payload = refresh_response.json()
    code = payload.get("code") or (payload.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_NOT_VERIFIED


async def test_refresh_rate_limit_is_optional_and_valid_requests_still_succeed(session: Session) -> None:
    """Without a refresh limiter, refresh-token rotation keeps the previous success behavior."""
    app = build_app(session)

    async with AsyncTestClient(app=app) as test_client:
        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        refresh_token = login_response.json()["refresh_token"]

        refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert refresh_response.status_code == HTTP_CREATED
    refresh_payload = refresh_response.json()
    assert refresh_payload["token_type"] == "bearer"
    assert isinstance(refresh_payload["access_token"], str)
    assert isinstance(refresh_payload["refresh_token"], str)


async def test_refresh_rate_limit_returns_429_after_repeated_invalid_attempts(session: Session) -> None:
    """Configured refresh throttling blocks repeated invalid refresh-token submissions."""
    rate_limit_config = AuthRateLimitConfig(
        refresh=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip",
            namespace="refresh",
        ),
    )
    app = build_app(session, rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as test_client:
        first_response = await test_client.post("/auth/refresh", json={"refresh_token": "not-a-valid-token"})
        second_response = await test_client.post("/auth/refresh", json={"refresh_token": "still-not-valid"})
        blocked_response = await test_client.post("/auth/refresh", json={"refresh_token": "another-invalid-token"})

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert blocked_response.status_code == HTTP_TOO_MANY_REQUESTS
    assert blocked_response.headers["Retry-After"].isdigit()
    assert int(blocked_response.headers["Retry-After"]) >= 1


async def test_refresh_rate_limit_resets_after_success(session: Session) -> None:
    """A successful refresh clears prior invalid-attempt state for the client."""
    rate_limit_config = AuthRateLimitConfig(
        refresh=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip",
            namespace="refresh",
        ),
    )
    app = build_app(session, rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as test_client:
        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        refresh_token = login_response.json()["refresh_token"]

        invalid_response = await test_client.post("/auth/refresh", json={"refresh_token": "not-a-valid-token"})
        success_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_token})
        second_login_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        second_refresh_token = second_login_response.json()["refresh_token"]
        post_reset_response = await test_client.post("/auth/refresh", json={"refresh_token": second_refresh_token})

    assert invalid_response.status_code == HTTP_BAD_REQUEST
    assert success_response.status_code == HTTP_CREATED
    assert post_reset_response.status_code == HTTP_CREATED
