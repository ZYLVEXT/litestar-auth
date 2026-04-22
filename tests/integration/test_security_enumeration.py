"""Integration tests for anti-enumeration behavior across auth endpoints."""

from __future__ import annotations

import hmac
import time
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar.testing import AsyncTestClient

from litestar_auth._manager import account_tokens as account_tokens_module
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import (
    create_auth_controller,
    create_register_controller,
    create_reset_password_controller,
)
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from tests._helpers import litestar_app_with_user_manager
from tests.integration.conftest import ExampleUser, InMemoryUserDatabase

if TYPE_CHECKING:
    from litestar import Litestar

    from litestar_auth.authentication.strategy.base import UserManagerProtocol
    from litestar_auth.types import StrategyProtocol

pytestmark = pytest.mark.integration
HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400
HTTP_CREATED = 201
# Hosted runners (especially macOS + xdist) add enough jitter to exceed a tight bound.
TIMING_TOLERANCE_SECONDS = 0.35
SLOW_OPERATION_SECONDS = 0.05


class SlowPasswordHelper(PasswordHelper):
    """Password helper that injects deterministic latency into hash and verify."""

    _HASH_PREFIX = "slow-test$"

    def __init__(self, *, delay_seconds: float) -> None:
        """Store the artificial per-operation delay."""
        super().__init__()
        self.delay_seconds = delay_seconds

    def hash(self, password: str) -> str:
        """Sleep before hashing to magnify timing differences.

        Returns:
            The generated password hash.
        """
        time.sleep(self.delay_seconds)
        return f"{self._HASH_PREFIX}{password}"

    def verify(self, password: str, hashed: str) -> bool:
        """Sleep before verification to magnify timing differences.

        Returns:
            ``True`` when the password matches the hash.
        """
        time.sleep(self.delay_seconds)
        return hmac.compare_digest(hashed, f"{self._HASH_PREFIX}{password}")

    def verify_and_update(self, password: str, hashed: str) -> tuple[bool, str | None]:
        """Verify a deterministic test hash without invoking expensive real hashers.

        Returns:
            Verification result plus no replacement hash.
        """
        return self.verify(password, hashed), None


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Manager variant that records forgot-password delivery hooks."""

    def __init__(
        self,
        user_db: InMemoryUserDatabase,
        password_helper: PasswordHelper,
        *,
        backends: tuple[object, ...] = (),
    ) -> None:
        """Configure predictable secrets and track forgot-password events."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret="reset-secret-1234567890-1234567890",
                id_parser=UUID,
            ),
            backends=backends,
        )
        self.forgot_password_events: list[tuple[ExampleUser, str]] = []

    async def on_after_forgot_password(self, user: ExampleUser | None, token: str | None) -> None:
        """Record real forgot-password deliveries."""
        if user is not None and token is not None:
            self.forgot_password_events.append((user, token))


class NoopStrategy:
    """Minimal strategy used to satisfy auth-controller construction."""

    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[ExampleUser, UUID],
    ) -> ExampleUser | None:
        """Never authenticate a token.

        Returns:
            Always ``None``.
        """
        del self
        del token
        del user_manager
        return None

    async def write_token(self, user: ExampleUser) -> str:
        """Return a deterministic test token."""
        del self
        del user
        return "test-token"

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """Discard the supplied token."""
        del self
        del token
        del user


def build_app(
    *,
    password_helper: PasswordHelper | None = None,
) -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create an app with login, register, and forgot-password endpoints.

    Returns:
        The application plus its in-memory user database and tracking manager.
    """
    helper = password_helper or PasswordHelper()
    user_db = InMemoryUserDatabase()
    existing_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=helper.hash("correct-password"),
    )
    user_db.users_by_id[existing_user.id] = existing_user
    user_db.user_ids_by_email[existing_user.email] = existing_user.id
    user_manager = TrackingUserManager(user_db, helper)
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="test-bearer",
        transport=BearerTransport(),
        strategy=cast("StrategyProtocol[ExampleUser, UUID]", NoopStrategy()),
    )
    app = litestar_app_with_user_manager(
        user_manager,
        create_auth_controller(
            backend=backend,
        ),
        create_register_controller(),
        create_reset_password_controller(),
    )
    return app, user_db, user_manager


async def _timed_post(
    client: AsyncTestClient[Litestar],
    path: str,
    *,
    json: dict[str, str],
) -> tuple[float, Any]:
    start = time.perf_counter()
    response = await client.post(path, json=json)
    return time.perf_counter() - start, response


def _assert_similar_duration(first: float, second: float) -> None:
    assert abs(first - second) <= TIMING_TOLERANCE_SECONDS


@pytest.fixture
def app() -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create the shared anti-enumeration app and collaborators.

    Returns:
        App plus the in-memory database and tracking manager.
    """
    return build_app()


async def test_login_uses_same_response_for_missing_email_and_wrong_password(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Login returns an identical error response for both invalid credential branches."""
    test_client, _, _ = client

    missing_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing@example.com", "password": "correct-password"},
    )
    wrong_password_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "wrong-password"},
    )

    assert missing_response.status_code == HTTP_BAD_REQUEST
    assert wrong_password_response.status_code == HTTP_BAD_REQUEST
    assert missing_response.content == wrong_password_response.content


async def test_forgot_password_always_returns_202_and_same_body(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Forgot-password keeps the external response constant for missing accounts."""
    test_client, _, user_manager = client

    existing_response = await test_client.post("/auth/forgot-password", json={"email": "user@example.com"})
    missing_response = await test_client.post("/auth/forgot-password", json={"email": "missing@example.com"})

    assert existing_response.status_code == HTTP_ACCEPTED
    assert missing_response.status_code == HTTP_ACCEPTED
    assert existing_response.content == missing_response.content
    assert len(user_manager.forgot_password_events) == 1


async def test_login_timing_does_not_depend_on_email_existence() -> None:
    """Login timing stays within a narrow bound for missing and existing emails."""
    app, _, user_manager = build_app(password_helper=SlowPasswordHelper(delay_seconds=SLOW_OPERATION_SECONDS))
    user_manager._get_dummy_hash()

    async with AsyncTestClient(app=app) as client:
        warmup_response = await client.post(
            "/auth/login",
            json={"identifier": "warmup@example.com", "password": "correct-password"},
        )
        assert warmup_response.status_code == HTTP_BAD_REQUEST

        missing_duration, missing_response = await _timed_post(
            client,
            "/auth/login",
            json={"identifier": "missing@example.com", "password": "correct-password"},
        )
        wrong_password_duration, wrong_password_response = await _timed_post(
            client,
            "/auth/login",
            json={"identifier": "user@example.com", "password": "wrong-password"},
        )

    assert missing_response.status_code == HTTP_BAD_REQUEST
    assert wrong_password_response.status_code == HTTP_BAD_REQUEST
    _assert_similar_duration(missing_duration, wrong_password_duration)


async def test_register_timing_does_not_depend_on_email_existence() -> None:
    """Register performs password hashing before duplicate-email rejection."""
    app, _, _ = build_app(password_helper=SlowPasswordHelper(delay_seconds=SLOW_OPERATION_SECONDS))

    async with AsyncTestClient(app=app) as client:
        duplicate_duration, duplicate_response = await _timed_post(
            client,
            "/auth/register",
            json={"email": "user@example.com", "password": "new-password"},
        )
        new_duration, new_response = await _timed_post(
            client,
            "/auth/register",
            json={"email": "fresh@example.com", "password": "new-password"},
        )

    assert duplicate_response.status_code == HTTP_BAD_REQUEST
    assert new_response.status_code == HTTP_CREATED
    _assert_similar_duration(duplicate_duration, new_duration)


async def test_forgot_password_timing_does_not_depend_on_email_existence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forgot-password performs the same token work for missing and existing emails."""
    original_encode = account_tokens_module.jwt.encode

    def delayed_encode(payload: dict[str, Any], key: str, algorithm: str) -> str:
        time.sleep(SLOW_OPERATION_SECONDS)
        return original_encode(payload, key, algorithm=algorithm)

    monkeypatch.setattr(account_tokens_module.jwt, "encode", delayed_encode)
    app, _, _ = build_app()

    async with AsyncTestClient(app=app) as client:
        warmup_response = await client.post("/auth/forgot-password", json={"email": "warmup@example.com"})
        assert warmup_response.status_code == HTTP_ACCEPTED

        existing_duration, existing_response = await _timed_post(
            client,
            "/auth/forgot-password",
            json={"email": "user@example.com"},
        )
        missing_duration, missing_response = await _timed_post(
            client,
            "/auth/forgot-password",
            json={"email": "missing@example.com"},
        )

    assert existing_response.status_code == HTTP_ACCEPTED
    assert missing_response.status_code == HTTP_ACCEPTED
    _assert_similar_duration(existing_duration, missing_duration)
