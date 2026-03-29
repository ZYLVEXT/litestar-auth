"""Integration tests for the generated authentication controller."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar, Request, get
from litestar.middleware import DefineMiddleware
from litestar.testing import AsyncTestClient
from pwdlib.hashers.bcrypt import BcryptHasher

from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers import create_auth_controller
from litestar_auth.exceptions import ErrorCode

if TYPE_CHECKING:
    from litestar_auth.db.base import BaseUserStore
from litestar_auth.guards import is_active
from litestar_auth.manager import BaseUserManager
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests._helpers import auth_middleware_get_request_session, litestar_app_with_user_manager
from tests.integration.conftest import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
)

pytestmark = pytest.mark.integration
HTTP_CREATED = 201
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_UNPROCESSABLE_ENTITY = 422

_LOGIN_TEST_EMAIL = "user@example.com"
_LOGIN_TEST_USERNAME = "testuser"


def login_identifier_credential(login_identifier: Literal["email", "username"]) -> str:
    """Return the identifier string used for successful login in integration tests."""
    return _LOGIN_TEST_EMAIL if login_identifier == "email" else _LOGIN_TEST_USERNAME


def missing_user_identifier(login_identifier: Literal["email", "username"]) -> str:
    """Return a nonexistent identifier for anti-enumeration tests."""
    return "missing@example.com" if login_identifier == "email" else "missinguser"


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records completed login hooks."""

    def __init__(  # noqa: PLR0913
        self,
        user_db: BaseUserStore[ExampleUser, UUID],
        password_helper: PasswordHelper,
        verification_token_secret: str | None = None,
        reset_password_token_secret: str | None = None,
        *,
        backends: tuple[object, ...] = (),
        login_identifier: Literal["email", "username"] = "email",
    ) -> None:
        """Initialize the manager with deterministic hook tracking."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            verification_token_secret=verification_token_secret,
            reset_password_token_secret=reset_password_token_secret,
            backends=backends,
            login_identifier=login_identifier,
        )
        self.logged_in_users: list[ExampleUser] = []

    async def on_after_login(self, user: ExampleUser) -> None:
        """Record successful login completion."""
        self.logged_in_users.append(user)


@get("/probe")
async def probe(request: Request[Any, Any, Any]) -> dict[str, str | None]:
    """Expose the authenticated email for token lifecycle assertions.

    Returns:
        Authenticated email when a user is present, otherwise ``None``.
    """
    await asyncio.sleep(0)
    user = cast("ExampleUser | None", request.user)
    return {"email": user.email if user is not None else None}


@get("/guarded", guards=[is_active])
async def guarded(request: Request[Any, Any, Any]) -> dict[str, bool]:
    """Return ok when the request has an active user."""
    await asyncio.sleep(0)
    del request
    return {"ok": True}


def build_app(  # noqa: PLR0913
    *,
    login_identifier: Literal["email", "username"] = "email",
    initial_hashed_password: str | None = None,
    requires_verification: bool = False,
    initial_is_verified: bool = True,
    initial_is_active: bool = True,
    enable_refresh: bool = False,
    totp_pending_secret: str | None = None,
    initial_totp_secret: str | None = None,
) -> tuple[Litestar, InMemoryTokenStrategy | InMemoryRefreshTokenStrategy, TrackingUserManager]:
    """Create an application wired with the generated auth controller.

    Args:
        login_identifier: Credential lookup mode for the controller and manager.
        initial_hashed_password: Optional precomputed hash for the test user.
            When omitted, the user gets an Argon2 hash of "correct-password".
        requires_verification: When True, login returns 400 for unverified users.
        initial_is_verified: Whether the test user is marked verified.
        initial_is_active: Whether the test user is marked active.
        enable_refresh: Whether the generated auth controller exposes refresh-token flows.
        totp_pending_secret: Optional TOTP pending secret enabling 2FA pending-login responses.
        initial_totp_secret: Optional persisted TOTP secret for the seeded user.

    Returns:
        Litestar application, the backing token strategy, and the tracking manager.
    """
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email=_LOGIN_TEST_EMAIL,
        username=_LOGIN_TEST_USERNAME if login_identifier == "username" else "",
        hashed_password=initial_hashed_password or password_helper.hash("correct-password"),
        is_active=initial_is_active,
        is_verified=initial_is_verified,
        totp_secret=initial_totp_secret,
    )
    user_db = InMemoryUserDatabase(users=[user])
    user_manager = TrackingUserManager(
        user_db,
        password_helper,
        verification_token_secret="test-secret-12345-verify-secret-12345",
        reset_password_token_secret="test-secret-12345-reset-secret-12345",
        login_identifier=login_identifier,
    )
    strategy: InMemoryTokenStrategy = InMemoryRefreshTokenStrategy() if enable_refresh else InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    controller = create_auth_controller(
        backend=backend,
        enable_refresh=enable_refresh,
        requires_verification=requires_verification,
        login_identifier=login_identifier,
        totp_pending_secret=totp_pending_secret,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = litestar_app_with_user_manager(
        user_manager,
        controller,
        probe,
        guarded,
        middleware=[middleware],
    )
    return app, strategy, user_manager


def build_cookie_refresh_app() -> tuple[Litestar, InMemoryRefreshTokenStrategy]:
    """Create a direct-controller cookie auth app with refresh-token support.

    Returns:
        Litestar application plus the backing refresh-capable strategy.
    """
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email=_LOGIN_TEST_EMAIL,
        username=_LOGIN_TEST_USERNAME,
        hashed_password=password_helper.hash("correct-password"),
        is_active=True,
        is_verified=True,
    )
    user_db = InMemoryUserDatabase(users=[user])
    user_manager = TrackingUserManager(
        user_db,
        password_helper,
        verification_token_secret="test-secret-12345-verify-secret-12345",
        reset_password_token_secret="test-secret-12345-reset-secret-12345",
    )
    strategy = InMemoryRefreshTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-cookie",
        transport=CookieTransport(cookie_name="auth-cookie", secure=False),
        strategy=cast("Any", strategy),
    )
    controller = create_auth_controller(
        backend=backend,
        enable_refresh=True,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = litestar_app_with_user_manager(
        user_manager,
        controller,
        probe,
        middleware=[middleware],
    )
    return app, strategy


class InMemoryRefreshTokenStrategy(InMemoryTokenStrategy):
    """In-memory token strategy that also supports refresh-token rotation."""

    def __init__(self) -> None:
        """Initialize access and refresh token storage."""
        super().__init__()
        self.refresh_tokens: dict[str, UUID] = {}
        self.refresh_counter = 0

    async def write_refresh_token(self, user: ExampleUser) -> str:
        """Persist and return a refresh token.

        Returns:
            The generated refresh token value.
        """
        self.refresh_counter += 1
        token = f"refresh-{self.refresh_counter}"
        self.refresh_tokens[token] = user.id
        return token

    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: BaseUserManager[ExampleUser, UUID],
    ) -> tuple[ExampleUser, str] | None:
        """Replace a refresh token with a new one for the same user.

        Returns:
            The resolved user plus a freshly minted refresh token, or ``None`` when rotation fails.
        """
        user_id = self.refresh_tokens.pop(refresh_token, None)
        if user_id is None:
            return None
        user = await user_manager.get(user_id)
        if user is None:
            return None
        return user, await self.write_refresh_token(user)


def build_cookie_plugin_app(*, login_identifier: Literal["email", "username"] = "email") -> Litestar:
    """Create an app that exercises plugin-managed CSRF for cookie auth.

    Args:
        login_identifier: Credential lookup mode for the plugin-managed auth stack.

    Returns:
        Litestar app configured with cookie auth and plugin-managed CSRF.
    """
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email=_LOGIN_TEST_EMAIL,
        username=_LOGIN_TEST_USERNAME if login_identifier == "username" else "",
        hashed_password=password_helper.hash("correct-password"),
        is_active=True,
        is_verified=True,
    )
    user_db = InMemoryUserDatabase(users=[user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie",
        transport=CookieTransport(cookie_name="auth-cookie", secure=False),
        strategy=cast("Any", InMemoryTokenStrategy()),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=TrackingUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "password_helper": password_helper,
            "verification_token_secret": "test-secret-12345-verify-secret-12345",
            "reset_password_token_secret": "test-secret-12345-reset-secret-12345",
        },
        csrf_secret="c" * 32,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        login_identifier=login_identifier,
    )
    return Litestar(route_handlers=[probe], plugins=[LitestarAuth(config)])


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_returns_token_and_logout_invalidates_it(
    login_identifier: Literal["email", "username"],
) -> None:
    """Login issues a bearer token and logout removes it from future requests."""
    cred = login_identifier_credential(login_identifier)
    app, strategy, user_manager = build_app(login_identifier=login_identifier)

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )

        assert login_response.status_code == HTTP_CREATED
        assert login_response.json() == {"access_token": "token-1", "token_type": "bearer"}
        assert list(strategy.tokens) == ["token-1"]
        assert [user.email for user in user_manager.logged_in_users] == [_LOGIN_TEST_EMAIL]

        authorized_response = await client.get("/probe", headers={"Authorization": "Bearer token-1"})
        assert authorized_response.status_code == HTTP_OK
        assert authorized_response.json() == {"email": _LOGIN_TEST_EMAIL}

        logout_response = await client.post("/auth/logout", headers={"Authorization": "Bearer token-1"})
        assert logout_response.status_code == HTTP_CREATED
        assert logout_response.json() is None
        assert strategy.tokens == {}

        logged_out_response = await client.get("/probe", headers={"Authorization": "Bearer token-1"})
        assert logged_out_response.status_code == HTTP_OK
        assert logged_out_response.json() == {"email": None}


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_inactive_user_is_rejected(login_identifier: Literal["email", "username"]) -> None:
    """Inactive users are rejected by the login endpoint."""
    cred = login_identifier_credential(login_identifier)
    app, _, _ = build_app(login_identifier=login_identifier, initial_is_active=False)
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )

    assert response.status_code != HTTP_CREATED
    assert response.status_code == HTTP_BAD_REQUEST
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_INACTIVE
    assert "inactive" in str(data.get("detail", "")).lower()


async def test_guarded_route_rejects_inactive_user_token() -> None:
    """Guards deny tokens belonging to inactive users."""
    app, strategy, user_manager = build_app(initial_is_active=False)
    user = await user_manager.user_db.get_by_email(_LOGIN_TEST_EMAIL)
    assert user is not None
    token = await strategy.write_token(user)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/guarded", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code in {401, 403}


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_uses_same_error_for_missing_user_and_wrong_password(
    login_identifier: Literal["email", "username"],
) -> None:
    """Invalid credentials return the same anti-enumeration response."""
    cred = login_identifier_credential(login_identifier)
    app, _, _ = build_app(login_identifier=login_identifier)
    async with AsyncTestClient(app=app) as client:
        missing_user_response = await client.post(
            "/auth/login",
            json={"identifier": missing_user_identifier(login_identifier), "password": "correct-password"},
        )
        wrong_password_response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "wrong-password"},
        )

    assert missing_user_response.status_code == HTTP_BAD_REQUEST
    assert wrong_password_response.status_code == HTTP_BAD_REQUEST
    assert missing_user_response.json() == wrong_password_response.json()
    data = missing_user_response.json()
    assert data["detail"] == "Invalid credentials."
    assert "code" in data or (isinstance(data.get("extra"), dict) and "code" in data["extra"])


async def test_login_error_response_contains_code() -> None:
    """Login error response includes machine-readable code (detail and code format)."""
    app, _, _ = build_app()
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": "wrong@example.com", "password": "wrong"},
        )
    assert response.status_code == HTTP_BAD_REQUEST
    data = response.json()
    assert "detail" in data
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_BAD_CREDENTIALS


async def test_login_returns_pending_token_when_totp_is_enabled() -> None:
    """A user with TOTP configured receives a pending token instead of a full login response."""
    app, strategy, user_manager = build_app(
        totp_pending_secret="pending-secret-for-integration-tests-123",
        initial_totp_secret="JBSWY3DPEHPK3PXP",
    )

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": _LOGIN_TEST_EMAIL, "password": "correct-password"},
        )

    assert response.status_code == HTTP_OK + 2
    assert response.json()["totp_required"] is True
    assert isinstance(response.json()["pending_token"], str)
    assert response.json().get("access_token") is None
    assert strategy.tokens == {}
    assert user_manager.logged_in_users == []


async def test_login_email_mode_accepts_case_insensitive_identifier() -> None:
    """Email-mode login succeeds when the identifier casing differs from storage."""
    app, strategy, _ = build_app()

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": "USER@EXAMPLE.COM", "password": "correct-password"},
        )

    assert response.status_code == HTTP_CREATED
    assert response.json() == {"access_token": "token-1", "token_type": "bearer"}
    assert list(strategy.tokens) == ["token-1"]


async def test_login_username_mode_accepts_whitespace_and_case_variations() -> None:
    """Username-mode login succeeds after controller and manager normalization."""
    app, strategy, _ = build_app(login_identifier="username")

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": "  TESTUSER  ", "password": "correct-password"},
        )

    assert response.status_code == HTTP_CREATED
    assert response.json() == {"access_token": "token-1", "token_type": "bearer"}
    assert list(strategy.tokens) == ["token-1"]


async def test_login_and_refresh_rotate_refresh_tokens_in_auth_controller() -> None:
    """Refresh-enabled auth controller rotates refresh tokens and rejects replay."""
    app, strategy, _ = build_app(enable_refresh=True)
    refresh_strategy = cast("InMemoryRefreshTokenStrategy", strategy)

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": _LOGIN_TEST_EMAIL, "password": "correct-password"},
        )
        refresh_token = login_response.json()["refresh_token"]

        refresh_response = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
        replay_response = await client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert login_response.status_code == HTTP_CREATED
    assert login_response.json() == {
        "access_token": "token-1",
        "token_type": "bearer",
        "refresh_token": "refresh-1",
    }
    assert refresh_response.status_code == HTTP_CREATED
    assert refresh_response.json() == {
        "access_token": "token-2",
        "token_type": "bearer",
        "refresh_token": "refresh-2",
    }
    assert replay_response.status_code == HTTP_BAD_REQUEST
    replay_code = replay_response.json().get("code") or (replay_response.json().get("extra") or {}).get("code")
    assert replay_code == ErrorCode.REFRESH_TOKEN_INVALID
    assert refresh_strategy.refresh_tokens == {"refresh-2": next(iter(strategy.tokens.values()))}


async def test_refresh_rejects_inactive_user_in_auth_controller() -> None:
    """Refresh denies issuing new tokens after the account becomes inactive."""
    app, strategy, user_manager = build_app(enable_refresh=True)
    refresh_strategy = cast("InMemoryRefreshTokenStrategy", strategy)

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": _LOGIN_TEST_EMAIL, "password": "correct-password"},
        )
        user = await user_manager.user_db.get_by_email(_LOGIN_TEST_EMAIL)
        assert user is not None
        user.is_active = False
        response = await client.post(
            "/auth/refresh",
            json={"refresh_token": login_response.json()["refresh_token"]},
        )

    assert response.status_code == HTTP_BAD_REQUEST
    code = response.json().get("code") or (response.json().get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_INACTIVE
    assert refresh_strategy.refresh_tokens == {"refresh-2": user.id}


async def test_cookie_logout_clears_access_and_refresh_cookies() -> None:
    """Cookie transport clears both auth and refresh cookies on logout."""
    app, _strategy = build_cookie_refresh_app()

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": _LOGIN_TEST_EMAIL, "password": "correct-password"},
        )
        logout_response = await client.post("/auth/logout")

    assert login_response.status_code == HTTP_CREATED
    assert login_response.cookies.get("auth-cookie") is not None
    assert login_response.cookies.get("auth-cookie_refresh") == "refresh-1"

    assert logout_response.status_code == HTTP_CREATED
    cleared_cookies = logout_response.headers.get_list("set-cookie")
    assert any(cookie.startswith('auth-cookie="";') and "Max-Age=0" in cookie for cookie in cleared_cookies)
    assert any(cookie.startswith('auth-cookie_refresh="";') and "Max-Age=0" in cookie for cookie in cleared_cookies)


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_hook_is_not_called_for_invalid_credentials(
    login_identifier: Literal["email", "username"],
) -> None:
    """The login hook only runs after a successful controller login."""
    cred = login_identifier_credential(login_identifier)
    app, _, user_manager = build_app(login_identifier=login_identifier)

    async with AsyncTestClient(app=app) as client:
        await client.post(
            "/auth/login",
            json={"identifier": missing_user_identifier(login_identifier), "password": "correct-password"},
        )
        await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "wrong-password"},
        )

    assert user_manager.logged_in_users == []


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_with_bcrypt_hash_upgrades_to_argon2(
    login_identifier: Literal["email", "username"],
) -> None:
    """Login with a user whose password is stored as bcrypt upgrades the hash to Argon2."""
    cred = login_identifier_credential(login_identifier)
    bcrypt_hash = BcryptHasher().hash("correct-password")
    app, _, user_manager = build_app(login_identifier=login_identifier, initial_hashed_password=bcrypt_hash)

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )
    assert response.status_code == HTTP_CREATED
    stored = await user_manager.user_db.get_by_email(_LOGIN_TEST_EMAIL)
    assert stored is not None
    assert stored.hashed_password.startswith("$argon2")


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_with_current_argon2_hash_does_not_update(
    login_identifier: Literal["email", "username"],
) -> None:
    """Login with an already current Argon2 hash does not rewrite the hash."""
    cred = login_identifier_credential(login_identifier)
    app, _, user_manager = build_app(login_identifier=login_identifier)
    before = await user_manager.user_db.get_by_email(_LOGIN_TEST_EMAIL)
    assert before is not None
    original_hash = before.hashed_password

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )
    assert response.status_code == HTTP_CREATED
    after = await user_manager.user_db.get_by_email(_LOGIN_TEST_EMAIL)
    assert after is not None
    assert after.hashed_password == original_hash


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_failed_login_does_not_update_hash(login_identifier: Literal["email", "username"]) -> None:
    """Failed login (wrong password) does not upgrade or change the stored hash."""
    cred = login_identifier_credential(login_identifier)
    bcrypt_hash = BcryptHasher().hash("correct-password")
    app, _, user_manager = build_app(login_identifier=login_identifier, initial_hashed_password=bcrypt_hash)

    async with AsyncTestClient(app=app) as client:
        await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "wrong-password"},
        )
    stored = await user_manager.user_db.get_by_email(_LOGIN_TEST_EMAIL)
    assert stored is not None
    assert stored.hashed_password == bcrypt_hash


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_requires_verification_true_unverified_returns_400(
    login_identifier: Literal["email", "username"],
) -> None:
    """When requires_verification=True, unverified user gets 400 with LOGIN_USER_NOT_VERIFIED."""
    cred = login_identifier_credential(login_identifier)
    app, _, _ = build_app(
        login_identifier=login_identifier,
        requires_verification=True,
        initial_is_verified=False,
    )
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )
    assert response.status_code == HTTP_BAD_REQUEST
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_NOT_VERIFIED
    assert "detail" in data


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_requires_verification_true_verified_succeeds(
    login_identifier: Literal["email", "username"],
) -> None:
    """When requires_verification=True, verified user gets token (201)."""
    cred = login_identifier_credential(login_identifier)
    app, strategy, user_manager = build_app(
        login_identifier=login_identifier,
        requires_verification=True,
        initial_is_verified=True,
    )
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )
    assert response.status_code == HTTP_CREATED
    assert response.json() == {"access_token": "token-1", "token_type": "bearer"}
    assert list(strategy.tokens) == ["token-1"]
    assert [u.email for u in user_manager.logged_in_users] == [_LOGIN_TEST_EMAIL]


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_requires_verification_false_allows_unverified_login(
    login_identifier: Literal["email", "username"],
) -> None:
    """When requires_verification=False, unverified user can log in (no verification check)."""
    cred = login_identifier_credential(login_identifier)
    app, strategy, user_manager = build_app(
        login_identifier=login_identifier,
        requires_verification=False,
        initial_is_verified=False,
    )
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )
    assert response.status_code == HTTP_CREATED
    assert response.json() == {"access_token": "token-1", "token_type": "bearer"}
    assert list(strategy.tokens) == ["token-1"]
    assert [u.email for u in user_manager.logged_in_users] == [_LOGIN_TEST_EMAIL]


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_cookie_plugin_logout_requires_csrf_header(
    login_identifier: Literal["email", "username"],
) -> None:
    """Cookie-authenticated logout is rejected without the seeded CSRF header."""
    cred = login_identifier_credential(login_identifier)
    async with AsyncTestClient(app=build_cookie_plugin_app(login_identifier=login_identifier)) as client:
        seed_response = await client.get("/probe")
        csrf_token = seed_response.cookies.get("litestar_auth_csrf")
        assert csrf_token is not None

        login_response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert login_response.status_code == HTTP_CREATED

        forbidden_response = await client.post("/auth/logout")
        assert forbidden_response.status_code == HTTP_FORBIDDEN

        logout_response = await client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
        assert logout_response.status_code == HTTP_CREATED


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_accepts_identifier_field(login_identifier: Literal["email", "username"]) -> None:
    r"""POST /auth/login accepts {"identifier": ..., "password": ...}."""
    cred = login_identifier_credential(login_identifier)
    app, strategy, _ = build_app(login_identifier=login_identifier)
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": "correct-password"},
        )
    assert response.status_code == HTTP_CREATED
    assert response.json() == {"access_token": "token-1", "token_type": "bearer"}
    assert list(strategy.tokens) == ["token-1"]


async def test_login_rejects_legacy_email_only_payload() -> None:
    r"""POST /auth/login rejects {"email": ..., "password": ...} (use identifier)."""
    app, _, _ = build_app()
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"email": _LOGIN_TEST_EMAIL, "password": "correct-password"},
        )
    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_PAYLOAD_INVALID


async def test_login_missing_identifier_returns_422() -> None:
    """Password without identifier is rejected before authentication (LOGIN_PAYLOAD_INVALID)."""
    app, _, _ = build_app()
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"password": "correct-password"},
        )
    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_PAYLOAD_INVALID


async def test_login_rejects_legacy_dual_field_payload() -> None:
    """Legacy email+username keys are rejected (single identifier field required)."""
    app, _, _ = build_app()
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={
                "email": _LOGIN_TEST_EMAIL,
                "username": _LOGIN_TEST_EMAIL,
                "password": "correct-password",
            },
        )
    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_PAYLOAD_INVALID


async def test_login_returns_422_for_invalid_identifier_format_in_email_mode() -> None:
    r"""POST /auth/login with identifier not matching email regex returns 422."""
    app, _, _ = build_app()
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": "notanemail", "password": "correct-password"},
        )
    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_PAYLOAD_INVALID


async def test_login_returns_422_for_identifier_longer_than_320() -> None:
    r"""POST /auth/login with identifier longer than 320 characters returns 422."""
    app, _, _ = build_app()
    long_local = "a" * 310
    long_username = f"{long_local}@example.com"
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": long_username, "password": "correct-password"},
        )
    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_PAYLOAD_INVALID


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_accepts_128_character_password(
    login_identifier: Literal["email", "username"],
) -> None:
    """POST /auth/login accepts passwords at the 128-character validation limit."""
    cred = login_identifier_credential(login_identifier)
    password = "p" * 128
    app, _, _ = build_app(login_identifier=login_identifier, initial_hashed_password=PasswordHelper().hash(password))

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": password},
        )

    assert response.status_code == HTTP_CREATED


@pytest.mark.parametrize("login_identifier", ["email", "username"])
async def test_login_rejects_password_longer_than_128_characters(
    login_identifier: Literal["email", "username"],
) -> None:
    """POST /auth/login rejects passwords longer than 128 characters with a validation error."""
    cred = login_identifier_credential(login_identifier)
    app, _, _ = build_app(login_identifier=login_identifier)
    password = "p" * 129

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": cred, "password": password},
        )

    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    data = response.json()
    code = data.get("code") or (data.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_PAYLOAD_INVALID
