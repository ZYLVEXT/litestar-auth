"""End-to-end OAuth flow with a mock provider and the auth plugin."""

from __future__ import annotations

import base64
import sqlite3
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Litestar, Request, get
from litestar.testing import AsyncTestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002
from sqlalchemy.pool import StaticPool

from litestar_auth._manager._coercions import _account_state_user
from litestar_auth._plugin.config import OAuthConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import create_oauth_associate_controller
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.exceptions import ErrorCode, InactiveUserError, UnverifiedUserError
from litestar_auth.guards import is_authenticated
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import OAuthAccount, User
from litestar_auth.oauth import create_provider_oauth_controller
from litestar_auth.oauth_encryption import OAuthTokenEncryption, bind_oauth_token_encryption
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import SessionMaker

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from litestar.types import ControllerRouterHandler
    from sqlalchemy.engine import Engine

pytestmark = pytest.mark.e2e

HTTP_BAD_REQUEST = 400
HTTP_CREATED = 201
HTTP_FOUND = 302
HTTP_NOT_FOUND = 404
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401


class OAuthUserManager(BaseUserManager[User, UUID]):
    """Concrete user manager used by the e2e OAuth app."""


class OAuthUserDatabaseProxy:
    """Session-per-call proxy exposing OAuth user DB operations."""

    def __init__(self, session_maker: SessionMaker, *, oauth_token_encryption: OAuthTokenEncryption) -> None:
        """Store the session factory and explicit OAuth token policy."""
        self._session_maker = session_maker
        self._oauth_token_encryption = oauth_token_encryption

    async def get_by_email(self, email: str) -> User | None:
        """Load a user by email.

        Returns:
            The matching user, if any.
        """
        async with self._session_maker() as session:
            return await SQLAlchemyUserDatabase(
                session,
                user_model=User,
                oauth_account_model=OAuthAccount,
                oauth_token_encryption=self._oauth_token_encryption,
            ).get_by_email(email)

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> User | None:
        """Load a user by linked OAuth account.

        Returns:
            The matching user, if any.
        """
        async with self._session_maker() as session:
            return await SQLAlchemyUserDatabase(
                session,
                user_model=User,
                oauth_account_model=OAuthAccount,
                oauth_token_encryption=self._oauth_token_encryption,
            ).get_by_oauth_account(oauth_name, account_id)

    async def upsert_oauth_account(  # noqa: PLR0913
        self,
        user: User,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        """Create or update a persisted OAuth account."""
        async with self._session_maker() as session:
            user_db = SQLAlchemyUserDatabase(
                session,
                user_model=User,
                oauth_account_model=OAuthAccount,
                oauth_token_encryption=self._oauth_token_encryption,
            )
            persistent_user = await user_db.get(user.id)
            assert persistent_user is not None
            await user_db.upsert_oauth_account(
                persistent_user,
                oauth_name=oauth_name,
                account_id=account_id,
                account_email=account_email,
                access_token=access_token,
                expires_at=expires_at,
                refresh_token=refresh_token,
            )


class OAuthManagerProxy:
    """Session-per-call proxy matching the OAuth controller contract."""

    def __init__(
        self,
        session_maker: SessionMaker,
        password_helper: PasswordHelper,
        *,
        oauth_token_encryption: OAuthTokenEncryption,
    ) -> None:
        """Store collaborators used to build real managers."""
        self._session_maker = session_maker
        self._password_helper = password_helper
        self._oauth_token_encryption = oauth_token_encryption
        self.user_db = OAuthUserDatabaseProxy(
            session_maker,
            oauth_token_encryption=oauth_token_encryption,
        )
        self.oauth_account_store = self.user_db

    def _build_manager(self, session: AsyncSession) -> OAuthUserManager:
        """Build a real user manager for one session.

        Returns:
            A session-bound user manager.
        """
        return OAuthUserManager(
            user_db=SQLAlchemyUserDatabase(
                session,
                user_model=User,
                oauth_account_model=OAuthAccount,
                oauth_token_encryption=self._oauth_token_encryption,
            ),
            password_helper=self._password_helper,
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            id_parser=UUID,
        )

    async def create(
        self,
        user_create: Mapping[str, Any],
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> User:
        """Create a user through the real manager.

        Returns:
            The created user.
        """
        async with self._session_maker() as session:
            return await self._build_manager(session).create(
                user_create,
                safe=safe,
                allow_privileged=allow_privileged,
            )

    async def update(self, user_update: Mapping[str, Any], user: User) -> User:
        """Update a user through the real manager.

        Returns:
            The updated user.
        """
        async with self._session_maker() as session:
            user_db = SQLAlchemyUserDatabase(
                session,
                user_model=User,
                oauth_account_model=OAuthAccount,
                oauth_token_encryption=self._oauth_token_encryption,
            )
            persistent_user = await user_db.get(user.id)
            assert persistent_user is not None
            return await self._build_manager(session).update(user_update, persistent_user)

    async def on_after_login(self, user: User) -> None:
        """Delegate post-login hooks to the real manager."""
        async with self._session_maker() as session:
            user_db = SQLAlchemyUserDatabase(
                session,
                user_model=User,
                oauth_account_model=OAuthAccount,
                oauth_token_encryption=self._oauth_token_encryption,
            )
            persistent_user = await user_db.get(user.id)
            assert persistent_user is not None
            await self._build_manager(session).on_after_login(persistent_user)

    def require_account_state(self, user: User, *, require_verified: bool = False) -> None:
        """Delegate account-state policy checks to the shared manager implementation.

        Raises:
            InactiveUserError: If the user is inactive.
            UnverifiedUserError: If verification is required and the user is unverified.
        """
        account_user = _account_state_user(user)
        if not account_user.is_active:
            raise InactiveUserError
        if require_verified and not account_user.is_verified:
            raise UnverifiedUserError


class FakeOAuthClient:
    """Mock OAuth provider with deterministic redirects and identities."""

    def __init__(
        self,
        *,
        account_id: str = "provider-user-1",
        email: str = "oauth@example.com",
        email_verified: bool = True,
    ) -> None:
        """Store the deterministic provider identity."""
        self.account_id = account_id
        self.email = email
        self.email_verified = email_verified
        self.authorization_calls: list[tuple[str, str, str | None]] = []
        self.access_token_calls: list[tuple[str, str]] = []
        self.id_email_calls: list[str] = []

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        *,
        scope: str | None = None,
    ) -> str:
        """Return a deterministic provider authorization URL."""
        self.authorization_calls.append((redirect_uri, state, scope))
        base = f"https://provider.example/authorize?state={state}"
        if scope:
            return f"{base}&scope={scope}"
        return base

    async def get_access_token(self, code: str, redirect_uri: str) -> dict[str, object]:
        """Return a deterministic OAuth token payload."""
        self.access_token_calls.append((code, redirect_uri))
        return {
            "access_token": "provider-access-token",
            "expires_at": 1_234_567_890,
            "refresh_token": "provider-refresh-token",
        }

    async def get_id_email(self, access_token: str) -> tuple[str, str]:
        """Return the deterministic provider account id and email."""
        self.id_email_calls.append(access_token)
        return self.account_id, self.email

    async def get_profile(self, access_token: str) -> dict[str, object]:
        """Return a deterministic provider profile payload."""
        del access_token
        return {"email_verified": self.email_verified}


@dataclass(slots=True)
class AppState:
    """Shared app state for the OAuth e2e tests."""

    engine: Engine
    session_maker: SessionMaker
    oauth_client: FakeOAuthClient
    password_helper: PasswordHelper
    oauth_token_encryption: OAuthTokenEncryption


@get("/protected", guards=[is_authenticated], sync_to_thread=False)
def protected_route(request: Request[Any, Any, Any]) -> dict[str, str]:
    """Return the authenticated user's email."""
    user = cast("User", request.user)
    return {"email": user.email}


def build_app(
    *,
    oauth_client: FakeOAuthClient | None = None,
    associate_by_email: bool = False,
    include_login_controller: bool = True,
    include_associate_controller: bool = False,
    plugin_oauth_config: OAuthConfig | None = None,
) -> tuple[Litestar, AppState]:
    """Create a Litestar app wired with the auth plugin and optional OAuth controllers.

    Returns:
        The configured app and its shared test state.
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

    password_helper = PasswordHelper()
    session_maker = SessionMaker(engine)
    jwt_secret = "oauth-jwt-secret-1234567890-extra"
    oauth_token_encryption_key = base64.urlsafe_b64encode(b"0" * 32).decode()
    configured_plugin_oauth = plugin_oauth_config or OAuthConfig()
    if configured_plugin_oauth.oauth_token_encryption_key is None:
        configured_plugin_oauth = replace(
            configured_plugin_oauth,
            oauth_token_encryption_key=oauth_token_encryption_key,
        )
    assert configured_plugin_oauth.oauth_token_encryption_key is not None
    oauth_token_encryption = OAuthTokenEncryption(configured_plugin_oauth.oauth_token_encryption_key)
    backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast("Any", JWTStrategy[User, UUID](secret=jwt_secret, subject_decoder=UUID)),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", session_maker),
        user_model=User,
        user_manager_class=OAuthUserManager,
        allow_nondurable_jwt_revocation=True,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(
            session,
            user_model=User,
            oauth_account_model=OAuthAccount,
        ),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            id_parser=UUID,
        ),
        user_manager_kwargs={"password_helper": password_helper},
        oauth_config=configured_plugin_oauth,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        include_users=False,
    )
    plugin = LitestarAuth(config)
    oauth_manager = OAuthManagerProxy(
        session_maker,
        password_helper,
        oauth_token_encryption=oauth_token_encryption,
    )
    fake_oauth_client = oauth_client or FakeOAuthClient()
    route_handlers: list[ControllerRouterHandler] = []
    if include_login_controller:
        route_handlers.append(
            create_provider_oauth_controller(
                provider_name="github",
                backend=backend,
                user_manager=oauth_manager,
                oauth_client=fake_oauth_client,
                redirect_base_url="https://testserver.local/auth/oauth",
                associate_by_email=associate_by_email,
                trust_provider_email_verified=True,
            ),
        )
    route_handlers.append(protected_route)
    if include_associate_controller:
        route_handlers.append(
            create_oauth_associate_controller(
                provider_name="github",
                user_manager=oauth_manager,
                oauth_client=fake_oauth_client,
                redirect_base_url="https://testserver.local/auth/associate",
            ),
        )
    app = Litestar(route_handlers=route_handlers, plugins=[plugin])
    return app, AppState(
        engine=engine,
        session_maker=session_maker,
        oauth_client=fake_oauth_client,
        password_helper=password_helper,
        oauth_token_encryption=oauth_token_encryption,
    )


async def get_user_by_email(state: AppState, email: str) -> User | None:
    """Load a user by email from the test database.

    Returns:
        The matching user, if any.
    """
    async with state.session_maker() as session:
        result = cast("Any", await session.execute(select(User).where(User.email == email)))
        return cast("User | None", result.scalar_one_or_none())


async def get_oauth_account(state: AppState, oauth_name: str, account_id: str) -> OAuthAccount | None:
    """Load an OAuth account from the test database.

    Returns:
        The matching OAuth account, if any.
    """
    async with state.session_maker() as session:
        bind_oauth_token_encryption(session, state.oauth_token_encryption)
        result = cast(
            "Any",
            await session.execute(
                select(OAuthAccount).where(
                    OAuthAccount.oauth_name == oauth_name,
                    OAuthAccount.account_id == account_id,
                ),
            ),
        )
        return cast("OAuthAccount | None", result.scalar_one_or_none())


async def create_local_user(
    state: AppState,
    *,
    email: str,
    password: str,
    is_active: bool = True,
    is_verified: bool = True,
) -> User:
    """Seed a local user through the real manager and persistence stack.

    Returns:
        The persisted local user.
    """
    async with state.session_maker() as session:
        manager = OAuthUserManager(
            user_db=SQLAlchemyUserDatabase(
                session,
                user_model=User,
                oauth_account_model=OAuthAccount,
                oauth_token_encryption=state.oauth_token_encryption,
            ),
            password_helper=state.password_helper,
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            id_parser=UUID,
        )
        user = await manager.create({"email": email, "password": password})
        if not is_active:
            user = await manager.update({"is_active": False}, user)
        if is_verified:
            user = await manager.update({"is_verified": True}, user)
        await session.commit()
        await session.refresh(user)
        session.expunge(user)
        return user


@pytest.fixture
def app() -> Iterator[tuple[Litestar, AppState]]:
    """Create the shared OAuth e2e app.

    Yields:
        The shared app and its backing test state.
    """
    oauth_app, state = build_app()
    yield oauth_app, state
    state.engine.dispose()


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so cookie and redirect behavior matches production wiring.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


async def test_oauth_authorize_callback_creates_user_and_returns_token(
    client: tuple[AsyncTestClient[Litestar], AppState],
) -> None:
    """Authorize and callback create a verified user and issue a usable local token."""
    test_client, state = client

    authorize_response = await test_client.get("/auth/oauth/github/authorize", follow_redirects=False)

    assert authorize_response.status_code == HTTP_FOUND
    state_cookie = authorize_response.cookies.get("__oauth_state_github")
    assert state_cookie is not None
    assert authorize_response.headers["location"].startswith("https://provider.example/authorize?state=")
    assert state.oauth_client.authorization_calls == [
        ("https://testserver.local/auth/oauth/github/callback", state_cookie, None),
    ]

    callback_response = await test_client.get(
        "/auth/oauth/github/callback",
        params={"code": "provider-code", "state": state_cookie},
    )

    assert callback_response.status_code == HTTP_OK
    token = callback_response.json()["access_token"]
    assert token
    created_user = await get_user_by_email(state, "oauth@example.com")
    assert created_user is not None
    assert created_user.is_verified is True
    oauth_account = await get_oauth_account(state, "github", "provider-user-1")
    assert oauth_account is not None
    assert oauth_account.user_id == created_user.id
    assert oauth_account.account_email == "oauth@example.com"

    protected_response = await test_client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert protected_response.status_code == HTTP_OK
    assert protected_response.json() == {"email": "oauth@example.com"}


async def test_oauth_callback_links_existing_user_by_email() -> None:
    """OAuth callback links the provider account to an existing local user (associate_by_email=True)."""
    app, state = build_app(
        oauth_client=FakeOAuthClient(account_id="provider-user-2", email="linked@example.com"),
        associate_by_email=True,
    )
    existing_user = await create_local_user(
        state,
        email="linked@example.com",
        password="existing-password",
    )

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={
                "code": "provider-code",
                "state": authorize_response.cookies["__oauth_state_github"],
            },
        )

    assert callback_response.status_code == HTTP_OK
    assert await get_user_by_email(state, "linked@example.com") is not None
    oauth_account = await get_oauth_account(state, "github", "provider-user-2")
    assert oauth_account is not None
    assert oauth_account.user_id == existing_user.id

    async with state.session_maker() as session:
        result = cast("Any", await session.execute(select(User)))
        users = list(result.scalars())
    assert len(users) == 1
    state.engine.dispose()


async def test_oauth_callback_rejects_inactive_existing_user_before_session_issue() -> None:
    """OAuth callback blocks inactive local accounts before issuing local session artifacts."""
    app, state = build_app(
        oauth_client=FakeOAuthClient(account_id="provider-user-inactive", email="inactive@example.com"),
        associate_by_email=True,
    )
    await create_local_user(
        state,
        email="inactive@example.com",
        password="inactive-password",
        is_active=False,
    )

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={
                "code": "provider-code",
                "state": authorize_response.cookies["__oauth_state_github"],
            },
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    assert callback_response.json().get("code") == ErrorCode.LOGIN_USER_INACTIVE
    assert "access_token" not in callback_response.json()
    assert await get_oauth_account(state, "github", "provider-user-inactive") is None
    state.engine.dispose()


async def test_oauth_callback_associate_by_email_false_returns_400_when_email_exists() -> None:
    """OAuth callback returns 400 with OAUTH_USER_ALREADY_EXISTS when associate_by_email=False and email exists."""
    app, state = build_app(
        oauth_client=FakeOAuthClient(account_id="provider-user-3", email="existing@example.com"),
        associate_by_email=False,
    )
    await create_local_user(state, email="existing@example.com", password="secret-password-12")

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={
                "code": "provider-code",
                "state": authorize_response.cookies["__oauth_state_github"],
            },
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    assert body.get("code") == ErrorCode.OAUTH_USER_ALREADY_EXISTS
    assert await get_oauth_account(state, "github", "provider-user-3") is None
    state.engine.dispose()


async def test_oauth_callback_returns_existing_user_when_provider_identity_already_linked() -> None:
    """OAuth callback returns the existing user's token when provider identity is already linked (one identity -> one user)."""
    app, state = build_app(
        oauth_client=FakeOAuthClient(account_id="shared-provider-id", email="first@example.com"),
    )
    user_a = await create_local_user(
        state,
        email="first@example.com",
        password="password-aaaa",
    )
    await create_local_user(
        state,
        email="second@example.com",
        password="password-bbbb",
    )
    async with state.session_maker() as session:
        user_db = SQLAlchemyUserDatabase(
            session,
            user_model=User,
            oauth_account_model=OAuthAccount,
            oauth_token_encryption=state.oauth_token_encryption,
        )
        await user_db.upsert_oauth_account(
            user_a,
            oauth_name="github",
            account_id="shared-provider-id",
            account_email="first@example.com",
            access_token="stored-token",
            expires_at=0,
            refresh_token=None,
        )

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state_cookie = authorize_response.cookies["__oauth_state_github"]
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state_cookie},
        )
        assert callback_response.status_code == HTTP_OK
        token = callback_response.json()["access_token"]
        assert token
        protected_response = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert protected_response.status_code == HTTP_OK
    assert protected_response.json() == {"email": "first@example.com"}
    oauth_account = await get_oauth_account(state, "github", "shared-provider-id")
    assert oauth_account is not None
    assert oauth_account.user_id == user_a.id
    state.engine.dispose()


async def test_oauth_callback_rejects_invalid_state(
    client: tuple[AsyncTestClient[Litestar], AppState],
) -> None:
    """OAuth callback rejects a mismatched state cookie."""
    test_client, state = client
    del state
    test_client.cookies.set(
        "__oauth_state_github",
        "cookie-state",
        domain="testserver.local",
        path="/auth/oauth/github",
    )

    response = await test_client.get(
        "/auth/oauth/github/callback",
        params={"code": "provider-code", "state": "query-state"},
    )

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == "Invalid OAuth state."

    protected_response = await test_client.get("/protected")
    assert protected_response.status_code == HTTP_UNAUTHORIZED


async def test_oauth_associate_links_provider_to_authenticated_user() -> None:
    """Authenticated users can link an OAuth provider without creating a new user."""
    app, state = build_app(
        oauth_client=FakeOAuthClient(account_id="associate-provider-id", email="provider@example.com"),
        include_associate_controller=True,
    )
    existing_user = await create_local_user(
        state,
        email="linked@example.com",
        password="existing-password",
    )

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "linked@example.com", "password": "existing-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        authorize_response = await client.get(
            "/auth/associate/github/authorize",
            headers={"Authorization": f"Bearer {access_token}"},
            follow_redirects=False,
        )
        assert authorize_response.status_code == HTTP_FOUND
        state_cookie = authorize_response.cookies.get("__oauth_associate_state_github")
        assert state_cookie is not None

        callback_response = await client.get(
            "/auth/associate/github/callback",
            params={"code": "provider-code", "state": state_cookie},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert callback_response.status_code == HTTP_OK
        assert callback_response.json() == {"linked": True}

    oauth_account = await get_oauth_account(state, "github", "associate-provider-id")
    assert oauth_account is not None
    assert oauth_account.user_id == existing_user.id

    async with state.session_maker() as session:
        result = cast("Any", await session.execute(select(User)))
        users = list(result.scalars())
    assert len(users) == 1
    state.engine.dispose()


async def test_plugin_managed_oauth_associate_routes_link_provider_to_authenticated_user() -> None:
    """Plugin-owned associate routes reuse the shared provider inventory and linking flow."""
    oauth_client = FakeOAuthClient(account_id="plugin-associate-provider-id", email="provider@example.com")
    app, state = build_app(
        oauth_client=oauth_client,
        include_login_controller=False,
        plugin_oauth_config=OAuthConfig(
            oauth_providers=[("github", oauth_client)],
            oauth_redirect_base_url="https://testserver.local/auth",
            include_oauth_associate=True,
        ),
    )
    existing_user = await create_local_user(
        state,
        email="linked@example.com",
        password="existing-password",
    )

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "linked@example.com", "password": "existing-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        authorize_response = await client.get(
            "/auth/associate/github/authorize",
            headers={"Authorization": f"Bearer {access_token}"},
            follow_redirects=False,
        )
        assert authorize_response.status_code == HTTP_FOUND
        state_cookie = authorize_response.cookies.get("__oauth_associate_state_github")
        assert state_cookie is not None
        assert "path=/auth/associate/github" in authorize_response.headers["set-cookie"].lower()

        callback_response = await client.get(
            "/auth/associate/github/callback",
            params={"code": "provider-code", "state": state_cookie},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert callback_response.status_code == HTTP_OK
        assert callback_response.json() == {"linked": True}

    oauth_account = await get_oauth_account(state, "github", "plugin-associate-provider-id")
    assert oauth_account is not None
    assert oauth_account.user_id == existing_user.id
    state.engine.dispose()


async def test_plugin_oauth_provider_inventory_auto_mounts_login_routes_and_keeps_associate_optional() -> None:
    """The single plugin-owned provider inventory mounts login routes without implying associate routes."""
    oauth_client = FakeOAuthClient(account_id="provider-user-login-only", email="oauth@example.com")
    app, state = build_app(
        oauth_client=oauth_client,
        include_login_controller=False,
        plugin_oauth_config=OAuthConfig(
            oauth_providers=[("github", oauth_client)],
            oauth_redirect_base_url="https://testserver.local/auth",
        ),
    )

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as client:
        login_authorize = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        assert login_authorize.status_code == HTTP_FOUND
        login_state = login_authorize.cookies.get("__oauth_state_github")
        assert login_state is not None

        missing_associate_route = await client.get(
            "/auth/associate/github/authorize",
            follow_redirects=False,
        )
        assert missing_associate_route.status_code == HTTP_NOT_FOUND

        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": login_state},
        )
        assert callback_response.status_code == HTTP_OK

    assert state.oauth_client.authorization_calls == [
        ("https://testserver.local/auth/oauth/github/callback", login_state, None),
    ]
    assert "path=/auth/oauth/github" in login_authorize.headers["set-cookie"].lower()
    oauth_account = await get_oauth_account(state, "github", "provider-user-login-only")
    assert oauth_account is not None
    state.engine.dispose()
