"""Integration tests for the generated OAuth controller."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar
from litestar.di import Provide
from litestar.middleware import DefineMiddleware
from litestar.testing import AsyncTestClient

from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import (
    create_oauth_associate_controller,
    create_oauth_controller,
)
from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import (
    ConfigurationError,
    ErrorCode,
    OAuthAccountAlreadyLinkedError,
    UnverifiedUserError,
)
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.oauth import create_provider_oauth_controller
from litestar_auth.password import PasswordHelper
from tests._helpers import ExampleUser, auth_middleware_get_request_session

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from litestar_auth.types import LoginIdentifier

pytestmark = pytest.mark.integration
HTTP_CREATED = 201
HTTP_FOUND = 302
HTTP_BAD_REQUEST = 400
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_INTERNAL_SERVER_ERROR = 500
MANUAL_LOGIN_REDIRECT_BASE_URL = "https://app.example/auth/oauth"
MANUAL_ASSOCIATE_REDIRECT_BASE_URL = "https://app.example/auth/associate"
MANUAL_IDENTITY_REDIRECT_BASE_URL = "https://app.example/identity/oauth"


@dataclass(slots=True)
class OAuthAccountRecord:
    """Stored provider account for test assertions."""

    user_id: UUID
    oauth_name: str
    account_id: str
    account_email: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None


class InMemoryOAuthUserDatabase(BaseUserStore[ExampleUser, UUID]):
    """Minimal user database supporting OAuth account linking."""

    def __init__(self, users: list[ExampleUser] | None = None) -> None:
        """Initialize user and OAuth-account indexes."""
        users = users or []
        self.users_by_id = {user.id: user for user in users}
        self.user_ids_by_email = {user.email: user.id for user in users}
        self.oauth_accounts: dict[tuple[str, str], OAuthAccountRecord] = {}

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Return a user by identifier."""
        return self.users_by_id.get(user_id)

    async def get_by_email(self, email: str) -> ExampleUser | None:
        """Return a user by email address."""
        user_id = self.user_ids_by_email.get(email)
        return self.users_by_id.get(user_id) if user_id is not None else None

    async def get_by_field(self, field_name: LoginIdentifier, value: str) -> ExampleUser | None:
        """Return a user by field value."""
        if field_name == "email":
            return await self.get_by_email(value)
        for user in self.users_by_id.values():
            if getattr(user, field_name, None) == value:
                return user
        return None

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> ExampleUser | None:
        """Return the user linked to the provider account, if present."""
        oauth_account = self.oauth_accounts.get((oauth_name, account_id))
        return await self.get(oauth_account.user_id) if oauth_account is not None else None

    async def upsert_oauth_account(  # noqa: PLR0913
        self,
        user: ExampleUser,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        """Create or update an OAuth account record."""
        self.oauth_accounts[oauth_name, account_id] = OAuthAccountRecord(
            user_id=user.id,
            oauth_name=oauth_name,
            account_id=account_id,
            account_email=account_email,
            access_token=access_token,
            expires_at=expires_at,
            refresh_token=refresh_token,
        )

    async def create(self, user_dict: Mapping[str, Any]) -> ExampleUser:
        """Create and store a new user.

        Returns:
            Newly created in-memory user.
        """
        user = ExampleUser(id=uuid4(), **dict(user_dict))
        self.users_by_id[user.id] = user
        self.user_ids_by_email[user.email] = user.id
        return user

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return a stable slice of users for BaseUserStore compatibility."""
        users = list(self.users_by_id.values())
        return users[offset : offset + limit], len(users)

    async def update(self, user: ExampleUser, update_dict: Mapping[str, Any]) -> ExampleUser:
        """Update a stored user.

        Returns:
            Updated in-memory user.
        """
        for field_name, value in update_dict.items():
            setattr(user, field_name, value)
        if "email" in update_dict:
            self.user_ids_by_email[user.email] = user.id
        return user

    async def delete(self, user_id: UUID) -> None:
        """Delete a stored user."""
        user = self.users_by_id.pop(user_id, None)
        if user is None:
            return

        self.user_ids_by_email.pop(user.email, None)


class InMemoryTokenStrategy:
    """Simple strategy used to verify OAuth callback login results."""

    def __init__(self) -> None:
        """Initialize token storage."""
        self.tokens: dict[str, UUID] = {}
        self.counter = 0

    async def read_token(
        self,
        token: str | None,
        user_manager: BaseUserManager[ExampleUser, UUID],
    ) -> ExampleUser | None:
        """Resolve a stored token back to a user.

        Returns:
            Matching user when the token exists, otherwise `None`.
        """
        if token is None:
            return None
        user_id = self.tokens.get(token)
        return await user_manager.get(user_id) if user_id is not None else None

    async def write_token(self, user: ExampleUser) -> str:
        """Persist and return a deterministic local token.

        Returns:
            Newly issued local token.
        """
        self.counter += 1
        token = f"oauth-token-{self.counter}"
        self.tokens[token] = user.id
        return token

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """Remove a stored token."""
        del user
        self.tokens.pop(token, None)


class FakeOAuthClient:
    """Fake upstream OAuth client for authorize/callback tests."""

    def __init__(
        self,
        *,
        account_id: str = "provider-user-1",
        email: str = "oauth@example.com",
        email_verified: bool | None = True,
    ) -> None:
        """Store deterministic account details for the callback flow."""
        self.account_id = account_id
        self.email = email
        self.email_verified = email_verified
        self.authorization_calls: list[tuple[str, str, str | None]] = []
        self.access_token_calls: list[tuple[str, str]] = []
        self.id_email_calls: list[str] = []
        self.profile_calls: list[str] = []

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
        """Return a deterministic token payload."""
        self.access_token_calls.append((code, redirect_uri))
        return {
            "access_token": "provider-access-token",
            "expires_at": 1_234_567_890,
            "refresh_token": "provider-refresh-token",
        }

    async def get_id_email(self, access_token: str) -> tuple[str, str]:
        """Return the deterministic account id and email for the token."""
        self.id_email_calls.append(access_token)
        return self.account_id, self.email

    async def get_profile(self, access_token: str) -> dict[str, object]:
        """Return deterministic profile details including email verification."""
        self.profile_calls.append(access_token)
        payload: dict[str, object] = {"id": self.account_id, "email": self.email}
        if self.email_verified is not None:
            payload["email_verified"] = self.email_verified
        return payload


class FakeOAuthProfileClient:
    """Fake OAuth client variant that exposes only profile lookup."""

    def __init__(
        self,
        *,
        account_id: str = "provider-user-1",
        email: str | None = "oauth@example.com",
        email_verified: bool | str | None = None,
    ) -> None:
        """Store deterministic profile details for the callback flow."""
        self.account_id = account_id
        self.email = email
        self.email_verified = email_verified
        self.authorization_calls: list[tuple[str, str, str | None]] = []
        self.access_token_calls: list[tuple[str, str]] = []
        self.profile_calls: list[str] = []

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
        """Return a deterministic token payload."""
        self.access_token_calls.append((code, redirect_uri))
        return {
            "access_token": "provider-access-token",
            "expires_at": 1_234_567_890,
            "refresh_token": "provider-refresh-token",
        }

    async def get_profile(self, access_token: str) -> dict[str, object]:
        """Return the deterministic profile payload for the token."""
        self.profile_calls.append(access_token)
        payload: dict[str, object] = {"id": self.account_id}
        if self.email is not None:
            payload["email"] = self.email
        if self.email_verified is not None:
            payload["email_verified"] = self.email_verified
        return payload


class _DummySession:
    """Placeholder session (async context manager + ``close`` like ``AsyncSession``)."""

    async def __aenter__(self) -> Self:
        """Enter async context.

        Returns:
            This session instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit async context (no-op)."""
        del exc_type, exc, traceback

    async def close(self) -> None:
        """No-op close for ``before_send`` handlers."""


class _DummySessionMaker:
    """Callable session factory for auth middleware (mirrors ``async_sessionmaker``)."""

    def __call__(self) -> _DummySession:
        return _DummySession()


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records OAuth-created users."""

    def __init__(
        self,
        user_db: InMemoryOAuthUserDatabase,
        password_helper: PasswordHelper,
        *,
        backends: tuple[object, ...] = (),
    ) -> None:
        """Initialize the tracking manager."""
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
        self.created_users: list[ExampleUser] = []
        self.logged_in_users: list[ExampleUser] = []

    async def on_after_register(self, user: ExampleUser, token: str) -> None:
        """Track newly created users."""
        del token
        self.created_users.append(user)

    async def on_after_login(self, user: ExampleUser) -> None:
        """Track users whose OAuth login flow completed."""
        self.logged_in_users.append(user)


def build_app(  # noqa: PLR0913
    *,
    users: list[ExampleUser] | None = None,
    oauth_client: FakeOAuthClient | None = None,
    use_provider_helper: bool = False,
    cookie_secure: bool = True,
    oauth_scopes: tuple[str, ...] | None = None,
    associate_by_email: bool = False,
    trust_provider_email_verified: bool = False,
) -> tuple[Litestar, InMemoryOAuthUserDatabase, TrackingUserManager, InMemoryTokenStrategy, FakeOAuthClient]:
    """Create an application wired with the generated OAuth controller.

    Returns:
        Litestar app with backing in-memory database, manager, strategy, and fake client.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryOAuthUserDatabase(users)
    user_manager = TrackingUserManager(user_db, password_helper)
    strategy = InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="oauth-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    client = oauth_client or FakeOAuthClient()
    if use_provider_helper:
        controller = create_provider_oauth_controller(
            provider_name="github",
            backend=backend,
            user_manager=cast("Any", user_manager),
            oauth_client=client,
            redirect_base_url=MANUAL_LOGIN_REDIRECT_BASE_URL,
            cookie_secure=cookie_secure,
            oauth_scopes=oauth_scopes,
            associate_by_email=associate_by_email,
            trust_provider_email_verified=trust_provider_email_verified,
        )
    else:
        controller = create_oauth_controller(
            provider_name="github",
            backend=backend,
            user_manager=cast("Any", user_manager),
            oauth_client=client,
            redirect_base_url=MANUAL_LOGIN_REDIRECT_BASE_URL,
            cookie_secure=cookie_secure,
            oauth_scopes=oauth_scopes,
            associate_by_email=associate_by_email,
            trust_provider_email_verified=trust_provider_email_verified,
        )
    app = Litestar(route_handlers=[controller])
    return app, user_db, user_manager, strategy, client


def build_app_with_associate(
    *,
    users: list[ExampleUser] | None = None,
    oauth_client: FakeOAuthClient | None = None,
    cookie_secure: bool = True,
) -> tuple[Litestar, InMemoryOAuthUserDatabase, TrackingUserManager, InMemoryTokenStrategy, FakeOAuthClient]:
    """Build an app with both login OAuth and associate controller for the same provider.

    Returns:
        App, user_db, user_manager, strategy, and fake OAuth client.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryOAuthUserDatabase(users)
    user_manager = TrackingUserManager(user_db, password_helper)
    strategy = InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="oauth-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    client = oauth_client or FakeOAuthClient()
    login_controller = create_oauth_controller(
        provider_name="github",
        backend=backend,
        user_manager=cast("Any", user_manager),
        oauth_client=client,
        redirect_base_url=MANUAL_LOGIN_REDIRECT_BASE_URL,
        path="/auth/oauth",
        cookie_secure=cookie_secure,
    )
    associate_controller = create_oauth_associate_controller(
        provider_name="github",
        user_manager=cast("Any", user_manager),
        oauth_client=client,
        redirect_base_url=MANUAL_ASSOCIATE_REDIRECT_BASE_URL,
        path="/auth/associate",
        cookie_secure=cookie_secure,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", _DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = Litestar(
        route_handlers=[login_controller, associate_controller],
        middleware=[middleware],
    )
    return app, user_db, user_manager, strategy, client


def build_app_with_dependency_key_associate(
    *,
    users: list[ExampleUser] | None = None,
    oauth_client: FakeOAuthClient | None = None,
    cookie_secure: bool = True,
    user_manager_dependency_key: str = "custom_manager_key",
) -> tuple[Litestar, InMemoryOAuthUserDatabase, TrackingUserManager, InMemoryTokenStrategy, FakeOAuthClient]:
    """Build an app whose manual associate controller resolves its manager through Litestar DI.

    Returns:
        App, user_db, user_manager, strategy, and fake OAuth client.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryOAuthUserDatabase(users)
    user_manager = TrackingUserManager(user_db, password_helper)
    strategy = InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="oauth-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    client = oauth_client or FakeOAuthClient()
    associate_controller = create_oauth_associate_controller(
        provider_name="github",
        user_manager_dependency_key=user_manager_dependency_key,
        oauth_client=client,
        redirect_base_url=MANUAL_ASSOCIATE_REDIRECT_BASE_URL,
        path="/auth/associate",
        cookie_secure=cookie_secure,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", _DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = Litestar(
        route_handlers=[associate_controller],
        dependencies={user_manager_dependency_key: Provide(lambda: user_manager, sync_to_thread=False)},
        middleware=[middleware],
    )
    return app, user_db, user_manager, strategy, client


@pytest.fixture
def app() -> tuple[
    Litestar,
    InMemoryOAuthUserDatabase,
    TrackingUserManager,
    InMemoryTokenStrategy,
    FakeOAuthClient,
]:
    """Create the shared OAuth-controller app and collaborators.

    Returns:
        App plus the backing OAuth test collaborators.
    """
    return build_app()


async def test_authorize_redirects_and_sets_secure_state_cookie(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryOAuthUserDatabase,
        TrackingUserManager,
        InMemoryTokenStrategy,
        FakeOAuthClient,
    ],
) -> None:
    """Authorize redirects to the provider and stores the state in a hardened cookie."""
    test_client, _, _, _, oauth_client = client

    response = await test_client.get("/auth/oauth/github/authorize", follow_redirects=False)

    assert response.status_code == HTTP_FOUND
    assert response.headers["location"].startswith("https://provider.example/authorize?state=")
    state_cookie = response.cookies.get("__oauth_state_github")
    assert state_cookie
    assert oauth_client.authorization_calls == [
        ("https://app.example/auth/oauth/github/callback", state_cookie, None),
    ]
    set_cookie = response.headers["set-cookie"].lower()
    assert "__oauth_state_github=" in set_cookie
    assert "max-age=300" in set_cookie
    assert "path=/auth/oauth/github" in set_cookie
    assert "secure" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


async def test_authorize_without_scopes_works_as_before(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryOAuthUserDatabase,
        TrackingUserManager,
        InMemoryTokenStrategy,
        FakeOAuthClient,
    ],
) -> None:
    """Authorize without scopes query param behaves as before (no scope passed to provider)."""
    test_client, _, _, _, oauth_client = client

    response = await test_client.get("/auth/oauth/github/authorize", follow_redirects=False)

    assert response.status_code == HTTP_FOUND
    assert len(oauth_client.authorization_calls) == 1
    _redirect_uri, state, scope = oauth_client.authorization_calls[0]
    assert scope is None
    assert response.headers["location"] == f"https://provider.example/authorize?state={state}"


async def test_authorize_uses_configured_server_owned_scopes() -> None:
    """Authorize uses configured server-owned scopes instead of caller input."""
    app, _, _, _, oauth_client = build_app(oauth_scopes=("openid", "email"))

    async with AsyncTestClient(app=app) as test_client:
        response = await test_client.get("/auth/oauth/github/authorize", follow_redirects=False)

    assert response.status_code == HTTP_FOUND
    assert len(oauth_client.authorization_calls) == 1
    _redirect_uri, _state, scope = oauth_client.authorization_calls[0]
    assert scope == "openid email"
    assert "scope=openid%20email" in response.headers["location"]


async def test_authorize_rejects_runtime_scope_override(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryOAuthUserDatabase,
        TrackingUserManager,
        InMemoryTokenStrategy,
        FakeOAuthClient,
    ],
) -> None:
    """Authorize rejects caller-controlled scope query parameters."""
    test_client, _, _, _, oauth_client = client

    response = await test_client.get(
        "/auth/oauth/github/authorize",
        params={"scopes": ["openid", "email"]},
        follow_redirects=False,
    )

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == "OAuth scopes must be configured on the server."
    assert oauth_client.authorization_calls == []


async def test_callback_does_not_auto_verify_new_user_by_default(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryOAuthUserDatabase,
        TrackingUserManager,
        InMemoryTokenStrategy,
        FakeOAuthClient,
    ],
) -> None:
    """Callback creates a new user without is_verified when trust_provider_email_verified is False."""
    test_client, user_db, user_manager, strategy, oauth_client = client
    authorize_response = await test_client.get("/auth/oauth/github/authorize", follow_redirects=False)
    state = authorize_response.cookies["__oauth_state_github"]
    test_client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")

    callback_response = await test_client.get(
        "/auth/oauth/github/callback",
        params={"code": "provider-code", "state": state},
    )

    assert callback_response.status_code == HTTP_OK
    assert callback_response.json() == {"access_token": "oauth-token-1", "token_type": "bearer"}
    created_user = await user_db.get_by_email("oauth@example.com")
    assert created_user is not None
    assert created_user.is_verified is False
    assert user_manager.created_users == [created_user]
    assert user_manager.logged_in_users == [created_user]
    assert strategy.tokens == {"oauth-token-1": created_user.id}
    oauth_account = user_db.oauth_accounts["github", "provider-user-1"]
    assert oauth_account.user_id == created_user.id
    assert oauth_account.account_email == "oauth@example.com"
    assert oauth_account.access_token == "provider-access-token"
    assert oauth_client.access_token_calls == [("provider-code", "https://app.example/auth/oauth/github/callback")]
    assert oauth_client.id_email_calls == ["provider-access-token"]
    assert not callback_response.cookies.get("__oauth_state_github")
    set_cookie = callback_response.headers["set-cookie"].lower()
    assert "__oauth_state_github=" in set_cookie
    assert "max-age=0" in set_cookie
    assert "path=/auth/oauth/github" in set_cookie
    assert "secure" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


async def test_callback_auto_verifies_new_user_when_opted_in() -> None:
    """Callback marks new OAuth users verified only when trust_provider_email_verified is True."""
    app, user_db, user_manager, strategy, _ = build_app(trust_provider_email_verified=True)

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_OK
    created_user = await user_db.get_by_email("oauth@example.com")
    assert created_user is not None
    assert created_user.is_verified is True
    assert user_manager.created_users == [created_user]
    assert user_manager.logged_in_users == [created_user]
    assert strategy.tokens == {"oauth-token-1": created_user.id}


async def test_callback_links_existing_user_by_email_without_creating_duplicate() -> None:
    """Callback links an existing local user when the provider email matches and the provider is trusted."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="linked@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
    )
    app, user_db, user_manager, strategy, oauth_client = build_app(
        users=[existing_user],
        oauth_client=FakeOAuthClient(account_id="provider-user-2", email="linked@example.com"),
        use_provider_helper=True,
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_OK
    assert callback_response.json() == {"access_token": "oauth-token-1", "token_type": "bearer"}
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == [existing_user]
    assert len(user_db.users_by_id) == 1
    oauth_account = user_db.oauth_accounts["github", "provider-user-2"]
    assert oauth_account.user_id == existing_user.id
    assert strategy.tokens == {"oauth-token-1": existing_user.id}
    assert oauth_client.id_email_calls == ["provider-access-token"]


async def test_callback_link_by_email_requires_runtime_verified_email() -> None:
    """Callback rejects email association when provider asserts email_verified=False."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="linked@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
    )
    app, user_db, user_manager, _strategy, _oauth_client = build_app(
        users=[existing_user],
        oauth_client=FakeOAuthClient(
            account_id="provider-user-2",
            email="linked@example.com",
            email_verified=False,
        ),
        use_provider_helper=True,
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_EMAIL_NOT_VERIFIED
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert len(user_db.users_by_id) == 1
    assert len(user_db.oauth_accounts) == 0


async def test_callback_link_by_email_requires_trusted_provider_email_verification() -> None:
    """Callback rejects linking by email when trust_provider_email_verified is disabled."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="linked@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
    )
    app, user_db, user_manager, _strategy, _oauth_client = build_app(
        users=[existing_user],
        oauth_client=FakeOAuthClient(account_id="provider-user-2", email="linked@example.com"),
        use_provider_helper=True,
        associate_by_email=True,
        trust_provider_email_verified=False,
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_USER_ALREADY_EXISTS
    detail = body.get("detail", "").lower()
    assert "verification" in detail
    assert "trust_provider_email_verified" in detail
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert len(user_db.users_by_id) == 1
    assert len(user_db.oauth_accounts) == 0


async def test_callback_trusted_provider_requires_runtime_email_verified_signal() -> None:
    """When trust_provider_email_verified=True, provider must assert email ownership at runtime."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="linked@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
    )
    app, user_db, user_manager, _strategy, _oauth_client = build_app(
        users=[existing_user],
        oauth_client=cast("Any", FakeOAuthProfileClient(account_id="provider-user-2", email="linked@example.com")),
        use_provider_helper=True,
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code >= HTTP_INTERNAL_SERVER_ERROR
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert len(user_db.users_by_id) == 1
    assert len(user_db.oauth_accounts) == 0


async def test_callback_associate_by_email_false_returns_400_when_email_exists() -> None:
    """Callback returns 400 with OAUTH_USER_ALREADY_EXISTS when associate_by_email=False and email already exists."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="existing@example.com",
        hashed_password=PasswordHelper().hash("secret"),
    )
    app, user_db, user_manager, _strategy, _ = build_app(
        users=[existing_user],
        oauth_client=FakeOAuthClient(account_id="oauth-id", email="existing@example.com"),
        associate_by_email=False,
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_USER_ALREADY_EXISTS
    assert "email" in body.get("detail", "").lower() or "already exists" in body.get("detail", "").lower()
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert len(user_db.oauth_accounts) == 0


async def test_callback_returns_existing_user_when_provider_identity_already_linked() -> None:
    """Callback returns the existing user's token when provider identity is already linked (one identity -> one user)."""
    user_a = ExampleUser(
        id=uuid4(),
        email="user-a@example.com",
        hashed_password=PasswordHelper().hash("pw-a"),
    )
    user_b = ExampleUser(
        id=uuid4(),
        email="user-b@example.com",
        hashed_password=PasswordHelper().hash("pw-b"),
    )
    oauth_client = FakeOAuthClient(account_id="shared-provider-id", email="user-a@example.com")
    app, user_db, user_manager, strategy, _ = build_app(
        users=[user_a, user_b],
        oauth_client=oauth_client,
    )
    user_db.oauth_accounts["github", "shared-provider-id"] = OAuthAccountRecord(
        user_id=user_a.id,
        oauth_name="github",
        account_id="shared-provider-id",
        account_email="user-a@example.com",
        access_token="old-token",
        expires_at=111,
        refresh_token="old-refresh",
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_OK
    token = callback_response.json()["access_token"]
    assert strategy.tokens.get(token) == user_a.id
    oauth_account = user_db.oauth_accounts.get(("github", "shared-provider-id"))
    assert oauth_account is not None
    assert oauth_account.user_id == user_a.id
    assert len(user_db.users_by_id) == 2  # noqa: PLR2004
    assert user_manager.created_users == []


async def test_callback_rejects_inactive_existing_user() -> None:
    """Callback rejects login when the resolved local account is inactive."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="inactive@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
        is_active=False,
    )
    app, user_db, user_manager, _strategy, _oauth_client = build_app(
        users=[existing_user],
        oauth_client=FakeOAuthClient(account_id="provider-user-inactive", email="inactive@example.com"),
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_INACTIVE
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert len(user_db.oauth_accounts) == 0


async def test_callback_maps_unverified_account_state_error_to_client_error() -> None:
    """Callback maps user-manager account-state rejections to the unverified login error contract."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="needs-verify@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
        is_verified=True,
    )
    app, user_db, user_manager, _strategy, _oauth_client = build_app(
        users=[existing_user],
        oauth_client=FakeOAuthClient(account_id="provider-user-unverified", email="needs-verify@example.com"),
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    def require_account_state(_user: ExampleUser, *, require_verified: bool) -> None:
        assert require_verified is False
        raise UnverifiedUserError

    user_manager.require_account_state = require_account_state  # ty:ignore[invalid-assignment]

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_NOT_VERIFIED
    assert body["detail"] == "The user account is not verified."
    assert user_db.oauth_accounts == {}


async def test_callback_maps_oauth_account_already_linked_error_on_upsert() -> None:
    """Callback keeps the one-provider-identity-per-user error mapping when persistence rejects the link."""
    existing_user = ExampleUser(
        id=uuid4(),
        email="linked@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
        is_verified=True,
    )
    app, user_db, user_manager, _strategy, _oauth_client = build_app(
        users=[existing_user],
        oauth_client=FakeOAuthClient(account_id="provider-user-linked", email="linked@example.com"),
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    async def fail_upsert(  # noqa: PLR0913
        user: ExampleUser,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        del user, oauth_name, account_id, account_email, access_token, expires_at, refresh_token
        await asyncio.sleep(0)
        raise OAuthAccountAlreadyLinkedError(
            provider="github",
            account_id="provider-user",
            existing_user_id=uuid4(),
        )

    user_db.upsert_oauth_account = fail_upsert  # ty: ignore[invalid-assignment]

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
    assert "already linked" in body["detail"].lower()
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert user_db.oauth_accounts == {}


async def test_callback_creates_new_user_when_email_not_found_with_associate_by_email_false() -> None:
    """New user is created when email is not in DB even with associate_by_email=False (default)."""
    app, user_db, _user_manager, _strategy, _ = build_app(associate_by_email=False)

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_OK
    created = await user_db.get_by_email("oauth@example.com")
    assert created is not None
    assert len(user_db.users_by_id) == 1
    assert len(user_db.oauth_accounts) == 1


async def test_callback_rejects_new_user_when_provider_email_is_unverified() -> None:
    """New-account callback rejects provider email_verified=False by default."""
    app, user_db, user_manager, strategy, _ = build_app(
        oauth_client=FakeOAuthClient(email_verified=False),
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_EMAIL_NOT_VERIFIED
    assert user_db.users_by_id == {}
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert strategy.tokens == {}
    assert user_db.oauth_accounts == {}


async def test_callback_accepts_profile_only_client_when_trusted_verification_claim_is_present() -> None:
    """Trusted profile-only clients can supply identity and verification from one profile payload."""
    app, user_db, user_manager, strategy, oauth_client = build_app(
        oauth_client=cast(
            "Any",
            FakeOAuthProfileClient(
                account_id="profile-only-provider-id",
                email="oauth@example.com",
                email_verified="true",
            ),
        ),
        trust_provider_email_verified=True,
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_OK
    created_user = await user_db.get_by_email("oauth@example.com")
    assert created_user is not None
    assert created_user.is_verified is True
    assert user_manager.created_users == [created_user]
    assert user_manager.logged_in_users == [created_user]
    assert strategy.tokens == {"oauth-token-1": created_user.id}
    assert oauth_client.profile_calls == ["provider-access-token"]


async def test_callback_rejects_new_user_when_provider_verification_claim_missing() -> None:
    """New-account callback rejects sign-in when provider omits verified-email evidence."""
    app, user_db, user_manager, strategy, _ = build_app(
        oauth_client=cast("Any", FakeOAuthProfileClient(email="oauth@example.com")),
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_EMAIL_NOT_VERIFIED
    assert user_db.users_by_id == {}
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert strategy.tokens == {}
    assert user_db.oauth_accounts == {}


async def test_callback_rejects_invalid_state(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryOAuthUserDatabase,
        TrackingUserManager,
        InMemoryTokenStrategy,
        FakeOAuthClient,
    ],
) -> None:
    """Callback fails with HTTP 400 when the state cookie does not match."""
    test_client, user_db, user_manager, strategy, _ = client
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
    assert user_db.users_by_id == {}
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert strategy.tokens == {}


async def test_callback_returns_400_when_provider_profile_has_no_email() -> None:
    """Callback returns HTTP 400 when the provider profile omits an email address."""
    app, user_db, user_manager, strategy, _ = build_app(
        oauth_client=cast("FakeOAuthClient", FakeOAuthProfileClient(email=None)),
    )

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    assert callback_response.json()["detail"] == (
        "OAuth provider did not return an email. Please use a different sign-in method."
    )
    assert user_db.users_by_id == {}
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert strategy.tokens == {}


async def test_oauth_state_cookie_secure_flag_can_be_disabled() -> None:
    """OAuth state cookies can opt out of the secure attribute independently of redirect-origin validation."""
    app, _, _, _, _ = build_app(cookie_secure=False)

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_response.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    authorize_set_cookie = authorize_response.headers["set-cookie"].lower()
    callback_set_cookie = callback_response.headers["set-cookie"].lower()
    assert "secure" not in authorize_set_cookie
    assert "secure" not in callback_set_cookie


async def test_provider_helper_forwards_cookie_secure_flag() -> None:
    """Provider helper keeps the OAuth secure-cookie override available."""
    app, _, _, _, _ = build_app(use_provider_helper=True, cookie_secure=False)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)

    assert "secure" not in response.headers["set-cookie"].lower()


def test_create_oauth_associate_controller_raises_when_both_or_neither_user_manager_and_key() -> None:
    """create_oauth_associate_controller raises ConfigurationError when both or neither user_manager and key are provided."""
    client = FakeOAuthClient()
    with pytest.raises(ConfigurationError, match="exactly one of user_manager or user_manager_dependency_key"):
        create_oauth_associate_controller(
            provider_name="github",
            user_manager=None,
            user_manager_dependency_key=None,
            oauth_client=client,
            redirect_base_url=MANUAL_ASSOCIATE_REDIRECT_BASE_URL,
        )
    password_helper = PasswordHelper()
    user_db = InMemoryOAuthUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    with pytest.raises(ConfigurationError, match="exactly one of user_manager or user_manager_dependency_key"):
        create_oauth_associate_controller(
            provider_name="github",
            user_manager=cast("Any", user_manager),
            user_manager_dependency_key="some_key",
            oauth_client=client,
            redirect_base_url=MANUAL_ASSOCIATE_REDIRECT_BASE_URL,
        )


@pytest.mark.parametrize(
    ("factory_name", "redirect_base_url", "expected_message"),
    [
        ("login", "http://app.example/auth/oauth", "public HTTPS origin"),
        ("associate", "https://localhost/auth/associate", "non-loopback public HTTPS origin"),
        ("provider", "http://app.example/auth/oauth", "public HTTPS origin"),
    ],
)
def test_manual_oauth_factories_reject_insecure_redirect_origins(
    factory_name: str,
    redirect_base_url: str,
    expected_message: str,
) -> None:
    """Manual OAuth factories fail closed for insecure redirect origins before app startup."""
    password_helper = PasswordHelper()
    user_manager = TrackingUserManager(InMemoryOAuthUserDatabase(), password_helper)
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="oauth-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy()),
    )

    if factory_name == "login":
        factory = create_oauth_controller
        factory_kwargs = {
            "provider_name": "github",
            "backend": backend,
            "user_manager": cast("Any", user_manager),
            "oauth_client": FakeOAuthClient(),
            "redirect_base_url": redirect_base_url,
        }
    elif factory_name == "associate":
        factory = create_oauth_associate_controller
        factory_kwargs = {
            "provider_name": "github",
            "user_manager": cast("Any", user_manager),
            "oauth_client": FakeOAuthClient(),
            "redirect_base_url": redirect_base_url,
        }
    else:
        factory = create_provider_oauth_controller
        factory_kwargs = {
            "provider_name": "github",
            "backend": backend,
            "user_manager": cast("Any", user_manager),
            "oauth_client": FakeOAuthClient(),
            "redirect_base_url": redirect_base_url,
        }

    with pytest.raises(ConfigurationError, match=expected_message):
        cast("Any", factory)(**factory_kwargs)


async def test_callback_returns_400_when_state_cookie_missing() -> None:
    """Callback fails with HTTP 400 when the state cookie is missing (cookie_state is None)."""
    app, user_db, user_manager, strategy, _ = build_app()

    async with AsyncTestClient(app=app) as client:
        response = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": "any-state"},
        )

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == "Invalid OAuth state."
    assert user_db.users_by_id == {}
    assert user_manager.created_users == []
    assert user_manager.logged_in_users == []
    assert strategy.tokens == {}


async def test_create_provider_oauth_controller_uses_oauth_client_factory() -> None:
    """create_provider_oauth_controller uses oauth_client_factory when oauth_client is None."""
    factory_calls: list[int] = []

    def make_client() -> FakeOAuthClient:
        factory_calls.append(1)
        return FakeOAuthClient(account_id="factory-user", email="factory@example.com")

    password_helper = PasswordHelper()
    user_db2 = InMemoryOAuthUserDatabase()
    user_manager = TrackingUserManager(user_db2, password_helper)
    strategy2 = InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="oauth-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy2),
    )
    controller = create_provider_oauth_controller(
        provider_name="github",
        backend=backend,
        user_manager=cast("Any", user_manager),
        oauth_client_factory=make_client,
        redirect_base_url=MANUAL_LOGIN_REDIRECT_BASE_URL,
    )
    app2 = Litestar(route_handlers=[controller])

    async with AsyncTestClient(app=app2) as client:
        authorize_resp = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = authorize_resp.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_resp = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_resp.status_code == HTTP_OK
    assert callback_resp.json() == {"access_token": "oauth-token-1", "token_type": "bearer"}
    assert factory_calls == [1]
    created = await user_db2.get_by_email("factory@example.com")
    assert created is not None
    assert strategy2.tokens == {"oauth-token-1": created.id}


# --- OAuth associate controller (link OAuth to authenticated user) ---


async def test_associate_authenticated_user_links_oauth() -> None:
    """Authenticated user can link an OAuth account via /associate/authorize and /associate/callback."""
    app, user_db, _, strategy, _ = build_app_with_associate()
    async with AsyncTestClient(app=app) as client:
        login_resp = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        state = login_resp.cookies["__oauth_state_github"]
        client.cookies.set("__oauth_state_github", state, domain="testserver.local", path="/auth/oauth/github")
        callback_resp = await client.get(
            "/auth/oauth/github/callback",
            params={"code": "provider-code", "state": state},
        )
        assert callback_resp.status_code == HTTP_OK
        token = callback_resp.json()["access_token"]
        created_user = await user_db.get_by_email("oauth@example.com")
        assert created_user is not None
        assert strategy.tokens == {token: created_user.id}

        associate_authorize = await client.get(
            "/auth/associate/github/authorize",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
        assert associate_authorize.status_code == HTTP_FOUND
        ass_state = associate_authorize.cookies.get("__oauth_associate_state_github")
        assert ass_state
        authorize_set_cookie = associate_authorize.headers["set-cookie"].lower()
        assert "__oauth_associate_state_github=" in authorize_set_cookie
        assert "max-age=300" in authorize_set_cookie
        assert "path=/auth/associate/github" in authorize_set_cookie
        assert "secure" in authorize_set_cookie
        assert "httponly" in authorize_set_cookie
        assert "samesite=lax" in authorize_set_cookie
        client.cookies.set(
            "__oauth_associate_state_github",
            ass_state,
            domain="testserver.local",
            path="/auth/associate/github",
        )
        associate_callback = await client.get(
            "/auth/associate/github/callback",
            params={"code": "associate-code", "state": ass_state},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert associate_callback.status_code == HTTP_OK
        assert associate_callback.json() == {"linked": True}
        callback_set_cookie = associate_callback.headers["set-cookie"].lower()
        assert "__oauth_associate_state_github=" in callback_set_cookie
        assert "max-age=0" in callback_set_cookie
        assert "path=/auth/associate/github" in callback_set_cookie
        assert "secure" in callback_set_cookie
        assert "httponly" in callback_set_cookie
        assert "samesite=lax" in callback_set_cookie
        oauth_account = user_db.oauth_accounts.get(("github", "provider-user-1"))
        assert oauth_account is not None
        assert oauth_account.user_id == created_user.id


async def test_associate_rejects_inactive_authenticated_user() -> None:
    """Inactive authenticated users cannot link new OAuth identities."""
    user = ExampleUser(
        id=uuid4(),
        email="inactive-link@example.com",
        hashed_password=PasswordHelper().hash("pw"),
        is_active=False,
    )
    app, user_db, _, strategy, _ = build_app_with_associate(users=[user])
    strategy.tokens["bearer-token"] = user.id

    async with AsyncTestClient(app=app) as client:
        authorize_response = await client.get(
            "/auth/associate/github/authorize",
            headers={"Authorization": "Bearer bearer-token"},
            follow_redirects=False,
        )
        assert authorize_response.status_code == HTTP_FOUND
        state = authorize_response.cookies["__oauth_associate_state_github"]
        client.cookies.set(
            "__oauth_associate_state_github",
            state,
            domain="testserver.local",
            path="/auth/associate/github",
        )
        callback_response = await client.get(
            "/auth/associate/github/callback",
            params={"code": "associate-code", "state": state},
            headers={"Authorization": "Bearer bearer-token"},
        )

    assert callback_response.status_code == HTTP_BAD_REQUEST
    body = callback_response.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.LOGIN_USER_INACTIVE
    assert user_db.oauth_accounts == {}


async def test_associate_unauthenticated_returns_401() -> None:
    """Unauthenticated request to associate authorize returns 401."""
    app, _, _, _, _ = build_app_with_associate()
    async with AsyncTestClient(app=app) as client:
        response = await client.get(
            "/auth/associate/github/authorize",
            follow_redirects=False,
        )
        assert response.status_code == HTTP_UNAUTHORIZED


async def test_associate_re_link_updates_tokens() -> None:
    """Re-linking the same provider updates the stored OAuth tokens."""
    user = ExampleUser(
        id=uuid4(),
        email="relink@example.com",
        hashed_password=PasswordHelper().hash("pw"),
    )
    oauth_client = FakeOAuthClient(account_id="same-id", email="relink@example.com")
    app, user_db, _, strategy, _ = build_app_with_associate(
        users=[user],
        oauth_client=oauth_client,
    )
    user_db.oauth_accounts["github", "same-id"] = OAuthAccountRecord(
        user_id=user.id,
        oauth_name="github",
        account_id="same-id",
        account_email="relink@example.com",
        access_token="old-token",
        expires_at=111,
        refresh_token="old-refresh",
    )
    strategy.tokens["bearer-token"] = user.id

    async with AsyncTestClient(app=app) as client:
        auth_headers = {"Authorization": "Bearer bearer-token"}
        auth_resp = await client.get(
            "/auth/associate/github/authorize",
            headers=auth_headers,
            follow_redirects=False,
        )
        assert auth_resp.status_code == HTTP_FOUND
        ass_state = auth_resp.cookies["__oauth_associate_state_github"]
        client.cookies.set(
            "__oauth_associate_state_github",
            ass_state,
            domain="testserver.local",
            path="/auth/associate/github",
        )
        callback_resp = await client.get(
            "/auth/associate/github/callback",
            params={"code": "new-code", "state": ass_state},
            headers=auth_headers,
        )
    assert callback_resp.status_code == HTTP_OK
    assert callback_resp.json() == {"linked": True}
    record = user_db.oauth_accounts["github", "same-id"]
    assert record.access_token == "provider-access-token"
    assert record.refresh_token == "provider-refresh-token"
    assert record.expires_at == 1_234_567_890  # noqa: PLR2004


async def test_associate_rejects_when_provider_identity_already_linked_to_another_user() -> None:
    """Associate callback returns 400 when the provider identity is already linked to a different user."""
    user_a = ExampleUser(
        id=uuid4(),
        email="user-a@example.com",
        hashed_password=PasswordHelper().hash("pw-a"),
    )
    user_b = ExampleUser(
        id=uuid4(),
        email="user-b@example.com",
        hashed_password=PasswordHelper().hash("pw-b"),
    )
    oauth_client = FakeOAuthClient(account_id="taken-provider-id", email="user-b@example.com")
    app, user_db, _, strategy, _ = build_app_with_associate(
        users=[user_a, user_b],
        oauth_client=oauth_client,
    )
    user_db.oauth_accounts["github", "taken-provider-id"] = OAuthAccountRecord(
        user_id=user_a.id,
        oauth_name="github",
        account_id="taken-provider-id",
        account_email="user-a@example.com",
        access_token="token-a",
        expires_at=1,
        refresh_token="refresh-a",
    )
    strategy.tokens["bearer-for-b"] = user_b.id

    async with AsyncTestClient(app=app) as client:
        auth_headers = {"Authorization": "Bearer bearer-for-b"}
        auth_resp = await client.get(
            "/auth/associate/github/authorize",
            headers=auth_headers,
            follow_redirects=False,
        )
        assert auth_resp.status_code == HTTP_FOUND
        ass_state = auth_resp.cookies["__oauth_associate_state_github"]
        client.cookies.set(
            "__oauth_associate_state_github",
            ass_state,
            domain="testserver.local",
            path="/auth/associate/github",
        )
        callback_resp = await client.get(
            "/auth/associate/github/callback",
            params={"code": "associate-code", "state": ass_state},
            headers=auth_headers,
        )

    assert callback_resp.status_code == HTTP_BAD_REQUEST
    body = callback_resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
    assert "already linked" in body.get("detail", "").lower()
    oauth_account = user_db.oauth_accounts.get(("github", "taken-provider-id"))
    assert oauth_account is not None
    assert oauth_account.user_id == user_a.id


async def test_associate_maps_oauth_account_already_linked_error_from_upsert() -> None:
    """Associate callback preserves the linked-account client error when the store rejects the upsert."""
    user = ExampleUser(
        id=uuid4(),
        email="linked@example.com",
        hashed_password=PasswordHelper().hash("pw"),
    )
    app, user_db, _, strategy, _ = build_app_with_associate(
        users=[user],
        oauth_client=FakeOAuthClient(account_id="provider-user-upsert", email="linked@example.com"),
    )

    async def fail_upsert(  # noqa: PLR0913
        user: ExampleUser,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        del user, oauth_name, account_id, account_email, access_token, expires_at, refresh_token
        await asyncio.sleep(0)
        raise OAuthAccountAlreadyLinkedError(
            provider="github",
            account_id="provider-user",
            existing_user_id=uuid4(),
        )

    user_db.upsert_oauth_account = fail_upsert  # ty: ignore[invalid-assignment]
    strategy.tokens["bearer-token"] = user.id

    async with AsyncTestClient(app=app) as client:
        auth_headers = {"Authorization": "Bearer bearer-token"}
        auth_resp = await client.get(
            "/auth/associate/github/authorize",
            headers=auth_headers,
            follow_redirects=False,
        )
        ass_state = auth_resp.cookies["__oauth_associate_state_github"]
        client.cookies.set(
            "__oauth_associate_state_github",
            ass_state,
            domain="testserver.local",
            path="/auth/associate/github",
        )
        callback_resp = await client.get(
            "/auth/associate/github/callback",
            params={"code": "associate-code", "state": ass_state},
            headers=auth_headers,
        )

    assert callback_resp.status_code == HTTP_BAD_REQUEST
    body = callback_resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
    assert "already linked" in body["detail"].lower()


def test_associate_flow_uses_di_key_variant_and_clears_state_cookie() -> None:
    """Factory successfully builds the DI-key associate controller variant."""
    controller = create_oauth_associate_controller(
        provider_name="github",
        user_manager_dependency_key="litestar_auth_oauth_associate_user_manager",
        oauth_client=FakeOAuthClient(),
        redirect_base_url=MANUAL_ASSOCIATE_REDIRECT_BASE_URL,
        path="/auth/associate",
        cookie_secure=True,
    )
    assert controller.path == "/auth/associate/github"
    assert controller.__name__.endswith("OAuthAssociateController")


def test_associate_di_key_variant_exposes_configured_dependency_parameter_name() -> None:
    """DI-key variant exposes the configured Litestar callback parameter name."""
    dependency_parameter_name = "custom_manager_key"
    controller = create_oauth_associate_controller(
        provider_name="github",
        user_manager_dependency_key=dependency_parameter_name,
        oauth_client=FakeOAuthClient(),
        redirect_base_url=MANUAL_ASSOCIATE_REDIRECT_BASE_URL,
        path="/auth/associate",
        cookie_secure=True,
    )

    controller_type = cast("Any", controller)
    callback_handler = controller_type.callback.fn
    parameters = inspect.signature(callback_handler).parameters
    assert dependency_parameter_name in parameters


def test_associate_direct_variant_omits_dependency_injection_callback_parameter() -> None:
    """Direct-manager variant keeps the simpler callback signature."""
    password_helper = PasswordHelper()
    user_manager = TrackingUserManager(InMemoryOAuthUserDatabase(), password_helper)
    controller = create_oauth_associate_controller(
        provider_name="github",
        user_manager=cast("Any", user_manager),
        oauth_client=FakeOAuthClient(),
        redirect_base_url=MANUAL_ASSOCIATE_REDIRECT_BASE_URL,
        path="/auth/associate",
        cookie_secure=True,
    )

    controller_type = cast("Any", controller)
    callback_handler = controller_type.callback.fn
    parameters = inspect.signature(callback_handler).parameters
    assert "litestar_auth_oauth_associate_user_manager" not in parameters


async def test_provider_helper_mounts_login_routes_under_custom_auth_path() -> None:
    """Canonical provider helper honors non-default auth_path values."""
    password_helper = PasswordHelper()
    user_db = InMemoryOAuthUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    strategy = InMemoryTokenStrategy()
    oauth_client = FakeOAuthClient()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="oauth-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    controller = create_provider_oauth_controller(
        provider_name="github",
        backend=backend,
        user_manager=cast("Any", user_manager),
        oauth_client=oauth_client,
        redirect_base_url=MANUAL_IDENTITY_REDIRECT_BASE_URL,
        auth_path="/identity",
    )
    app = Litestar(route_handlers=[controller])

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/identity/oauth/github/authorize", follow_redirects=False)

    assert response.status_code == HTTP_FOUND
    assert len(oauth_client.authorization_calls) == 1
    redirect_uri, _state, scopes = oauth_client.authorization_calls[0]
    assert redirect_uri == "https://app.example/identity/oauth/github/callback"
    assert scopes is None
    assert "path=/identity/oauth/github" in response.headers["set-cookie"].lower()


async def test_associate_di_key_variant_links_oauth_via_litestar_dependency_injection() -> None:
    """DI-key variant links an OAuth account when Litestar injects the configured manager dependency."""
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="linked@example.com",
        hashed_password=password_helper.hash("pw"),
        is_verified=True,
    )
    oauth_client = FakeOAuthClient(account_id="provider-user-99", email="linked@example.com")
    dependency_parameter_name = "custom_manager_key"
    app, user_db, _, strategy, _ = build_app_with_dependency_key_associate(
        users=[user],
        oauth_client=oauth_client,
        user_manager_dependency_key=dependency_parameter_name,
    )
    strategy.tokens["bearer-token"] = user.id

    async with AsyncTestClient(app=app) as client:
        auth_headers = {"Authorization": "Bearer bearer-token"}
        authorize_response = await client.get(
            "/auth/associate/github/authorize",
            headers=auth_headers,
            follow_redirects=False,
        )

        assert authorize_response.status_code == HTTP_FOUND
        state = authorize_response.cookies["__oauth_associate_state_github"]
        client.cookies.set(
            "__oauth_associate_state_github",
            state,
            domain="testserver.local",
            path="/auth/associate/github",
        )
        callback_response = await client.get(
            "/auth/associate/github/callback",
            params={"code": "associate-code", "state": state},
            headers=auth_headers,
        )

    assert callback_response.status_code == HTTP_OK
    assert callback_response.json() == {"linked": True}

    record = user_db.oauth_accounts.get(("github", "provider-user-99"))
    assert record is not None
    assert record.user_id == user.id
