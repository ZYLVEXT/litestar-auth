"""End-to-end users CRUD flow through the Litestar auth plugin."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Any, ClassVar, Self, cast
from uuid import UUID

import pytest
from litestar import Litestar, Request, get
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session as SASession
from sqlalchemy.pool import StaticPool

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import has_all_roles, has_any_role
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence
    from types import TracebackType

    from litestar.testing import AsyncTestClient
    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.sql.base import Executable

pytestmark = [pytest.mark.e2e]

HTTP_BAD_REQUEST = 400
HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
PAGINATION_LIMIT = 2
PAGINATION_OFFSET = 1
TOTAL_USERS = 3


@get("/role-guarded/any", guards=[has_any_role("admin")], sync_to_thread=False)
def role_guarded_any() -> dict[str, bool]:
    """Return success when the request user has any required role."""
    return {"ok": True}


@get("/role-guarded/all", guards=[has_all_roles("admin", "billing")], sync_to_thread=False)
def role_guarded_all() -> dict[str, bool]:
    """Return success when the request user has all required roles."""
    return {"ok": True}


@get("/role-guarded/runtime", guards=[has_all_roles("admin", "billing")], sync_to_thread=False)
def role_guarded_runtime(request: Request[User, Any, Any]) -> dict[str, list[str]]:
    """Return normalized role membership from the runtime request user."""
    user = request.user
    assert user is not None
    return {"roles": list(user.roles)}


class AsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped sync session."""
        self._session = session
        self.info: dict[str, Any] = {}

    async def __aenter__(self) -> Self:
        """Match :class:`AsyncSession` (``async with session_maker()``).

        Returns:
            This adapter instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close when leaving ``async with`` (mirrors SQLAlchemy ``AsyncSession``)."""
        del exc_type, exc, traceback
        await self.close()

    @property
    def bind(self) -> Engine | Connection | None:
        """Expose the wrapped session bind."""
        return self._session.bind

    def get_bind(self) -> Engine | Connection:
        """Expose the wrapped session bind via SQLAlchemy's API.

        Returns:
            The bound connectable.
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
        sync_session = cast("Any", self._session)
        return cast("object", sync_session.execute(statement, params=params, execution_options=execution_options))

    async def flush(self) -> None:
        """Flush pending changes."""
        self._session.flush()

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Merge an instance into the session.

        Returns:
            The merged instance.
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

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        self._session.rollback()

    async def close(self) -> None:
        """Close the underlying sync session (``before_send`` / AA lifecycle)."""
        self._session.close()


class SessionMaker:
    """Callable session factory compatible with the auth plugin."""

    def __init__(self, engine: Engine) -> None:
        """Store the shared engine."""
        self._engine = engine

    def __call__(self) -> AsyncSession:
        """Return a new session (same contract as :class:`async_sessionmaker`)."""
        return cast("AsyncSession", AsyncSessionAdapter(SASession(self._engine)))


class UsersFlowManager(BaseUserManager[User, UUID]):
    """Concrete manager used by the users e2e app."""

    verification_tokens: ClassVar[dict[str, str]] = {}

    async def on_after_request_verify_token(self, user: User | None, token: str | None) -> None:
        """Capture re-verification tokens emitted after identity changes."""
        if user is not None and token is not None:
            type(self).verification_tokens[user.email] = token


async def _login_headers(
    client: AsyncTestClient[Litestar],
    *,
    email: str,
    password: str,
) -> dict[str, str]:
    """Authenticate a user and return bearer auth headers.

    Returns:
        Authorization headers containing the issued bearer token.
    """
    response = await client.post("/auth/login", json={"identifier": email, "password": password})
    assert response.status_code == HTTP_CREATED
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _verify_then_login_headers(
    client: AsyncTestClient[Litestar],
    *,
    email: str,
    password: str,
) -> dict[str, str]:
    """Verify the current email address and then return fresh bearer headers.

    Returns:
        Authorization headers for the newly verified account.
    """
    response = await client.post("/auth/login", json={"identifier": email, "password": password})
    assert response.status_code == HTTP_BAD_REQUEST
    login_payload = response.json()
    login_code = login_payload.get("code") or (login_payload.get("extra") or {}).get("code")
    assert login_code == ErrorCode.LOGIN_USER_NOT_VERIFIED

    verify_token = UsersFlowManager.verification_tokens[email]
    response = await client.post("/auth/verify", json={"token": verify_token})
    assert response.status_code == HTTP_OK
    assert response.json()["is_verified"] is True

    return await _login_headers(client, email=email, password=password)


def _assert_public_user(payload: dict[str, object], expected: dict[str, object]) -> None:
    """Assert a public user payload matches the expected values."""
    assert payload == expected


@pytest.fixture
def app() -> Iterator[tuple[Litestar, Engine, PasswordHelper, dict[str, UUID]]]:
    """Create a Litestar app wired with bearer JWT auth and users CRUD routes.

    Yields:
        App under test, backing engine, password helper, and seeded user ids.
    """
    UsersFlowManager.verification_tokens.clear()
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

    with SASession(engine) as session:
        admin_user = User(
            email="admin@example.com",
            hashed_password=password_helper.hash("admin-password"),
            is_verified=True,
            roles=["admin"],
        )
        regular_user = User(
            email="member@example.com",
            hashed_password=password_helper.hash("member-password"),
            is_verified=True,
            roles=["member"],
        )
        extra_user = User(
            email="extra@example.com",
            hashed_password=password_helper.hash("extra-password"),
            is_verified=True,
            roles=["support"],
        )
        session.add_all([admin_user, regular_user, extra_user])
        session.commit()
        session.refresh(admin_user)
        session.refresh(regular_user)
        session.refresh(extra_user)
        user_ids = {
            "admin": admin_user.id,
            "member": regular_user.id,
            "extra": extra_user.id,
        }

    backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](
                secret="jwt-bearer-secret-1234567890-extra",
                subject_decoder=UUID,
                allow_inmemory_denylist=True,
            ),
        ),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=User,
        user_manager_class=UsersFlowManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            id_parser=UUID,
            password_helper=password_helper,
        ),
        superuser_role_name="admin",
        include_users=True,
    )
    yield (
        Litestar(
            route_handlers=[role_guarded_any, role_guarded_all, role_guarded_runtime],
            plugins=[LitestarAuth(config)],
        ),
        engine,
        password_helper,
        user_ids,
    )
    UsersFlowManager.verification_tokens.clear()
    engine.dispose()


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so cookie and redirect behavior matches production wiring.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


async def test_users_crud_flow_via_plugin(
    client: tuple[AsyncTestClient[Litestar], Engine, PasswordHelper, dict[str, UUID]],
) -> None:
    """The plugin exposes the complete users CRUD flow with guards and pagination."""
    test_client, engine, password_helper, user_ids = client

    response = await test_client.get("/users/me")
    assert response.status_code == HTTP_UNAUTHORIZED

    regular_headers = await _login_headers(
        test_client,
        email="member@example.com",
        password="member-password",
    )

    response = await test_client.get("/users/me", headers=regular_headers)
    assert response.status_code == HTTP_OK
    _assert_public_user(
        response.json(),
        {
            "id": str(user_ids["member"]),
            "email": "member@example.com",
            "is_active": True,
            "is_verified": True,
            "roles": ["member"],
        },
    )

    response = await test_client.patch(
        "/users/me",
        headers=regular_headers,
        json={
            "email": "member-updated@example.com",
            "password": "member-new-password",
            "roles": [" Billing ", "ADMIN"],
        },
    )
    assert response.status_code == HTTP_OK
    _assert_public_user(
        response.json(),
        {
            "id": str(user_ids["member"]),
            "email": "member-updated@example.com",
            "is_active": True,
            "is_verified": False,
            "roles": ["member"],
        },
    )

    # Updating email/password changes the JWT session fingerprint. Previously minted access tokens
    # should no longer authenticate.
    response = await test_client.get(f"/users/{user_ids['admin']}", headers=regular_headers)
    assert response.status_code == HTTP_UNAUTHORIZED
    response = await test_client.get("/users", headers=regular_headers)
    assert response.status_code == HTTP_UNAUTHORIZED

    regular_headers = await _verify_then_login_headers(
        test_client,
        email="member-updated@example.com",
        password="member-new-password",
    )

    response = await test_client.get(f"/users/{user_ids['admin']}", headers=regular_headers)
    assert response.status_code == HTTP_FORBIDDEN
    response = await test_client.get("/users", headers=regular_headers)
    assert response.status_code == HTTP_FORBIDDEN

    response = await test_client.post(
        "/auth/login",
        json={"identifier": "member-updated@example.com", "password": "member-password"},
    )
    assert response.status_code == HTTP_BAD_REQUEST
    response = await test_client.post(
        "/auth/login",
        json={"identifier": "member-updated@example.com", "password": "member-new-password"},
    )
    assert response.status_code == HTTP_CREATED

    admin_headers = await _login_headers(
        test_client,
        email="admin@example.com",
        password="admin-password",
    )

    response = await test_client.get(f"/users/{user_ids['member']}", headers=admin_headers)
    assert response.status_code == HTTP_OK
    _assert_public_user(
        response.json(),
        {
            "id": str(user_ids["member"]),
            "email": "member-updated@example.com",
            "is_active": True,
            "is_verified": True,
            "roles": ["member"],
        },
    )

    response = await test_client.patch(
        f"/users/{user_ids['member']}",
        headers=admin_headers,
        json={"email": "vip@example.com", "is_verified": False, "roles": [" Billing ", "ADMIN"]},
    )
    assert response.status_code == HTTP_OK
    _assert_public_user(
        response.json(),
        {
            "id": str(user_ids["member"]),
            "email": "vip@example.com",
            "is_active": True,
            "is_verified": False,
            "roles": ["admin", "billing"],
        },
    )

    response = await test_client.get(
        f"/users?limit={PAGINATION_LIMIT}&offset={PAGINATION_OFFSET}",
        headers=admin_headers,
    )
    assert response.status_code == HTTP_OK
    list_payload = response.json()
    assert list_payload["total"] == TOTAL_USERS
    assert list_payload["limit"] == PAGINATION_LIMIT
    assert list_payload["offset"] == PAGINATION_OFFSET
    assert list_payload["items"] == [
        {
            "id": str(user_ids["extra"]),
            "email": "extra@example.com",
            "is_active": True,
            "is_verified": True,
            "roles": ["support"],
        },
        {
            "id": str(user_ids["admin"]),
            "email": "admin@example.com",
            "is_active": True,
            "is_verified": True,
            "roles": ["admin"],
        },
    ]

    response = await test_client.delete(f"/users/{user_ids['member']}", headers=admin_headers)
    assert response.status_code == HTTP_OK
    _assert_public_user(
        response.json(),
        {
            "id": str(user_ids["member"]),
            "email": "vip@example.com",
            "is_active": False,
            "is_verified": False,
            "roles": ["admin", "billing"],
        },
    )

    with SASession(engine) as session:
        stored_member = session.scalar(select(User).where(User.id == user_ids["member"]))

    assert stored_member is not None
    assert stored_member.email == "vip@example.com"
    assert stored_member.is_active is False
    assert stored_member.is_verified is False
    assert stored_member.roles == ["admin", "billing"]
    assert password_helper.verify("member-new-password", stored_member.hashed_password)


async def test_users_me_rejects_deactivated_user_with_existing_session(
    client: tuple[AsyncTestClient[Litestar], Engine, PasswordHelper, dict[str, UUID]],
) -> None:
    """A previously authenticated user is blocked from /users/me once deactivated."""
    test_client, _, _, user_ids = client
    member_headers = await _login_headers(
        test_client,
        email="member@example.com",
        password="member-password",
    )
    admin_headers = await _login_headers(
        test_client,
        email="admin@example.com",
        password="admin-password",
    )

    deactivate_response = await test_client.delete(f"/users/{user_ids['member']}", headers=admin_headers)
    assert deactivate_response.status_code == HTTP_OK
    assert deactivate_response.json()["is_active"] is False

    me_response = await test_client.get("/users/me", headers=member_headers)
    assert me_response.status_code == HTTP_BAD_REQUEST
    assert me_response.json()["detail"] == "The user account is inactive."
    assert me_response.json()["code"] == ErrorCode.LOGIN_USER_INACTIVE


async def test_role_guards_and_request_user_roles_survive_relational_storage(
    client: tuple[AsyncTestClient[Litestar], Engine, PasswordHelper, dict[str, UUID]],
) -> None:
    """Role guards and request-time role access keep working after relation-backed admin updates."""
    test_client, engine, _, user_ids = client
    admin_headers = await _login_headers(
        test_client,
        email="admin@example.com",
        password="admin-password",
    )
    member_headers = await _login_headers(
        test_client,
        email="member@example.com",
        password="member-password",
    )

    patch_response = await test_client.patch(
        f"/users/{user_ids['member']}",
        headers=admin_headers,
        json={"roles": [" Billing ", "ADMIN"]},
    )
    any_response = await test_client.get("/role-guarded/any", headers=member_headers)
    all_response = await test_client.get("/role-guarded/all", headers=member_headers)
    runtime_response = await test_client.get("/role-guarded/runtime", headers=member_headers)

    assert patch_response.status_code == HTTP_OK
    assert patch_response.json()["roles"] == ["admin", "billing"]
    assert any_response.status_code == HTTP_OK
    assert any_response.json() == {"ok": True}
    assert all_response.status_code == HTTP_OK
    assert all_response.json() == {"ok": True}
    assert runtime_response.status_code == HTTP_OK
    assert runtime_response.json() == {"roles": ["admin", "billing"]}

    with SASession(engine) as session:
        stored_member = session.scalar(select(User).where(User.id == user_ids["member"]))

    assert stored_member is not None
    assert stored_member.roles == ["admin", "billing"]


async def test_role_guard_failures_return_sanitized_insufficient_roles_payload(
    client: tuple[AsyncTestClient[Litestar], Engine, PasswordHelper, dict[str, UUID]],
) -> None:
    """Plugin-wired role guards return sanitized 403 payloads by default."""
    test_client, _, _, _ = client
    member_headers = await _login_headers(
        test_client,
        email="member@example.com",
        password="member-password",
    )

    any_response = await test_client.get("/role-guarded/any", headers=member_headers)
    all_response = await test_client.get("/role-guarded/all", headers=member_headers)

    assert any_response.status_code == HTTP_FORBIDDEN
    assert any_response.json() == {
        "detail": "The authenticated user does not have any of the required roles.",
        "code": "INSUFFICIENT_ROLES",
    }
    assert all_response.status_code == HTTP_FORBIDDEN
    assert all_response.json() == {
        "detail": "The authenticated user does not have all of the required roles.",
        "code": "INSUFFICIENT_ROLES",
    }
