"""Integration tests for the opt-in contrib role-admin controller."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Self, cast
from uuid import UUID

import pytest
from advanced_alchemy.base import create_registry
from litestar import Litestar
from litestar.testing import AsyncTestClient
from sqlalchemy import ForeignKey, create_engine, event, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.orm import Session as SASession
from sqlalchemy.pool import StaticPool

from litestar_auth._plugin.role_admin import SQLAlchemyRoleAdmin
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.contrib.role_admin import create_role_admin_controller
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import RoleMixin, User, UserModelMixin, UserRoleAssociationMixin, UserRoleRelationshipMixin
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.sql.base import Executable

pytestmark = pytest.mark.integration

HTTP_CONFLICT = 409
HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_NO_CONTENT = 204
HTTP_OK = 200
HTTP_UNPROCESSABLE_ENTITY = 422
ROLE_ROUTE_PREFIX = "/roles"


@dataclass(frozen=True, slots=True)
class _RoleAdminUpdateEvent:
    """Captured manager lifecycle payload for one HTTP-driven role mutation."""

    email: str
    roles: list[str]


class RoleAdminTestUserManager(BaseUserManager[User, UUID]):
    """Concrete manager used by the role-admin integration app."""

    update_events: ClassVar[list[_RoleAdminUpdateEvent]] = []

    async def on_after_update(self, user: User, update_dict: dict[str, Any]) -> None:
        """Record the normalized role payload surfaced through the manager lifecycle."""
        self.update_events.append(_RoleAdminUpdateEvent(email=user.email, roles=list(update_dict["roles"])))


class IntegerRoleAdminBase(DeclarativeBase):
    """Dedicated registry for integer-key role-admin integration tests."""

    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class IntegerRoleAdminUser(UserModelMixin, UserRoleRelationshipMixin, IntegerRoleAdminBase):
    """Custom role-capable user model with an integer primary key."""

    __tablename__ = "integer_role_admin_user"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    auth_user_role_model = "IntegerRoleAdminUserRole"


class IntegerRoleAdminRole(RoleMixin, IntegerRoleAdminBase):
    """Custom role catalog row for integer-key integration tests."""

    __tablename__ = "integer_role_admin_role"
    auth_user_role_model = "IntegerRoleAdminUserRole"
    description: Mapped[str | None] = mapped_column(default=None, nullable=True)


class IntegerRoleAdminUserRole(UserRoleAssociationMixin, IntegerRoleAdminBase):
    """Custom user-role association row for integer-key integration tests."""

    __tablename__ = "integer_role_admin_user_role"
    auth_user_model = "IntegerRoleAdminUser"
    auth_user_table = "integer_role_admin_user"
    auth_role_model = "IntegerRoleAdminRole"
    auth_role_table = "integer_role_admin_role"
    user_id: Mapped[int] = mapped_column(
        ForeignKey(f"{auth_user_table}.id"),
        primary_key=True,
    )


class IntegerRoleAdminTestUserManager(BaseUserManager[IntegerRoleAdminUser, int]):
    """Concrete manager used by the integer-key role-admin integration app."""

    update_events: ClassVar[list[_RoleAdminUpdateEvent]] = []

    async def on_after_update(self, user: IntegerRoleAdminUser, update_dict: dict[str, Any]) -> None:
        """Record the normalized role payload surfaced through the manager lifecycle."""
        self.update_events.append(_RoleAdminUpdateEvent(email=user.email, roles=list(update_dict["roles"])))


class _AsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session for role-admin tests."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped sync session."""
        self._session = session
        self.info: dict[str, Any] = {}

    async def __aenter__(self) -> Self:
        """Return the adapter itself for ``async with`` compatibility."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Mirror SQLAlchemy session cleanup semantics for the test adapter."""
        del exc, traceback
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        await self.close()

    def add(self, instance: object) -> None:
        """Add one instance to the wrapped sync session."""
        self._session.add(instance)

    def add_all(self, instances: list[object]) -> None:
        """Add multiple instances to the wrapped sync session."""
        self._session.add_all(instances)

    @property
    def bind(self) -> Engine | Connection | None:
        """Expose the wrapped session bind."""
        return cast("Engine | Connection | None", self._session.bind)

    def expunge(self, instance: object) -> None:
        """Expunge one instance from the wrapped sync session."""
        self._session.expunge(instance)

    def get_bind(self) -> Engine | Connection:
        """Expose the wrapped session bind via SQLAlchemy's API.

        Returns:
            The bound SQLAlchemy connectable.
        """
        return cast("Engine | Connection", self._session.get_bind())

    async def close(self) -> None:
        """Close the wrapped sync session."""
        self._session.close()

    async def commit(self) -> None:
        """Commit the current transaction."""
        self._session.commit()

    async def execute(
        self,
        statement: Executable,
        params: object | None = None,
        *,
        execution_options: object | None = None,
    ) -> object:
        """Execute one SQLAlchemy statement.

        Returns:
            The SQLAlchemy execution result.
        """
        sync_session = cast("Any", self._session)
        return cast(
            "object",
            sync_session.execute(statement, params=params, execution_options=execution_options),
        )

    async def flush(self) -> None:
        """Flush pending ORM changes."""
        self._session.flush()

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Merge one instance into the wrapped session.

        Returns:
            The merged ORM instance.
        """
        return self._session.merge(instance, load=load)

    async def refresh(
        self,
        instance: object,
        *,
        attribute_names: object | None = None,
        with_for_update: ForUpdateParameter = None,
    ) -> None:
        """Refresh one instance from the wrapped session."""
        self._session.refresh(
            instance,
            attribute_names=cast("Any", attribute_names),
            with_for_update=cast("Any", with_for_update),
        )

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        self._session.rollback()

    async def scalar(self, statement: object) -> object:
        """Return the first scalar result for a statement."""
        return self._session.scalar(cast("Any", statement))

    async def scalars(self, statement: object) -> object:
        """Return the scalar result collection for a statement."""
        return self._session.scalars(cast("Any", statement))

    @property
    def no_autoflush(self) -> object:
        """Expose the wrapped session no-autoflush context manager."""
        return self._session.no_autoflush


class SessionMaker:
    """Callable session factory compatible with the role-admin helper contract."""

    def __init__(self, engine: Engine) -> None:
        """Store the shared engine."""
        self._engine = engine

    def __call__(self) -> AsyncSession:
        """Return a new adapter-backed session."""
        return cast("AsyncSession", _AsyncSessionAdapter(SASession(self._engine, expire_on_commit=False)))


async def _login_headers(
    client: AsyncTestClient[Litestar],
    *,
    email: str,
    password: str,
) -> dict[str, str]:
    """Authenticate one user and return bearer authorization headers.

    Returns:
        Authorization headers containing the issued bearer token.
    """
    response = await client.post("/auth/login", json={"identifier": email, "password": password})
    assert response.status_code == HTTP_CREATED
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _load_role_assignments(engine: Engine, *, email: str) -> list[str]:
    """Return one user's persisted normalized role membership."""
    with SASession(engine, expire_on_commit=False) as session:
        statement = select(User).where(User.email == email)
        user = session.scalar(statement)
        assert user is not None
        return list(user.roles)


def _load_user_id(engine: Engine, *, email: str) -> UUID:
    """Return one bundled user's identifier."""
    with SASession(engine, expire_on_commit=False) as session:
        statement = select(User).where(User.email == email)
        user = session.scalar(statement)
        assert user is not None
        return user.id


def _load_role_assignment_row_count(engine: Engine, *, email: str, role_name: str) -> int:
    """Return the number of persisted user-role rows for one bundled user-role pair."""
    with SASession(engine, expire_on_commit=False) as session:
        statement = select(User).where(User.email == email).where(User.role_assignments.any(role_name=role_name))
        user = session.scalar(statement)
        if user is None:
            return 0
        return sum(1 for assignment in user.role_assignments if assignment.role_name == role_name)


def _load_integer_role_assignments(engine: Engine, *, user_id: int) -> list[str]:
    """Return one integer-key user's persisted normalized role membership."""
    with SASession(engine, expire_on_commit=False) as session:
        user = session.get(IntegerRoleAdminUser, user_id)
        assert user is not None
        return list(user.roles)


def _load_integer_user_id(engine: Engine, *, email: str) -> int:
    """Return one integer-key user's identifier."""
    with SASession(engine, expire_on_commit=False) as session:
        statement = select(IntegerRoleAdminUser).where(IntegerRoleAdminUser.email == email)
        user = session.scalar(statement)
        assert user is not None
        return user.id


def _load_integer_role_assignment_row_count(engine: Engine, *, user_id: int, role_name: str) -> int:
    """Return the number of persisted user-role rows for one integer-key user-role pair."""
    with SASession(engine, expire_on_commit=False) as session:
        statement = select(IntegerRoleAdminUserRole).where(
            IntegerRoleAdminUserRole.user_id == user_id,
            IntegerRoleAdminUserRole.role_name == role_name,
        )
        return len(list(session.scalars(statement)))


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so bearer auth matches the repository's end-to-end tests.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


@pytest.fixture
def app() -> Iterator[tuple[Litestar, Engine, LitestarAuthConfig[User, UUID]]]:
    """Create a plugin-backed app with the opt-in role-admin controller mounted.

    Yields:
        The app under test, backing engine, and auth config.
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
                User(
                    email="auditor@example.com",
                    hashed_password=password_helper.hash("auditor-password"),
                    is_verified=True,
                    roles=[],
                ),
            ],
        )
        session.commit()

    backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](
                secret="jwt-role-admin-secret-12345678901234567890",
                subject_decoder=UUID,
                allow_inmemory_denylist=True,
            ),
        ),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=User,
        user_manager_class=RoleAdminTestUserManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=password_helper,
        ),
        superuser_role_name="admin",
        include_users=False,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
    )
    role_admin_controller = create_role_admin_controller(config=config)
    yield Litestar(route_handlers=[role_admin_controller], plugins=[LitestarAuth(config)]), engine, config
    RoleAdminTestUserManager.update_events = []
    engine.dispose()


@pytest.fixture
def integer_role_admin_app() -> Iterator[tuple[Litestar, Engine]]:
    """Create a config-backed app for integer-key role-admin assignment coverage.

    Yields:
        The app under test and its backing engine.
    """
    IntegerRoleAdminTestUserManager.update_events = []
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_integer_sqlite_foreign_keys(dbapi_connection: sqlite3.Connection, _: object) -> None:
        if not isinstance(dbapi_connection, sqlite3.Connection):
            return

        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    IntegerRoleAdminBase.metadata.create_all(engine)
    with SASession(engine, expire_on_commit=False) as session:
        session.add_all(
            [
                IntegerRoleAdminRole(name="reviewer", description="Can review content"),
                IntegerRoleAdminRole(name="admin", description=None),
                IntegerRoleAdminUser(
                    email="integer-admin@example.com",
                    hashed_password="hash",
                    is_active=True,
                    is_verified=True,
                    roles=["admin"],
                ),
                IntegerRoleAdminUser(
                    email="integer-member@example.com",
                    hashed_password="hash",
                    is_active=True,
                    is_verified=False,
                    roles=[],
                ),
            ],
        )
        session.commit()

    config = LitestarAuthConfig[IntegerRoleAdminUser, int](
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=IntegerRoleAdminUser,
        user_manager_class=IntegerRoleAdminTestUserManager,
        user_manager_security=UserManagerSecurity[int](
            verification_token_secret="integer-verify-secret-12345678901234567890",
            reset_password_token_secret="integer-reset-secret-123456789012345678901",
            id_parser=int,
            password_helper=PasswordHelper(),
        ),
        include_users=False,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
    )
    role_admin_controller = create_role_admin_controller(config=config, guards=[])
    yield Litestar(route_handlers=[role_admin_controller]), engine
    IntegerRoleAdminTestUserManager.update_events = []
    engine.dispose()


async def test_role_admin_role_catalog_crud_and_http_cli_parity(
    client: tuple[AsyncTestClient[Litestar], Engine, LitestarAuthConfig[User, UUID]],
) -> None:
    """The contrib controller exposes paginated CRUD with normalized HTTP/CLI parity."""
    test_client, _, config = client
    admin_headers = await _login_headers(test_client, email="admin@example.com", password="admin-password")

    create_response = await test_client.post(
        ROLE_ROUTE_PREFIX,
        headers=admin_headers,
        json={"name": " \uff22illing ", "description": "Billing access"},
    )
    list_response = await test_client.get(
        ROLE_ROUTE_PREFIX,
        headers=admin_headers,
        params={"limit": 10, "offset": 0},
    )
    read_response = await test_client.get(f"{ROLE_ROUTE_PREFIX}/billing", headers=admin_headers)
    update_response = await test_client.patch(
        f"{ROLE_ROUTE_PREFIX}/billing",
        headers=admin_headers,
        json={"description": "Updated billing access"},
    )

    assert create_response.status_code == HTTP_CREATED
    assert create_response.json() == {"name": "billing", "description": "Billing access"}
    assert list_response.status_code == HTTP_OK
    assert list_response.json() == {
        "items": [
            {"name": "admin", "description": None},
            {"name": "billing", "description": "Billing access"},
        ],
        "total": 2,
        "limit": 10,
        "offset": 0,
    }
    assert read_response.status_code == HTTP_OK
    assert read_response.json() == {"name": "billing", "description": "Billing access"}
    assert update_response.status_code == HTTP_OK
    assert update_response.json() == {"name": "billing", "description": "Updated billing access"}

    role_admin = SQLAlchemyRoleAdmin.from_config(config)
    assert await role_admin.list_roles() == ["admin", "billing"]


async def test_role_admin_create_duplicate_missing_role_and_immutable_name_are_refused(
    client: tuple[AsyncTestClient[Litestar], Engine, LitestarAuthConfig[User, UUID]],
) -> None:
    """Duplicate create, missing-role reads, and name changes use the documented failure contract."""
    test_client, _, _ = client
    admin_headers = await _login_headers(test_client, email="admin@example.com", password="admin-password")
    await test_client.post(
        ROLE_ROUTE_PREFIX,
        headers=admin_headers,
        json={"name": "support", "description": "Support access"},
    )

    duplicate_response = await test_client.post(
        ROLE_ROUTE_PREFIX,
        headers=admin_headers,
        json={"name": "Support", "description": "Duplicate support access"},
    )
    missing_response = await test_client.get(f"{ROLE_ROUTE_PREFIX}/missing", headers=admin_headers)
    rename_attempt_response = await test_client.patch(
        f"{ROLE_ROUTE_PREFIX}/support",
        headers=admin_headers,
        json={"name": "renamed"},
    )

    assert duplicate_response.status_code == HTTP_CONFLICT
    assert duplicate_response.json() == {
        "status_code": HTTP_CONFLICT,
        "detail": "Role 'support' already exists.",
        "extra": {"code": ErrorCode.ROLE_ALREADY_EXISTS},
    }
    assert missing_response.status_code == HTTP_NOT_FOUND
    assert missing_response.json() == {
        "detail": "Role 'missing' not found.",
        "code": ErrorCode.ROLE_NOT_FOUND,
    }
    assert rename_attempt_response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert rename_attempt_response.json() == {
        "status_code": HTTP_UNPROCESSABLE_ENTITY,
        "detail": "Role names are immutable.",
        "extra": {"code": ErrorCode.ROLE_NAME_INVALID},
    }


async def test_role_admin_delete_fails_closed_when_assignments_exist_and_succeeds_when_unassigned(
    client: tuple[AsyncTestClient[Litestar], Engine, LitestarAuthConfig[User, UUID]],
) -> None:
    """Delete defaults to fail closed when assignments exist and returns 204 when they do not."""
    test_client, engine, _ = client
    admin_headers = await _login_headers(test_client, email="admin@example.com", password="admin-password")

    delete_assigned_response = await test_client.delete(f"{ROLE_ROUTE_PREFIX}/admin", headers=admin_headers)

    assert delete_assigned_response.status_code == HTTP_CONFLICT
    assert delete_assigned_response.json() == {
        "detail": (
            "Role admin will not delete role 'admin' while assignments still exist. "
            "Re-run with --force to remove dependent user-role assignments."
        ),
        "code": ErrorCode.ROLE_STILL_ASSIGNED,
    }
    assert _load_role_assignments(engine, email="admin@example.com") == ["admin"]

    await test_client.post(
        ROLE_ROUTE_PREFIX,
        headers=admin_headers,
        json={"name": "temp-role", "description": "Temporary role"},
    )
    delete_unassigned_response = await test_client.delete(f"{ROLE_ROUTE_PREFIX}/temp-role", headers=admin_headers)
    final_list_response = await test_client.get(ROLE_ROUTE_PREFIX, headers=admin_headers)

    assert delete_unassigned_response.status_code == HTTP_NO_CONTENT
    assert delete_unassigned_response.content == b""
    assert final_list_response.status_code == HTTP_OK
    assert final_list_response.json() == {
        "items": [{"name": "admin", "description": None}],
        "total": 1,
        "limit": 50,
        "offset": 0,
    }


async def test_role_admin_assignment_routes_use_manager_lifecycle_and_stay_idempotent(
    client: tuple[AsyncTestClient[Litestar], Engine, LitestarAuthConfig[User, UUID]],
) -> None:
    """Assigning and revoking through HTTP emit one lifecycle event per actual mutation."""
    test_client, engine, _ = client
    admin_headers = await _login_headers(test_client, email="admin@example.com", password="admin-password")
    member_id = _load_user_id(engine, email="member@example.com")

    first_assign_response = await test_client.post(
        f"{ROLE_ROUTE_PREFIX}/admin/users/{member_id}",
        headers=admin_headers,
    )
    second_assign_response = await test_client.post(
        f"{ROLE_ROUTE_PREFIX}/admin/users/{member_id}",
        headers=admin_headers,
    )
    assert _load_role_assignment_row_count(engine, email="member@example.com", role_name="admin") == 1
    first_unassign_response = await test_client.delete(
        f"{ROLE_ROUTE_PREFIX}/admin/users/{member_id}",
        headers=admin_headers,
    )
    second_unassign_response = await test_client.delete(
        f"{ROLE_ROUTE_PREFIX}/admin/users/{member_id}",
        headers=admin_headers,
    )

    assert first_assign_response.status_code == HTTP_OK
    assert first_assign_response.json() == {"name": "admin", "description": None}
    assert second_assign_response.status_code == HTTP_OK
    assert second_assign_response.json() == {"name": "admin", "description": None}
    assert first_unassign_response.status_code == HTTP_NO_CONTENT
    assert second_unassign_response.status_code == HTTP_NO_CONTENT
    assert _load_role_assignment_row_count(engine, email="member@example.com", role_name="admin") == 0
    assert _load_role_assignments(engine, email="member@example.com") == []
    assert RoleAdminTestUserManager.update_events == [
        _RoleAdminUpdateEvent(email="member@example.com", roles=["admin"]),
        _RoleAdminUpdateEvent(email="member@example.com", roles=[]),
    ]


async def test_role_admin_list_role_users_returns_user_briefs_in_deterministic_order(
    client: tuple[AsyncTestClient[Litestar], Engine, LitestarAuthConfig[User, UUID]],
) -> None:
    """The role-user listing is paginated, deterministic, and serialized as ``UserBrief``."""
    test_client, engine, _ = client
    admin_headers = await _login_headers(test_client, email="admin@example.com", password="admin-password")
    member_id = _load_user_id(engine, email="member@example.com")
    auditor_id = _load_user_id(engine, email="auditor@example.com")

    await test_client.post(f"{ROLE_ROUTE_PREFIX}/admin/users/{member_id}", headers=admin_headers)
    await test_client.post(f"{ROLE_ROUTE_PREFIX}/admin/users/{auditor_id}", headers=admin_headers)

    first_page_response = await test_client.get(
        f"{ROLE_ROUTE_PREFIX}/admin/users",
        headers=admin_headers,
        params={"limit": 2, "offset": 0},
    )
    second_page_response = await test_client.get(
        f"{ROLE_ROUTE_PREFIX}/admin/users",
        headers=admin_headers,
        params={"limit": 1, "offset": 2},
    )

    assert first_page_response.status_code == HTTP_OK
    assert first_page_response.json() == {
        "items": [
            {
                "id": str(_load_user_id(engine, email="admin@example.com")),
                "email": "admin@example.com",
                "is_active": True,
                "is_verified": True,
            },
            {
                "id": str(auditor_id),
                "email": "auditor@example.com",
                "is_active": True,
                "is_verified": True,
            },
        ],
        "total": 3,
        "limit": 2,
        "offset": 0,
    }
    assert second_page_response.status_code == HTTP_OK
    assert second_page_response.json() == {
        "items": [
            {
                "id": str(member_id),
                "email": "member@example.com",
                "is_active": True,
                "is_verified": True,
            },
        ],
        "total": 3,
        "limit": 1,
        "offset": 2,
    }


async def test_role_admin_assignment_routes_map_missing_users_and_integer_path_ids(
    client: tuple[AsyncTestClient[Litestar], Engine, LitestarAuthConfig[User, UUID]],
    integer_role_admin_app: tuple[Litestar, Engine],
) -> None:
    """Assignment routes report missing users with the role-admin code and parse integer ids."""
    test_client, _, _ = client
    admin_headers = await _login_headers(test_client, email="admin@example.com", password="admin-password")
    missing_user_response = await test_client.post(
        f"{ROLE_ROUTE_PREFIX}/admin/users/{UUID(int=99)}",
        headers=admin_headers,
    )

    assert missing_user_response.status_code == HTTP_NOT_FOUND
    assert missing_user_response.json() == {
        "detail": f"Role admin could not find a user with id {UUID(int=99)!r}.",
        "code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND,
    }

    integer_app, integer_engine = integer_role_admin_app
    integer_member_id = _load_integer_user_id(integer_engine, email="integer-member@example.com")

    async with AsyncTestClient(app=integer_app) as integer_client:
        first_assign_response = await integer_client.post(f"{ROLE_ROUTE_PREFIX}/reviewer/users/{integer_member_id}")
        second_assign_response = await integer_client.post(f"{ROLE_ROUTE_PREFIX}/reviewer/users/{integer_member_id}")
        assert (
            _load_integer_role_assignment_row_count(
                integer_engine,
                user_id=integer_member_id,
                role_name="reviewer",
            )
            == 1
        )
        list_response = await integer_client.get(
            f"{ROLE_ROUTE_PREFIX}/reviewer/users",
            params={"limit": 10, "offset": 0},
        )
        first_unassign_response = await integer_client.delete(
            f"{ROLE_ROUTE_PREFIX}/reviewer/users/{integer_member_id}",
        )
        second_unassign_response = await integer_client.delete(
            f"{ROLE_ROUTE_PREFIX}/reviewer/users/{integer_member_id}",
        )

    assert first_assign_response.status_code == HTTP_OK
    assert first_assign_response.json() == {"name": "reviewer", "description": "Can review content"}
    assert second_assign_response.status_code == HTTP_OK
    assert list_response.status_code == HTTP_OK
    assert list_response.json() == {
        "items": [
            {
                "id": str(integer_member_id),
                "email": "integer-member@example.com",
                "is_active": True,
                "is_verified": False,
            },
        ],
        "total": 1,
        "limit": 10,
        "offset": 0,
    }
    assert first_unassign_response.status_code == HTTP_NO_CONTENT
    assert second_unassign_response.status_code == HTTP_NO_CONTENT
    assert _load_integer_role_assignments(integer_engine, user_id=integer_member_id) == []
    assert (
        _load_integer_role_assignment_row_count(
            integer_engine,
            user_id=integer_member_id,
            role_name="reviewer",
        )
        == 0
    )
    assert IntegerRoleAdminTestUserManager.update_events == [
        _RoleAdminUpdateEvent(email="integer-member@example.com", roles=["reviewer"]),
        _RoleAdminUpdateEvent(email="integer-member@example.com", roles=[]),
    ]


@pytest.mark.parametrize(
    ("method", "path", "json_body"),
    [
        ("get", ROLE_ROUTE_PREFIX, None),
        ("post", ROLE_ROUTE_PREFIX, {"name": "ops", "description": "Ops access"}),
        ("get", f"{ROLE_ROUTE_PREFIX}/admin", None),
        ("patch", f"{ROLE_ROUTE_PREFIX}/admin", {"description": "Updated admin access"}),
        ("delete", f"{ROLE_ROUTE_PREFIX}/admin", None),
        ("post", f"{ROLE_ROUTE_PREFIX}/admin/users/ignored-user", None),
        ("delete", f"{ROLE_ROUTE_PREFIX}/admin/users/ignored-user", None),
        ("get", f"{ROLE_ROUTE_PREFIX}/admin/users", None),
    ],
)
async def test_role_admin_default_superuser_guard_refuses_non_superusers(
    client: tuple[AsyncTestClient[Litestar], Engine, LitestarAuthConfig[User, UUID]],
    method: str,
    path: str,
    json_body: dict[str, str] | None,
) -> None:
    """Every endpoint is refused for authenticated users who are not superusers."""
    test_client, _, _ = client
    member_headers = await _login_headers(test_client, email="member@example.com", password="member-password")
    request_kwargs: dict[str, object] = {"headers": member_headers}
    if json_body is not None:
        request_kwargs["json"] = json_body

    response = await getattr(test_client, method)(path, **request_kwargs)

    assert response.status_code == HTTP_FORBIDDEN
