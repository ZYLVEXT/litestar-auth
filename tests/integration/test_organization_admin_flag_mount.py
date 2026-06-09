"""Characterization coverage for organization-admin config-flag mounting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar
from litestar.routes import HTTPRoute
from litestar.testing import AsyncTestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore, SQLAlchemyUserDatabase
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import Organization, OrganizationInvitation, OrganizationMembership, User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig, OrganizationConfig
from tests.integration.conftest import enable_aiosqlite_foreign_keys
from tests.integration.test_contrib_role_admin import _login_headers

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

HTTP_BAD_REQUEST = 400
HTTP_CONFLICT = 409
HTTP_NOT_FOUND = 404


@dataclass(frozen=True, slots=True)
class _FlagMountState:
    """Seeded users and organizations used by flag-mount characterization requests."""

    acme_id: UUID
    acme_admin_id: UUID


@dataclass(frozen=True, slots=True)
class _FlagMountApp:
    """Flag-mounted organization app plus cleanup resources."""

    app: Litestar
    state: _FlagMountState
    engine: Any


class OrganizationFlagMountUserManager(BaseUserManager[User, UUID]):
    """Concrete manager used by config-flag organization-admin integration apps."""


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so bearer authentication matches the integration client defaults.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


async def _seed_database(
    session_maker: async_sessionmaker[AsyncSession],
    password_helper: PasswordHelper,
) -> _FlagMountState:
    async with session_maker() as session:
        global_admin = User(
            email="global-admin@example.com",
            hashed_password=password_helper.hash("global-admin-password"),
            is_verified=True,
            roles=["admin"],
        )
        acme_admin = User(
            email="acme-admin@example.com",
            hashed_password=password_helper.hash("acme-admin-password"),
            is_verified=True,
            roles=[],
        )
        acme = Organization(slug="acme", name="Acme")
        session.add_all([global_admin, acme_admin, acme])
        await session.flush()
        session.add_all(
            [
                OrganizationMembership(organization_id=acme.id, user_id=global_admin.id, roles=["owner"]),
                OrganizationMembership(organization_id=acme.id, user_id=acme_admin.id, roles=["owner"]),
            ],
        )
        await session.commit()
        return _FlagMountState(acme_id=acme.id, acme_admin_id=acme_admin.id)


async def _build_flag_mount_app(
    tmp_path: Path,
    *,
    include_organization_admin: bool,
    include_organization_invitations: bool,
) -> _FlagMountApp:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / f'{uuid4()}.sqlite'}")
    enable_aiosqlite_foreign_keys(engine)
    async with engine.begin() as connection:
        await connection.run_sync(User.metadata.create_all)

    password_helper = PasswordHelper()
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    state = await _seed_database(session_maker, password_helper)
    backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](
                secret="jwt-organization-admin-flag-secret-123456789012345",
                subject_decoder=UUID,
                allow_inmemory_denylist=True,
            ),
        ),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", session_maker),
        user_model=User,
        user_manager_class=OrganizationFlagMountUserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            organization_invitation_token_secret="0011223344556677" * 4,
            id_parser=UUID,
            password_helper=password_helper,
        ),
        superuser_role_name="admin",
        organization_config=OrganizationConfig(
            enabled=True,
            store_factory=lambda session: SQLAlchemyOrganizationStore(
                session=session,
                organization_model=Organization,
                membership_model=OrganizationMembership,
                invitation_model=OrganizationInvitation,
            ),
            include_organization_admin=include_organization_admin,
            include_organization_invitations=include_organization_invitations,
        ),
        include_users=False,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
    )
    return _FlagMountApp(app=Litestar(plugins=[LitestarAuth(config)]), state=state, engine=engine)


def _organization_route_table(app: Litestar, *, prefix: str) -> dict[str, tuple[str, ...]]:
    return {
        route.path_format: tuple(sorted(route.route_handler_map))
        for route in app.routes
        if isinstance(route, HTTPRoute) and route.path_format.startswith(prefix)
    }


def _organization_routes(app: Litestar, *, prefix: str) -> list[HTTPRoute]:
    return [route for route in app.routes if isinstance(route, HTTPRoute) and route.path_format.startswith(prefix)]


def _route_by_path(app: Litestar, path: str) -> HTTPRoute:
    for route in app.routes:
        if isinstance(route, HTTPRoute) and route.path_format == path:
            return route
    msg = f"Route not found: {path}"
    raise AssertionError(msg)


def _guard_name(guard: object) -> str:
    name = getattr(guard, "__name__", None)
    if isinstance(name, str):
        return name
    return repr(guard)


def _guard_names(guards: object) -> tuple[str, ...]:
    if guards is None:
        return ()
    return tuple(_guard_name(guard) for guard in cast("list[object]", guards))


def _owner_guard_names(route: HTTPRoute) -> tuple[str, ...]:
    handler = route.route_handlers[0]
    owner = handler.owner
    return _guard_names(getattr(owner, "guards", None))


def _handler_guard_names(route: HTTPRoute, method: str) -> tuple[str, ...]:
    handler = route.route_handler_map[cast("Any", method)][0]
    return _guard_names(handler.guards)


def _openapi_security_by_operation(app: Litestar, *, prefix: str) -> dict[tuple[str, str], object]:
    operations: dict[tuple[str, str], object] = {}
    paths = app.openapi_schema.paths
    assert paths is not None
    for path, path_item in sorted(paths.items()):
        if not path.startswith(prefix):
            continue
        for method in ("get", "post", "patch", "delete"):
            operation = getattr(path_item, method, None)
            if operation is not None:
                operations[path, method] = operation.security
    return operations


async def test_config_flag_mounts_exact_organization_admin_routes_guards_and_openapi_security(tmp_path: Path) -> None:
    """The include_organization_admin config flag mounts today's direct controller surface."""
    flag_app = await _build_flag_mount_app(
        tmp_path,
        include_organization_admin=True,
        include_organization_invitations=False,
    )
    try:
        assert _organization_route_table(flag_app.app, prefix="/organizations") == {
            "/organizations": ("GET", "OPTIONS", "POST"),
            "/organizations/{organization_id}": ("DELETE", "GET", "OPTIONS", "PATCH"),
            "/organizations/{organization_id}/members": ("GET", "OPTIONS"),
            "/organizations/{organization_id}/members/{user_id}": ("DELETE", "OPTIONS", "POST"),
            "/organizations/{organization_id}/members/{user_id}/roles": ("OPTIONS", "PATCH"),
            "/organizations/{organization_id}/invitations": ("GET", "OPTIONS", "POST"),
            "/organizations/invitations/{invitation_id}": ("DELETE", "OPTIONS"),
        }
        for route in _organization_routes(flag_app.app, prefix="/organizations"):
            assert _owner_guard_names(route) == ("is_superuser",)
        assert all(
            security is None
            for security in _openapi_security_by_operation(flag_app.app, prefix="/organizations").values()
        )
    finally:
        await flag_app.engine.dispose()


async def test_config_flag_mounts_exact_invitation_routes_guards_and_openapi_security(tmp_path: Path) -> None:
    """The include_organization_invitations config flag mounts today's authenticated invitation surface."""
    flag_app = await _build_flag_mount_app(
        tmp_path,
        include_organization_admin=False,
        include_organization_invitations=True,
    )
    try:
        assert _organization_route_table(flag_app.app, prefix="/auth/organization-invitations") == {
            "/auth/organization-invitations/accept": ("OPTIONS", "POST"),
            "/auth/organization-invitations/decline": ("OPTIONS", "POST"),
        }
        for route in _organization_routes(flag_app.app, prefix="/auth/organization-invitations"):
            assert _handler_guard_names(route, "POST") == ("is_active", "is_verified")
        assert _openapi_security_by_operation(flag_app.app, prefix="/auth/organization-invitations") == {
            ("/auth/organization-invitations/accept", "post"): [{"bearer": []}],
            ("/auth/organization-invitations/decline", "post"): [{"bearer": []}],
        }
    finally:
        await flag_app.engine.dispose()


async def test_config_flag_error_envelopes_are_current_stable_error_code_shapes(
    tmp_path: Path,
    test_client_base_url: str,
) -> None:
    """Representative flag-mounted failures keep today's stable ErrorCode envelopes."""
    flag_app = await _build_flag_mount_app(
        tmp_path,
        include_organization_admin=True,
        include_organization_invitations=True,
    )
    try:
        async with AsyncTestClient(flag_app.app, base_url=test_client_base_url) as client:
            headers = await _login_headers(
                client,
                email="global-admin@example.com",
                password="global-admin-password",
            )
            unknown_response = await client.get(f"/organizations/{uuid4()}", headers=headers)
            duplicate_member_response = await client.post(
                f"/organizations/{flag_app.state.acme_id}/members/{flag_app.state.acme_admin_id}",
                json={"roles": ["owner"]},
                headers=headers,
            )
            invalid_invitation_response = await client.post(
                "/auth/organization-invitations/accept",
                json={"token": "not-a-valid-token"},
                headers=headers,
            )

        assert unknown_response.status_code == HTTP_NOT_FOUND
        assert unknown_response.json() == {
            "detail": "Organization not found.",
            "code": ErrorCode.ORGANIZATION_NOT_FOUND,
        }
        assert duplicate_member_response.status_code == HTTP_CONFLICT
        assert duplicate_member_response.json() == {
            "status_code": HTTP_CONFLICT,
            "detail": "Organization membership already exists.",
            "extra": {"code": ErrorCode.ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS},
        }
        assert invalid_invitation_response.status_code == HTTP_BAD_REQUEST
        assert invalid_invitation_response.json() == {
            "status_code": HTTP_BAD_REQUEST,
            "detail": "Organization invitation cannot be used.",
            "extra": {"code": ErrorCode.ORGANIZATION_INVITATION_INVALID},
        }
    finally:
        await flag_app.engine.dispose()
