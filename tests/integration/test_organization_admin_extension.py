"""End-to-end coverage for mounting organization-admin through the first-party extension."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from litestar_auth._tenant_resolution import HeaderTenantResolver
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.contrib.organization_admin import OrganizationAdminExtension
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore, SQLAlchemyUserDatabase
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import has_organization_role
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import Organization, OrganizationInvitation, OrganizationMembership, User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig, OrganizationConfig
from tests.integration.conftest import enable_aiosqlite_foreign_keys
from tests.integration.test_contrib_role_admin import _login_headers

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from litestar.testing import AsyncTestClient


pytestmark = pytest.mark.integration

HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_OK = 200
ORGANIZATION_ROUTE_PREFIX = "/organizations"


@dataclass(frozen=True, slots=True)
class _OrganizationAdminState:
    """Seeded organization identifiers used by request-level assertions."""

    acme_id: UUID
    beta_id: UUID
    acme_admin_id: UUID


class OrganizationAdminTestUserManager(BaseUserManager[User, UUID]):
    """Concrete manager used by the organization-admin extension integration app."""


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so bearer auth matches the repository's end-to-end tests.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


async def _seed_database(
    session_maker: async_sessionmaker[AsyncSession],
    password_helper: PasswordHelper,
) -> _OrganizationAdminState:
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
        beta_admin = User(
            email="beta-admin@example.com",
            hashed_password=password_helper.hash("beta-admin-password"),
            is_verified=True,
            roles=[],
        )
        acme = Organization(slug="acme", name="Acme")
        beta = Organization(slug="beta", name="Beta")
        session.add_all([global_admin, acme_admin, beta_admin, acme, beta])
        await session.flush()
        session.add_all(
            [
                OrganizationMembership(organization_id=acme.id, user_id=global_admin.id, roles=["owner"]),
                OrganizationMembership(organization_id=acme.id, user_id=acme_admin.id, roles=["owner"]),
                OrganizationMembership(organization_id=beta.id, user_id=beta_admin.id, roles=["owner"]),
            ],
        )
        await session.commit()
        return _OrganizationAdminState(acme_id=acme.id, beta_id=beta.id, acme_admin_id=acme_admin.id)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[tuple[Litestar, _OrganizationAdminState]]:
    """Create an app whose organization-admin routes are mounted only by OrganizationAdminExtension.

    Yields:
        Litestar app under test and seeded organization identifiers.
    """
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'organization-admin-extension.sqlite'}")
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
                secret="jwt-organization-admin-extension-secret-123456789012345",
                subject_decoder=UUID,
                allow_inmemory_denylist=True,
            ),
        ),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", session_maker),
        user_model=User,
        user_manager_class=OrganizationAdminTestUserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
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
            include_switch_organization=True,
            tenant_resolver=HeaderTenantResolver(),
        ),
        include_users=False,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        extensions=(OrganizationAdminExtension(guards=[has_organization_role("owner")]),),
    )

    yield Litestar(plugins=[LitestarAuth(config)]), state
    await engine.dispose()


async def test_organization_admin_extension_mounts_functional_tenant_scoped_routes(
    client: tuple[AsyncTestClient[Litestar], _OrganizationAdminState],
) -> None:
    """Extension-contributed organization-admin routes enforce tenant and auth-owned behavior."""
    test_client, state = client
    global_headers = await _login_headers(
        test_client,
        email="global-admin@example.com",
        password="global-admin-password",
    )
    acme_headers = await _login_headers(test_client, email="acme-admin@example.com", password="acme-admin-password")
    beta_headers = await _login_headers(test_client, email="beta-admin@example.com", password="beta-admin-password")
    global_acme_headers = global_headers | {"X-Organization": "acme"}
    acme_tenant_headers = acme_headers | {"X-Organization": "acme"}
    beta_tenant_headers = beta_headers | {"X-Organization": "beta"}

    create_response = await test_client.post(
        ORGANIZATION_ROUTE_PREFIX,
        headers=global_acme_headers,
        json={"slug": " Support Team ", "name": "Support Team"},
    )
    list_response = await test_client.get(
        ORGANIZATION_ROUTE_PREFIX,
        headers=global_acme_headers,
        params={"user_id": str(state.acme_admin_id)},
    )
    catalog_denied_response = await test_client.get(
        ORGANIZATION_ROUTE_PREFIX,
        headers=acme_tenant_headers,
        params={"user_id": str(state.acme_admin_id)},
    )
    acme_response = await test_client.get(f"{ORGANIZATION_ROUTE_PREFIX}/{state.acme_id}", headers=acme_tenant_headers)
    path_denied_response = await test_client.get(
        f"{ORGANIZATION_ROUTE_PREFIX}/{state.acme_id}",
        headers=beta_tenant_headers,
    )
    missing_response = await test_client.get(f"{ORGANIZATION_ROUTE_PREFIX}/{uuid4()}", headers=global_acme_headers)

    assert create_response.status_code == HTTP_CREATED
    assert create_response.json()["slug"] == "support team"
    assert list_response.status_code == HTTP_OK
    assert list_response.json() == {
        "items": [{"id": str(state.acme_id), "slug": "acme", "name": "Acme"}],
        "total": 1,
        "limit": 50,
        "offset": 0,
    }
    assert catalog_denied_response.status_code == HTTP_FORBIDDEN
    assert acme_response.status_code == HTTP_OK
    assert acme_response.json() == {"id": str(state.acme_id), "slug": "acme", "name": "Acme"}
    assert path_denied_response.status_code == HTTP_FORBIDDEN
    assert missing_response.status_code == HTTP_NOT_FOUND
    assert missing_response.json() == {
        "detail": "Organization not found.",
        "code": ErrorCode.ORGANIZATION_NOT_FOUND,
    }


def test_organization_admin_extension_fails_closed_when_organizations_are_disabled() -> None:
    """Startup validation rejects organization-admin extension use when organizations are disabled."""
    backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](
                secret="jwt-disabled-organization-admin-extension-secret-123456789012345",
                subject_decoder=UUID,
                allow_inmemory_denylist=True,
            ),
        ),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", object()),
        user_model=User,
        user_manager_class=OrganizationAdminTestUserManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
        extensions=(OrganizationAdminExtension(),),
    )

    with pytest.raises(
        ConfigurationError,
        match=r"OrganizationAdminExtension requires organization_config\.enabled=True",
    ):
        Litestar(plugins=[LitestarAuth(config)])
