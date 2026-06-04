"""Unit tests for organization plugin behavior (switch-org, admin, invitations)."""

from __future__ import annotations

import asyncio
import importlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from litestar import Litestar, get
from litestar.config.app import AppConfig
from litestar.di import NamedDependency
from litestar.testing import AsyncTestClient

import litestar_auth._plugin.organization_admin._mutations as organization_mutations_module
import litestar_auth.contrib.organization_admin as organization_admin_contrib
import litestar_auth.plugin as plugin_module
from litestar_auth._plugin.organization_admin import SQLAlchemyOrganizationAdmin
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.db import OrganizationInvitationData
from litestar_auth.exceptions import (
    ConfigurationError,
    ErrorCode,
    InvalidOrganizationInvitationTokenError,
    OrganizationInvitationEmailMismatchError,
)
from litestar_auth.guards import is_superuser
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryUserDatabase,
    PluginUserManager,
)
from tests.unit.test_plugin_orchestrator import (
    HTTP_BAD_REQUEST,
    HTTP_CONFLICT,
    HTTP_CREATED,
    HTTP_FORBIDDEN,
    HTTP_NO_CONTENT,
    HTTP_NOT_FOUND,
    HTTP_OK,
    HTTP_TOO_MANY_REQUESTS,
    HTTP_UNPROCESSABLE_ENTITY,
    ORGANIZATION_INVITATION_SECRET,
    RESET_PASSWORD_SECRET,
    TOKEN_HASH_SECRET,
    VERIFICATION_SECRET,
    _minimal_config,
    _response_error_code,
)

LitestarAuth = plugin_module.LitestarAuth
LitestarAuthConfig = plugin_module.LitestarAuthConfig

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.middleware import DefineMiddleware

    from litestar_auth.db import MembershipData, OrganizationData

pytestmark = pytest.mark.unit

EXPECTED_ORGANIZATION_MEMBER_TOTAL = 2
ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH = 128


class AlwaysBlockedRateLimiter:
    """Rate-limiter backend that forces the route-level 429 path."""

    @property
    def is_shared_across_workers(self) -> bool:
        """Report shared-worker safety for startup validation."""
        return True

    async def check(self, key: str) -> bool:
        """Reject every request key.

        Returns:
            Always false.
        """
        return False

    async def increment(self, key: str) -> None:
        """Keep the forced-block backend stateless."""
        return

    async def reset(self, key: str) -> None:
        """Keep the forced-block backend stateless."""
        return

    async def retry_after(self, key: str) -> int:
        """Return a stable retry hint for response assertions.

        Returns:
            Retry-after seconds.
        """
        return 2


@dataclass(frozen=True, slots=True)
class SwitchOrganizationRow:
    """Organization row used by switch-organization route tests."""

    id: UUID
    slug: str
    name: str


@dataclass(frozen=True, slots=True)
class SwitchOrganizationMembership:
    """Membership row used by switch-organization route tests."""

    organization_id: UUID
    user_id: UUID
    roles: list[str]


@dataclass(slots=True)
class SwitchOrganizationInvitation:
    """Invitation row used by organization invitation route tests."""

    id: UUID
    organization_id: UUID
    invited_email: str
    roles: list[str]
    token_hash: bytes
    expires_at: datetime
    status: str = "pending"


def _has_any_role(roles: list[str], privileged_roles: frozenset[str]) -> bool:
    """Return whether ``roles`` contains any privileged role."""
    return bool(set(roles) & privileged_roles)


def _is_final_privileged_membership(
    target: SwitchOrganizationMembership,
    *,
    memberships: list[SwitchOrganizationMembership],
    privileged_roles: frozenset[str],
) -> bool:
    """Return whether ``target`` is the final privileged membership in its organization."""
    if not _has_any_role(target.roles, privileged_roles):
        return False
    return (
        sum(
            1
            for membership in memberships
            if membership.organization_id == target.organization_id
            and _has_any_role(membership.roles, privileged_roles)
        )
        <= 1
    )


class SwitchOrganizationStore:
    """In-memory organization store for switch-organization route tests."""

    def __init__(
        self,
        *,
        organizations: list[SwitchOrganizationRow],
        memberships: list[SwitchOrganizationMembership],
        invitations: list[SwitchOrganizationInvitation] | None = None,
    ) -> None:
        """Index configured rows by their lookup keys."""
        self.organizations_by_id = {organization.id: organization for organization in organizations}
        self.organizations_by_slug = {organization.slug: organization for organization in organizations}
        self.memberships = {(membership.organization_id, membership.user_id): membership for membership in memberships}
        self.invitations_by_id = {invitation.id: invitation for invitation in invitations or []}
        self.organization_slug_calls: list[str] = []
        self.membership_calls: list[tuple[UUID, UUID]] = []

    async def create_organization(self, data: OrganizationData) -> SwitchOrganizationRow:
        """Persist an organization row.

        Returns:
            The stored organization row.
        """
        organization = SwitchOrganizationRow(id=uuid4(), slug=data.slug, name=data.name)
        self.organizations_by_id[organization.id] = organization
        self.organizations_by_slug[organization.slug] = organization
        return organization

    async def get_organization(self, organization_id: UUID) -> SwitchOrganizationRow | None:
        """Return an organization by id."""
        await asyncio.sleep(0)
        return self.organizations_by_id.get(organization_id)

    async def get_organization_by_slug(self, slug: str) -> SwitchOrganizationRow | None:
        """Return an organization by normalized slug."""
        await asyncio.sleep(0)
        self.organization_slug_calls.append(slug)
        return self.organizations_by_slug.get(slug)

    async def update_organization(
        self,
        organization_id: UUID,
        data: OrganizationData,
    ) -> SwitchOrganizationRow | None:
        """Update an organization row when present.

        Returns:
            Updated organization when present, otherwise ``None``.
        """
        organization = self.organizations_by_id.get(organization_id)
        if organization is None:
            return None
        self.organizations_by_slug.pop(organization.slug, None)
        updated = SwitchOrganizationRow(id=organization_id, slug=data.slug, name=data.name)
        self.organizations_by_id[organization_id] = updated
        self.organizations_by_slug[updated.slug] = updated
        return updated

    async def delete_organization(self, organization_id: UUID) -> bool:
        """Delete one organization and its memberships.

        Returns:
            Whether an organization was removed.
        """
        organization = self.organizations_by_id.pop(organization_id, None)
        if organization is None:
            return False
        self.organizations_by_slug.pop(organization.slug, None)
        self.memberships = {
            key: membership
            for key, membership in self.memberships.items()
            if membership.organization_id != organization_id
        }
        return True

    async def add_membership(self, data: MembershipData[UUID]) -> SwitchOrganizationMembership:
        """Persist a membership row.

        Returns:
            The stored membership row.

        Raises:
            ValueError: If the organization is unknown or the membership already exists.
        """
        if data.organization_id not in self.organizations_by_id:
            msg = "Organization not found."
            raise ValueError(msg)
        if (data.organization_id, data.user_id) in self.memberships:
            msg = "Organization membership already exists."
            raise ValueError(msg)
        membership = SwitchOrganizationMembership(
            organization_id=data.organization_id,
            user_id=data.user_id,
            roles=data.roles,
        )
        self.memberships[membership.organization_id, membership.user_id] = membership
        return membership

    async def get_membership(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> SwitchOrganizationMembership | None:
        """Return membership for the exact organization/user pair."""
        await asyncio.sleep(0)
        self.membership_calls.append((organization_id, user_id))
        return self.memberships.get((organization_id, user_id))

    async def list_memberships(
        self,
        organization_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[SwitchOrganizationMembership], int]:
        """Return memberships for one organization."""
        memberships = [
            membership for membership in self.memberships.values() if membership.organization_id == organization_id
        ]
        return memberships[offset : offset + limit], len(memberships)

    async def remove_membership(self, *, organization_id: UUID, user_id: UUID) -> bool:
        """Remove one membership.

        Returns:
            Whether a membership was removed.
        """
        return self.memberships.pop((organization_id, user_id), None) is not None

    async def remove_membership_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        privileged_roles: frozenset[str],
    ) -> bool:
        """Remove one membership while preserving privileged administration.

        Returns:
            Whether a membership was removed.

        Raises:
            ValueError: If removing the membership would remove the final privileged member.
        """
        membership = self.memberships.get((organization_id, user_id))
        if membership is not None and _is_final_privileged_membership(
            membership,
            memberships=list(self.memberships.values()),
            privileged_roles=privileged_roles,
        ):
            msg = "Cannot remove final privileged member."
            raise ValueError(msg)
        return await self.remove_membership(organization_id=organization_id, user_id=user_id)

    async def set_membership_roles(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
    ) -> SwitchOrganizationMembership | None:
        """Replace roles on an existing membership.

        Returns:
            Updated membership when present, otherwise ``None``.
        """
        if (organization_id, user_id) not in self.memberships:
            return None
        membership = SwitchOrganizationMembership(organization_id=organization_id, user_id=user_id, roles=roles)
        self.memberships[organization_id, user_id] = membership
        return membership

    async def set_membership_roles_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
        privileged_roles: frozenset[str],
    ) -> SwitchOrganizationMembership | None:
        """Replace roles on an existing membership while preserving privileged administration.

        Returns:
            Updated membership when present, otherwise ``None``.

        Raises:
            ValueError: If replacing roles would demote the final privileged member.
        """
        membership = self.memberships.get((organization_id, user_id))
        if (
            membership is not None
            and _has_any_role(membership.roles, privileged_roles)
            and not _has_any_role(roles, privileged_roles)
            and _is_final_privileged_membership(
                membership,
                memberships=list(self.memberships.values()),
                privileged_roles=privileged_roles,
            )
        ):
            msg = "Cannot demote final privileged member."
            raise ValueError(msg)
        return await self.set_membership_roles(organization_id=organization_id, user_id=user_id, roles=roles)

    async def list_organizations_for_user(
        self,
        user_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[SwitchOrganizationRow], int]:
        """Return organizations where the user has a membership."""
        organization_ids = {
            membership.organization_id for membership in self.memberships.values() if membership.user_id == user_id
        }
        organizations = [
            organization
            for organization_id, organization in self.organizations_by_id.items()
            if organization_id in organization_ids
        ]
        return organizations[offset : offset + limit], len(organizations)

    async def create_invitation(self, data: OrganizationInvitationData[UUID]) -> SwitchOrganizationInvitation:
        """Persist an invitation row.

        Returns:
            The stored invitation row.
        """
        invitation = SwitchOrganizationInvitation(
            id=uuid4(),
            organization_id=data.organization_id,
            invited_email=data.invited_email,
            roles=list(data.roles),
            token_hash=data.token_hash,
            expires_at=data.expires_at,
        )
        self.invitations_by_id[invitation.id] = invitation
        return invitation

    async def get_invitation_by_token_hash(self, token_hash: bytes) -> SwitchOrganizationInvitation | None:
        """Return an invitation by token hash.

        Returns:
            Matching invitation when present.
        """
        for invitation in self.invitations_by_id.values():
            if invitation.token_hash == token_hash:
                return invitation
        return None

    async def get_invitation(self, invitation_id: UUID) -> SwitchOrganizationInvitation | None:
        """Return an invitation by id.

        Returns:
            Matching invitation when present.
        """
        return self.invitations_by_id.get(invitation_id)

    async def list_pending_invitations(
        self,
        organization_id: UUID,
        *,
        now: datetime,
        offset: int,
        limit: int,
    ) -> tuple[list[SwitchOrganizationInvitation], int]:
        """Return pending invitations for one organization.

        Returns:
            Matching pending invitations.
        """
        invitations = [
            invitation
            for invitation in self.invitations_by_id.values()
            if invitation.organization_id == organization_id
            and invitation.status == "pending"
            and invitation.expires_at > now
        ]
        return invitations[offset : offset + limit], len(invitations)

    async def revoke_invitation(self, invitation_id: UUID) -> SwitchOrganizationInvitation | None:
        """Mark a pending invitation as revoked.

        Returns:
            Updated invitation when pending.
        """
        invitation = self.invitations_by_id.get(invitation_id)
        if invitation is None or invitation.status != "pending":
            return None
        invitation.status = "revoked"
        return invitation

    async def consume_invitation(
        self,
        invitation_id: UUID,
        *,
        consumed_at: datetime,
    ) -> SwitchOrganizationInvitation | None:
        """Mark a pending, unexpired invitation as consumed.

        Returns:
            Updated invitation when pending and unexpired.
        """
        invitation = self.invitations_by_id.get(invitation_id)
        if invitation is None or invitation.status != "pending" or invitation.expires_at <= consumed_at:
            return None
        invitation.status = "consumed"
        return invitation


_CurrentOrganizationDep = NamedDependency[object | None]


@get("/current-organization", sync_to_thread=False)
def current_organization_probe(litestar_auth_current_organization: _CurrentOrganizationDep) -> dict[str, str | None]:
    """Expose the middleware-published current organization slug.

    Returns:
        Current organization slug, if middleware published one.
    """
    organization_context = litestar_auth_current_organization
    organization = getattr(organization_context, "organization", None)
    return {"slug": getattr(organization, "slug", None)}


def _switch_organization_app(  # noqa: PLR0913
    *,
    user: ExampleUser,
    strategy: JWTStrategy[ExampleUser, UUID],
    organization_store: SwitchOrganizationStore,
    include_switch_organization: bool,
    include_organization_admin: bool = False,
    include_organization_invitations: bool = False,
    rate_limit_config: AuthRateLimitConfig | None = None,
    user_manager_class: type[PluginUserManager] = PluginUserManager,
) -> Litestar:
    """Build a plugin app configured for switch-organization route tests.

    Returns:
        Litestar app with the auth plugin and current-organization probe route.
    """
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="jwt",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=user_manager_class,
        user_db_factory=lambda _session: InMemoryUserDatabase([user]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            organization_invitation_token_secret=ORGANIZATION_INVITATION_SECRET,
            id_parser=UUID,
        ),
        rate_limit_config=rate_limit_config,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        organization_config=plugin_module.OrganizationConfig(
            enabled=True,
            store_factory=cast("Any", lambda _session: organization_store),
            include_switch_organization=include_switch_organization,
            include_organization_admin=include_organization_admin,
            include_organization_invitations=include_organization_invitations,
        ),
    )
    return Litestar(route_handlers=[current_organization_probe], plugins=[LitestarAuth(config)])


class OrganizationInvitationCaptureManager(PluginUserManager):
    """Test manager that records raw organization invitation hook tokens."""

    invitation_events: ClassVar[list[tuple[object, str]]] = []

    async def on_after_organization_invitation(self, invitation: object, token: str) -> None:
        """Record the raw token supplied only through the delivery hook."""
        self.invitation_events.append((invitation, token))


def _organization_invitation_manager(user: ExampleUser) -> PluginUserManager:
    """Build a manager configured to issue organization-invitation tokens.

    Returns:
        User manager using the same organization-invitation secret as the test app.
    """
    return PluginUserManager(
        InMemoryUserDatabase([user]),
        security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            organization_invitation_token_secret=ORGANIZATION_INVITATION_SECRET,
            id_parser=UUID,
        ),
    )


async def _create_organization_invitation(  # noqa: PLR0913
    *,
    store: SwitchOrganizationStore,
    manager: PluginUserManager,
    organization_id: UUID,
    invited_email: str,
    roles: list[str],
    expires_at: datetime | None = None,
) -> tuple[SwitchOrganizationInvitation, str]:
    """Create a token-bound invitation row for route tests.

    Returns:
        Stored invitation row and raw signed token.
    """
    issued = manager.tokens.write_organization_invitation_token()
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization_id,
            invited_email=invited_email,
            roles=roles,
            token_hash=issued.token_hash,
            expires_at=expires_at or issued.expires_at,
        ),
    )
    return invitation, issued.token


async def test_switch_organization_issues_member_org_bound_token_and_publishes_context() -> None:
    """Authenticated members can activate an organization through a signed JWT claim."""
    user = ExampleUser(id=uuid4(), email="member@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(
        organizations=[organization],
        memberships=[
            SwitchOrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                roles=["owner"],
            ),
        ],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=True,
    )
    initial_token = await strategy.write_token(user)

    async with AsyncTestClient(app) as client:
        switch_response = await client.post(
            "/auth/switch-organization",
            json={"organization_slug": " Acme "},
            headers={"Authorization": f"Bearer {initial_token}"},
        )
        assert store.organization_slug_calls == ["acme"]
        assert store.membership_calls == [(organization.id, user.id)]

        access_token = switch_response.json()["access_token"]
        probe_response = await client.get(
            "/current-organization",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    assert switch_response.status_code == HTTP_OK
    assert probe_response.status_code == HTTP_OK
    assert probe_response.json() == {"slug": "acme"}


async def test_switch_organization_denies_nonmember_unknown_and_malformed_slugs_uniformly() -> None:
    """Membership failures collapse to the same fail-closed response."""
    user = ExampleUser(id=uuid4(), email="member@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=True,
    )
    initial_token = await strategy.write_token(user)

    async with AsyncTestClient(app) as client:
        nonmember_response = await client.post(
            "/auth/switch-organization",
            json={"organization_slug": "acme"},
            headers={"Authorization": f"Bearer {initial_token}"},
        )
        unknown_response = await client.post(
            "/auth/switch-organization",
            json={"organization_slug": "missing"},
            headers={"Authorization": f"Bearer {initial_token}"},
        )
        malformed_response = await client.post(
            "/auth/switch-organization",
            json={"organization_slug": "   "},
            headers={"Authorization": f"Bearer {initial_token}"},
        )

    assert nonmember_response.status_code == HTTP_FORBIDDEN
    assert unknown_response.status_code == HTTP_FORBIDDEN
    assert malformed_response.status_code == HTTP_FORBIDDEN
    assert nonmember_response.json() == unknown_response.json() == malformed_response.json()
    assert nonmember_response.json()["extra"]["code"] == "ORGANIZATION_SWITCH_DENIED"
    assert store.organization_slug_calls == ["acme", "missing"]
    assert store.membership_calls == [(organization.id, user.id)]


async def test_switch_organization_uses_configured_rate_limit_slot() -> None:
    """Configured switch-organization rate limits reject before organization lookup."""
    user = ExampleUser(id=uuid4(), email="member@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(
        organizations=[organization],
        memberships=[
            SwitchOrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                roles=["owner"],
            ),
        ],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=True,
        rate_limit_config=AuthRateLimitConfig(
            organization_switch=EndpointRateLimit(
                backend=AlwaysBlockedRateLimiter(),
                scope="ip",
                namespace="organization-switch",
            ),
        ),
    )
    initial_token = await strategy.write_token(user)

    async with AsyncTestClient(app) as client:
        response = await client.post(
            "/auth/switch-organization",
            json={"organization_slug": "acme"},
            headers={"Authorization": f"Bearer {initial_token}"},
        )

    assert response.status_code == HTTP_TOO_MANY_REQUESTS
    assert response.headers["Retry-After"] == "2"
    assert response.json()["detail"] == "Too many requests."
    assert store.organization_slug_calls == []
    assert store.membership_calls == []


async def test_switch_organization_route_is_absent_without_route_flag() -> None:
    """The switch-organization route is opt-in even when organization lookup is enabled."""
    user = ExampleUser(id=uuid4(), email="member@example.com", is_verified=True)
    store = SwitchOrganizationStore(organizations=[], memberships=[])
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
    )

    async with AsyncTestClient(app) as client:
        response = await client.post("/auth/switch-organization", json={"organization_slug": "acme"})

    assert response.status_code == HTTP_NOT_FOUND


async def test_switch_organization_route_is_absent_for_non_organization_token_backends() -> None:
    """The switch route is not registered for backends that cannot sign organization claims."""
    organization_config = plugin_module.OrganizationConfig(
        enabled=True,
        store_factory=cast("Any", lambda _session: SwitchOrganizationStore(organizations=[], memberships=[])),
        include_switch_organization=True,
    )
    app = Litestar(route_handlers=[], plugins=[LitestarAuth(_minimal_config(organization_config=organization_config))])

    async with AsyncTestClient(app) as client:
        response = await client.post("/auth/switch-organization", json={"organization_slug": "acme"})

    assert response.status_code == HTTP_NOT_FOUND


async def test_organization_admin_routes_are_absent_without_route_flag() -> None:
    """Organization admin routes are not mounted by the organization feature alone."""
    user = ExampleUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    store = SwitchOrganizationStore(organizations=[], memberships=[])
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
    )
    token = await strategy.write_token(user)

    async with AsyncTestClient(app) as client:
        response = await client.get("/organizations", headers={"Authorization": f"Bearer {token}"})
        invitation_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": "not-a-token"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == HTTP_NOT_FOUND
    assert invitation_response.status_code == HTTP_NOT_FOUND


async def test_organization_invitation_accept_creates_membership_and_consumes_token_once() -> None:
    """Invited authenticated users can accept exactly one pending invitation."""
    invited_user = ExampleUser(id=uuid4(), email="Invited.User@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    manager = _organization_invitation_manager(invited_user)
    invitation, invitation_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email="invited.user@example.com",
        roles=["admin", "member"],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=invited_user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_invitations=True,
    )
    auth_token = await strategy.write_token(invited_user)
    headers = {"Authorization": f"Bearer {auth_token}"}

    async with AsyncTestClient(app) as client:
        accept_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": invitation_token},
            headers=headers,
        )
        reuse_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": invitation_token},
            headers=headers,
        )

    assert accept_response.status_code == HTTP_OK
    assert accept_response.json()["organization_id"] == str(organization.id)
    assert accept_response.json()["user_id"] == str(invited_user.id)
    assert accept_response.json()["roles"] == ["admin", "member"]
    assert invitation.status == "consumed"
    assert len(store.memberships) == 1
    assert reuse_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(reuse_response.json()) == "ORGANIZATION_INVITATION_INVALID"
    assert len(store.memberships) == 1


@pytest.mark.parametrize(
    ("route_path", "account_state"),
    [
        pytest.param(
            "/auth/organization-invitations/accept",
            "inactive",
            id="accept-inactive",
        ),
        pytest.param(
            "/auth/organization-invitations/accept",
            "unverified",
            id="accept-unverified",
        ),
        pytest.param(
            "/auth/organization-invitations/decline",
            "inactive",
            id="decline-inactive",
        ),
        pytest.param(
            "/auth/organization-invitations/decline",
            "unverified",
            id="decline-unverified",
        ),
    ],
)
async def test_organization_invitation_routes_require_active_verified_invitees(
    route_path: str,
    account_state: Literal["inactive", "unverified"],
) -> None:
    """Invitee route guards deny account-state failures before mutating invitation rows."""
    user = ExampleUser(
        id=uuid4(),
        email="invited@example.com",
        is_active=account_state != "inactive",
        is_verified=account_state != "unverified",
    )
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    manager = _organization_invitation_manager(user)
    invitation, invitation_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email=user.email,
        roles=["member"],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_invitations=True,
    )
    auth_token = await strategy.write_token(user)

    async with AsyncTestClient(app) as client:
        response = await client.post(
            route_path,
            json={"token": invitation_token},
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    assert response.status_code == HTTP_FORBIDDEN
    assert invitation.status == "pending"
    assert store.memberships == {}


async def test_organization_invitation_accept_denies_mismatched_authenticated_email_and_is_rate_limited() -> None:
    """A valid invitation token is insufficient without authenticated email ownership."""
    user = ExampleUser(id=uuid4(), email="attacker@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    manager = _organization_invitation_manager(user)
    invitation, invitation_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email="invited@example.com",
        roles=["member"],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    rate_limit_config = AuthRateLimitConfig(
        organization_invitation_accept=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=1, window_seconds=60),
            scope="ip",
            namespace="organization-invitation-accept",
        ),
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_invitations=True,
        rate_limit_config=rate_limit_config,
    )
    auth_token = await strategy.write_token(user)
    headers = {"Authorization": f"Bearer {auth_token}"}

    async with AsyncTestClient(app) as client:
        mismatch_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": invitation_token},
            headers=headers,
        )
        limited_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": invitation_token},
            headers=headers,
        )

    assert mismatch_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(mismatch_response.json()) == "ORGANIZATION_INVITATION_EMAIL_MISMATCH"
    assert limited_response.status_code == HTTP_TOO_MANY_REQUESTS
    assert invitation.status == "pending"
    assert store.memberships == {}


async def test_organization_invitation_accept_denies_revoked_and_expired_tokens() -> None:
    """Invitation accept fails closed for revoked and expired invitation rows."""
    user = ExampleUser(id=uuid4(), email="invited@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    manager = _organization_invitation_manager(user)
    revoked_invitation, revoked_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email=user.email,
        roles=["member"],
    )
    await store.revoke_invitation(revoked_invitation.id)
    expired_invitation, expired_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email=user.email,
        roles=["member"],
        expires_at=datetime.now(tz=UTC) - timedelta(seconds=1),
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_invitations=True,
    )
    auth_token = await strategy.write_token(user)
    headers = {"Authorization": f"Bearer {auth_token}"}

    async with AsyncTestClient(app) as client:
        revoked_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": revoked_token},
            headers=headers,
        )
        expired_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": expired_token},
            headers=headers,
        )

    assert revoked_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(revoked_response.json()) == "ORGANIZATION_INVITATION_INVALID"
    assert expired_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(expired_response.json()) == "ORGANIZATION_INVITATION_EXPIRED"
    assert expired_invitation.status == "pending"
    assert store.memberships == {}


async def test_organization_invitation_decline_revokes_without_membership_creation() -> None:
    """Declining a valid invitation revokes it without adding the user as a member."""
    user = ExampleUser(id=uuid4(), email="invited@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    manager = _organization_invitation_manager(user)
    invitation, invitation_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email=user.email,
        roles=["member"],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_invitations=True,
    )
    auth_token = await strategy.write_token(user)
    headers = {"Authorization": f"Bearer {auth_token}"}

    async with AsyncTestClient(app) as client:
        decline_response = await client.post(
            "/auth/organization-invitations/decline",
            json={"token": invitation_token},
            headers=headers,
        )
        decline_again_response = await client.post(
            "/auth/organization-invitations/decline",
            json={"token": invitation_token},
            headers=headers,
        )
        accept_after_decline_response = await client.post(
            "/auth/organization-invitations/accept",
            json={"token": invitation_token},
            headers=headers,
        )

    assert decline_response.status_code == HTTP_NO_CONTENT
    assert invitation.status == "revoked"
    assert store.memberships == {}
    assert decline_again_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(decline_again_response.json()) == "ORGANIZATION_INVITATION_INVALID"
    assert accept_after_decline_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(accept_after_decline_response.json()) == "ORGANIZATION_INVITATION_INVALID"


async def test_organization_invitation_operations_fail_closed_for_transition_and_email_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invitation operations collapse race and malformed-user edges to stable denial."""
    user = ExampleUser(id=uuid4(), email="invited@example.com", is_verified=True)
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    manager = _organization_invitation_manager(user)
    admin = SQLAlchemyOrganizationAdmin(store=store)
    _invitation, invitation_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email=user.email,
        roles=["member"],
    )

    async def consume_missing(
        _invitation_id: UUID,
        *,
        consumed_at: datetime,
    ) -> SwitchOrganizationInvitation | None:
        await asyncio.sleep(0)
        return None

    monkeypatch.setattr(store, "consume_invitation", consume_missing)
    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.accept_invitation(token=invitation_token, user=user, user_manager=manager)

    monkeypatch.setattr(store, "consume_invitation", SwitchOrganizationStore.consume_invitation.__get__(store))

    async def add_membership_fails(_data: object) -> SwitchOrganizationMembership:
        await asyncio.sleep(0)
        msg = "Organization membership already exists."
        raise ValueError(msg)

    monkeypatch.setattr(store, "add_membership", add_membership_fails)
    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.accept_invitation(token=invitation_token, user=user, user_manager=manager)

    decline_invitation, decline_token = await _create_organization_invitation(
        store=store,
        manager=manager,
        organization_id=organization.id,
        invited_email=user.email,
        roles=["member"],
    )

    async def revoke_missing(_invitation_id: UUID) -> SwitchOrganizationInvitation | None:
        await asyncio.sleep(0)
        return None

    monkeypatch.setattr(store, "revoke_invitation", revoke_missing)
    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.decline_invitation(token=decline_token, user=user, user_manager=manager)

    with pytest.raises(OrganizationInvitationEmailMismatchError):
        organization_mutations_module._require_matching_invitee(object(), decline_invitation)
    malformed_user = ExampleUser(id=uuid4(), email="not-an-email", is_verified=True)
    with pytest.raises(OrganizationInvitationEmailMismatchError):
        organization_mutations_module._require_matching_invitee(malformed_user, decline_invitation)


async def test_organization_admin_crud_and_membership_routes_use_store_operations() -> None:
    """Superusers can administer organizations and memberships through the opt-in controller."""
    admin = ExampleUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    member_id = uuid4()
    store = SwitchOrganizationStore(organizations=[], memberships=[])
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=admin,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_admin=True,
    )
    token = await strategy.write_token(admin)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncTestClient(app) as client:
        create_response = await client.post("/organizations", json={"slug": " Acme ", "name": "Acme"}, headers=headers)
        organization_id = create_response.json()["id"]
        get_response = await client.get(f"/organizations/{organization_id}", headers=headers)
        add_member_response = await client.post(
            f"/organizations/{organization_id}/members/{member_id}",
            json={"roles": [" Owner "]},
            headers=headers,
        )
        add_admin_member_response = await client.post(
            f"/organizations/{organization_id}/members/{admin.id}",
            json={"roles": ["owner"]},
            headers=headers,
        )
        list_members_response = await client.get(f"/organizations/{organization_id}/members", headers=headers)
        list_members_page_response = await client.get(
            f"/organizations/{organization_id}/members?limit=1&offset=1",
            headers=headers,
        )
        list_members_beyond_response = await client.get(
            f"/organizations/{organization_id}/members?limit=100&offset=100",
            headers=headers,
        )
        list_user_organizations_response = await client.get(f"/organizations?user_id={member_id}", headers=headers)
        list_user_organizations_beyond_response = await client.get(
            f"/organizations?user_id={member_id}&limit=100&offset=100",
            headers=headers,
        )
        set_roles_response = await client.patch(
            f"/organizations/{organization_id}/members/{member_id}/roles",
            json={"roles": ["admin"]},
            headers=headers,
        )
        remove_member_response = await client.delete(
            f"/organizations/{organization_id}/members/{member_id}",
            headers=headers,
        )
        update_response = await client.patch(
            f"/organizations/{organization_id}",
            json={"slug": "Acme Labs", "name": "Acme Labs"},
            headers=headers,
        )
        delete_response = await client.delete(f"/organizations/{organization_id}", headers=headers)

    assert create_response.status_code == HTTP_CREATED
    assert create_response.json()["slug"] == "acme"
    assert get_response.json()["name"] == "Acme"
    assert add_member_response.status_code == HTTP_CREATED
    assert add_member_response.json()["roles"] == ["owner"]
    assert add_admin_member_response.status_code == HTTP_CREATED
    assert list_members_response.json()["total"] == EXPECTED_ORGANIZATION_MEMBER_TOTAL
    assert len(list_members_page_response.json()["items"]) == 1
    assert list_members_page_response.json()["total"] == EXPECTED_ORGANIZATION_MEMBER_TOTAL
    assert list_members_beyond_response.json()["items"] == []
    assert list_members_beyond_response.json()["total"] == EXPECTED_ORGANIZATION_MEMBER_TOTAL
    assert list_user_organizations_response.json()["items"][0]["slug"] == "acme"
    assert list_user_organizations_beyond_response.json()["items"] == []
    assert list_user_organizations_beyond_response.json()["total"] == 1
    assert set_roles_response.json()["roles"] == ["admin"]
    assert remove_member_response.status_code == HTTP_NO_CONTENT
    assert update_response.json()["slug"] == "acme labs"
    assert delete_response.status_code == HTTP_NO_CONTENT


async def test_organization_admin_create_update_payload_bounds_and_strict_fields() -> None:
    """Organization admin create/update payloads reject oversized or undeclared fields."""
    admin = ExampleUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    store = SwitchOrganizationStore(organizations=[], memberships=[])
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=admin,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_admin=True,
    )
    token = await strategy.write_token(admin)
    headers = {"Authorization": f"Bearer {token}"}
    slug_at_limit = "s" * ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH
    name_at_limit = "N" * ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH
    slug_too_long = "s" * (ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH + 1)
    name_too_long = "N" * (ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH + 1)

    async with AsyncTestClient(app) as client:
        create_response = await client.post(
            "/organizations",
            json={"slug": slug_at_limit, "name": name_at_limit},
            headers=headers,
        )
        organization_id = create_response.json()["id"]
        update_response = await client.patch(
            f"/organizations/{organization_id}",
            json={
                "slug": "t" * ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH,
                "name": "T" * ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH,
            },
            headers=headers,
        )
        invalid_responses = [
            await client.post("/organizations", json={"slug": slug_at_limit, "name": name_too_long}, headers=headers),
            await client.post("/organizations", json={"slug": slug_too_long, "name": name_at_limit}, headers=headers),
            await client.post(
                "/organizations",
                json={"slug": "extra", "name": "Extra", "unexpected": True},
                headers=headers,
            ),
            await client.patch(
                f"/organizations/{organization_id}",
                json={"slug": slug_at_limit, "name": name_too_long},
                headers=headers,
            ),
            await client.patch(
                f"/organizations/{organization_id}",
                json={"slug": slug_too_long, "name": name_at_limit},
                headers=headers,
            ),
            await client.patch(
                f"/organizations/{organization_id}",
                json={"slug": "extra-update", "name": "Extra Update", "unexpected": True},
                headers=headers,
            ),
        ]

    assert create_response.status_code == HTTP_CREATED
    assert create_response.json()["slug"] == slug_at_limit
    assert create_response.json()["name"] == name_at_limit
    assert update_response.status_code == HTTP_OK
    assert update_response.json()["slug"] == "t" * ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH
    assert update_response.json()["name"] == "T" * ORGANIZATION_ADMIN_TEXT_FIELD_MAX_LENGTH
    for response in invalid_responses:
        assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
        assert _response_error_code(response.json()) == ErrorCode.REQUEST_BODY_INVALID


async def test_organization_admin_invitation_routes_use_operations_without_echoing_token() -> None:
    """Superusers can invite, list, and revoke through the opt-in admin controller."""
    admin = ExampleUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    store = SwitchOrganizationStore(organizations=[organization], memberships=[])
    OrganizationInvitationCaptureManager.invitation_events = []
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=admin,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_admin=True,
        user_manager_class=OrganizationInvitationCaptureManager,
    )
    token = await strategy.write_token(admin)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncTestClient(app) as client:
        invite_response = await client.post(
            f"/organizations/{organization.id}/invitations",
            json={"invited_email": " Invited.User@example.com ", "roles": [" Owner "]},
            headers=headers,
        )
        list_response = await client.get(f"/organizations/{organization.id}/invitations", headers=headers)
        list_beyond_response = await client.get(
            f"/organizations/{organization.id}/invitations?limit=100&offset=100",
            headers=headers,
        )
        invitation_id = invite_response.json()["id"]
        revoke_response = await client.delete(f"/organizations/invitations/{invitation_id}", headers=headers)
        list_after_revoke_response = await client.get(f"/organizations/{organization.id}/invitations", headers=headers)

    assert invite_response.status_code == HTTP_CREATED
    assert invite_response.json()["invited_email"] == "invited.user@example.com"
    assert invite_response.json()["roles"] == ["owner"]
    assert invite_response.json()["status"] == "pending"
    assert "token" not in invite_response.json()
    assert list_response.json()["total"] == 1
    assert list_beyond_response.json()["items"] == []
    assert list_beyond_response.json()["total"] == 1
    assert "token" not in list_response.text
    assert revoke_response.status_code == HTTP_NO_CONTENT
    assert list_after_revoke_response.json()["total"] == 0
    assert len(OrganizationInvitationCaptureManager.invitation_events) == 1
    captured_invitation, captured_token = OrganizationInvitationCaptureManager.invitation_events[0]
    assert captured_invitation is next(iter(store.invitations_by_id.values()))
    assert captured_token
    assert captured_token not in invite_response.text
    assert captured_token not in list_response.text


async def test_organization_admin_denies_non_superuser_by_default() -> None:
    """The bundled controller default guard is fail-closed."""
    user = ExampleUser(id=uuid4(), email="user@example.com", is_verified=True)
    store = SwitchOrganizationStore(organizations=[], memberships=[])
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=user,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_admin=True,
    )
    token = await strategy.write_token(user)

    async with AsyncTestClient(app) as client:
        response = await client.post(
            "/organizations",
            json={"slug": "acme", "name": "Acme"},
            headers={"Authorization": f"Bearer {token}"},
        )
        invite_response = await client.post(
            f"/organizations/{uuid4()}/invitations",
            json={"invited_email": "invited@example.com", "roles": ["member"]},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == HTTP_FORBIDDEN
    assert invite_response.status_code == HTTP_FORBIDDEN


async def test_organization_admin_failures_are_non_enumerating_and_stable() -> None:
    """Unknown organizations and duplicate memberships return stable org-admin codes."""
    admin = ExampleUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    member_id = uuid4()
    store = SwitchOrganizationStore(
        organizations=[organization],
        memberships=[SwitchOrganizationMembership(organization_id=organization.id, user_id=member_id, roles=["owner"])],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=admin,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_admin=True,
    )
    token = await strategy.write_token(admin)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncTestClient(app) as client:
        unknown_response = await client.get(f"/organizations/{uuid4()}", headers=headers)
        duplicate_member_response = await client.post(
            f"/organizations/{organization.id}/members/{member_id}",
            json={"roles": ["owner"]},
            headers=headers,
        )
        last_privileged_response = await client.patch(
            f"/organizations/{organization.id}/members/{member_id}/roles",
            json={"roles": ["member"]},
            headers=headers,
        )

    assert unknown_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(unknown_response.json()) == "ORGANIZATION_NOT_FOUND"
    assert duplicate_member_response.status_code == HTTP_CONFLICT
    assert _response_error_code(duplicate_member_response.json()) == "ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS"
    assert last_privileged_response.status_code == HTTP_CONFLICT
    assert _response_error_code(last_privileged_response.json()) == "ORGANIZATION_LAST_PRIVILEGED_MEMBER"


async def test_organization_admin_validation_and_lookup_error_branches() -> None:
    """Organization admin maps invalid IDs and operation failures to stable responses."""
    admin = ExampleUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    organization = SwitchOrganizationRow(id=uuid4(), slug="acme", name="Acme")
    slug_owner = SwitchOrganizationRow(id=uuid4(), slug="taken", name="Taken")
    member_id = uuid4()
    store = SwitchOrganizationStore(
        organizations=[organization, slug_owner],
        memberships=[
            SwitchOrganizationMembership(organization_id=organization.id, user_id=member_id, roles=["owner"]),
            SwitchOrganizationMembership(organization_id=organization.id, user_id=admin.id, roles=["owner"]),
        ],
    )
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=TOKEN_HASH_SECRET,
        algorithm="HS256",
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    app = _switch_organization_app(
        user=admin,
        strategy=strategy,
        organization_store=store,
        include_switch_organization=False,
        include_organization_admin=True,
    )
    token = await strategy.write_token(admin)
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncTestClient(app) as client:
        invalid_organization_id_response = await client.get("/organizations/not-a-uuid", headers=headers)
        invalid_user_id_response = await client.get("/organizations?user_id=not-a-uuid", headers=headers)
        duplicate_organization_response = await client.post(
            "/organizations",
            json={"slug": "acme", "name": "Duplicate"},
            headers=headers,
        )
        update_slug_conflict_response = await client.patch(
            f"/organizations/{organization.id}",
            json={"slug": "taken", "name": "Conflict"},
            headers=headers,
        )
        delete_unknown_response = await client.delete(f"/organizations/{uuid4()}", headers=headers)
        add_member_unknown_organization_response = await client.post(
            f"/organizations/{uuid4()}/members/{uuid4()}",
            json={"roles": ["member"]},
            headers=headers,
        )
        list_unknown_members_response = await client.get(f"/organizations/{uuid4()}/members", headers=headers)
        remove_unknown_member_response = await client.delete(
            f"/organizations/{organization.id}/members/{uuid4()}",
            headers=headers,
        )
        invalid_invitation_id_response = await client.delete("/organizations/invitations/not-a-uuid", headers=headers)
        invite_unknown_organization_response = await client.post(
            f"/organizations/{uuid4()}/invitations",
            json={"invited_email": "invited@example.com", "roles": ["member"]},
            headers=headers,
        )
        list_unknown_invitations_response = await client.get(f"/organizations/{uuid4()}/invitations", headers=headers)
        revoke_unknown_invitation_response = await client.delete(
            f"/organizations/invitations/{uuid4()}",
            headers=headers,
        )

    assert invalid_organization_id_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(invalid_organization_id_response.json()) == "ORGANIZATION_NOT_FOUND"
    assert invalid_user_id_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(invalid_user_id_response.json()) == "ORGANIZATION_MEMBERSHIP_NOT_FOUND"
    assert duplicate_organization_response.status_code == HTTP_CONFLICT
    assert _response_error_code(duplicate_organization_response.json()) == "ORGANIZATION_ALREADY_EXISTS"
    assert update_slug_conflict_response.status_code == HTTP_CONFLICT
    assert _response_error_code(update_slug_conflict_response.json()) == "ORGANIZATION_ALREADY_EXISTS"
    assert delete_unknown_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(delete_unknown_response.json()) == "ORGANIZATION_NOT_FOUND"
    assert add_member_unknown_organization_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(add_member_unknown_organization_response.json()) == "ORGANIZATION_NOT_FOUND"
    assert list_unknown_members_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(list_unknown_members_response.json()) == "ORGANIZATION_NOT_FOUND"
    assert remove_unknown_member_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(remove_unknown_member_response.json()) == "ORGANIZATION_MEMBERSHIP_NOT_FOUND"
    assert invalid_invitation_id_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(invalid_invitation_id_response.json()) == "ORGANIZATION_INVITATION_INVALID"
    assert invite_unknown_organization_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(invite_unknown_organization_response.json()) == "ORGANIZATION_NOT_FOUND"
    assert list_unknown_invitations_response.status_code == HTTP_NOT_FOUND
    assert _response_error_code(list_unknown_invitations_response.json()) == "ORGANIZATION_NOT_FOUND"
    assert revoke_unknown_invitation_response.status_code == HTTP_BAD_REQUEST
    assert _response_error_code(revoke_unknown_invitation_response.json()) == "ORGANIZATION_INVITATION_INVALID"


def test_organization_admin_factory_validation_and_lazy_exports() -> None:
    """Factory validation keeps the opt-in controller configuration explicit."""
    controller_factory = organization_admin_contrib.create_organization_admin_controller
    config_type = organization_admin_contrib.OrganizationAdminControllerConfig
    invitation_controller_factory = organization_admin_contrib.create_organization_invitation_controller
    invitation_config_type = organization_admin_contrib.OrganizationInvitationControllerConfig

    def custom_admin_guard(
        _connection: ASGIConnection[Any, Any, Any, Any],
        _route_handler: BaseRouteHandler,
    ) -> None:
        return None

    default_guarded_controller = controller_factory(id_parser=UUID)
    custom_guarded_controller = controller_factory(id_parser=UUID, guards=[custom_admin_guard])
    controller = controller_factory(id_parser=UUID, route_prefix="/tenant-admin/")
    invitation_controller = invitation_controller_factory()
    custom_invitation_controller = invitation_controller_factory(
        invitation_config_type(
            path="/tenant-invitations",
            rate_limit_config=AuthRateLimitConfig(
                organization_invitation_accept=EndpointRateLimit(
                    backend=InMemoryRateLimiter(max_attempts=1, window_seconds=60),
                    scope="ip",
                    namespace="custom-organization-invitation-accept",
                ),
            ),
        ),
    )

    assert default_guarded_controller.guards == [is_superuser]
    assert custom_guarded_controller.guards == [custom_admin_guard]
    assert controller.path == "/tenant-admin"
    assert invitation_controller.path == "/auth"
    assert custom_invitation_controller.path == "/tenant-invitations"
    assert config_type(id_parser=UUID).id_parser is UUID
    assert invitation_config_type().path == "/auth"
    with pytest.raises(ConfigurationError, match="guards"):
        controller_factory(id_parser=UUID, guards=[])
    with pytest.raises(ConfigurationError, match="route_prefix"):
        controller_factory(id_parser=UUID, route_prefix="/")
    with pytest.raises(ConfigurationError, match="id_parser"):
        controller_factory()
    with pytest.raises(ValueError, match="either"):
        controller_factory(controller_config=config_type(id_parser=UUID), id_parser=UUID)
    with pytest.raises(AttributeError, match="missing"):
        _ = organization_admin_contrib.missing


def test_organization_admin_error_mapper_reraises_unknown_errors() -> None:
    """The org-admin mapper only handles known domain errors."""
    error_module = importlib.import_module("litestar_auth.contrib.organization_admin._error_responses")
    unknown_error = RuntimeError("unknown")

    with pytest.raises(RuntimeError, match="unknown"):
        error_module._map_organization_admin_error(unknown_error)


def test_register_middleware_passes_enabled_organization_resolution_settings() -> None:
    """Plugin middleware config carries enabled organization store and tenant resolver settings."""
    store_factory = Mock()
    tenant_resolver = Mock()
    organization_config = plugin_module.OrganizationConfig(
        enabled=True,
        store_factory=store_factory,
        tenant_resolver=tenant_resolver,
    )
    plugin = LitestarAuth(_minimal_config(organization_config=organization_config))
    app_config = AppConfig()

    plugin._register_middleware(app_config)

    middleware = cast("DefineMiddleware", app_config.middleware[0])
    middleware_config = middleware.kwargs["config"]
    assert middleware_config.organization_store_factory is store_factory
    assert middleware_config.tenant_resolver is tenant_resolver


def test_register_middleware_omits_disabled_organization_resolution_settings() -> None:
    """Disabled organization config does not activate middleware organization lookups."""
    store_factory = Mock()
    tenant_resolver = Mock()
    organization_config = plugin_module.OrganizationConfig(
        enabled=False,
        store_factory=store_factory,
        tenant_resolver=tenant_resolver,
    )
    plugin = LitestarAuth(_minimal_config(organization_config=organization_config))
    app_config = AppConfig()

    plugin._register_middleware(app_config)

    middleware = cast("DefineMiddleware", app_config.middleware[0])
    middleware_config = middleware.kwargs["config"]
    assert middleware_config.organization_store_factory is None
    assert middleware_config.tenant_resolver is None
