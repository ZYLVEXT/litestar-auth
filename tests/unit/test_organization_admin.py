"""Unit tests for store-backed organization administration operations."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.exceptions import PermissionDeniedException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from litestar_auth._plugin.organization_admin import SQLAlchemyOrganizationAdmin
from litestar_auth._plugin.organization_admin import _mutations as organization_mutations_module
from litestar_auth.contrib.organization_admin._controller import (
    _require_global_organization_catalog_admin,
    _require_path_organization_authority,
)
from litestar_auth.contrib.organization_admin._schemas import (
    MembershipCreate,
    MembershipRolesUpdate,
    OrganizationInvitationCreate,
    OrganizationInvitationTokenRequest,
)
from litestar_auth.db import MembershipData, OrganizationData
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore
from litestar_auth.exceptions import (
    InvalidOrganizationInvitationTokenError,
    OrganizationAlreadyExistsError,
    OrganizationLastPrivilegedMemberError,
    OrganizationMembershipAlreadyExistsError,
    OrganizationMembershipNotFoundError,
    OrganizationNotFoundError,
)
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import Organization, OrganizationInvitation, OrganizationMembership, User
from litestar_auth.password import PasswordHelper
from tests.integration.conftest import enable_aiosqlite_foreign_keys

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._manager.hooks import ManagerHookEvent

pytestmark = pytest.mark.unit
_EXPECTED_ADMIN_MEMBERSHIP_TOTAL = 2
_EXPECTED_ADMIN_INVITATION_TOTAL = 2
_MAX_ORGANIZATION_ADMIN_ROLES = 64
_MAX_ORGANIZATION_ADMIN_ROLE_LENGTH = 255
_MAX_ORGANIZATION_INVITATION_TOKEN_LENGTH = 2048
_STALE_MEMBERSHIP_PRECHECKS = 2


@pytest.fixture
async def organization_admin_session(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    """Create a real async SQLite session for organization-admin tests.

    Yields:
        Async SQLAlchemy session bound to isolated SQLite tables.
    """
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'organization-admin.sqlite'}")
    enable_aiosqlite_foreign_keys(engine)
    async with engine.begin() as connection:
        await connection.run_sync(User.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session

    await engine.dispose()


def create_admin(
    session: AsyncSession,
) -> SQLAlchemyOrganizationAdmin[Organization, OrganizationMembership, OrganizationInvitation, UUID]:
    """Create an organization admin backed by the SQLAlchemy organization store.

    Returns:
        Organization admin bound to ``session``.
    """
    store = SQLAlchemyOrganizationStore(
        session=session,
        organization_model=Organization,
        membership_model=OrganizationMembership,
        invitation_model=OrganizationInvitation,
    )
    return SQLAlchemyOrganizationAdmin(store=store)


def create_invitation_manager() -> BaseUserManager[User, UUID]:
    """Create a manager with real organization-invitation token issuance.

    Returns:
        User manager configured with an organization-invitation token secret.
    """
    return BaseUserManager(
        AsyncMock(),
        password_helper=PasswordHelper(),
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            organization_invitation_token_secret="c4b7e9a13f6d8c2059ab7e3041f8d6e2" * 2,
            login_identifier_telemetry_secret="2d1236ee6fd646dcb7574a8ff916e4e2" * 2,
            id_parser=UUID,
        ),
    )


@pytest.mark.parametrize("schema", [MembershipCreate, MembershipRolesUpdate, OrganizationInvitationCreate])
def test_organization_admin_role_payloads_reject_oversized_role_lists(schema: type[msgspec.Struct]) -> None:
    """Organization-admin schemas bound role-list size before normalization and persistence."""
    payload: dict[str, object] = {"roles": ["member"] * (_MAX_ORGANIZATION_ADMIN_ROLES + 1)}
    if schema is OrganizationInvitationCreate:
        payload["invited_email"] = "invitee@example.com"

    with pytest.raises(msgspec.ValidationError, match=r"array` of length <= 64"):
        msgspec.convert(payload, schema)


@pytest.mark.parametrize("schema", [MembershipCreate, MembershipRolesUpdate, OrganizationInvitationCreate])
def test_organization_admin_role_payloads_reject_oversized_role_names(schema: type[msgspec.Struct]) -> None:
    """Organization-admin schemas bound each role name before normalization and persistence."""
    payload: dict[str, object] = {"roles": ["x" * (_MAX_ORGANIZATION_ADMIN_ROLE_LENGTH + 1)]}
    if schema is OrganizationInvitationCreate:
        payload["invited_email"] = "invitee@example.com"

    with pytest.raises(msgspec.ValidationError, match=r"str` of length <= 255"):
        msgspec.convert(payload, schema)


def test_organization_invitation_token_request_rejects_oversized_token() -> None:
    """Invitation accept/decline schemas bound token size before JWT parsing."""
    with pytest.raises(msgspec.ValidationError, match=r"str` of length <= 2048"):
        msgspec.convert(
            {"token": "x" * (_MAX_ORGANIZATION_INVITATION_TOKEN_LENGTH + 1)},
            OrganizationInvitationTokenRequest,
        )


async def create_user(session: AsyncSession, email: str) -> User:
    """Persist one bundled user row for membership tests.

    Returns:
        Persisted user row.
    """
    user = User(email=email, hashed_password="hashed-password")
    session.add(user)
    await session.commit()
    return user


async def test_organization_admin_crud_and_membership_operations(
    organization_admin_session: AsyncSession,
) -> None:
    """Organization admin delegates create/read/update/delete and membership mutations to the store."""
    first_user = await create_user(organization_admin_session, "org-admin-one@example.com")
    second_user = await create_user(organization_admin_session, "org-admin-two@example.com")
    admin = create_admin(organization_admin_session)

    organization = await admin.create_organization(slug=" Acme Team ", name="Acme Team")
    first_membership = await admin.add_member(
        organization_id=organization.id,
        user_id=first_user.id,
        roles=[" Owner ", "admin", "owner"],
    )
    second_membership = await admin.add_member(
        organization_id=organization.id,
        user_id=second_user.id,
        roles=["member"],
    )

    assert organization.slug == "acme team"
    assert await admin.get_organization(organization.id) is organization
    assert await admin.get_organization_by_slug(" Acme Team ") is organization
    assert await admin.get_membership(organization_id=organization.id, user_id=first_user.id) is first_membership
    assert admin.membership_roles(first_membership) == ["admin", "owner"]
    memberships, total_memberships = await admin.list_members(organization.id, offset=0, limit=10)
    assert total_memberships == _EXPECTED_ADMIN_MEMBERSHIP_TOTAL
    assert {membership.user_id: membership for membership in memberships} == {
        first_user.id: first_membership,
        second_user.id: second_membership,
    }
    organizations, total_organizations = await admin.list_organizations_for_user(first_user.id, offset=0, limit=10)
    assert organizations == [organization]
    assert total_organizations == 1

    updated_organization = await admin.update_organization(
        organization.id,
        slug=" Acme Renamed ",
        name="Acme Renamed",
    )
    updated_membership = await admin.set_member_roles(
        organization_id=organization.id,
        user_id=second_user.id,
        roles=[" Admin ", "member", "admin"],
    )
    await admin.remove_member(organization_id=organization.id, user_id=first_user.id)
    await admin.delete_organization(organization.id)

    assert updated_organization is organization
    assert organization.slug == "acme renamed"
    assert updated_membership is second_membership
    assert second_membership.roles == ["admin", "member"]
    with pytest.raises(OrganizationNotFoundError):
        await admin.get_organization(organization.id)


async def test_organization_admin_fails_closed_for_unknown_targets(
    organization_admin_session: AsyncSession,
) -> None:
    """Unknown organization and membership operations raise stable non-enumerating exceptions."""
    user = await create_user(organization_admin_session, "org-admin-unknown@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="known-team", name="Known Team")

    with pytest.raises(OrganizationNotFoundError):
        await admin.get_organization(uuid4())
    with pytest.raises(OrganizationNotFoundError):
        await admin.get_organization_by_slug("missing-team")
    with pytest.raises(OrganizationNotFoundError):
        await admin.list_members(uuid4(), offset=0, limit=10)
    with pytest.raises(OrganizationNotFoundError):
        await admin.add_member(organization_id=uuid4(), user_id=user.id, roles=["member"])
    with pytest.raises(OrganizationMembershipNotFoundError):
        await admin.get_membership(organization_id=organization.id, user_id=uuid4())
    with pytest.raises(OrganizationMembershipNotFoundError):
        await admin.remove_member(organization_id=organization.id, user_id=uuid4())
    with pytest.raises(OrganizationMembershipNotFoundError):
        await admin.set_member_roles(organization_id=organization.id, user_id=uuid4(), roles=["owner"])


async def test_organization_admin_rejects_slug_collisions(
    organization_admin_session: AsyncSession,
) -> None:
    """Create and update operations enforce normalized slug uniqueness before persistence."""
    admin = create_admin(organization_admin_session)
    first = await admin.create_organization(slug="alpha-team", name="Alpha Team")
    await admin.create_organization(slug="beta-team", name="Beta Team")

    with pytest.raises(OrganizationAlreadyExistsError):
        await admin.create_organization(slug=" Alpha-Team ", name="Duplicate Alpha")
    with pytest.raises(OrganizationAlreadyExistsError):
        await admin.update_organization(first.id, slug=" beta-team ", name="Collision")

    assert first.slug == "alpha-team"
    assert first.name == "Alpha Team"


async def test_organization_admin_rejects_duplicate_membership(
    organization_admin_session: AsyncSession,
) -> None:
    """Adding the same user to an organization twice maps to the membership conflict error."""
    user = await create_user(organization_admin_session, "org-admin-duplicate@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="duplicate-members", name="Duplicate Members")

    await admin.add_member(organization_id=organization.id, user_id=user.id, roles=["owner"])

    with pytest.raises(OrganizationMembershipAlreadyExistsError):
        await admin.add_member(organization_id=organization.id, user_id=user.id, roles=["owner"])


async def test_organization_admin_maps_late_duplicate_membership_conflict(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Membership uniqueness races map to the public organization-admin conflict error."""
    user = await create_user(organization_admin_session, "org-admin-membership-race@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="membership-race", name="Membership Race")
    await admin.add_member(organization_id=organization.id, user_id=user.id, roles=["member"])
    await organization_admin_session.commit()
    original_get_membership = admin.store.get_membership
    get_membership_calls = 0

    async def stale_membership_prechecks(
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> OrganizationMembership | None:
        nonlocal get_membership_calls
        get_membership_calls += 1
        if get_membership_calls <= _STALE_MEMBERSHIP_PRECHECKS:
            return None
        return await original_get_membership(organization_id=organization_id, user_id=user_id)

    monkeypatch.setattr(admin.store, "get_membership", stale_membership_prechecks)

    with pytest.raises(OrganizationMembershipAlreadyExistsError):
        await admin.add_member(organization_id=organization.id, user_id=user.id, roles=["member"])


async def test_organization_admin_invites_member_and_dispatches_delivery_hook(
    organization_admin_session: AsyncSession,
) -> None:
    """Invitation creation stores only the token hash and delivers the raw token once."""
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="invite-team", name="Invite Team")
    events: list[tuple[str, tuple[object, ...]]] = []

    async def record(event: ManagerHookEvent) -> None:
        await asyncio.sleep(0)
        events.append((event.name, event.args))

    manager.hook_bus.subscribe(record)

    issue = await admin.invite_member(
        organization_id=organization.id,
        invited_email=" Invited.User@Example.COM ",
        roles=[" Member ", "admin", "member"],
        user_manager=manager,
    )

    invitation = issue.invitation
    assert invitation.organization_id == organization.id
    assert invitation.invited_email == "invited.user@example.com"
    assert invitation.roles == ["admin", "member"]
    assert invitation.status == "pending"
    assert isinstance(issue.token, str)
    assert invitation.token_hash == manager.tokens.organization_invitation_token_hash(issue.token)
    assert await admin.store.get_invitation_by_token_hash(invitation.token_hash) is invitation
    assert events == [("after_organization_invitation", (invitation, issue.token))]


async def test_organization_admin_invite_validates_email_roles_and_unknown_organization(
    organization_admin_session: AsyncSession,
) -> None:
    """Invitation input validation matches membership role normalization and unknown-org handling."""
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="invite-validation", name="Invite Validation")

    with pytest.raises(ValueError, match="Invalid email"):
        await admin.invite_member(
            organization_id=organization.id,
            invited_email="not-an-email",
            roles=["member"],
            user_manager=manager,
        )
    with pytest.raises(ValueError, match="Roles"):
        await admin.invite_member(
            organization_id=organization.id,
            invited_email="valid@example.com",
            roles=[" "],
            user_manager=manager,
        )
    with pytest.raises(OrganizationNotFoundError):
        await admin.invite_member(
            organization_id=uuid4(),
            invited_email="valid@example.com",
            roles=["member"],
            user_manager=manager,
        )


async def test_organization_admin_lists_and_revokes_pending_invitations(
    organization_admin_session: AsyncSession,
) -> None:
    """Pending invitation reads require a known organization and revocation fails closed."""
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="pending-invites", name="Pending Invites")
    first = await admin.invite_member(
        organization_id=organization.id,
        invited_email="zeta@example.com",
        roles=["member"],
        user_manager=manager,
    )
    second = await admin.invite_member(
        organization_id=organization.id,
        invited_email="alpha@example.com",
        roles=["admin"],
        user_manager=manager,
    )

    invitations, total_invitations = await admin.list_pending_invitations(organization.id, offset=0, limit=10)
    assert invitations == [second.invitation, first.invitation]
    assert total_invitations == _EXPECTED_ADMIN_INVITATION_TOTAL

    revoked = await admin.revoke_invitation(first.invitation.id)

    assert revoked is first.invitation
    assert first.invitation.status == "revoked"
    invitations, total_invitations = await admin.list_pending_invitations(organization.id, offset=0, limit=10)
    assert invitations == [second.invitation]
    assert total_invitations == 1
    with pytest.raises(OrganizationNotFoundError):
        await admin.list_pending_invitations(uuid4(), offset=0, limit=10)
    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.revoke_invitation(uuid4())
    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.revoke_invitation(first.invitation.id)


async def test_organization_admin_reinviting_email_supersedes_pending_invitation(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-inviting the same normalized email revokes the old pending row and creates a fresh token."""
    monkeypatch.setattr(organization_mutations_module, "_PENDING_INVITATION_REVOKE_PAGE_SIZE", 1)
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="reinvite-team", name="Reinvite Team")

    first = await admin.invite_member(
        organization_id=organization.id,
        invited_email="Repeat@Example.com",
        roles=["member"],
        user_manager=manager,
    )
    unrelated = await admin.invite_member(
        organization_id=organization.id,
        invited_email="zeta@example.com",
        roles=["member"],
        user_manager=manager,
    )
    second = await admin.invite_member(
        organization_id=organization.id,
        invited_email=" repeat@example.com ",
        roles=["admin"],
        user_manager=manager,
    )

    assert first.invitation.status == "revoked"
    assert second.invitation.status == "pending"
    assert first.invitation.invited_email == second.invitation.invited_email == "repeat@example.com"
    assert first.invitation.token_hash != second.invitation.token_hash
    invitations, total_invitations = await admin.list_pending_invitations(organization.id, offset=0, limit=10)
    assert invitations == [second.invitation, unrelated.invitation]
    assert total_invitations == _EXPECTED_ADMIN_INVITATION_TOTAL
    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await manager.tokens.validate_organization_invitation_token(first.token, organization_store=admin.store)
    assert (
        await manager.tokens.validate_organization_invitation_token(second.token, organization_store=admin.store)
        is second.invitation
    )


async def test_organization_admin_invite_maps_late_store_missing_organization(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invitation creation maps store-level unknown-organization races to the admin error."""
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="late-invite-missing", name="Late Invite Missing")

    async def create_invitation_missing_organization(_data: object) -> OrganizationInvitation:
        await asyncio.sleep(0)
        msg = "referenced organization is unavailable"
        raise ValueError(msg)

    monkeypatch.setattr(admin.store, "create_invitation", create_invitation_missing_organization)

    with pytest.raises(OrganizationNotFoundError):
        await admin.invite_member(
            organization_id=organization.id,
            invited_email="late-missing@example.com",
            roles=["member"],
            user_manager=manager,
        )


async def test_organization_admin_blocks_removing_or_demoting_final_privileged_member(
    organization_admin_session: AsyncSession,
) -> None:
    """The final owner/admin membership cannot be removed or stripped of privileged roles."""
    owner = await create_user(organization_admin_session, "org-admin-owner@example.com")
    member = await create_user(organization_admin_session, "org-admin-member@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="guarded-team", name="Guarded Team")
    await admin.add_member(organization_id=organization.id, user_id=owner.id, roles=["owner"])
    await admin.add_member(organization_id=organization.id, user_id=member.id, roles=["member"])

    with pytest.raises(OrganizationLastPrivilegedMemberError):
        await admin.remove_member(organization_id=organization.id, user_id=owner.id)
    with pytest.raises(OrganizationLastPrivilegedMemberError):
        await admin.set_member_roles(organization_id=organization.id, user_id=owner.id, roles=["member"])

    other_owner = await create_user(organization_admin_session, "org-admin-other-owner@example.com")
    await admin.add_member(organization_id=organization.id, user_id=other_owner.id, roles=["admin"])

    await admin.set_member_roles(organization_id=organization.id, user_id=owner.id, roles=["member"])
    with pytest.raises(OrganizationLastPrivilegedMemberError):
        await admin.remove_member(organization_id=organization.id, user_id=other_owner.id)

    owner_membership = await admin.get_membership(organization_id=organization.id, user_id=owner.id)
    other_owner_membership = await admin.get_membership(organization_id=organization.id, user_id=other_owner.id)
    assert owner_membership.roles == ["member"]
    assert other_owner_membership.roles == ["admin"]


async def test_organization_admin_uses_store_surface_without_duplicate_persistence_queries(
    organization_admin_session: AsyncSession,
) -> None:
    """The operations layer is constructed from the store produced by TASK-023."""
    store = SQLAlchemyOrganizationStore(
        session=organization_admin_session,
        organization_model=Organization,
        membership_model=OrganizationMembership,
        invitation_model=OrganizationInvitation,
    )
    admin = SQLAlchemyOrganizationAdmin(store=store)
    organization = await store.create_organization(OrganizationData(slug="store-backed", name="Store Backed"))
    user = await create_user(organization_admin_session, "org-admin-store-backed@example.com")
    membership = await store.add_membership(
        MembershipData(organization_id=organization.id, user_id=user.id, roles=["owner"]),
    )

    assert await admin.get_organization(organization.id) is organization
    assert await admin.get_membership(organization_id=organization.id, user_id=user.id) is membership


async def test_organization_admin_maps_store_failure_branches(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store-level conflicts and concurrent deletion races map to organization-admin errors."""
    user = await create_user(organization_admin_session, "org-admin-failure-branches@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="failure-branches", name="Failure Branches")
    await admin.add_member(organization_id=organization.id, user_id=user.id, roles=["member"])

    async def create_organization_collision(_data: OrganizationData) -> Organization:
        await asyncio.sleep(0)
        msg = "late create collision"
        raise ValueError(msg)

    monkeypatch.setattr(admin.store, "create_organization", create_organization_collision)
    with pytest.raises(OrganizationAlreadyExistsError):
        await admin.create_organization(slug="late-create-collision", name="Late Create Collision")

    async def update_organization_collision(_organization_id: UUID, _data: OrganizationData) -> Organization | None:
        await asyncio.sleep(0)
        msg = "late update collision"
        raise ValueError(msg)

    monkeypatch.setattr(admin.store, "update_organization", update_organization_collision)
    with pytest.raises(OrganizationAlreadyExistsError):
        await admin.update_organization(organization.id, slug="late-update-collision", name="Late Update Collision")

    async def update_organization_missing(_organization_id: UUID, _data: OrganizationData) -> Organization | None:
        await asyncio.sleep(0)
        return None

    monkeypatch.setattr(admin.store, "update_organization", update_organization_missing)
    with pytest.raises(OrganizationNotFoundError):
        await admin.update_organization(organization.id, slug="late-update-missing", name="Late Update Missing")

    async def delete_organization_missing(_organization_id: UUID) -> bool:
        await asyncio.sleep(0)
        return False

    monkeypatch.setattr(admin.store, "delete_organization", delete_organization_missing)
    with pytest.raises(OrganizationNotFoundError):
        await admin.delete_organization(organization.id)

    async def add_membership_unknown_user(_data: MembershipData[UUID]) -> OrganizationMembership:
        await asyncio.sleep(0)
        msg = "referenced user is unavailable"
        raise ValueError(msg)

    monkeypatch.setattr(admin.store, "add_membership", add_membership_unknown_user)
    with pytest.raises(OrganizationNotFoundError):
        await admin.add_member(organization_id=organization.id, user_id=uuid4(), roles=["member"])

    async def remove_membership_missing(
        *,
        organization_id: UUID,
        user_id: UUID,
        privileged_roles: frozenset[str],
    ) -> bool:
        await asyncio.sleep(0)
        return False

    monkeypatch.setattr(admin.store, "remove_membership_preserving_privileged_member", remove_membership_missing)
    with pytest.raises(OrganizationMembershipNotFoundError):
        await admin.remove_member(organization_id=organization.id, user_id=user.id)

    async def set_membership_roles_missing(
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
        privileged_roles: frozenset[str],
    ) -> OrganizationMembership | None:
        await asyncio.sleep(0)
        return None

    monkeypatch.setattr(admin.store, "set_membership_roles_preserving_privileged_member", set_membership_roles_missing)
    with pytest.raises(OrganizationMembershipNotFoundError):
        await admin.set_member_roles(organization_id=organization.id, user_id=user.id, roles=["member"])


async def test_caller_has_organization_authority_requires_privileged_membership(
    organization_admin_session: AsyncSession,
) -> None:
    """Authority is granted only to privileged members of the specific organization."""
    privileged_user = await create_user(organization_admin_session, "authority-owner@example.com")
    plain_user = await create_user(organization_admin_session, "authority-member@example.com")
    outsider = await create_user(organization_admin_session, "authority-outsider@example.com")
    admin = create_admin(organization_admin_session)

    organization = await admin.create_organization(slug="authority-org", name="Authority Org")
    await admin.add_member(organization_id=organization.id, user_id=privileged_user.id, roles=["owner"])
    await admin.add_member(organization_id=organization.id, user_id=plain_user.id, roles=["member"])

    assert await admin.caller_has_organization_authority(organization_id=organization.id, user_id=privileged_user.id)
    assert not await admin.caller_has_organization_authority(organization_id=organization.id, user_id=plain_user.id)
    assert not await admin.caller_has_organization_authority(organization_id=organization.id, user_id=outsider.id)


def test_require_global_organization_catalog_admin_allows_superuser() -> None:
    """Org-less catalog routes stay available to global superusers."""
    request = cast(
        "Any",
        SimpleNamespace(user=SimpleNamespace(id=uuid4(), roles=["superuser"]), scope={}),
    )

    _require_global_organization_catalog_admin(request)


async def test_require_global_organization_catalog_admin_denies_org_privileged_member(
    organization_admin_session: AsyncSession,
) -> None:
    """Tenant org admins cannot use org-less catalog routes even inside their organization."""
    owner = await create_user(organization_admin_session, "catalog-owner@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="catalog-org", name="Catalog Org")
    await admin.add_member(organization_id=organization.id, user_id=owner.id, roles=["owner"])
    request = cast("Any", SimpleNamespace(user=SimpleNamespace(id=owner.id, roles=[]), scope={}))

    with pytest.raises(PermissionDeniedException):
        _require_global_organization_catalog_admin(request)


async def test_accept_invitation_rolls_back_consumed_invitation_when_membership_insert_fails(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invitation consumption and membership creation commit or roll back together."""
    invitee = await create_user(organization_admin_session, "rollback-invitee@example.com")
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="rollback-org", name="Rollback Org")
    issue = await admin.invite_member(
        organization_id=organization.id,
        invited_email=invitee.email,
        roles=["member"],
        user_manager=manager,
    )
    invitation_id = issue.invitation.id

    real_flush = organization_admin_session.flush
    flush_calls = 0
    membership_persist_flush_order = 2

    async def fail_membership_flush(objects: list[object] | None = None) -> None:
        nonlocal flush_calls
        flush_calls += 1
        if flush_calls >= membership_persist_flush_order:
            msg = "Organization membership already exists."
            raise ValueError(msg)
        await real_flush(objects)

    monkeypatch.setattr(organization_admin_session, "flush", fail_membership_flush)

    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.accept_invitation(token=issue.token, user=invitee, user_manager=manager)

    organization_admin_session.expire_all()
    refreshed = await admin.get_invitation(invitation_id)
    assert refreshed is not None
    assert refreshed.status == "pending"


async def test_accept_invitation_succeeds_with_sqlalchemy_finalize(
    organization_admin_session: AsyncSession,
) -> None:
    """Acceptance persists membership and consumes the invitation through the SQLAlchemy savepoint."""
    invitee = await create_user(organization_admin_session, "accept-invitee@example.com")
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="accept-org", name="Accept Org")
    issue = await admin.invite_member(
        organization_id=organization.id,
        invited_email=invitee.email,
        roles=["member"],
        user_manager=manager,
    )

    membership = await admin.accept_invitation(token=issue.token, user=invitee, user_manager=manager)

    assert membership.organization_id == organization.id
    assert membership.user_id == invitee.id
    refreshed = await admin.get_invitation(issue.invitation.id)
    assert refreshed is not None
    assert refreshed.status == "consumed"


async def test_accept_invitation_raises_when_finalize_returns_none(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance fails closed when the SQLAlchemy finalize hook reports no transition."""
    invitee = await create_user(organization_admin_session, "finalize-none@example.com")
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="finalize-none-org", name="Finalize None Org")
    issue = await admin.invite_member(
        organization_id=organization.id,
        invited_email=invitee.email,
        roles=["member"],
        user_manager=manager,
    )

    monkeypatch.setattr(
        admin.store,
        "_finalize_invitation_acceptance",
        AsyncMock(return_value=None),
    )

    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.accept_invitation(token=issue.token, user=invitee, user_manager=manager)


async def test_accept_invitation_falls_back_when_finalize_is_unavailable(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-SQLAlchemy stores without finalize still accept through consume plus add_membership."""
    invitee = await create_user(organization_admin_session, "fallback-invitee@example.com")
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="fallback-org", name="Fallback Org")
    issue = await admin.invite_member(
        organization_id=organization.id,
        invited_email=invitee.email,
        roles=["member"],
        user_manager=manager,
    )
    monkeypatch.setattr(admin.store, "_finalize_invitation_acceptance", None)

    membership = await admin.accept_invitation(token=issue.token, user=invitee, user_manager=manager)

    assert membership.organization_id == organization.id
    assert membership.user_id == invitee.id


async def test_accept_invitation_falls_back_and_fails_when_membership_insert_rejected(
    organization_admin_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fallback acceptance maps store membership validation failures to invitation denial."""
    invitee = await create_user(organization_admin_session, "fallback-fail@example.com")
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="fallback-fail-org", name="Fallback Fail Org")
    issue = await admin.invite_member(
        organization_id=organization.id,
        invited_email=invitee.email,
        roles=["member"],
        user_manager=manager,
    )
    monkeypatch.setattr(admin.store, "_finalize_invitation_acceptance", None)

    async def reject_membership(_data: MembershipData[UUID]) -> OrganizationMembership:
        await asyncio.sleep(0)
        msg = "Organization membership already exists."
        raise ValueError(msg)

    monkeypatch.setattr(admin.store, "add_membership", reject_membership)

    with pytest.raises(InvalidOrganizationInvitationTokenError):
        await admin.accept_invitation(token=issue.token, user=invitee, user_manager=manager)


async def test_require_path_organization_authority_allows_global_superuser_without_membership(
    organization_admin_session: AsyncSession,
) -> None:
    """A global superuser may administer any organization despite holding no membership."""
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="superuser-org", name="Superuser Org")
    request = cast(
        "Any",
        SimpleNamespace(user=SimpleNamespace(id=uuid4(), roles=["superuser"]), scope={}),
    )

    # Must not raise: the default is_superuser admin flow is preserved.
    await _require_path_organization_authority(request=request, organization_id=organization.id, admin=admin)


async def test_require_path_organization_authority_allows_privileged_member(
    organization_admin_session: AsyncSession,
) -> None:
    """A privileged member of the path organization passes the in-depth authority check."""
    owner = await create_user(organization_admin_session, "path-owner@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="member-org", name="Member Org")
    await admin.add_member(organization_id=organization.id, user_id=owner.id, roles=["admin"])
    request = cast("Any", SimpleNamespace(user=SimpleNamespace(id=owner.id, roles=[]), scope={}))

    await _require_path_organization_authority(request=request, organization_id=organization.id, admin=admin)


@pytest.mark.parametrize("caller_roles", [["member"], []])
async def test_require_path_organization_authority_denies_non_privileged_caller(
    organization_admin_session: AsyncSession,
    caller_roles: list[str],
) -> None:
    """A caller who is neither superuser nor privileged member is denied on the path organization.

    This closes the cross-tenant footgun: org-scoped guards authorize the tenant-resolved
    current organization, so authority over the path organization must be re-verified here.
    """
    caller = await create_user(organization_admin_session, "denied-caller@example.com")
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="protected-org", name="Protected Org")
    if caller_roles:
        await admin.add_member(organization_id=organization.id, user_id=caller.id, roles=caller_roles)
    request = cast("Any", SimpleNamespace(user=SimpleNamespace(id=caller.id, roles=[]), scope={}))

    with pytest.raises(PermissionDeniedException):
        await _require_path_organization_authority(request=request, organization_id=organization.id, admin=admin)


async def test_require_path_organization_authority_denies_anonymous_request(
    organization_admin_session: AsyncSession,
) -> None:
    """A request without an authenticated user is denied (no superuser role, no membership)."""
    admin = create_admin(organization_admin_session)
    organization = await admin.create_organization(slug="anon-org", name="Anon Org")
    request = cast("Any", SimpleNamespace(user=None, scope={}))

    with pytest.raises(PermissionDeniedException):
        await _require_path_organization_authority(request=request, organization_id=organization.id, admin=admin)


async def test_get_invitation_scopes_revoke_authority_to_invitation_organization(
    organization_admin_session: AsyncSession,
) -> None:
    """Revoking by invitation id verifies authority against the invitation's own organization."""
    admin = create_admin(organization_admin_session)
    manager = create_invitation_manager()
    organization = await admin.create_organization(slug="revoke-authority-org", name="Revoke Authority Org")
    owner = await create_user(organization_admin_session, "revoke-owner@example.com")
    await admin.add_member(organization_id=organization.id, user_id=owner.id, roles=["admin"])
    outsider = await create_user(organization_admin_session, "revoke-outsider@example.com")
    issue = await admin.invite_member(
        organization_id=organization.id,
        invited_email="revoke-invitee@example.com",
        roles=["member"],
        user_manager=manager,
    )

    fetched = await admin.get_invitation(issue.invitation.id)
    assert fetched is not None
    assert fetched.organization_id == organization.id
    assert await admin.get_invitation(uuid4()) is None

    owner_request = cast("Any", SimpleNamespace(user=SimpleNamespace(id=owner.id, roles=[]), scope={}))
    await _require_path_organization_authority(
        request=owner_request,
        organization_id=fetched.organization_id,
        admin=admin,
    )

    # An outsider, and a missing invitation (no organization id), are both denied without
    # leaking whether the invitation exists.
    outsider_request = cast("Any", SimpleNamespace(user=SimpleNamespace(id=outsider.id, roles=[]), scope={}))
    missing = await admin.get_invitation(uuid4())
    for organization_id in (fetched.organization_id, getattr(missing, "organization_id", None)):
        with pytest.raises(PermissionDeniedException):
            await _require_path_organization_authority(
                request=outsider_request,
                organization_id=organization_id,
                admin=admin,
            )
