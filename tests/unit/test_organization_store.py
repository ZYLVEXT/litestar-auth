"""Unit tests for SQLAlchemy organization persistence."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import litestar_auth
import litestar_auth.db as db_module
import litestar_auth.db.sqlalchemy as sqlalchemy_module
from litestar_auth.db import BaseOrganizationStore, MembershipData, OrganizationData, OrganizationInvitationData
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore
from litestar_auth.models import Organization, OrganizationInvitation, OrganizationMembership, User
from tests.integration.conftest import enable_aiosqlite_foreign_keys

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.unit
_EXPECTED_RACE_MEMBERSHIP_COUNT = 2
_EXPECTED_CRUD_MEMBERSHIP_TOTAL = 2
_EXPECTED_CRUD_USER_ORGANIZATION_TOTAL = 2


@pytest.fixture
async def organization_session(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    """Create a real async SQLite session for organization-store tests.

    Yields:
        Async SQLAlchemy session bound to isolated SQLite tables.
    """
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'organization-store.sqlite'}")
    enable_aiosqlite_foreign_keys(engine)
    async with engine.begin() as connection:
        await connection.run_sync(User.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session

    await engine.dispose()


def create_store(
    session: AsyncSession,
) -> SQLAlchemyOrganizationStore[Organization, OrganizationMembership, OrganizationInvitation]:
    """Create an organization store backed by a real async SQLAlchemy session.

    Returns:
        SQLAlchemy organization store bound to ``session``.
    """
    return SQLAlchemyOrganizationStore(
        session=session,
        organization_model=Organization,
        membership_model=OrganizationMembership,
        invitation_model=OrganizationInvitation,
    )


async def test_sqlalchemy_organization_store_crud_memberships(organization_session: AsyncSession) -> None:
    """The store creates, looks up, lists, and removes organization memberships."""
    first_user = User(email="org-member-one@example.com", hashed_password="hashed-password")
    second_user = User(email="org-member-two@example.com", hashed_password="hashed-password")
    organization_session.add_all([first_user, second_user])
    await organization_session.commit()
    store = create_store(organization_session)

    organization = await store.create_organization(OrganizationData(slug=" Acme Team ", name="Acme Team"))
    other_organization = await store.create_organization(OrganizationData(slug="beta-team", name="Beta Team"))
    membership = await store.add_membership(
        MembershipData(organization_id=organization.id, user_id=first_user.id, roles=[" Owner ", "admin", "owner"]),
    )
    other_membership = await store.add_membership(
        MembershipData(organization_id=organization.id, user_id=second_user.id, roles=["member"]),
    )
    await store.add_membership(
        MembershipData(organization_id=other_organization.id, user_id=first_user.id, roles=["viewer"]),
    )

    assert isinstance(store, BaseOrganizationStore)
    assert organization.slug == "acme team"
    assert await store.get_organization(organization.id) is organization
    assert await store.get_organization(uuid4()) is None
    assert await store.get_organization_by_slug("acme team") is organization
    assert await store.get_organization_by_slug("missing") is None
    assert membership.roles == ["admin", "owner"]
    assert await store.get_membership(organization_id=organization.id, user_id=first_user.id) is membership
    assert await store.get_membership(organization_id=organization.id, user_id=uuid4()) is None
    memberships, total_memberships = await store.list_memberships(organization.id, offset=0, limit=10)
    assert total_memberships == _EXPECTED_CRUD_MEMBERSHIP_TOTAL
    assert {row.user_id: row for row in memberships} == {
        first_user.id: membership,
        second_user.id: other_membership,
    }
    memberships, total_memberships = await store.list_memberships(organization.id, offset=5, limit=10)
    assert memberships == []
    assert total_memberships == _EXPECTED_CRUD_MEMBERSHIP_TOTAL
    organizations, total_organizations = await store.list_organizations_for_user(first_user.id, offset=0, limit=1)
    assert organizations == [organization]
    assert total_organizations == _EXPECTED_CRUD_USER_ORGANIZATION_TOTAL
    organizations, total_organizations = await store.list_organizations_for_user(first_user.id, offset=1, limit=1)
    assert organizations == [other_organization]
    assert total_organizations == _EXPECTED_CRUD_USER_ORGANIZATION_TOTAL
    assert await store.list_organizations_for_user(uuid4(), offset=0, limit=10) == ([], 0)
    assert await store.remove_membership(organization_id=organization.id, user_id=first_user.id) is True
    assert await store.get_membership(organization_id=organization.id, user_id=first_user.id) is None
    assert await store.remove_membership(organization_id=organization.id, user_id=first_user.id) is False


async def test_sqlalchemy_organization_store_updates_organization_and_rejects_slug_collision(
    organization_session: AsyncSession,
) -> None:
    """Organization updates normalize slugs and reject collisions with existing tenants."""
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="alpha-team", name="Alpha Team"))
    await store.create_organization(OrganizationData(slug="beta-team", name="Beta Team"))

    updated = await store.update_organization(
        organization.id,
        OrganizationData(slug=" Alpha Renamed ", name="Alpha Renamed"),
    )

    assert updated is organization
    assert organization.slug == "alpha renamed"
    assert organization.name == "Alpha Renamed"
    assert await store.get_organization_by_slug("alpha renamed") is organization
    assert await store.update_organization(uuid4(), OrganizationData(slug="missing", name="Missing")) is None
    with pytest.raises(ValueError, match="slug already exists"):
        await store.update_organization(organization.id, OrganizationData(slug=" Beta-Team ", name="Collision"))
    assert organization.slug == "alpha renamed"
    assert organization.name == "Alpha Renamed"


async def test_sqlalchemy_organization_store_maps_duplicate_slug_integrity_error(
    organization_session: AsyncSession,
) -> None:
    """Duplicate slug constraint failures map to the store conflict contract."""
    store = create_store(organization_session)
    await store.create_organization(OrganizationData(slug="race-team", name="Race Team"))
    await organization_session.commit()

    with pytest.raises(ValueError, match="slug already exists"):
        await store.create_organization(OrganizationData(slug="race-team", name="Race Loser"))

    recovery = await store.create_organization(OrganizationData(slug="recovery-team", name="Recovery Team"))

    assert await store.get_organization_by_slug("race-team") is not None
    assert recovery.slug == "recovery-team"


async def test_sqlalchemy_organization_store_maps_update_duplicate_slug_integrity_error(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Late update slug constraint failures map to the store conflict contract."""
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="alpha-update-race", name="Alpha Team"))
    await store.create_organization(OrganizationData(slug="update-race-target", name="Target Team"))
    await organization_session.commit()

    original_get_organization_by_slug = store.get_organization_by_slug
    missed_precheck = False

    async def miss_target_slug_once(slug: str) -> Organization | None:
        nonlocal missed_precheck
        if slug == "update-race-target" and not missed_precheck:
            missed_precheck = True
            return None
        return await original_get_organization_by_slug(slug)

    monkeypatch.setattr(store, "get_organization_by_slug", miss_target_slug_once)

    with pytest.raises(ValueError, match="slug already exists"):
        await store.update_organization(
            organization.id,
            OrganizationData(slug="update-race-target", name="Race Loser"),
        )

    await organization_session.refresh(organization)
    recovery = await store.create_organization(OrganizationData(slug="update-race-recovery", name="Recovery Team"))

    assert organization.slug == "alpha-update-race"
    assert organization.name == "Alpha Team"
    assert recovery.slug == "update-race-recovery"


async def test_sqlalchemy_organization_store_reraises_unclassified_update_integrity_error(
    organization_session: AsyncSession,
) -> None:
    """Non-slug update integrity failures are not mislabeled as conflicts."""
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="invalid-update-team", name="Valid Name"))
    await organization_session.commit()

    with pytest.raises(IntegrityError):
        await store.update_organization(
            organization.id,
            cast("Any", OrganizationData)(slug="invalid-update-team", name=None),
        )

    await organization_session.refresh(organization)
    recovery = await store.create_organization(
        OrganizationData(slug="organization-update-integrity-recovery", name="Recovery Team"),
    )

    assert organization.name == "Valid Name"
    assert recovery.slug == "organization-update-integrity-recovery"


async def test_sqlalchemy_organization_store_duplicate_slug_preserves_outer_transaction_work(
    organization_session: AsyncSession,
) -> None:
    """Handled slug races do not roll back earlier writes owned by the caller."""
    store = create_store(organization_session)
    await store.create_organization(OrganizationData(slug="existing-race-team", name="Existing Race Team"))
    await organization_session.commit()

    pending = await store.create_organization(OrganizationData(slug="pending-race-team", name="Pending Race Team"))

    with pytest.raises(ValueError, match="slug already exists"):
        await store.create_organization(OrganizationData(slug="existing-race-team", name="Race Loser"))

    assert await store.get_organization_by_slug("pending-race-team") is pending
    recovery = await store.create_organization(OrganizationData(slug="slug-savepoint-recovery", name="Recovery Team"))
    await organization_session.commit()

    assert await store.get_organization_by_slug("pending-race-team") is not None
    assert recovery.slug == "slug-savepoint-recovery"


async def test_sqlalchemy_organization_store_reraises_unclassified_create_integrity_error(
    organization_session: AsyncSession,
) -> None:
    """Non-slug organization integrity failures are not mislabeled as conflicts."""
    store = create_store(organization_session)

    with pytest.raises(IntegrityError):
        await store.create_organization(cast("Any", OrganizationData)(slug="invalid-organization", name=None))

    recovery = await store.create_organization(
        OrganizationData(slug="organization-integrity-recovery", name="Organization Integrity Recovery"),
    )

    assert recovery.slug == "organization-integrity-recovery"


async def test_sqlalchemy_organization_store_deletes_organization_and_memberships(
    organization_session: AsyncSession,
) -> None:
    """Deleting an organization removes its memberships in the same transaction."""
    user = User(email="org-delete-member@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="delete-team", name="Delete Team"))
    await store.add_membership(MembershipData(organization_id=organization.id, user_id=user.id, roles=["owner"]))

    assert await store.delete_organization(organization.id) is True
    assert await store.get_organization(organization.id) is None
    assert await store.list_memberships(organization.id, offset=0, limit=10) == ([], 0)
    assert await store.get_membership(organization_id=organization.id, user_id=user.id) is None
    assert await store.delete_organization(organization.id) is False


async def test_sqlalchemy_organization_store_replaces_membership_roles(
    organization_session: AsyncSession,
) -> None:
    """Membership role replacement uses the model's normalized role boundary."""
    user = User(email="org-set-roles-member@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="roles-team", name="Roles Team"))
    membership = await store.add_membership(
        MembershipData(organization_id=organization.id, user_id=user.id, roles=["member"]),
    )

    updated = await store.set_membership_roles(
        organization_id=organization.id,
        user_id=user.id,
        roles=[" Owner ", "admin", "owner"],
    )

    assert updated is membership
    assert membership.roles == ["admin", "owner"]
    assert (await store.set_membership_roles(organization_id=organization.id, user_id=uuid4(), roles=["owner"])) is None
    assert await store.list_memberships(organization.id, offset=0, limit=10) == ([membership], 1)


async def test_sqlalchemy_organization_store_preserves_final_privileged_membership(
    organization_session: AsyncSession,
) -> None:
    """Store-level membership mutations reject orphaning organization administration."""
    owner = User(email="store-final-owner@example.com", hashed_password="hashed-password")
    member = User(email="store-final-member@example.com", hashed_password="hashed-password")
    other_owner = User(email="store-final-other-owner@example.com", hashed_password="hashed-password")
    organization_session.add_all([owner, member, other_owner])
    await organization_session.commit()
    store = create_store(organization_session)
    privileged_roles = frozenset({"admin", "owner"})
    organization = await store.create_organization(OrganizationData(slug="store-final-team", name="Store Final Team"))
    owner_membership = await store.add_membership(
        MembershipData(organization_id=organization.id, user_id=owner.id, roles=["owner"]),
    )
    await store.add_membership(
        MembershipData(organization_id=organization.id, user_id=member.id, roles=["member"]),
    )

    assert not await store.remove_membership_preserving_privileged_member(
        organization_id=organization.id,
        user_id=uuid4(),
        privileged_roles=privileged_roles,
    )
    assert (
        await store.set_membership_roles_preserving_privileged_member(
            organization_id=organization.id,
            user_id=uuid4(),
            roles=["member"],
            privileged_roles=privileged_roles,
        )
        is None
    )
    with pytest.raises(ValueError, match="final privileged"):
        await store.remove_membership_preserving_privileged_member(
            organization_id=organization.id,
            user_id=owner.id,
            privileged_roles=privileged_roles,
        )
    with pytest.raises(ValueError, match="final privileged"):
        await store.set_membership_roles_preserving_privileged_member(
            organization_id=organization.id,
            user_id=owner.id,
            roles=["member"],
            privileged_roles=privileged_roles,
        )

    assert await store.get_membership(organization_id=organization.id, user_id=owner.id) is owner_membership
    assert owner_membership.roles == ["owner"]
    assert await store.remove_membership_preserving_privileged_member(
        organization_id=organization.id,
        user_id=member.id,
        privileged_roles=privileged_roles,
    )
    assert await store.get_membership(organization_id=organization.id, user_id=member.id) is None

    other_owner_membership = await store.add_membership(
        MembershipData(organization_id=organization.id, user_id=other_owner.id, roles=["admin"]),
    )
    updated = await store.set_membership_roles_preserving_privileged_member(
        organization_id=organization.id,
        user_id=owner.id,
        roles=["member"],
        privileged_roles=privileged_roles,
    )

    assert updated is owner_membership
    assert owner_membership.roles == ["member"]
    with pytest.raises(ValueError, match="final privileged"):
        await store.remove_membership_preserving_privileged_member(
            organization_id=organization.id,
            user_id=other_owner.id,
            privileged_roles=privileged_roles,
        )
    assert await store.get_membership(organization_id=organization.id, user_id=other_owner.id) is other_owner_membership


async def test_sqlalchemy_organization_store_fails_closed_for_duplicate_membership(
    organization_session: AsyncSession,
) -> None:
    """Adding the same user to the same organization is rejected before a silent upsert."""
    user = User(email="org-member-duplicate@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="duplicate-team", name="Duplicate Team"))
    data = MembershipData(organization_id=organization.id, user_id=user.id, roles=["member"])

    await store.add_membership(data)

    with pytest.raises(ValueError, match="already exists"):
        await store.add_membership(data)

    memberships, total = await store.list_memberships(organization.id, offset=0, limit=10)
    assert len(memberships) == total == 1


async def test_sqlalchemy_organization_store_maps_duplicate_membership_integrity_error(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicate membership constraint failures map to the store conflict contract."""
    first_user = User(email="org-member-race@example.com", hashed_password="hashed-password")
    second_user = User(email="org-member-recovery@example.com", hashed_password="hashed-password")
    organization_session.add_all([first_user, second_user])
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="membership-race", name="Membership Race"))
    organization_id = organization.id
    first_user_id = first_user.id
    second_user_id = second_user.id
    data = MembershipData(organization_id=organization.id, user_id=first_user.id, roles=["member"])
    await store.add_membership(data)
    await organization_session.commit()

    original_get_membership = store.get_membership
    get_membership_calls = 0

    async def stale_membership_precheck(
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> OrganizationMembership | None:
        nonlocal get_membership_calls
        get_membership_calls += 1
        if get_membership_calls == 1:
            return None
        return await original_get_membership(organization_id=organization_id, user_id=user_id)

    monkeypatch.setattr(store, "get_membership", stale_membership_precheck)

    with pytest.raises(ValueError, match="membership already exists"):
        await store.add_membership(data)

    recovery = await store.add_membership(
        MembershipData(organization_id=organization_id, user_id=second_user_id, roles=["member"]),
    )

    assert recovery.user_id == second_user_id
    assert await store.get_membership(organization_id=organization_id, user_id=first_user_id) is not None
    memberships, total = await store.list_memberships(organization_id, offset=0, limit=10)
    assert len(memberships) == total == _EXPECTED_RACE_MEMBERSHIP_COUNT


async def test_sqlalchemy_organization_store_duplicate_membership_preserves_outer_transaction_work(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handled membership races do not discard earlier caller-owned writes."""
    first_user = User(email="org-member-savepoint-race@example.com", hashed_password="hashed-password")
    pending_user = User(email="org-member-savepoint-pending@example.com", hashed_password="hashed-password")
    organization_session.add_all([first_user, pending_user])
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(
        OrganizationData(slug="membership-savepoint-race", name="Membership Savepoint Race"),
    )
    organization_id = organization.id
    first_user_id = first_user.id
    pending_user_id = pending_user.id
    data = MembershipData(organization_id=organization_id, user_id=first_user_id, roles=["member"])
    await store.add_membership(data)
    await organization_session.commit()

    pending = await store.create_organization(
        OrganizationData(slug="membership-savepoint-pending", name="Membership Savepoint Pending"),
    )
    original_get_membership = store.get_membership
    get_membership_calls = 0

    async def stale_membership_precheck(
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> OrganizationMembership | None:
        nonlocal get_membership_calls
        get_membership_calls += 1
        if get_membership_calls == 1:
            return None
        return await original_get_membership(organization_id=organization_id, user_id=user_id)

    monkeypatch.setattr(store, "get_membership", stale_membership_precheck)

    with pytest.raises(ValueError, match="membership already exists"):
        await store.add_membership(data)

    assert await store.get_organization_by_slug("membership-savepoint-pending") is pending
    recovery = await store.add_membership(
        MembershipData(organization_id=organization_id, user_id=pending_user_id, roles=["member"]),
    )
    await organization_session.commit()

    assert recovery.user_id == pending_user_id
    assert await store.get_organization_by_slug("membership-savepoint-pending") is not None


async def test_sqlalchemy_organization_store_maps_late_unknown_organization_integrity_error(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Membership foreign-key failures for deleted organizations preserve the unknown-org contract."""
    user = User(email="org-member-late-unknown-org@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    get_organization_calls = 0

    async def stale_organization_precheck(organization_id: UUID) -> Organization | None:
        nonlocal get_organization_calls
        get_organization_calls += 1
        if get_organization_calls == 1:
            return cast("Organization", object())
        return await SQLAlchemyOrganizationStore.get_organization(store, organization_id)

    monkeypatch.setattr(store, "get_organization", stale_organization_precheck)

    with pytest.raises(ValueError, match="unknown organization"):
        await store.add_membership(MembershipData(organization_id=uuid4(), user_id=user.id, roles=["member"]))

    recovery = await store.create_organization(
        OrganizationData(slug="late-unknown-org-recovery", name="Late Unknown Org Recovery"),
    )

    assert recovery.slug == "late-unknown-org-recovery"


async def test_sqlalchemy_organization_store_reraises_unclassified_membership_integrity_error(
    organization_session: AsyncSession,
) -> None:
    """Membership integrity failures that are not duplicate or unknown-org races stay raw."""
    store = create_store(organization_session)
    organization = await store.create_organization(
        OrganizationData(slug="membership-integrity", name="Membership Integrity"),
    )
    organization_id = organization.id
    await organization_session.commit()

    with pytest.raises(IntegrityError):
        await store.add_membership(MembershipData(organization_id=organization_id, user_id=uuid4(), roles=["member"]))

    recovery_user = User(email="org-member-integrity-recovery@example.com", hashed_password="hashed-password")
    organization_session.add(recovery_user)
    await organization_session.commit()
    recovery = await store.add_membership(
        MembershipData(organization_id=organization_id, user_id=recovery_user.id, roles=["member"]),
    )

    assert recovery.user_id == recovery_user.id


async def test_sqlalchemy_organization_store_fails_closed_for_unknown_organization(
    organization_session: AsyncSession,
) -> None:
    """Membership creation for an unknown organization is rejected explicitly."""
    user = User(email="org-member-unknown@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)

    with pytest.raises(ValueError, match="unknown organization"):
        await store.add_membership(MembershipData(organization_id=uuid4(), user_id=user.id, roles=["member"]))


async def test_sqlalchemy_organization_store_creates_and_fetches_invitation_by_token_hash(
    organization_session: AsyncSession,
) -> None:
    """Invitations persist normalized metadata and never store the raw token."""
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="invite-team", name="Invite Team"))
    raw_token = "invite-token-secret"
    token_hash = b"hashed-invitation-token-reference".ljust(64, b"0")
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email="  Invitee@Example.COM  ",
            roles=[" Member ", "admin", "member"],
            token_hash=token_hash,
            expires_at=expires_at,
        ),
    )

    assert invitation.organization_id == organization.id
    assert invitation.invited_email == "invitee@example.com"
    assert invitation.roles == ["admin", "member"]
    assert invitation.status == "pending"
    assert invitation.token_hash == token_hash
    assert raw_token.encode() not in bytes(invitation.token_hash)
    assert await store.get_invitation_by_token_hash(token_hash) is invitation
    assert await store.get_invitation_by_token_hash(b"missing".ljust(64, b"0")) is None


async def test_sqlalchemy_organization_store_lists_pending_and_revokes_invitation(
    organization_session: AsyncSession,
) -> None:
    """Pending invitation listing excludes expired and revoked rows."""
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="pending-team", name="Pending Team"))
    now = datetime.now(UTC)
    pending = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email="pending@example.com",
            roles=["member"],
            token_hash=b"pending".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )
    consumed = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email="consumed@example.com",
            roles=["member"],
            token_hash=b"consumed".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )
    expired = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email="expired@example.com",
            roles=["member"],
            token_hash=b"expired".ljust(64, b"0"),
            expires_at=now - timedelta(seconds=1),
        ),
    )
    assert await store.consume_invitation(consumed.id, consumed_at=now) is consumed

    assert await store.list_pending_invitations(organization.id, now=now, offset=0, limit=1) == ([pending], 1)
    assert await store.list_pending_invitations(organization.id, now=now, offset=1, limit=1) == ([], 1)
    assert await store.revoke_invitation(pending.id) is pending
    assert pending.status == "revoked"
    assert await store.revoke_invitation(pending.id) is None
    assert await store.list_pending_invitations(organization.id, now=now, offset=0, limit=10) == ([], 0)
    assert consumed.status == "consumed"
    assert expired.status == "pending"


async def test_sqlalchemy_organization_store_consumes_invitation_once(
    organization_session: AsyncSession,
) -> None:
    """Invitation consumption is a single conditional status transition."""
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="consume-team", name="Consume Team"))
    now = datetime.now(UTC)
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email="consume@example.com",
            roles=["member"],
            token_hash=b"consume".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )

    assert await store.consume_invitation(invitation.id, consumed_at=now) is invitation
    assert invitation.status == "consumed"
    assert await store.consume_invitation(invitation.id, consumed_at=now) is None
    assert await store.list_memberships(organization.id, offset=0, limit=10) == ([], 0)


async def test_sqlalchemy_organization_store_finalize_invitation_acceptance_validates_membership_data(
    organization_session: AsyncSession,
) -> None:
    """Finalize rejects unknown organizations and duplicate memberships before opening a savepoint."""
    user = User(email="finalize-validate@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="finalize-validate", name="Finalize Validate"))
    now = datetime.now(tz=UTC)
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email=user.email,
            roles=["member"],
            token_hash=b"finalize-validate".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )
    membership_data = MembershipData(organization_id=organization.id, user_id=user.id, roles=["member"])

    with pytest.raises(ValueError, match="unknown organization"):
        await store._finalize_invitation_acceptance(
            invitation.id,
            consumed_at=now,
            membership_data=MembershipData(organization_id=uuid4(), user_id=user.id, roles=["member"]),
        )

    await store.add_membership(membership_data)

    with pytest.raises(ValueError, match="membership already exists"):
        await store._finalize_invitation_acceptance(
            invitation.id,
            consumed_at=now,
            membership_data=membership_data,
        )


async def test_sqlalchemy_organization_store_finalize_invitation_acceptance_succeeds(
    organization_session: AsyncSession,
) -> None:
    """Finalize consumes the invitation and inserts membership in one savepoint."""
    user = User(email="finalize-success@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(
        OrganizationData(slug="finalize-success", name="Finalize Success"),
    )
    organization_id = organization.id
    now = datetime.now(tz=UTC)
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization_id,
            invited_email=user.email,
            roles=["member"],
            token_hash=b"finalize-success".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )
    invitation_id = invitation.id
    membership = await store._finalize_invitation_acceptance(
        invitation_id,
        consumed_at=now,
        membership_data=MembershipData(organization_id=organization_id, user_id=user.id, roles=["member"]),
    )

    assert membership is not None
    assert membership.user_id == user.id
    organization_session.expire_all()
    refreshed_invitation = await store.get_invitation(invitation_id)
    assert refreshed_invitation is not None
    assert refreshed_invitation.status == "consumed"

    second_user = User(email="finalize-success-second@example.com", hashed_password="hashed-password")
    organization_session.add(second_user)
    await organization_session.commit()
    second_user_id = second_user.id
    assert (
        await store._finalize_invitation_acceptance(
            invitation_id,
            consumed_at=now,
            membership_data=MembershipData(organization_id=organization_id, user_id=second_user_id, roles=["member"]),
        )
        is None
    )


async def test_sqlalchemy_organization_store_finalize_invitation_acceptance_raises_on_organization_mismatch(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finalize rejects invitations whose consumed row no longer matches the membership target."""
    user = User(email="finalize-mismatch@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(
        OrganizationData(slug="finalize-mismatch", name="Finalize Mismatch"),
    )
    now = datetime.now(tz=UTC)
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email=user.email,
            roles=["member"],
            token_hash=b"finalize-mismatch".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )
    real_transition = store._transition_invitation

    async def mismatched_transition(
        invitation_id: UUID,
        *,
        status: str,
        unexpired_after: datetime | None = None,
    ) -> OrganizationInvitation | None:
        consumed = await real_transition(
            invitation_id,
            status=status,
            unexpired_after=unexpired_after,
        )
        if consumed is None:
            return None
        return cast(
            "OrganizationInvitation",
            SimpleNamespace(
                id=consumed.id,
                organization_id=uuid4(),
                invited_email=consumed.invited_email,
                roles=consumed.roles,
                status=consumed.status,
                token_hash=consumed.token_hash,
                expires_at=consumed.expires_at,
            ),
        )

    monkeypatch.setattr(store, "_transition_invitation", mismatched_transition)

    with pytest.raises(ValueError, match="organization mismatch"):
        await store._finalize_invitation_acceptance(
            invitation.id,
            consumed_at=now,
            membership_data=MembershipData(organization_id=organization.id, user_id=user.id, roles=["member"]),
        )


async def test_sqlalchemy_organization_store_finalize_invitation_acceptance_maps_duplicate_membership_integrity_error(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicate membership races during finalize collapse to the existing membership contract."""
    user = User(email="finalize-race@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(OrganizationData(slug="finalize-race", name="Finalize Race"))
    now = datetime.now(tz=UTC)
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email=user.email,
            roles=["member"],
            token_hash=b"finalize-race".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )
    membership_data = MembershipData(organization_id=organization.id, user_id=user.id, roles=["member"])
    await store.add_membership(membership_data)
    original_get_membership = store.get_membership
    get_membership_calls = 0

    async def stale_membership_precheck(
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> OrganizationMembership | None:
        nonlocal get_membership_calls
        get_membership_calls += 1
        if get_membership_calls == 1:
            return None
        return await original_get_membership(organization_id=organization_id, user_id=user_id)

    monkeypatch.setattr(store, "get_membership", stale_membership_precheck)

    with pytest.raises(ValueError, match="membership already exists"):
        await store._finalize_invitation_acceptance(
            invitation.id,
            consumed_at=now,
            membership_data=membership_data,
        )


async def test_sqlalchemy_organization_store_finalize_invitation_acceptance_maps_unknown_organization_integrity_error(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Foreign-key failures for deleted organizations preserve the unknown-org contract during finalize."""
    user = User(email="finalize-late-unknown@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(
        OrganizationData(slug="finalize-late-unknown", name="Finalize Late Unknown"),
    )
    now = datetime.now(tz=UTC)
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email=user.email,
            roles=["member"],
            token_hash=b"finalize-late-unknown".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )
    get_organization_calls = 0

    async def stale_organization_precheck(_organization_id: UUID) -> Organization | None:
        nonlocal get_organization_calls
        get_organization_calls += 1
        await asyncio.sleep(0)
        if get_organization_calls == 1:
            return organization
        return None

    async def flush_integrity_error(_objects: list[object] | None = None) -> None:
        await asyncio.sleep(0)
        msg = "foreign key mismatch"
        raise IntegrityError(msg, params=None, orig=RuntimeError(msg))

    monkeypatch.setattr(store, "get_organization", stale_organization_precheck)
    monkeypatch.setattr(organization_session, "flush", flush_integrity_error)

    with pytest.raises(ValueError, match="unknown organization"):
        await store._finalize_invitation_acceptance(
            invitation.id,
            consumed_at=now,
            membership_data=MembershipData(organization_id=organization.id, user_id=user.id, roles=["member"]),
        )


async def test_sqlalchemy_organization_store_finalize_invitation_acceptance_reraises_unclassified_integrity_error(
    organization_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unhandled finalize integrity failures stay raw for caller-visible diagnostics."""
    user = User(email="finalize-integrity@example.com", hashed_password="hashed-password")
    organization_session.add(user)
    await organization_session.commit()
    store = create_store(organization_session)
    organization = await store.create_organization(
        OrganizationData(slug="finalize-integrity", name="Finalize Integrity"),
    )
    now = datetime.now(tz=UTC)
    invitation = await store.create_invitation(
        OrganizationInvitationData(
            organization_id=organization.id,
            invited_email=user.email,
            roles=["member"],
            token_hash=b"finalize-integrity".ljust(64, b"0"),
            expires_at=now + timedelta(hours=1),
        ),
    )

    async def flush_integrity_error(_objects: list[object] | None = None) -> None:
        await asyncio.sleep(0)
        msg = "unclassified integrity failure"
        raise IntegrityError(msg, params=None, orig=RuntimeError(msg))

    monkeypatch.setattr(organization_session, "flush", flush_integrity_error)

    with pytest.raises(IntegrityError, match="unclassified integrity failure"):
        await store._finalize_invitation_acceptance(
            invitation.id,
            consumed_at=now,
            membership_data=MembershipData(organization_id=organization.id, user_id=user.id, roles=["member"]),
        )


async def test_sqlalchemy_organization_store_rejects_invitation_for_unknown_organization(
    organization_session: AsyncSession,
) -> None:
    """Invitation creation fails closed when the organization does not exist."""
    store = create_store(organization_session)

    with pytest.raises(ValueError, match="unknown organization"):
        await store.create_invitation(
            OrganizationInvitationData(
                organization_id=uuid4(),
                invited_email="missing@example.com",
                roles=["member"],
                token_hash=b"unknown".ljust(64, b"0"),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            ),
        )


def test_sqlalchemy_organization_store_requires_explicit_models(organization_session: AsyncSession) -> None:
    """The adapter constructor requires both SQLAlchemy models as keyword-only inputs."""
    with pytest.raises(TypeError, match="organization_model"):
        cast("Any", SQLAlchemyOrganizationStore)(session=organization_session, membership_model=OrganizationMembership)
    with pytest.raises(TypeError, match="membership_model"):
        cast("Any", SQLAlchemyOrganizationStore)(session=organization_session, organization_model=Organization)


async def test_sqlalchemy_organization_store_invitation_methods_require_model(
    organization_session: AsyncSession,
) -> None:
    """Invitation methods fail explicitly when no invitation model is configured."""
    store = SQLAlchemyOrganizationStore(
        session=organization_session,
        organization_model=Organization,
        membership_model=OrganizationMembership,
    )

    with pytest.raises(TypeError, match="invitation_model"):
        await store.get_invitation_by_token_hash(b"hash".ljust(64, b"0"))


def test_sqlalchemy_organization_store_methods_stay_on_sqlalchemy_module() -> None:
    """The SQLAlchemy adapter keeps admin persistence methods off the root and db packages."""
    assert hasattr(sqlalchemy_module.SQLAlchemyOrganizationStore, "update_organization")
    assert hasattr(sqlalchemy_module.SQLAlchemyOrganizationStore, "delete_organization")
    assert hasattr(sqlalchemy_module.SQLAlchemyOrganizationStore, "set_membership_roles")
    assert hasattr(sqlalchemy_module.SQLAlchemyOrganizationStore, "create_invitation")
    assert not hasattr(litestar_auth, "OrganizationInvitation")
    assert not hasattr(litestar_auth, "SQLAlchemyOrganizationStore")
    assert not hasattr(db_module, "OrganizationInvitation")
    assert not hasattr(db_module, "SQLAlchemyOrganizationStore")
