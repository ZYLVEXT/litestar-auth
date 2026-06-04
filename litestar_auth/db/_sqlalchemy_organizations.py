"""SQLAlchemy-backed organization store implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, TypedDict, Unpack, cast, override
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from litestar_auth._roles import normalize_role_name, normalize_roles
from litestar_auth.db.base import BaseOrganizationStore, MembershipData, OrganizationData, OrganizationInvitationData

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session
    from sqlalchemy.orm import InstrumentedAttribute

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]
_INVITATION_STATUS_PENDING = "pending"
_INVITATION_STATUS_CONSUMED = "consumed"
_INVITATION_STATUS_REVOKED = "revoked"


class _OrganizationRow(ModelProtocol, Protocol):
    """Structural fields used by the SQLAlchemy organization store."""

    id: UUID
    slug: str
    name: str


class _MembershipRow(ModelProtocol, Protocol):
    """Structural fields used by the SQLAlchemy organization membership store."""

    organization_id: UUID
    user_id: UUID
    roles: list[str]


class _InvitationRow(ModelProtocol, Protocol):
    """Structural fields used by the SQLAlchemy organization invitation store."""

    id: UUID
    organization_id: UUID
    invited_email: str
    roles: list[str]
    token_hash: bytes
    expires_at: datetime
    status: str


class _OrganizationColumnsProtocol(Protocol):
    """SQLAlchemy class-level organization columns consumed by query builders."""

    id: ClassVar[InstrumentedAttribute[UUID]]
    slug: ClassVar[InstrumentedAttribute[str]]


class _MembershipColumnsProtocol(Protocol):
    """SQLAlchemy class-level membership columns consumed by query builders."""

    organization_id: ClassVar[InstrumentedAttribute[UUID]]
    user_id: ClassVar[InstrumentedAttribute[UUID]]


class _InvitationColumnsProtocol(Protocol):
    """SQLAlchemy class-level invitation columns consumed by query builders."""

    id: ClassVar[InstrumentedAttribute[UUID]]
    organization_id: ClassVar[InstrumentedAttribute[UUID]]
    token_hash: ClassVar[InstrumentedAttribute[bytes]]
    expires_at: ClassVar[InstrumentedAttribute[datetime]]
    invited_email: ClassVar[InstrumentedAttribute[str]]
    status: ClassVar[InstrumentedAttribute[str]]


class _OrganizationRowCreateKwargs(TypedDict):
    """Keyword payload used to construct an organization ORM row."""

    slug: str
    name: str


class _MembershipRowCreateKwargs(TypedDict):
    """Keyword payload used to construct an organization-membership ORM row."""

    organization_id: UUID
    user_id: UUID
    roles: list[str]


class _InvitationRowCreateKwargs(TypedDict):
    """Keyword payload used to construct an organization-invitation ORM row."""

    organization_id: UUID
    invited_email: str
    roles: list[str]
    token_hash: bytes
    expires_at: datetime


class _OrganizationRowFactory[ORG: _OrganizationRow](Protocol):
    """Constructor shape used by the organization SQLAlchemy model."""

    def __call__(self, **kwargs: Unpack[_OrganizationRowCreateKwargs]) -> ORG:
        """Return a new organization ORM row."""


class _MembershipRowFactory[MEMBERSHIP: _MembershipRow](Protocol):
    """Constructor shape used by the organization-membership SQLAlchemy model."""

    def __call__(self, **kwargs: Unpack[_MembershipRowCreateKwargs]) -> MEMBERSHIP:
        """Return a new organization-membership ORM row."""


class _InvitationRowFactory[INVITATION: _InvitationRow](Protocol):
    """Constructor shape used by the organization-invitation SQLAlchemy model."""

    def __call__(self, **kwargs: Unpack[_InvitationRowCreateKwargs]) -> INVITATION:
        """Return a new organization-invitation ORM row."""


class _RowcountResult(Protocol):
    """Result shape for SQLAlchemy DML statements that report affected rows."""

    rowcount: int


def _has_privileged_role(roles: object, *, privileged_roles: frozenset[str]) -> bool:
    """Return whether ``roles`` intersects the configured privileged role set."""
    return bool(set(normalize_roles(roles)) & privileged_roles)


def _find_membership[MEMBERSHIP: _MembershipRow](
    memberships: list[MEMBERSHIP],
    *,
    user_id: UUID,
) -> MEMBERSHIP | None:
    """Return the membership row for ``user_id`` from an already-loaded organization row set."""
    for membership in memberships:
        if membership.user_id == user_id:
            return membership
    return None


class SQLAlchemyOrganizationStore[
    ORG: _OrganizationRow,
    MEMBERSHIP: _MembershipRow,
    INVITATION: _InvitationRow,
](
    BaseOrganizationStore[ORG, MEMBERSHIP, INVITATION, UUID],
):
    """Persist organizations and memberships via caller-provided SQLAlchemy models."""

    def __init__(
        self,
        session: AsyncSessionT,
        *,
        organization_model: type[ORG],
        membership_model: type[MEMBERSHIP],
        invitation_model: type[INVITATION] | None = None,
    ) -> None:
        """Initialize the organization store.

        Args:
            session: Async SQLAlchemy session used for all store operations.
            organization_model: SQLAlchemy model implementing the organization-row contract.
            membership_model: SQLAlchemy model implementing the organization-membership-row contract.
            invitation_model: Optional SQLAlchemy model implementing the organization-invitation-row contract.
        """
        self.session = session
        self.organization_model = organization_model
        self.membership_model = membership_model
        self.invitation_model = invitation_model

    def _organization_columns(self) -> type[_OrganizationColumnsProtocol]:
        """Return the organization model as the typed SQLAlchemy column surface."""
        return cast("type[_OrganizationColumnsProtocol]", self.organization_model)

    def _membership_columns(self) -> type[_MembershipColumnsProtocol]:
        """Return the membership model as the typed SQLAlchemy column surface."""
        return cast("type[_MembershipColumnsProtocol]", self.membership_model)

    def _require_invitation_model(self) -> type[INVITATION]:
        """Return the configured invitation model or raise a configuration error.

        Raises:
            TypeError: If no invitation model was configured.
        """
        if self.invitation_model is None:
            msg = "SQLAlchemyOrganizationStore invitation methods require invitation_model."
            raise TypeError(msg)
        return self.invitation_model

    def _invitation_columns(self) -> type[_InvitationColumnsProtocol]:
        """Return the invitation model as the typed SQLAlchemy column surface."""
        return cast("type[_InvitationColumnsProtocol]", self._require_invitation_model())

    @override
    async def create_organization(self, data: OrganizationData) -> ORG:
        """Persist and return a newly created organization.

        Returns:
            Newly persisted organization row.

        Raises:
            ValueError: If the organization slug already exists.
            IntegrityError: If persistence fails for another database constraint.
        """
        organization_model = cast("_OrganizationRowFactory[ORG]", self.organization_model)
        organization = organization_model(slug=data.slug, name=data.name)
        try:
            async with self.session.begin_nested():
                self.session.add(organization)
                await self.session.flush()
        except IntegrityError as exc:
            if await self.get_organization_by_slug(data.slug) is not None:
                msg = "Organization slug already exists."
                raise ValueError(msg) from exc
            raise
        await self.session.refresh(organization)
        return organization

    @override
    async def get_organization(self, organization_id: UUID) -> ORG | None:
        """Return an organization by primary identifier when present."""
        organization_columns = self._organization_columns()
        result = await self.session.execute(
            select(self.organization_model).where(organization_columns.id == organization_id),
        )
        return result.scalar_one_or_none()

    @override
    async def get_organization_by_slug(self, slug: str) -> ORG | None:
        """Return an organization by normalized slug when present."""
        organization_columns = self._organization_columns()
        result = await self.session.execute(select(self.organization_model).where(organization_columns.slug == slug))
        return result.scalar_one_or_none()

    @override
    async def update_organization(self, organization_id: UUID, data: OrganizationData) -> ORG | None:
        """Persist mutable organization fields and return the updated row when present.

        Returns:
            Updated organization row when present, otherwise ``None``.

        Raises:
            ValueError: If the requested slug is already used by a different organization.
            IntegrityError: If persistence fails for another database constraint.
        """
        organization = await self.get_organization(organization_id)
        if organization is None:
            return None

        normalized_slug = normalize_role_name(data.slug)
        slug_owner = await self.get_organization_by_slug(normalized_slug)
        if slug_owner is not None and slug_owner.id != organization_id:
            msg = "Organization slug already exists."
            raise ValueError(msg)

        try:
            async with self.session.begin_nested():
                organization.slug = data.slug
                organization.name = data.name
                await self.session.flush()
        except IntegrityError as exc:
            slug_owner = await self.get_organization_by_slug(normalized_slug)
            if slug_owner is not None and slug_owner.id != organization_id:
                msg = "Organization slug already exists."
                raise ValueError(msg) from exc
            raise
        await self.session.refresh(organization)
        return organization

    @override
    async def delete_organization(self, organization_id: UUID) -> bool:
        """Delete one organization and its memberships in the same transaction.

        Returns:
            ``True`` when one organization row was removed, otherwise ``False``.
        """
        organization_columns = self._organization_columns()
        membership_columns = self._membership_columns()
        await self.session.execute(
            delete(self.membership_model).where(membership_columns.organization_id == organization_id),
        )
        result = await self.session.execute(
            delete(self.organization_model).where(organization_columns.id == organization_id),
        )
        await self.session.flush()
        return int(getattr(result, "rowcount", 0) or 0) == 1

    @override
    async def add_membership(self, data: MembershipData[UUID]) -> MEMBERSHIP:
        """Persist and return a user's membership in an organization.

        Returns:
            Newly persisted organization-membership row.

        Raises:
            ValueError: If the organization is unknown or the membership already exists.
            IntegrityError: If persistence fails for another database constraint.
        """
        if await self.get_organization(data.organization_id) is None:
            msg = "Cannot add membership for an unknown organization."
            raise ValueError(msg)
        if await self.get_membership(organization_id=data.organization_id, user_id=data.user_id) is not None:
            msg = "Organization membership already exists."
            raise ValueError(msg)

        membership_model = cast("_MembershipRowFactory[MEMBERSHIP]", self.membership_model)
        membership = membership_model(
            organization_id=data.organization_id,
            user_id=data.user_id,
            roles=list(data.roles),
        )
        try:
            async with self.session.begin_nested():
                self.session.add(membership)
                await self.session.flush()
        except IntegrityError as exc:
            if await self.get_membership(organization_id=data.organization_id, user_id=data.user_id) is not None:
                msg = "Organization membership already exists."
                raise ValueError(msg) from exc
            if await self.get_organization(data.organization_id) is None:
                msg = "Cannot add membership for an unknown organization."
                raise ValueError(msg) from exc
            raise
        await self.session.refresh(membership)
        return membership

    @override
    async def get_membership(self, *, organization_id: UUID, user_id: UUID) -> MEMBERSHIP | None:
        """Return the exact organization membership for ``user_id`` when present."""
        membership_columns = self._membership_columns()
        result = await self.session.execute(
            select(self.membership_model).where(
                membership_columns.organization_id == organization_id,
                membership_columns.user_id == user_id,
            ),
        )
        return result.scalar_one_or_none()

    @override
    async def list_memberships(self, organization_id: UUID, *, offset: int, limit: int) -> tuple[list[MEMBERSHIP], int]:
        """Return paginated memberships for one organization and the total available count."""
        membership_columns = self._membership_columns()
        total_result = await self.session.execute(
            select(func.count())
            .select_from(self.membership_model)
            .where(
                membership_columns.organization_id == organization_id,
            ),
        )
        result = await self.session.execute(
            select(self.membership_model)
            .where(membership_columns.organization_id == organization_id)
            .order_by(membership_columns.user_id)
            .offset(offset)
            .limit(limit),
        )
        return list(result.scalars().all()), total_result.scalar_one()

    @override
    async def remove_membership(self, *, organization_id: UUID, user_id: UUID) -> bool:
        """Remove the exact organization membership and report whether a row was removed.

        Returns:
            ``True`` when one row was removed, otherwise ``False``.
        """
        membership_columns = self._membership_columns()
        result = await self.session.execute(
            delete(self.membership_model).where(
                membership_columns.organization_id == organization_id,
                membership_columns.user_id == user_id,
            ),
        )
        await self.session.flush()
        return int(getattr(result, "rowcount", 0) or 0) == 1

    @override
    async def remove_membership_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        privileged_roles: frozenset[str],
    ) -> bool:
        """Remove a membership after locking peer rows for final-privileged-member checks.

        Returns:
            ``True`` when one row was removed, otherwise ``False``.
        """
        async with self.session.begin_nested():
            memberships = await self._locked_organization_memberships(organization_id)
            target = _find_membership(memberships, user_id=user_id)
            if target is None:
                return False
            self._raise_if_final_privileged_member(
                target,
                memberships=memberships,
                privileged_roles=privileged_roles,
            )
            membership_columns = self._membership_columns()
            result = await self.session.execute(
                delete(self.membership_model).where(
                    membership_columns.organization_id == organization_id,
                    membership_columns.user_id == user_id,
                ),
            )
            await self.session.flush()
            return int(getattr(result, "rowcount", 0) or 0) == 1

    @override
    async def set_membership_roles(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
    ) -> MEMBERSHIP | None:
        """Replace roles on an existing organization membership and return the updated row.

        Returns:
            Updated membership row when present, otherwise ``None``.
        """
        membership = await self.get_membership(organization_id=organization_id, user_id=user_id)
        if membership is None:
            return None

        membership.roles = list(roles)
        await self.session.flush()
        await self.session.refresh(membership)
        return membership

    @override
    async def set_membership_roles_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
        privileged_roles: frozenset[str],
    ) -> MEMBERSHIP | None:
        """Replace roles after locking peer rows for final-privileged-member checks.

        Returns:
            Updated membership row when present, otherwise ``None``.
        """
        async with self.session.begin_nested():
            memberships = await self._locked_organization_memberships(organization_id)
            membership = _find_membership(memberships, user_id=user_id)
            if membership is None:
                return None
            if _has_privileged_role(membership.roles, privileged_roles=privileged_roles) and not _has_privileged_role(
                roles,
                privileged_roles=privileged_roles,
            ):
                self._raise_if_final_privileged_member(
                    membership,
                    memberships=memberships,
                    privileged_roles=privileged_roles,
                )
            membership.roles = list(roles)
            await self.session.flush()
        await self.session.refresh(membership)
        return membership

    async def _locked_organization_memberships(self, organization_id: UUID) -> list[MEMBERSHIP]:
        """Return organization memberships under a row lock when the database supports it."""
        membership_columns = self._membership_columns()
        result = await self.session.execute(
            select(self.membership_model)
            .where(membership_columns.organization_id == organization_id)
            .with_for_update(),
        )
        return list(result.scalars().all())

    @staticmethod
    def _raise_if_final_privileged_member(
        target: MEMBERSHIP,
        *,
        memberships: list[MEMBERSHIP],
        privileged_roles: frozenset[str],
    ) -> None:
        """Reject removing or demoting the last locked privileged membership.

        Raises:
            ValueError: If the operation would remove or demote the final privileged member.
        """
        if not _has_privileged_role(target.roles, privileged_roles=privileged_roles):
            return
        privileged_count = sum(
            1 for membership in memberships if _has_privileged_role(membership.roles, privileged_roles=privileged_roles)
        )
        if privileged_count > 1:
            return
        msg = "Cannot remove or demote the final privileged organization member."
        raise ValueError(msg)

    @override
    async def list_organizations_for_user(self, user_id: UUID, *, offset: int, limit: int) -> tuple[list[ORG], int]:
        """Return paginated organizations for ``user_id`` and the total available count."""
        organization_columns = self._organization_columns()
        membership_columns = self._membership_columns()
        total_result = await self.session.execute(
            select(func.count())
            .select_from(self.organization_model)
            .join(self.membership_model, membership_columns.organization_id == organization_columns.id)
            .where(membership_columns.user_id == user_id),
        )
        result = await self.session.execute(
            select(self.organization_model)
            .join(self.membership_model, membership_columns.organization_id == organization_columns.id)
            .where(membership_columns.user_id == user_id)
            .order_by(organization_columns.slug)
            .offset(offset)
            .limit(limit),
        )
        return list(result.scalars().all()), total_result.scalar_one()

    @override
    async def create_invitation(self, data: OrganizationInvitationData[UUID]) -> INVITATION:
        """Persist and return a newly created organization invitation.

        Returns:
            Newly persisted organization-invitation row.

        Raises:
            ValueError: If the organization is unknown.
        """
        if await self.get_organization(data.organization_id) is None:
            msg = "Cannot create invitation for an unknown organization."
            raise ValueError(msg)

        invitation_model = cast("_InvitationRowFactory[INVITATION]", self._require_invitation_model())
        invitation = invitation_model(
            organization_id=data.organization_id,
            invited_email=data.invited_email,
            roles=list(data.roles),
            token_hash=data.token_hash,
            expires_at=data.expires_at,
        )
        self.session.add(invitation)
        await self.session.flush()
        await self.session.refresh(invitation)
        return invitation

    @override
    async def get_invitation_by_token_hash(self, token_hash: bytes) -> INVITATION | None:
        """Return an invitation by token digest when present."""
        invitation_model = self._require_invitation_model()
        invitation_columns = self._invitation_columns()
        result = await self.session.execute(
            select(invitation_model).where(invitation_columns.token_hash == token_hash),
        )
        return result.scalar_one_or_none()

    @override
    async def get_invitation(self, invitation_id: UUID) -> INVITATION | None:
        """Return an invitation by primary identifier when present."""
        invitation_model = self._require_invitation_model()
        invitation_columns = self._invitation_columns()
        result = await self.session.execute(
            select(invitation_model).where(invitation_columns.id == invitation_id),
        )
        return result.scalar_one_or_none()

    @override
    async def list_pending_invitations(
        self,
        organization_id: UUID,
        *,
        now: datetime,
        offset: int,
        limit: int,
    ) -> tuple[list[INVITATION], int]:
        """Return paginated unexpired pending invitations and the total available count."""
        invitation_model = self._require_invitation_model()
        invitation_columns = self._invitation_columns()
        filters = (
            invitation_columns.organization_id == organization_id,
            invitation_columns.status == _INVITATION_STATUS_PENDING,
            invitation_columns.expires_at > now,
        )
        total_result = await self.session.execute(select(func.count()).select_from(invitation_model).where(*filters))
        result = await self.session.execute(
            select(invitation_model)
            .where(*filters)
            .order_by(invitation_columns.invited_email)
            .offset(offset)
            .limit(limit),
        )
        return list(result.scalars().all()), total_result.scalar_one()

    @override
    async def revoke_invitation(self, invitation_id: UUID) -> INVITATION | None:
        """Mark a pending invitation as revoked and return the updated row.

        Returns:
            Updated invitation row when a pending invitation was revoked, otherwise ``None``.
        """
        return await self._transition_invitation(
            invitation_id,
            status=_INVITATION_STATUS_REVOKED,
        )

    @override
    async def consume_invitation(self, invitation_id: UUID, *, consumed_at: datetime) -> INVITATION | None:
        """Atomically mark one pending invitation as consumed and return it when successful.

        Returns:
            Updated invitation row when a pending unexpired invitation was consumed, otherwise ``None``.
        """
        return await self._transition_invitation(
            invitation_id,
            status=_INVITATION_STATUS_CONSUMED,
            unexpired_after=consumed_at,
        )

    async def _finalize_invitation_acceptance(
        self,
        invitation_id: UUID,
        *,
        consumed_at: datetime,
        membership_data: MembershipData[UUID],
    ) -> MEMBERSHIP | None:
        """Consume one pending invitation and create membership in a single savepoint.

        Returns:
            Newly created membership when both steps succeed, otherwise ``None``.

        Raises:
            ValueError: If membership validation fails before persistence.
            IntegrityError: If persistence fails for another database constraint.
        """
        if await self.get_organization(membership_data.organization_id) is None:
            msg = "Cannot add membership for an unknown organization."
            raise ValueError(msg)
        if (
            await self.get_membership(
                organization_id=membership_data.organization_id,
                user_id=membership_data.user_id,
            )
            is not None
        ):
            msg = "Organization membership already exists."
            raise ValueError(msg)

        membership_model = cast("_MembershipRowFactory[MEMBERSHIP]", self.membership_model)
        membership = membership_model(
            organization_id=membership_data.organization_id,
            user_id=membership_data.user_id,
            roles=list(membership_data.roles),
        )
        try:
            async with self.session.begin_nested():
                inserted = await self._consume_and_insert_membership_in_savepoint(
                    invitation_id,
                    consumed_at=consumed_at,
                    membership_data=membership_data,
                    membership=membership,
                )
            if inserted is None:
                return None
        except IntegrityError as exc:
            if (
                await self.get_membership(
                    organization_id=membership_data.organization_id,
                    user_id=membership_data.user_id,
                )
                is not None
            ):
                msg = "Organization membership already exists."
                raise ValueError(msg) from exc
            if await self.get_organization(membership_data.organization_id) is None:
                msg = "Cannot add membership for an unknown organization."
                raise ValueError(msg) from exc
            raise

        await self.session.refresh(membership)
        return membership

    async def _consume_and_insert_membership_in_savepoint(
        self,
        invitation_id: UUID,
        *,
        consumed_at: datetime,
        membership_data: MembershipData[UUID],
        membership: MEMBERSHIP,
    ) -> MEMBERSHIP | None:
        consumed = await self._transition_invitation(
            invitation_id,
            status=_INVITATION_STATUS_CONSUMED,
            unexpired_after=consumed_at,
        )
        if consumed is None:
            return None
        if consumed.organization_id != membership_data.organization_id:
            msg = "Invitation organization mismatch."
            raise ValueError(msg)
        self.session.add(membership)
        await self.session.flush()
        return membership

    async def _transition_invitation(
        self,
        invitation_id: UUID,
        *,
        status: str,
        unexpired_after: datetime | None = None,
    ) -> INVITATION | None:
        """Conditionally update one pending invitation status and return the refreshed row.

        Returns:
            Refreshed invitation row when the transition was applied, otherwise ``None``.
        """
        invitation_model = self._require_invitation_model()
        invitation_columns = self._invitation_columns()
        statement = (
            update(invitation_model)
            .where(invitation_columns.id == invitation_id)
            .where(invitation_columns.status == _INVITATION_STATUS_PENDING)
            .values(status=status)
            .execution_options(synchronize_session=False)
        )
        if unexpired_after is not None:
            statement = statement.where(invitation_columns.expires_at > unexpired_after)
        result = await self.session.execute(statement)
        if cast("_RowcountResult", result).rowcount != 1:
            return None

        await self.session.flush()
        refreshed = await self.session.execute(
            select(invitation_model)
            .where(invitation_columns.id == invitation_id)
            .execution_options(populate_existing=True),
        )
        return refreshed.scalar_one_or_none()
