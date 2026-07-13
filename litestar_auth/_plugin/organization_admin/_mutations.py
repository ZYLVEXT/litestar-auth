"""Mutation helpers for organization administration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from litestar_auth._email import normalize_email
from litestar_auth._roles import normalize_role_name, normalize_roles
from litestar_auth.db import MembershipData, OrganizationData, OrganizationInvitationData
from litestar_auth.exceptions import (
    InvalidOrganizationInvitationTokenError,
    OrganizationAlreadyExistsError,
    OrganizationInvitationEmailMismatchError,
    OrganizationLastPrivilegedMemberError,
    OrganizationMembershipAlreadyExistsError,
    OrganizationMembershipNotFoundError,
    OrganizationNotFoundError,
)

if TYPE_CHECKING:
    from litestar_auth._manager.account_tokens import OrganizationInvitationLookupStore

_PENDING_INVITATION_REVOKE_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class OrganizationInvitationIssue[INVITATION]:
    """New invitation row and the one-time raw token for out-of-band delivery."""

    invitation: INVITATION
    token: str


class _OrganizationInvitationToken(Protocol):
    """Signed organization-invitation token material from the manager service."""

    @property
    def token(self) -> str:
        """Raw invitation token delivered out-of-band."""

    @property
    def token_hash(self) -> bytes:
        """Persisted digest for invitation lookup."""

    @property
    def expires_at(self) -> datetime:
        """Invitation token expiry timestamp."""


class _OrganizationInvitationTokenService(Protocol):
    """Manager token surface required by organization-admin invitations."""

    def write_organization_invitation_token(self, *, issued_at: datetime | None = None) -> _OrganizationInvitationToken:
        """Issue one invitation token and return its persistence digest."""

    async def validate_organization_invitation_token[INVITATION](
        self,
        token: str,
        *,
        organization_store: OrganizationInvitationLookupStore[INVITATION],
        now: datetime | None = None,
    ) -> INVITATION:
        """Return the pending invitation row for a valid signed invitation token."""


class _OrganizationInvitationHookBus(Protocol):
    """Manager hook bus surface required by organization-admin invitations."""

    async def fire(
        self,
        name: Literal["after_organization_invitation"],
        invitation: object,
        token: str,
    ) -> None:
        """Dispatch the organization-invitation delivery hook."""


class _OrganizationInvitationManager(Protocol):
    """Manager surface required to issue and deliver organization invitations."""

    @property
    def tokens(self) -> _OrganizationInvitationTokenService:
        """The account-token service."""

    @property
    def hook_bus(self) -> _OrganizationInvitationHookBus:
        """The manager hook dispatcher."""


class _OrganizationInvitationUser[ID](Protocol):
    """Authenticated user fields required to accept or decline an invitation."""

    @property
    def id(self) -> ID:
        """Authenticated user identifier."""

    @property
    def email(self) -> str:
        """Authenticated user email address."""


def _normalize_invited_email(email: str) -> str:
    """Return the normalized invitation email address."""
    return normalize_email(email)


class _OrganizationAdminMutationMixin[ORG, MEMBERSHIP, INVITATION, ID]:
    """Store-backed organization and membership mutations."""

    async def create_organization(self: Any, *, slug: str, name: str) -> ORG:
        """Create one organization after normalized slug collision checks.

        Returns:
            Newly created organization row.

        Raises:
            OrganizationAlreadyExistsError: If the normalized slug is already assigned.
        """
        normalized_slug = normalize_role_name(slug)
        if await self.store.get_organization_by_slug(normalized_slug) is not None:
            msg = "Organization already exists."
            raise OrganizationAlreadyExistsError(message=msg)
        try:
            return await self.store.create_organization(OrganizationData(slug=normalized_slug, name=name))
        except ValueError as exc:
            msg = "Organization already exists."
            raise OrganizationAlreadyExistsError(message=msg) from exc

    async def update_organization(self: Any, organization_id: ID, *, slug: str, name: str) -> ORG:
        """Update one known organization after normalized slug collision checks.

        Returns:
            Updated organization row.

        Raises:
            OrganizationAlreadyExistsError: If the normalized slug is already assigned.
            OrganizationNotFoundError: If the organization is unknown.
        """
        await self._require_organization(organization_id)
        normalized_slug = normalize_role_name(slug)
        slug_owner = await self.store.get_organization_by_slug(normalized_slug)
        if slug_owner is not None and self.organization_id(slug_owner) != organization_id:
            msg = "Organization already exists."
            raise OrganizationAlreadyExistsError(message=msg)
        try:
            organization = await self.store.update_organization(
                organization_id,
                OrganizationData(slug=normalized_slug, name=name),
            )
        except ValueError as exc:
            msg = "Organization already exists."
            raise OrganizationAlreadyExistsError(message=msg) from exc
        if organization is None:
            msg = "Organization not found."
            raise OrganizationNotFoundError(message=msg)
        return organization

    async def delete_organization(self: Any, organization_id: ID) -> None:
        """Delete one known organization and its memberships.

        Raises:
            OrganizationNotFoundError: If the organization is unknown.
        """
        await self._require_organization(organization_id)
        deleted = await self.store.delete_organization(organization_id)
        if not deleted:
            msg = "Organization not found."
            raise OrganizationNotFoundError(message=msg)

    async def add_member(self: Any, *, organization_id: ID, user_id: ID, roles: object) -> MEMBERSHIP:
        """Add one user membership to a known organization.

        Returns:
            Newly created membership row.

        Raises:
            OrganizationMembershipAlreadyExistsError: If the user is already a member.
            OrganizationNotFoundError: If the organization is unknown.
        """
        await self._require_organization(organization_id)
        if await self.store.get_membership(organization_id=organization_id, user_id=user_id) is not None:
            msg = "Organization membership already exists."
            raise OrganizationMembershipAlreadyExistsError(message=msg)
        normalized_roles = normalize_roles(roles)
        try:
            return await self.store.add_membership(
                MembershipData(organization_id=organization_id, user_id=user_id, roles=normalized_roles),
            )
        except ValueError as exc:
            if await self.store.get_membership(organization_id=organization_id, user_id=user_id) is not None:
                msg = "Organization membership already exists."
                raise OrganizationMembershipAlreadyExistsError(message=msg) from exc
            msg = "Organization not found."
            raise OrganizationNotFoundError(message=msg) from exc

    async def remove_member(self: Any, *, organization_id: ID, user_id: ID) -> None:
        """Remove one existing membership without orphaning privileged administration.

        Raises:
            OrganizationLastPrivilegedMemberError: If this would remove the final privileged member.
            OrganizationMembershipNotFoundError: If the membership is unknown.
        """
        await self._require_membership(organization_id=organization_id, user_id=user_id)
        try:
            removed = await self.store.remove_membership_preserving_privileged_member(
                organization_id=organization_id,
                user_id=user_id,
                privileged_roles=self.privileged_role_names,
            )
        except ValueError as exc:
            msg = "Organization admin will not remove the final privileged organization member."
            raise OrganizationLastPrivilegedMemberError(message=msg) from exc
        if not removed:
            msg = "Organization membership not found."
            raise OrganizationMembershipNotFoundError(message=msg)

    async def set_member_roles(self: Any, *, organization_id: ID, user_id: ID, roles: object) -> MEMBERSHIP:
        """Replace roles on an existing membership while preserving privileged access.

        Returns:
            Updated membership row.

        Raises:
            OrganizationLastPrivilegedMemberError: If this would demote the final privileged member.
            OrganizationMembershipNotFoundError: If the membership is unknown.
        """
        await self._require_membership(organization_id=organization_id, user_id=user_id)
        normalized_roles = normalize_roles(roles)
        try:
            membership = await self.store.set_membership_roles_preserving_privileged_member(
                organization_id=organization_id,
                user_id=user_id,
                roles=normalized_roles,
                privileged_roles=self.privileged_role_names,
            )
        except ValueError as exc:
            msg = "Organization admin will not demote the final privileged organization member."
            raise OrganizationLastPrivilegedMemberError(message=msg) from exc
        if membership is None:
            msg = "Organization membership not found."
            raise OrganizationMembershipNotFoundError(message=msg)
        return membership

    async def invite_member(
        self: Any,
        *,
        organization_id: ID,
        invited_email: str,
        roles: object,
        user_manager: _OrganizationInvitationManager,
    ) -> OrganizationInvitationIssue[INVITATION]:
        """Create one organization invitation and dispatch the delivery hook.

        Existing unexpired pending invitations for the same organization and
        normalized email are revoked before the new invitation is persisted.
        The raw token is returned and sent through the manager hook exactly
        once; only its digest is stored.

        Returns:
            Invitation row and raw token for out-of-band delivery.

        Raises:
            OrganizationNotFoundError: If the organization is unknown.
        """
        await self._require_organization(organization_id)
        normalized_email = _normalize_invited_email(invited_email)
        normalized_roles = normalize_roles(roles)
        now = datetime.now(tz=UTC)
        await self._revoke_matching_pending_invitations(
            organization_id=organization_id,
            invited_email=normalized_email,
            now=now,
        )
        issued = user_manager.tokens.write_organization_invitation_token(issued_at=now)
        try:
            invitation: INVITATION = await self.store.create_invitation(
                OrganizationInvitationData(
                    organization_id=organization_id,
                    invited_email=normalized_email,
                    roles=normalized_roles,
                    token_hash=issued.token_hash,
                    expires_at=issued.expires_at,
                ),
            )
        except ValueError as exc:
            msg = "Organization not found."
            raise OrganizationNotFoundError(message=msg) from exc

        await user_manager.hook_bus.fire("after_organization_invitation", invitation, issued.token)
        return OrganizationInvitationIssue(invitation=invitation, token=issued.token)

    async def accept_invitation(
        self: Any,
        *,
        token: str,
        user: _OrganizationInvitationUser[ID],
        user_manager: _OrganizationInvitationManager,
    ) -> MEMBERSHIP:
        """Consume a valid invitation for the authenticated invitee and create membership.

        Returns:
            Newly created membership with the invitation's organization-scoped roles.

        Raises:
            InvalidOrganizationInvitationTokenError: If the token is invalid or acceptance cannot complete.
        """
        now = datetime.now(tz=UTC)
        invitation: INVITATION = await user_manager.tokens.validate_organization_invitation_token(
            token,
            organization_store=self.store,
            now=now,
        )
        _require_matching_invitee(user, invitation)
        invitation_id = cast("Any", invitation).id
        membership_data = MembershipData(
            organization_id=cast("Any", invitation).organization_id,
            user_id=user.id,
            roles=list(cast("Any", invitation).roles),
        )
        finalize = getattr(self.store, "_finalize_invitation_acceptance", None)
        if finalize is not None:
            try:
                membership = await finalize(
                    invitation_id,
                    consumed_at=now,
                    membership_data=membership_data,
                )
            except ValueError as exc:
                raise InvalidOrganizationInvitationTokenError from exc
            if membership is None:
                raise InvalidOrganizationInvitationTokenError
            return membership

        consumed = await self.store.consume_invitation(invitation_id, consumed_at=now)
        if consumed is None:
            raise InvalidOrganizationInvitationTokenError
        try:
            return await self.store.add_membership(membership_data)
        except ValueError as exc:
            raise InvalidOrganizationInvitationTokenError from exc

    async def decline_invitation(
        self: Any,
        *,
        token: str,
        user: _OrganizationInvitationUser[ID],
        user_manager: _OrganizationInvitationManager,
    ) -> None:
        """Revoke a valid invitation for the authenticated invitee.

        Raises:
            InvalidOrganizationInvitationTokenError: If the token or invitation row cannot be used.
        """
        now = datetime.now(tz=UTC)
        invitation: INVITATION = await user_manager.tokens.validate_organization_invitation_token(
            token,
            organization_store=self.store,
            now=now,
        )
        _require_matching_invitee(user, invitation)
        invitation_id = cast("Any", invitation).id
        declined = await self.store.revoke_invitation(invitation_id)
        if declined is None:
            raise InvalidOrganizationInvitationTokenError

    async def _revoke_matching_pending_invitations(
        self: Any,
        *,
        organization_id: ID,
        invited_email: str,
        now: datetime,
    ) -> None:
        """Supersede pending invitations for one normalized email."""
        offset = 0
        invitation_ids_to_revoke: list[ID] = []
        while True:
            invitations, total = await self.store.list_pending_invitations(
                organization_id,
                now=now,
                offset=offset,
                limit=_PENDING_INVITATION_REVOKE_PAGE_SIZE,
            )
            invitation_ids_to_revoke.extend(
                invitation.id for invitation in invitations if invitation.invited_email == invited_email
            )
            offset += len(invitations)
            if offset >= total or not invitations:
                break
        for invitation_id in invitation_ids_to_revoke:
            await self.store.revoke_invitation(invitation_id)

    async def list_pending_invitations(
        self: Any,
        organization_id: ID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[INVITATION], int]:
        """Return paginated pending invitations for a known organization and the total available count."""
        await self._require_organization(organization_id)
        return await self.store.list_pending_invitations(
            organization_id,
            now=datetime.now(tz=UTC),
            offset=offset,
            limit=limit,
        )

    async def get_invitation(self: Any, invitation_id: ID) -> INVITATION | None:
        """Return one invitation row by id, or ``None`` when unknown.

        Returns the raw row without raising so callers can make authority
        decisions (e.g. path-organization checks) before acting on it.
        """
        return await self.store.get_invitation(invitation_id)

    async def revoke_invitation(self: Any, invitation_id: ID) -> INVITATION:
        """Revoke one pending organization invitation or fail closed.

        Returns:
            Revoked invitation row.

        Raises:
            InvalidOrganizationInvitationTokenError: If the invitation is unknown or no longer pending.
        """
        invitation = await self.store.revoke_invitation(invitation_id)
        if invitation is None:
            raise InvalidOrganizationInvitationTokenError
        return invitation


def _require_matching_invitee(user: object, invitation: object) -> None:
    """Reject invitation use when the authenticated email does not match.

    Raises:
        OrganizationInvitationEmailMismatchError: If either email is unavailable, invalid, or different.
    """
    invited_email = getattr(invitation, "invited_email", None)
    user_email = getattr(user, "email", None)
    if not isinstance(invited_email, str) or not isinstance(user_email, str):
        raise OrganizationInvitationEmailMismatchError
    try:
        normalized_user_email = _normalize_invited_email(user_email)
    except ValueError as exc:
        raise OrganizationInvitationEmailMismatchError from exc
    if normalized_user_email != invited_email:
        raise OrganizationInvitationEmailMismatchError
