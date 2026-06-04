"""Abstract persistence contracts for user and OAuth-account storage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class OAuthAccountData:
    """Provider account identity and token fields for OAuth-account persistence."""

    oauth_name: str
    account_id: str
    account_email: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None


@dataclass(frozen=True, slots=True)
class ApiKeyData[ID]:
    """Persistence fields required to create an API-key row."""

    key_id: str
    user_id: ID
    hashed_secret: bytes
    encrypted_secret: bytes | None
    name: str
    scopes: list[str]
    prefix_env: str
    signing_required: bool
    expires_at: datetime | None
    created_via: str
    client_metadata: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class OrganizationData:
    """Persistence fields required to create an organization row."""

    slug: str
    name: str


@dataclass(frozen=True, slots=True)
class MembershipData[ID]:
    """Persistence fields required to create an organization membership row."""

    organization_id: ID
    user_id: ID
    roles: list[str]


@dataclass(frozen=True, slots=True)
class OrganizationInvitationData[ID]:
    """Persistence fields required to create an organization invitation row."""

    organization_id: ID
    invited_email: str
    roles: list[str]
    token_hash: bytes
    expires_at: datetime


@runtime_checkable
class BaseUserStore[UP: UserProtocol[Any], ID](Protocol):
    """Structural CRUD interface for user persistence backends."""

    async def get(self, user_id: ID) -> UP | None:
        """Return the user with the given identifier, if present."""

    async def get_by_email(self, email: str) -> UP | None:
        """Return the user matching the provided email, if present."""

    async def get_by_field(self, field_name: LoginIdentifier, value: str) -> UP | None:
        """Return the user where ``field_name`` equals ``value``, if present.

        ``field_name`` must be ``"email"`` or ``"username"`` (see
        :data:`~litestar_auth.types.LoginIdentifier`). Implementations may perform a
        direct column/attribute lookup. Values outside that set are a
        programming error and may surface as backend-specific errors at
        runtime when callers bypass static typing.
        """

    async def create(self, user_dict: Mapping[str, Any]) -> UP:
        """Persist and return a newly created user."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return paginated users and the total available count."""

    async def update(self, user: UP, update_dict: Mapping[str, Any]) -> UP:
        """Persist and return updates for an existing user."""

    async def delete(self, user_id: ID) -> None:
        """Delete the user identified by ``user_id`` from storage."""


@runtime_checkable
class BaseOAuthAccountStore[UP: UserProtocol[Any], ID](Protocol):
    """Structural contract for linked OAuth-account persistence backends."""

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Return a user linked to the given provider account, if present."""

    async def upsert_oauth_account(
        self,
        user: UP,
        *,
        account: OAuthAccountData,
    ) -> None:
        """Create or update the linked OAuth account for ``user``."""


@runtime_checkable
class BaseApiKeyStore[AK, ID](Protocol):
    """Structural CRUD contract for API-key persistence backends."""

    async def create(self, data: ApiKeyData[ID]) -> AK:
        """Persist and return a newly created API key."""

    async def create_for_user_with_limit(self, data: ApiKeyData[ID], *, max_keys_per_user: int) -> AK | None:
        """Persist an API key only when the user is still below the active-key limit."""

    async def get_by_key_id(self, key_id: str, *, include_inactive: bool = False) -> AK | None:
        """Return an API key by public key id when present and active."""

    async def list_for_user(self, user_id: ID, *, include_inactive: bool = False) -> list[AK]:
        """Return API keys for a user, excluding revoked or expired rows by default."""

    async def delete_for_user(self, user_id: ID) -> int:
        """Permanently delete all API-key rows for ``user_id``.

        Returns:
            Number of rows deleted when the backend can report it, otherwise ``0``.
        """

    async def revoke(self, key_id: str, *, revoked_at: datetime) -> AK | None:
        """Soft-revoke an API key and return the updated row when present."""

    async def update(self, key_id: str, *, name: str | None = None, scopes: list[str] | None = None) -> AK | None:
        """Update mutable API-key metadata and return the updated active row."""

    async def update_last_used_at(self, key_id: str, *, last_used_at: datetime) -> AK | None:
        """Update the last-used timestamp for an active API key."""

    async def list_signing_keys_requiring_reencrypt(
        self,
        requires_reencrypt: Callable[[AK], bool],
        *,
        include_inactive: bool = False,
    ) -> list[AK]:
        """Return signing API-key rows whose encrypted secret needs keyring rotation."""

    async def replace_signing_key_encrypted_secret(self, key_id: str, *, encrypted_secret: bytes) -> AK | None:
        """Replace one signing API-key row's encrypted secret without changing other fields."""


@runtime_checkable
class BaseOrganizationStore[ORG, MEMBERSHIP, INVITATION, ID](Protocol):
    """Structural CRUD contract for organization persistence backends."""

    async def create_organization(self, data: OrganizationData) -> ORG:
        """Persist and return a newly created organization."""

    async def get_organization(self, organization_id: ID) -> ORG | None:
        """Return an organization by primary identifier when present."""

    async def get_organization_by_slug(self, slug: str) -> ORG | None:
        """Return an organization by normalized slug when present."""

    async def update_organization(self, organization_id: ID, data: OrganizationData) -> ORG | None:
        """Persist mutable organization fields and return the updated row when present."""

    async def delete_organization(self, organization_id: ID) -> bool:
        """Delete one organization and report whether a row was removed."""

    async def add_membership(self, data: MembershipData[ID]) -> MEMBERSHIP:
        """Persist and return a user's membership in an organization."""

    async def get_membership(self, *, organization_id: ID, user_id: ID) -> MEMBERSHIP | None:
        """Return the exact organization membership for ``user_id`` when present."""

    async def list_memberships(self, organization_id: ID, *, offset: int, limit: int) -> tuple[list[MEMBERSHIP], int]:
        """Return paginated memberships for one organization and the total available count."""

    async def remove_membership(self, *, organization_id: ID, user_id: ID) -> bool:
        """Remove the exact organization membership and report whether a row was removed."""

    async def remove_membership_preserving_privileged_member(
        self,
        *,
        organization_id: ID,
        user_id: ID,
        privileged_roles: frozenset[str],
    ) -> bool:
        """Atomically remove a membership without removing the final privileged member.

        Raises:
            ValueError: If removing the row would leave the organization without a privileged member.
        """

    async def set_membership_roles(self, *, organization_id: ID, user_id: ID, roles: list[str]) -> MEMBERSHIP | None:
        """Replace roles on an existing organization membership and return the updated row."""

    async def set_membership_roles_preserving_privileged_member(
        self,
        *,
        organization_id: ID,
        user_id: ID,
        roles: list[str],
        privileged_roles: frozenset[str],
    ) -> MEMBERSHIP | None:
        """Atomically replace roles without demoting the final privileged member.

        Raises:
            ValueError: If replacing roles would leave the organization without a privileged member.
        """

    async def list_organizations_for_user(self, user_id: ID, *, offset: int, limit: int) -> tuple[list[ORG], int]:
        """Return paginated organizations for ``user_id`` and the total available count."""

    async def create_invitation(self, data: OrganizationInvitationData[ID]) -> INVITATION:
        """Persist and return a newly created organization invitation."""

    async def get_invitation_by_token_hash(self, token_hash: bytes) -> INVITATION | None:
        """Return an invitation by token digest when present."""

    async def get_invitation(self, invitation_id: ID) -> INVITATION | None:
        """Return an invitation by primary identifier when present."""

    async def list_pending_invitations(
        self,
        organization_id: ID,
        *,
        now: datetime,
        offset: int,
        limit: int,
    ) -> tuple[list[INVITATION], int]:
        """Return paginated unexpired pending invitations and the total available count."""

    async def revoke_invitation(self, invitation_id: ID) -> INVITATION | None:
        """Mark a pending invitation as revoked and return the updated row."""

    async def consume_invitation(self, invitation_id: ID, *, consumed_at: datetime) -> INVITATION | None:
        """Atomically mark one pending invitation as consumed and return it when successful."""
