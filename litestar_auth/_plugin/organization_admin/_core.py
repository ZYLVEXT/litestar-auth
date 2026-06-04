"""Store-backed organization administration operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from litestar_auth._plugin.organization_admin._invariants import _OrganizationAdminInvariantMixin
from litestar_auth._plugin.organization_admin._mutations import (
    OrganizationInvitationIssue,
    _OrganizationAdminMutationMixin,
)
from litestar_auth._plugin.organization_admin._queries import _OrganizationAdminQueryMixin

if TYPE_CHECKING:
    from litestar_auth.db import BaseOrganizationStore

__all__ = ("DEFAULT_PRIVILEGED_ORGANIZATION_ROLES", "OrganizationInvitationIssue", "SQLAlchemyOrganizationAdmin")

DEFAULT_PRIVILEGED_ORGANIZATION_ROLES = frozenset({"admin", "owner"})


class _OrganizationIdentity(Protocol):
    """Minimal organization row surface used by collision checks."""

    id: object


class _MembershipRoles(Protocol):
    """Minimal membership row surface used by read-model helpers."""

    roles: list[str]


@dataclass(slots=True)
class SQLAlchemyOrganizationAdmin[ORG, MEMBERSHIP, INVITATION, ID](
    _OrganizationAdminMutationMixin[ORG, MEMBERSHIP, INVITATION, ID],
    _OrganizationAdminInvariantMixin[ORG, MEMBERSHIP, ID],
    _OrganizationAdminQueryMixin[ORG, MEMBERSHIP, ID],
):
    """Operations layer for organization administration over a configured store."""

    store: BaseOrganizationStore[ORG, MEMBERSHIP, INVITATION, ID]
    privileged_role_names: frozenset[str] = DEFAULT_PRIVILEGED_ORGANIZATION_ROLES

    @staticmethod
    def organization_id(organization: object) -> object:
        """Return the primary identifier from an organization row."""
        return cast("_OrganizationIdentity", organization).id

    @staticmethod
    def membership_roles(membership: object) -> list[str]:
        """Return the normalized role snapshot from a membership row."""
        return list(cast("_MembershipRoles", membership).roles)
