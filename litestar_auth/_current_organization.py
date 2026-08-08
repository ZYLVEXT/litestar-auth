"""Request-scope helpers for the verified current organization context."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from litestar.connection import ASGIConnection

CURRENT_ORGANIZATION_CONTEXT_SENTINEL = "litestar_auth.current_organization_context"

__all__ = (
    "CURRENT_ORGANIZATION_CONTEXT_SENTINEL",
    "CurrentOrganizationContext",
    "ElevatedMembershipResolver",
    "clear_scope_current_organization_context",
    "current_organization_is_elevated",
    "read_scope_current_organization_context",
    "set_scope_current_organization_context",
)


@dataclass(frozen=True, slots=True)
class CurrentOrganizationContext[ORG, MEMBERSHIP]:
    """Verified organization and membership for the authenticated request user."""

    organization: ORG
    membership: MEMBERSHIP
    elevated: bool = False
    """``True`` when the application supplied this membership instead of the store returning one.

    Stored membership and application-granted access carry the same permissions on purpose, so
    guards stay simple. They are not the same event to an auditor: one is a member acting in their
    own organization, the other is an operator acting in someone else's. Attribution needs to tell
    them apart, so the request records which it was.
    """


class ElevatedMembershipResolver[ORG, MEMBERSHIP](Protocol):
    """Request seam for granting organization access to a user with no stored membership.

    Called only after the store reports no membership, so it can never widen a member's own
    authority. Returning ``None`` leaves the request without organization context, which is the
    default and keeps the unconfigured path fail-closed.

    Who deserves elevated access, and under which organization roles, is authorization policy the
    application owns; this library only carries the answer and marks it as elevated.
    """

    def __call__(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        *,
        organization: ORG,
        user: object,
    ) -> Awaitable[MEMBERSHIP | None]:
        """Return a membership granting access to ``organization``, or ``None`` to refuse."""
        ...


def set_scope_current_organization_context(scope: object, context: CurrentOrganizationContext[Any, Any]) -> None:
    """Store a verified current-organization context on ASGI request scope state."""
    mutable_scope = cast("MutableMapping[str, Any]", scope)
    state = cast("MutableMapping[str, Any]", mutable_scope.setdefault("state", {}))
    state[CURRENT_ORGANIZATION_CONTEXT_SENTINEL] = context


def clear_scope_current_organization_context(scope: object) -> None:
    """Remove any current-organization context from ASGI request scope state."""
    mutable_scope = cast("MutableMapping[str, Any]", scope)
    scope_state = mutable_scope.get("state")
    if isinstance(scope_state, MutableMapping):
        scope_state.pop(CURRENT_ORGANIZATION_CONTEXT_SENTINEL, None)


def read_scope_current_organization_context(
    connection: ASGIConnection[Any, Any, Any, Any],
) -> CurrentOrganizationContext[Any, Any] | None:
    """Return the verified current-organization context for the request, if present."""
    scope_state = connection.scope.get("state")
    if not isinstance(scope_state, Mapping):
        return None

    context = scope_state.get(CURRENT_ORGANIZATION_CONTEXT_SENTINEL)
    if isinstance(context, CurrentOrganizationContext):
        return context
    return None


def current_organization_is_elevated(connection: ASGIConnection[Any, Any, Any, Any]) -> bool:
    """Return whether organization access came from the elevation resolver, not stored membership.

    Intended for audit attribution: a request that answers ``True`` is an operator acting inside an
    organization they do not belong to. A request with no organization context answers ``False``,
    because there is no elevated access to report.
    """
    context = read_scope_current_organization_context(connection)
    return context is not None and context.elevated
