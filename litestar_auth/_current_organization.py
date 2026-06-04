"""Request-scope helpers for the verified current organization context."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

CURRENT_ORGANIZATION_CONTEXT_SENTINEL = "litestar_auth.current_organization_context"

__all__ = (
    "CURRENT_ORGANIZATION_CONTEXT_SENTINEL",
    "CurrentOrganizationContext",
    "clear_scope_current_organization_context",
    "read_scope_current_organization_context",
    "set_scope_current_organization_context",
)


@dataclass(frozen=True, slots=True)
class CurrentOrganizationContext[ORG, MEMBERSHIP]:
    """Verified organization and membership for the authenticated request user."""

    organization: ORG
    membership: MEMBERSHIP


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
