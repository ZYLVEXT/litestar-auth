"""Shared typing primitives and authentication protocols.

Protocol selection (abbreviated)
--------------------------------
Implement the narrowest protocol that matches the features you use:

| Feature area | Required protocol |
|--------------|-------------------|
| Basic authentication (identity in strategies, ``User`` typing) | ``UserProtocol`` — ``id`` |
| ``is_active``, ``is_verified`` guards | ``GuardedUserProtocol`` — account state booleans |
| ``is_superuser``, ``has_any_role``, ``has_all_roles`` guards | ``RoleCapableUserProtocol`` — flat ``roles`` |
| TOTP enrollment / verification | ``TotpUserProtocol`` — ``email``, ``totp_secret`` |

``UserProtocol`` remains ``@runtime_checkable`` so runtime guard code can use ``isinstance(...)``.
Use ``UserProtocolStrict`` for static-typing-only contracts where no runtime check is needed; avoiding
``@runtime_checkable`` keeps the protocol's stricter static intent clear and avoids protocol runtime-check overhead.

The full decision table, guard cross-links, and a multi-protocol model example are in
``docs/api/types.md`` (API → Types in the built docs).
"""

from __future__ import annotations

import keyword
from collections.abc import Hashable
from typing import TYPE_CHECKING, Annotated, Any, Literal, Protocol, TypeVar, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.connection import ASGIConnection
    from litestar.response import Response

ID = TypeVar("ID", bound=Hashable)


def _valid_python_identifier_validator(value: str) -> str:
    """Return ``value`` when it is a valid non-keyword Python identifier.

    Raises:
        ValueError: When ``value`` is not a valid identifier or is a reserved keyword.
    """
    if not value.isidentifier() or keyword.iskeyword(value):
        msg = (
            "db_session_dependency_key must be a valid Python identifier because Litestar matches dependency "
            f"keys to callable parameter names, got {value!r}"
        )
        raise ValueError(msg)
    return value


type DbSessionDependencyKey = Annotated[str, _valid_python_identifier_validator]


class UserProtocolStrict(Protocol[ID]):
    """Static-only protocol for user models handled by the library.

    Prefer this variant for annotations and TypeVar bounds that do not need ``isinstance(...)`` checks.
    """

    id: ID


@runtime_checkable
class UserProtocol(UserProtocolStrict[ID], Protocol[ID]):
    """Runtime-checkable protocol for user models handled by the library.

    This variant supports ``isinstance(...)`` checks, which are convenient at runtime but slower and less precise
    than static protocol validation. Use :class:`UserProtocolStrict` when runtime checks are unnecessary.
    """


@runtime_checkable
class GuardedUserProtocol(UserProtocol[ID], Protocol[ID]):
    """Protocol for user models that support account-state guards."""

    is_active: bool
    is_verified: bool


@runtime_checkable
class RoleCapableUserProtocol(UserProtocol[ID], Protocol[ID]):
    """Protocol for user models that expose normalized flat role membership."""

    roles: Sequence[str]


@runtime_checkable
class TotpUserProtocol(UserProtocol[ID], Protocol[ID]):
    """Protocol for user models that support TOTP 2FA."""

    email: str
    totp_secret: str | None


UP = TypeVar("UP", bound=UserProtocol)


@runtime_checkable
class TransportProtocol(Protocol):
    """Protocol describing how auth tokens move in and out of requests."""

    async def read_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Extract a login token from an incoming connection."""

    def set_login_token(self, response: Response[Any], token: str) -> Response[Any]:
        """Persist a login token on an outgoing response."""

    def set_logout(self, response: Response[Any]) -> Response[Any]:
        """Clear any transport-specific authentication state."""


@runtime_checkable
class StrategyProtocol(Protocol[UP, ID]):
    """Protocol describing how auth tokens map to users."""

    async def read_token(self, token: str | None, user_manager: object) -> UP | None:
        """Resolve a user from a transport token."""

    async def write_token(self, user: UP) -> str:
        """Create a token for a given user."""

    async def destroy_token(self, token: str, user: UP) -> None:
        """Invalidate a token for strategies that keep server-side state."""


type LoginIdentifier = Literal["email", "username"]
