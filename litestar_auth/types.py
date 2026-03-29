"""Shared typing primitives and authentication protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeVar, runtime_checkable

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.response import Response

ID = TypeVar("ID")


@runtime_checkable
class UserProtocol(Protocol[ID]):
    """Protocol for user models handled by the library."""

    id: ID


@runtime_checkable
class GuardedUserProtocol(UserProtocol[ID], Protocol[ID]):
    """Protocol for user models that support account-state guards."""

    is_active: bool
    is_verified: bool
    is_superuser: bool


@runtime_checkable
class TotpUserProtocol(UserProtocol[ID], Protocol[ID]):
    """Protocol for user models that support TOTP 2FA."""

    email: str
    totp_secret: str | None


UP = TypeVar("UP", bound=UserProtocol[Any])


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
