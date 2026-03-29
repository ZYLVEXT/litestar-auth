"""Abstract persistence contracts for user and OAuth-account storage."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping


class BaseUserStore[UP: UserProtocol[Any], ID](ABC):
    """Abstract CRUD interface for user persistence backends."""

    @abstractmethod
    async def get(self, user_id: ID) -> UP | None:
        """Return the user with the given identifier, if present."""

    @abstractmethod
    async def get_by_email(self, email: str) -> UP | None:
        """Return the user matching the provided email, if present."""

    @abstractmethod
    async def get_by_field(self, field_name: str, value: str) -> UP | None:
        """Return the user where ``field_name`` equals ``value``, if present.

        Implementations may perform a direct column/attribute lookup. Invalid
        ``field_name`` values are a programming error and may surface as
        backend-specific errors at runtime.
        """

    @abstractmethod
    async def create(self, user_dict: Mapping[str, Any]) -> UP:
        """Persist and return a newly created user."""

    @abstractmethod
    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return paginated users and the total available count."""

    @abstractmethod
    async def update(self, user: UP, update_dict: Mapping[str, Any]) -> UP:
        """Persist and return updates for an existing user."""

    @abstractmethod
    async def delete(self, user_id: ID) -> None:
        """Delete the user identified by ``user_id`` from storage."""


@runtime_checkable
class BaseOAuthAccountStore[UP: UserProtocol[Any], ID](Protocol):
    """Structural contract for linked OAuth-account persistence backends."""

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Return a user linked to the given provider account, if present."""

    async def upsert_oauth_account(  # noqa: PLR0913
        self,
        user: UP,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        """Create or update the linked OAuth account for ``user``."""
