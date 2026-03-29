"""Shared test infrastructure for integration tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, Self, cast, override
from uuid import UUID, uuid4

from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.db.base import BaseUserStore
from litestar_auth.types import UserProtocol
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from types import TracebackType


class _EmailUserProtocol(UserProtocol[UUID], Protocol):
    """User contract needed by the shared in-memory integration store."""

    email: str


class InMemoryUserDatabase[UP: _EmailUserProtocol](BaseUserStore[UP, UUID]):
    """Simple in-memory user store for integration tests."""

    def __init__(
        self,
        users: list[UP] | None = None,
        *,
        create_user: Callable[[Mapping[str, Any]], UP] | None = None,
    ) -> None:
        """Index users by id and email."""
        self.users_by_id: dict[UUID, UP] = {}
        self.user_ids_by_email: dict[str, UUID] = {}
        self._create_user = create_user
        if users:
            for user in users:
                self.users_by_id[user.id] = user
                self.user_ids_by_email[user.email] = user.id

    @override
    async def get(self, user_id: UUID) -> UP | None:
        """Return a user by id."""
        return self.users_by_id.get(user_id)

    @override
    async def get_by_email(self, email: str) -> UP | None:
        """Return a user by email."""
        user_id = self.user_ids_by_email.get(email)
        return self.users_by_id.get(user_id) if user_id is not None else None

    @override
    async def get_by_field(self, field_name: str, value: str) -> UP | None:
        """Return a user by field value."""
        if field_name == "email":
            return await self.get_by_email(value)
        for user in self.users_by_id.values():
            if getattr(user, field_name, None) == value:
                return user
        return None

    @override
    async def create(self, user_dict: Mapping[str, Any]) -> UP:
        """Create and store a user.

        Returns:
            The stored user instance.
        """
        if self._create_user is None:
            user = cast("UP", ExampleUser(id=uuid4(), **dict(user_dict)))
        else:
            user = self._create_user(user_dict)
        self.users_by_id[user.id] = user
        self.user_ids_by_email[user.email] = user.id
        return user

    @override
    async def update(self, user: UP, update_dict: Mapping[str, Any]) -> UP:
        """Update a user.

        Returns:
            The updated user instance.
        """
        old_email = user.email
        for field_name, value in update_dict.items():
            setattr(user, field_name, value)

        if "email" in update_dict and old_email != user.email:
            self.user_ids_by_email.pop(old_email, None)
            self.user_ids_by_email[user.email] = user.id
        return user

    @override
    async def delete(self, user_id: UUID) -> None:
        """Delete a user."""
        user = self.users_by_id.pop(user_id, None)
        if user is None:
            return
        self.user_ids_by_email.pop(user.email, None)

    @override
    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """List stored users with offset/limit slicing.

        Returns:
            A page of users plus the total count.
        """
        users = list(self.users_by_id.values())
        return users[offset : offset + limit], len(users)


class InMemoryTokenStrategy(Strategy[ExampleUser, UUID]):
    """Deterministic token strategy for integration tests."""

    def __init__(self) -> None:
        """Initialize token storage."""
        self.tokens: dict[str, UUID] = {}
        self.counter = 0

    @override
    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[ExampleUser, UUID],
    ) -> ExampleUser | None:
        """Resolve a user from a token.

        Returns:
            The matching user, or ``None`` when the token is unknown.
        """
        if token is None:
            return None
        user_id = self.tokens.get(token)
        if user_id is None:
            return None
        return await user_manager.get(user_id)

    @override
    async def write_token(self, user: ExampleUser) -> str:
        """Persist and return a token.

        Returns:
            The generated token value.
        """
        self.counter += 1
        token = f"token-{self.counter}"
        self.tokens[token] = user.id
        return token

    @override
    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """Delete a token."""
        del user
        self.tokens.pop(token, None)


class DummySession:
    """Placeholder session (async context manager + ``close`` like ``AsyncSession``)."""

    async def __aenter__(self) -> Self:
        """Enter async context.

        Returns:
            This session instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit async context (no-op)."""
        del exc_type, exc, traceback

    async def close(self) -> None:
        """No-op close for ``before_send`` handlers."""

    async def commit(self) -> None:
        """No-op commit for lifecycle parity."""

    async def rollback(self) -> None:
        """No-op rollback for lifecycle parity."""


class DummySessionMaker:
    """Callable session factory for auth middleware wiring (mirrors ``async_sessionmaker()``)."""

    def __call__(self) -> DummySession:
        """Return a new dummy session instance."""
        return DummySession()


class CountingSessionMaker:
    """Wraps a session factory and counts ``__call__`` invocations.

    Each call corresponds to ``session_maker()`` when creating a scoped session.
    """

    def __init__(self, inner: DummySessionMaker | None = None) -> None:
        """Store the delegate factory; default matches :class:`DummySessionMaker`."""
        self._inner = inner if inner is not None else DummySessionMaker()
        self.call_count = 0

    def __call__(self) -> DummySession:
        """Increment the call counter and delegate session construction.

        Returns:
            Dummy session from the inner factory.
        """
        self.call_count += 1
        return self._inner()
