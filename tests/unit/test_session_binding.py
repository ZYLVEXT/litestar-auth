"""Unit tests for session-bound plugin helpers."""

from __future__ import annotations

import importlib
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

import litestar_auth._plugin.session_binding as session_binding_module
from litestar_auth._plugin.session_binding import _ScopedUserDatabaseProxy
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

pytestmark = pytest.mark.unit


@dataclass(slots=True)
class _ScopeEvent:
    phase: str
    scope: object


class _DummyUserStore:
    """Test double with awaitable delegates for every proxied store method."""

    def __init__(self) -> None:
        """Initialize awaitable delegates for the proxied store contract."""
        self.get_mock = AsyncMock()
        self.get_by_email_mock = AsyncMock()
        self.get_by_field_mock = AsyncMock()
        self.create_mock = AsyncMock()
        self.list_users_mock = AsyncMock()
        self.update_mock = AsyncMock()
        self.delete_mock = AsyncMock()
        self.get_by_oauth_account_mock = AsyncMock()
        self.upsert_oauth_account_mock = AsyncMock()

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Delegate ``get`` calls to the tracked async mock.

        Returns:
            Result produced by ``get_mock``.
        """
        return await self.get_mock(user_id)

    async def get_by_email(self, email: str) -> ExampleUser | None:
        """Delegate ``get_by_email`` calls to the tracked async mock.

        Returns:
            Result produced by ``get_by_email_mock``.
        """
        return await self.get_by_email_mock(email)

    async def get_by_field(self, field_name: str, value: str) -> ExampleUser | None:
        """Delegate ``get_by_field`` calls to the tracked async mock.

        Returns:
            Result produced by ``get_by_field_mock``.
        """
        return await self.get_by_field_mock(field_name, value)

    async def create(self, user_dict: Mapping[str, Any]) -> ExampleUser:
        """Delegate ``create`` calls to the tracked async mock.

        Returns:
            Result produced by ``create_mock``.
        """
        return await self.create_mock(user_dict)

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Delegate ``list_users`` calls to the tracked async mock.

        Returns:
            Result produced by ``list_users_mock``.
        """
        return await self.list_users_mock(offset=offset, limit=limit)

    async def update(self, user: ExampleUser, update_dict: Mapping[str, Any]) -> ExampleUser:
        """Delegate ``update`` calls to the tracked async mock.

        Returns:
            Result produced by ``update_mock``.
        """
        return await self.update_mock(user, update_dict)

    async def delete(self, user_id: UUID) -> None:
        """Delegate ``delete`` calls to the tracked async mock."""
        await self.delete_mock(user_id)

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> ExampleUser | None:
        """Delegate OAuth-account lookup to the tracked async mock.

        Returns:
            Result produced by ``get_by_oauth_account_mock``.
        """
        return await self.get_by_oauth_account_mock(oauth_name, account_id)

    async def upsert_oauth_account(  # noqa: PLR0913
        self,
        user: ExampleUser,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        """Delegate OAuth-account upsert to the tracked async mock."""
        await self.upsert_oauth_account_mock(
            user,
            oauth_name=oauth_name,
            account_id=account_id,
            account_email=account_email,
            access_token=access_token,
            expires_at=expires_at,
            refresh_token=refresh_token,
        )


def _build_user(*, email: str = "user@example.com") -> ExampleUser:
    """Return a predictable test user."""
    return ExampleUser(id=uuid4(), email=email)


def _tracking_scope(
    received_scope: object,
    *,
    expected_scope: object,
    events: list[_ScopeEvent],
) -> Iterator[None]:
    """Record encryption-scope entry and exit for assertions."""
    assert received_scope is expected_scope
    events.append(_ScopeEvent("enter", received_scope))
    try:
        yield
    finally:
        events.append(_ScopeEvent("exit", received_scope))


TRACKING_SCOPE_CONTEXT = contextmanager(_tracking_scope)


def _build_proxy(
    user_store: _DummyUserStore,
    *,
    oauth_scope: object,
) -> _ScopedUserDatabaseProxy[ExampleUser, UUID]:
    """Build the proxy under test with the given store and scope.

    Returns:
        Proxy instance bound to ``user_store`` and ``oauth_scope``.
    """
    return _ScopedUserDatabaseProxy(cast("Any", user_store), oauth_scope=oauth_scope)


def test_session_binding_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records class-body execution."""
    reloaded_module = importlib.reload(session_binding_module)

    assert reloaded_module._ScopedUserDatabaseProxy is not None
    assert reloaded_module._ScopedUserDatabaseProxy.__name__ == _ScopedUserDatabaseProxy.__name__


@pytest.mark.parametrize(
    ("method_name", "mock_name", "args", "kwargs", "expected"),
    [
        ("get", "get_mock", (uuid4(),), {}, _build_user()),
        ("get_by_email", "get_by_email_mock", ("user@example.com",), {}, _build_user()),
        ("get_by_field", "get_by_field_mock", ("username", "ralph"), {}, _build_user()),
        ("create", "create_mock", ({"email": "new@example.com"},), {}, _build_user(email="new@example.com")),
        ("list_users", "list_users_mock", (), {"offset": 5, "limit": 3}, ([_build_user()], 1)),
        (
            "update",
            "update_mock",
            (_build_user(), {"email": "updated@example.com"}),
            {},
            _build_user(email="updated@example.com"),
        ),
        ("delete", "delete_mock", (uuid4(),), {}, None),
    ],
)
async def test_scoped_user_database_proxy_delegates_crud_methods(
    method_name: str,
    mock_name: str,
    args: tuple[object, ...],
    kwargs: dict[str, object],
    expected: object,
) -> None:
    """Each CRUD-style method forwards directly to the wrapped user store."""
    user_store = _DummyUserStore()
    proxy = _build_proxy(user_store, oauth_scope=object())
    mock = getattr(user_store, mock_name)
    mock.return_value = expected

    result = await getattr(proxy, method_name)(*args, **kwargs)

    assert result is expected
    mock.assert_awaited_once_with(*args, **kwargs)


async def test_scoped_user_database_proxy_wraps_oauth_lookup_in_encryption_scope() -> None:
    """OAuth-account lookup activates the configured encryption scope."""
    user_store = _DummyUserStore()
    oauth_scope = object()
    proxy = _build_proxy(user_store, oauth_scope=oauth_scope)
    expected_user = _build_user()
    user_store.get_by_oauth_account_mock.return_value = expected_user
    events: list[_ScopeEvent] = []

    with patch(
        "litestar_auth._plugin.session_binding.oauth_token_encryption_scope",
        side_effect=lambda scope: TRACKING_SCOPE_CONTEXT(scope, expected_scope=oauth_scope, events=events),
    ):
        result = await proxy.get_by_oauth_account("github", "account-123")

    assert result is expected_user
    user_store.get_by_oauth_account_mock.assert_awaited_once_with("github", "account-123")
    assert events == [_ScopeEvent("enter", oauth_scope), _ScopeEvent("exit", oauth_scope)]


async def test_scoped_user_database_proxy_wraps_oauth_upsert_in_encryption_scope() -> None:
    """OAuth-account upsert activates the configured encryption scope."""
    user_store = _DummyUserStore()
    oauth_scope = object()
    proxy = _build_proxy(user_store, oauth_scope=oauth_scope)
    user = _build_user()
    events: list[_ScopeEvent] = []

    with patch(
        "litestar_auth._plugin.session_binding.oauth_token_encryption_scope",
        side_effect=lambda scope: TRACKING_SCOPE_CONTEXT(scope, expected_scope=oauth_scope, events=events),
    ):
        await proxy.upsert_oauth_account(
            user,
            oauth_name="github",
            account_id="account-123",
            account_email="oauth@example.com",
            access_token="access-token",
            expires_at=12345,
            refresh_token="refresh-token",
        )

    user_store.upsert_oauth_account_mock.assert_awaited_once_with(
        user,
        oauth_name="github",
        account_id="account-123",
        account_email="oauth@example.com",
        access_token="access-token",
        expires_at=12345,
        refresh_token="refresh-token",
    )
    assert events == [_ScopeEvent("enter", oauth_scope), _ScopeEvent("exit", oauth_scope)]
