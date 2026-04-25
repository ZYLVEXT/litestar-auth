"""Unit tests for session-bound plugin helpers."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

import litestar_auth._plugin.session_binding as session_binding_module
from litestar_auth._plugin.session_binding import _ScopedUserDatabaseProxy
from litestar_auth.oauth_encryption import OAuthTokenEncryption
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_auth.types import LoginIdentifier

pytestmark = pytest.mark.unit


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
        self.set_recovery_code_hashes_mock = AsyncMock()
        self.read_recovery_code_hashes_mock = AsyncMock()
        self.consume_recovery_code_hash_mock = AsyncMock()
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

    async def get_by_field(self, field_name: LoginIdentifier, value: str) -> ExampleUser | None:
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

    async def set_recovery_code_hashes(self, user: ExampleUser, hashes: tuple[str, ...]) -> ExampleUser:
        """Delegate recovery-code hash replacement to the tracked async mock.

        Returns:
            Result produced by ``set_recovery_code_hashes_mock``.
        """
        return await self.set_recovery_code_hashes_mock(user, hashes)

    async def read_recovery_code_hashes(self, user: ExampleUser) -> tuple[str, ...]:
        """Delegate recovery-code hash reads to the tracked async mock.

        Returns:
            Result produced by ``read_recovery_code_hashes_mock``.
        """
        return await self.read_recovery_code_hashes_mock(user)

    async def consume_recovery_code_hash(self, user: ExampleUser, matched_hash: str) -> bool:
        """Delegate recovery-code hash consumption to the tracked async mock.

        Returns:
            Result produced by ``consume_recovery_code_hash_mock``.
        """
        return await self.consume_recovery_code_hash_mock(user, matched_hash)

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


class _BindingUserStore(_DummyUserStore):
    """Store double that supports explicit OAuth token encryption binding."""

    def __init__(self) -> None:
        """Initialize the bind tracker alongside the base async delegates."""
        super().__init__()
        self.bind_calls: list[OAuthTokenEncryption] = []
        self.bind_result: object = self

    def bind_oauth_token_encryption(self, oauth_token_encryption: OAuthTokenEncryption) -> object:
        """Record the requested policy and return the configured rebound store.

        Returns:
            The store instance that the proxy should delegate through.
        """
        self.bind_calls.append(oauth_token_encryption)
        return self.bind_result


class _NonCallableBindingUserStore(_DummyUserStore):
    """Store double exposing a non-callable bind attribute."""

    bind_oauth_token_encryption = "not-callable"


def _build_user(*, email: str = "user@example.com") -> ExampleUser:
    """Return a predictable test user."""
    return ExampleUser(id=uuid4(), email=email)


def _build_proxy(
    user_store: _DummyUserStore,
    *,
    oauth_token_encryption: OAuthTokenEncryption | None = None,
) -> _ScopedUserDatabaseProxy[ExampleUser, UUID]:
    """Build the proxy under test with the given store and OAuth policy.

    Returns:
        Proxy instance bound to ``user_store``.
    """
    return _ScopedUserDatabaseProxy(
        cast("Any", user_store),
        oauth_token_encryption=oauth_token_encryption,
    )


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
        (
            "set_recovery_code_hashes",
            "set_recovery_code_hashes_mock",
            (_build_user(), ("hash-1", "hash-2")),
            {},
            _build_user(),
        ),
        (
            "read_recovery_code_hashes",
            "read_recovery_code_hashes_mock",
            (_build_user(),),
            {},
            ("hash-1", "hash-2"),
        ),
        (
            "consume_recovery_code_hash",
            "consume_recovery_code_hash_mock",
            (_build_user(), "hash-1"),
            {},
            True,
        ),
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
    proxy = _build_proxy(user_store)
    mock = getattr(user_store, mock_name)
    mock.return_value = expected

    result = await getattr(proxy, method_name)(*args, **kwargs)

    assert result is expected
    mock.assert_awaited_once_with(*args, **kwargs)


def test_scoped_user_database_proxy_binds_explicit_oauth_policy_when_supported() -> None:
    """Proxy construction binds the plugin-owned OAuth token policy once."""
    user_store = _BindingUserStore()
    oauth_token_encryption = OAuthTokenEncryption(key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")

    _build_proxy(user_store, oauth_token_encryption=oauth_token_encryption)

    assert user_store.bind_calls == [oauth_token_encryption]


def test_scoped_user_database_proxy_skips_binding_when_no_policy_is_supplied() -> None:
    """Proxy construction leaves bind-capable stores untouched without an explicit policy."""
    user_store = _BindingUserStore()

    _build_proxy(user_store)

    assert not user_store.bind_calls


def test_scoped_user_database_proxy_ignores_non_callable_bind_attribute() -> None:
    """Proxy construction leaves stores alone when the bind attribute is not callable."""
    user_store = _NonCallableBindingUserStore()

    proxy = _build_proxy(
        user_store,
        oauth_token_encryption=OAuthTokenEncryption(key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="),
    )

    assert proxy._user_db is user_store


async def test_scoped_user_database_proxy_uses_store_returned_by_bind_call() -> None:
    """Proxy delegates through the rebound store returned by ``bind_oauth_token_encryption()``."""
    original_store = _BindingUserStore()
    rebound_store = _DummyUserStore()
    original_store.bind_result = rebound_store
    proxy = _build_proxy(
        original_store,
        oauth_token_encryption=OAuthTokenEncryption(key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="),
    )
    expected_user = _build_user()
    rebound_store.get_by_email_mock.return_value = expected_user

    result = await proxy.get_by_email("user@example.com")

    assert result is expected_user
    rebound_store.get_by_email_mock.assert_awaited_once_with("user@example.com")
    assert original_store.get_by_email_mock.await_count == 0


async def test_scoped_user_database_proxy_delegates_oauth_lookup() -> None:
    """OAuth-account lookup forwards directly to the wrapped OAuth store."""
    user_store = _DummyUserStore()
    proxy = _build_proxy(user_store)
    expected_user = _build_user()
    user_store.get_by_oauth_account_mock.return_value = expected_user
    result = await proxy.get_by_oauth_account("github", "account-123")

    assert result is expected_user
    user_store.get_by_oauth_account_mock.assert_awaited_once_with("github", "account-123")


async def test_scoped_user_database_proxy_delegates_oauth_upsert() -> None:
    """OAuth-account upsert forwards directly to the wrapped OAuth store."""
    user_store = _DummyUserStore()
    proxy = _build_proxy(user_store)
    user = _build_user()
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
