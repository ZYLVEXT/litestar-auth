"""Static typing contract tests for public generic auth surfaces."""

from __future__ import annotations

from collections.abc import Hashable, Mapping
from typing import TYPE_CHECKING, Any, assert_type
from uuid import UUID, uuid4

import pytest

from litestar_auth._plugin.config import LitestarAuthConfig
from litestar_auth.db.base import BaseUserStore
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar_auth.types import LoginIdentifier, UserProtocol

pytestmark = pytest.mark.unit


class _TypingUserStore(BaseUserStore[ExampleUser, UUID]):
    """Minimal typed store for manager inference tests."""

    def __init__(self, user: ExampleUser) -> None:
        """Initialize the store with the user returned by lookup methods."""
        self._user = user

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Return the stored user when the ID matches."""
        if user_id == self._user.id:
            return self._user
        return None

    async def get_by_email(self, email: str) -> ExampleUser | None:
        """Return the stored user when the email matches."""
        if email == self._user.email:
            return self._user
        return None

    async def get_by_field(self, field_name: LoginIdentifier, value: str) -> ExampleUser | None:
        """Return the stored user when the selected login field matches."""
        if getattr(self._user, field_name) == value:
            return self._user
        return None

    async def create(self, user_dict: Mapping[str, Any]) -> ExampleUser:
        """Return the stored user for shape-only tests."""
        del user_dict
        return self._user

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return a page containing the stored user."""
        del offset, limit
        return [self._user], 1

    async def update(self, user: ExampleUser, update_dict: Mapping[str, Any]) -> ExampleUser:
        """Return the supplied user for shape-only tests."""
        del update_dict
        return user

    async def delete(self, user_id: UUID) -> None:
        """Accept deletion calls for shape-only tests."""
        del user_id


class _TypingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager used to verify generic inference."""


def _user_id[TypedID: Hashable](user: UserProtocol[TypedID]) -> TypedID:
    """Return a protocol user's ID while preserving the concrete ID type."""
    return user.id


async def test_public_typing_contracts_preserve_user_and_id_types() -> None:
    """Public generic contracts preserve configured user and ID types."""
    config = LitestarAuthConfig.create(
        user_model=ExampleUser,
        user_manager_class=_TypingUserManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )

    assert_type(config, LitestarAuthConfig[ExampleUser, UUID])
    assert config.user_model is ExampleUser
    assert config.user_manager_class is _TypingUserManager

    user = ExampleUser(id=uuid4(), email="typing@example.com")
    manager = _TypingUserManager(
        _TypingUserStore(user),
        security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )

    found_user = await manager.get(user.id)

    assert_type(found_user, ExampleUser | None)
    assert found_user is user

    user_id = _user_id(user)

    assert_type(user_id, UUID)
    assert user_id == user.id

    with pytest.raises(ValueError, match="db_session_dependency_key must be a valid Python identifier"):
        LitestarAuthConfig.create(
            user_model=ExampleUser,
            user_manager_class=_TypingUserManager,
            db_session_dependency_key="class",
        )
