"""Unit tests for :class:`~litestar_auth.db.base.BaseUserStore` contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest

from litestar_auth.db.base import BaseUserStore
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from collections.abc import Mapping


def test_base_user_store_requires_get_by_field() -> None:
    """``get_by_field`` is part of the abstract contract."""
    assert "get_by_field" in BaseUserStore.__abstractmethods__


def test_base_user_store_cannot_instantiate_without_get_by_field() -> None:
    """``BaseUserStore`` subclasses must implement ``get_by_field``."""

    class IncompleteUserDb(BaseUserStore[ExampleUser, UUID]):
        async def get(self, user_id: UUID) -> ExampleUser | None:
            return None

        async def get_by_email(self, email: str) -> ExampleUser | None:
            return None

        async def create(self, user_dict: Mapping[str, Any]) -> ExampleUser:
            raise NotImplementedError

        async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
            return [], 0

        async def update(self, user: ExampleUser, update_dict: Mapping[str, Any]) -> ExampleUser:
            raise NotImplementedError

        async def delete(self, user_id: UUID) -> None:
            return None

    with pytest.raises(TypeError, match="get_by_field"):
        IncompleteUserDb()
