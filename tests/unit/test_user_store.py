"""Unit tests for :class:`~litestar_auth.db.base.BaseUserStore` contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from litestar_auth.db.base import BaseUserStore

if TYPE_CHECKING:
    from collections.abc import Mapping
    from uuid import UUID

    from litestar_auth.types import LoginIdentifier
    from tests._helpers import ExampleUser


@dataclass(slots=True)
class _StructuralUserStore:
    async def get(self, user_id: UUID) -> ExampleUser | None:
        del user_id
        return None

    async def get_by_email(self, email: str) -> ExampleUser | None:
        del email
        return None

    async def get_by_field(self, field_name: LoginIdentifier, value: str) -> ExampleUser | None:
        del field_name, value
        return None

    async def create(self, user_dict: Mapping[str, Any]) -> ExampleUser:
        raise NotImplementedError(user_dict)

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        del offset, limit
        return [], 0

    async def update(self, user: ExampleUser, update_dict: Mapping[str, Any]) -> ExampleUser:
        raise NotImplementedError((user, update_dict))

    async def delete(self, user_id: UUID) -> None:
        del user_id


def test_base_user_store_exposes_runtime_checkable_method_contract() -> None:
    """``BaseUserStore`` remains a runtime-checkable structural interface."""
    assert "get_by_field" in BaseUserStore.__dict__
    assert isinstance(_StructuralUserStore(), BaseUserStore)


def test_base_user_store_rejects_missing_methods_at_runtime() -> None:
    """Objects missing required methods should not satisfy the runtime-checkable protocol."""

    @dataclass(slots=True)
    class _IncompleteUserStore:
        async def get(self, user_id: UUID) -> ExampleUser | None:
            del user_id
            return None

        async def get_by_email(self, email: str) -> ExampleUser | None:
            del email
            return None

        async def create(self, user_dict: Mapping[str, Any]) -> ExampleUser:
            raise NotImplementedError(user_dict)

        async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
            del offset, limit
            return [], 0

        async def update(self, user: ExampleUser, update_dict: Mapping[str, Any]) -> ExampleUser:
            raise NotImplementedError((user, update_dict))

        async def delete(self, user_id: UUID) -> None:
            del user_id

    assert isinstance(_IncompleteUserStore(), BaseUserStore) is False
