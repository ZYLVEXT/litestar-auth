"""Tests for multi-backend authentication coordination."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection

from litestar_auth.authentication.authenticator import Authenticator
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar.types import HTTPScope

    from litestar_auth.authentication.backend import AuthenticationBackend

pytestmark = pytest.mark.unit
REPO_ROOT = Path(__file__).resolve().parents[2]


def _build_connection() -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal HTTP connection for authenticator tests.

    Returns:
        Minimal Litestar connection object.
    """
    scope = {
        "type": "http",
        "headers": [],
        "path_params": {},
        "query_string": b"",
    }
    return ASGIConnection(scope=cast("HTTPScope", scope))


async def test_authenticator_returns_first_successful_backend() -> None:
    """Authentication stops at the first backend that resolves a user."""
    connection = _build_connection()
    user_manager = AsyncMock()
    user = ExampleUser(id=uuid4())

    first_backend = AsyncMock()
    first_backend.name = "bearer-jwt"
    first_backend.authenticate.return_value = None

    second_backend = AsyncMock()
    second_backend.name = "cookie-db"
    second_backend.authenticate.return_value = user

    third_backend = AsyncMock()
    third_backend.name = "redis-cookie"
    third_backend.authenticate.return_value = ExampleUser(id=uuid4())

    authenticator = Authenticator(
        cast(
            "list[AuthenticationBackend[ExampleUser, UUID]]",
            [first_backend, second_backend, third_backend],
        ),
        user_manager,
    )

    result = await authenticator.authenticate(connection)

    assert result == (user, "cookie-db")
    first_backend.authenticate.assert_awaited_once_with(connection, user_manager)
    second_backend.authenticate.assert_awaited_once_with(connection, user_manager)
    third_backend.authenticate.assert_not_awaited()


async def test_authenticator_returns_none_when_all_backends_miss() -> None:
    """Authentication returns ``(None, None)`` when no backend succeeds."""
    connection = _build_connection()
    user_manager = AsyncMock()

    first_backend = AsyncMock()
    first_backend.name = "bearer-jwt"
    first_backend.authenticate.return_value = None

    second_backend = AsyncMock()
    second_backend.name = "cookie-db"
    second_backend.authenticate.return_value = None

    authenticator = Authenticator(
        cast("list[AuthenticationBackend[ExampleUser, UUID]]", [first_backend, second_backend]),
        user_manager,
    )

    result = await authenticator.authenticate(connection)

    assert result == (None, None)
    first_backend.authenticate.assert_awaited_once_with(connection, user_manager)
    second_backend.authenticate.assert_awaited_once_with(connection, user_manager)
