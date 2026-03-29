"""Tests for multi-backend authentication coordination."""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import sys
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


def test_authenticator_module_executes_under_coverage() -> None:
    """Reload an alias module so coverage records the authenticator definitions without mutating shared imports."""

    class _AliasFinder:
        """Resolve the authenticator source file for the reload-only alias."""

        def find_spec(
            self,
            fullname: str,
            path: object,
            target: object = None,
        ) -> importlib.machinery.ModuleSpec | None:
            del path, target
            if fullname != "_coverage_alias_authenticator":
                return None
            return importlib.util.spec_from_file_location(
                fullname,
                REPO_ROOT / "litestar_auth" / "authentication" / "authenticator.py",
            )

    alias_name = "_coverage_alias_authenticator"
    spec = importlib.util.spec_from_file_location(
        alias_name,
        REPO_ROOT / "litestar_auth" / "authentication" / "authenticator.py",
    )
    assert spec is not None
    assert spec.loader is not None
    alias_module = importlib.util.module_from_spec(spec)
    original_meta_path = sys.meta_path[:]
    sys.meta_path.insert(0, _AliasFinder())

    try:
        sys.modules[alias_name] = alias_module
        spec.loader.exec_module(alias_module)
        reloaded_module = importlib.reload(alias_module)
    finally:
        sys.meta_path[:] = original_meta_path
        sys.modules.pop(alias_name, None)

    assert reloaded_module is alias_module
    assert reloaded_module.Authenticator.__name__ == Authenticator.__name__


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
