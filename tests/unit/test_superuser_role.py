"""Tests for the shared superuser-role helper surface."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.exceptions import PermissionDeniedException

import litestar_auth._superuser_role as superuser_role_module
from litestar_auth._superuser_role import (
    DEFAULT_SUPERUSER_ROLE_NAME,
    SUPERUSER_ROLE_NAME_SENTINEL,
    normalize_superuser_role_name,
    read_scope_superuser_role_name,
    resolve_superuser_role_name,
    set_scope_superuser_role_name,
)
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit

HTTP_403_FORBIDDEN = 403


class _ConfiguredSource:
    superuser_role_name = " Admin "


def _build_connection(
    *,
    state: object | None = None,
) -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal connection with optional request-scope state.

    Returns:
        A minimal Litestar ASGI connection.
    """
    scope: dict[str, object] = {
        "type": "http",
        "headers": [],
        "path_params": {},
        "query_string": b"",
        "user": ExampleUser(id=uuid4(), roles=["admin"]),
    }
    if state is not None:
        scope["state"] = state
    return ASGIConnection(scope=cast("HTTPScope", scope))


def test_superuser_role_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(superuser_role_module)

    assert reloaded_module.DEFAULT_SUPERUSER_ROLE_NAME == DEFAULT_SUPERUSER_ROLE_NAME


def test_default_superuser_role_name_is_normalized() -> None:
    """The canonical default is the normalized role value used by plugin defaults."""
    assert DEFAULT_SUPERUSER_ROLE_NAME == "superuser"


def test_resolve_superuser_role_name_uses_configured_or_default_value() -> None:
    """Objects can expose ``superuser_role_name`` and otherwise fall back to the default."""
    assert resolve_superuser_role_name(_ConfiguredSource()) == "admin"
    assert resolve_superuser_role_name(object()) == DEFAULT_SUPERUSER_ROLE_NAME


def test_normalize_superuser_role_name_rejects_invalid_values() -> None:
    """Invalid superuser role names fail closed before reaching guard checks."""
    with pytest.raises(TypeError, match="must be a string"):
        normalize_superuser_role_name(cast("Any", 123))

    with pytest.raises(ValueError, match="non-empty role name"):
        normalize_superuser_role_name("   ")


def test_set_scope_superuser_role_name_writes_normalized_state() -> None:
    """Request scope state carries the resolved value for guard-time lookup."""
    scope: dict[str, Any] = {}

    set_scope_superuser_role_name(scope, _ConfiguredSource())

    assert scope["state"][SUPERUSER_ROLE_NAME_SENTINEL] == "admin"


def test_read_scope_superuser_role_name_uses_configured_scope_state() -> None:
    """Scope-state reads mirror the writer-side normalized configured value."""
    connection = _build_connection(state={SUPERUSER_ROLE_NAME_SENTINEL: " ADMIN "})

    assert read_scope_superuser_role_name(connection) == "admin"


def test_read_scope_superuser_role_name_falls_back_to_default_without_state_mapping() -> None:
    """Direct guard usage outside plugin-managed state uses the canonical default."""
    connection = cast(
        "ASGIConnection[Any, Any, Any, Any]",
        SimpleNamespace(scope={"state": object()}),
    )

    assert read_scope_superuser_role_name(_build_connection()) == DEFAULT_SUPERUSER_ROLE_NAME
    assert read_scope_superuser_role_name(connection) == DEFAULT_SUPERUSER_ROLE_NAME


@pytest.mark.parametrize(
    "configured_role",
    [
        pytest.param(object(), id="non-string"),
        pytest.param("   ", id="blank-string"),
    ],
)
def test_read_scope_superuser_role_name_rejects_invalid_configured_values(configured_role: object) -> None:
    """Invalid plugin-provided role names preserve the guard rejection detail."""
    connection = _build_connection(state={SUPERUSER_ROLE_NAME_SENTINEL: configured_role})

    with pytest.raises(PermissionDeniedException) as exc_info:
        read_scope_superuser_role_name(connection)

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "The configured superuser role name is invalid."
