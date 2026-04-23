"""Tests for the shared superuser-role helper surface."""

from __future__ import annotations

import importlib
from typing import Any, cast

import pytest

import litestar_auth._superuser_role as superuser_role_module
from litestar_auth._superuser_role import (
    DEFAULT_SUPERUSER_ROLE_NAME,
    SUPERUSER_ROLE_NAME_SENTINEL,
    normalize_superuser_role_name,
    resolve_superuser_role_name,
    set_scope_superuser_role_name,
)

pytestmark = pytest.mark.unit


class _ConfiguredSource:
    superuser_role_name = " Admin "


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
