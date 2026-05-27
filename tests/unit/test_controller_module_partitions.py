"""Import-only coverage for private controller partition modules."""

from __future__ import annotations

import importlib

import pytest


@pytest.mark.unit
@pytest.mark.parametrize(
    "module_name",
    [
        "litestar_auth.controllers._auth_helpers",
        "litestar_auth.controllers._oauth_assembly",
        "litestar_auth.controllers._oauth_helpers",
        "litestar_auth.controllers._users_helpers",
    ],
)
def test_controller_partition_module_imports(module_name: str) -> None:
    """Private controller partitions remain importable after collection-time imports."""
    assert importlib.import_module(module_name).__name__ == module_name
