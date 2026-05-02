"""Coverage regression tests for private controller partition modules."""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest


@pytest.mark.unit
@pytest.mark.parametrize(
    "module_name",
    [
        "litestar_auth.controllers._auth_helpers",
        "litestar_auth.controllers._auth_routes",
        "litestar_auth.controllers._oauth_assembly",
        "litestar_auth.controllers._oauth_associate_routes",
        "litestar_auth.controllers._oauth_helpers",
        "litestar_auth.controllers._users_helpers",
        "litestar_auth.controllers._users_routes",
    ],
)
def test_controller_partition_module_reload(module_name: str) -> None:
    """Private controller partitions remain importable after collection-time imports."""
    module = importlib.import_module(module_name)

    assert isinstance(importlib.reload(module), ModuleType)
