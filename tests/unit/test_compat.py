"""Unit tests for optional dependency compatibility helpers."""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest

import litestar_auth._compat as compat_module
from litestar_auth._compat import _load_redis_asyncio

pytestmark = pytest.mark.unit


def test_compat_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(compat_module)

    assert reloaded_module._load_redis_asyncio.__name__ == _load_redis_asyncio.__name__


def test_load_redis_asyncio_uses_custom_importer() -> None:
    """The helper returns the module loaded by the provided importer."""
    module = ModuleType("redis.asyncio")

    def importer(name: str) -> ModuleType:
        assert name == "redis.asyncio"
        return module

    assert _load_redis_asyncio(feature_name="RedisTokenStrategy", import_module=importer) is module


def test_load_redis_asyncio_raises_helpful_error_when_dependency_missing() -> None:
    """Missing optional redis dependency produces installation guidance."""

    def importer(_: str) -> ModuleType:
        msg = "redis is not installed"
        raise ImportError(msg)

    with pytest.raises(ImportError, match=r"Install litestar-auth\[redis\] to use RedisTokenStrategy"):
        _load_redis_asyncio(feature_name="RedisTokenStrategy", import_module=importer)
