"""Unit tests for optional dependency loaders."""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest

import litestar_auth._optional_deps as optional_deps_module
from litestar_auth._optional_deps import _require_redis_asyncio, require_cryptography_fernet

pytestmark = pytest.mark.unit


def test_optional_deps_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(optional_deps_module)

    assert reloaded_module._require_redis_asyncio.__name__ == _require_redis_asyncio.__name__
    assert reloaded_module.require_cryptography_fernet.__name__ == require_cryptography_fernet.__name__


def test_require_redis_asyncio_uses_importlib_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """The helper returns the module loaded by ``importlib.import_module``."""
    module = ModuleType("redis.asyncio")

    def importer(name: str) -> ModuleType:
        assert name == "redis.asyncio"
        return module

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", importer)

    assert _require_redis_asyncio(feature_name="RedisTokenStrategy") is module


def test_require_redis_asyncio_raises_helpful_error_when_dependency_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing optional redis dependency produces installation guidance."""

    def importer(_: str) -> ModuleType:
        msg = "redis is not installed"
        raise ImportError(msg)

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", importer)

    with pytest.raises(ImportError, match=r"Install litestar-auth\[redis\] to use RedisTokenStrategy"):
        _require_redis_asyncio(feature_name="RedisTokenStrategy")


def test_require_cryptography_fernet_uses_importlib_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """The helper returns the Fernet module loaded by ``importlib.import_module``."""
    module = ModuleType("cryptography.fernet")

    def importer(name: str) -> ModuleType:
        assert name == "cryptography.fernet"
        return module

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", importer)

    assert require_cryptography_fernet(install_hint="Install cryptography") is module


def test_require_cryptography_fernet_raises_supplied_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing optional cryptography dependency preserves caller-owned guidance."""

    def importer(_: str) -> ModuleType:
        msg = "cryptography is not installed"
        raise ImportError(msg)

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", importer)

    with pytest.raises(ImportError, match="Install cryptography") as exc_info:
        require_cryptography_fernet(install_hint="Install cryptography")

    assert isinstance(exc_info.value.__cause__, ImportError)
