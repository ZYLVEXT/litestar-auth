"""Compatibility helpers for optional runtime dependencies."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType


def _load_redis_asyncio(
    *,
    feature_name: str,
    import_module: Callable[[str], ModuleType] | None = None,
) -> ModuleType:
    """Import the optional ``redis.asyncio`` dependency for a feature.

    Args:
        feature_name: Name used in the installation guidance error message.
        import_module: Optional import hook used to load the module.

    Returns:
        The imported ``redis.asyncio`` module.

    Raises:
        ImportError: If the optional Redis dependency is not installed.
    """
    importer = importlib.import_module if import_module is None else import_module
    try:
        return importer("redis.asyncio")
    except ImportError as exc:
        msg = f"Install litestar-auth[redis] to use {feature_name}"
        raise ImportError(msg) from exc
