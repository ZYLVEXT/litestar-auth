"""Optional dependency loaders for runtime integrations."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType


def _require_redis_asyncio(*, feature_name: str) -> ModuleType:
    """Import the optional ``redis.asyncio`` dependency for a feature.

    Args:
        feature_name: Name used in the installation-guidance error message.

    Returns:
        The imported ``redis.asyncio`` module.

    Raises:
        ImportError: If the optional Redis dependency is not installed.
    """
    try:
        return importlib.import_module("redis.asyncio")
    except ImportError as exc:
        msg = f"Install litestar-auth[redis] to use {feature_name}"
        raise ImportError(msg) from exc


def require_cryptography_fernet(*, install_hint: str) -> ModuleType:
    """Import the optional ``cryptography.fernet`` dependency.

    Args:
        install_hint: Exact installation-guidance message raised when the dependency is missing.

    Returns:
        The imported ``cryptography.fernet`` module.

    Raises:
        ImportError: If the optional cryptography dependency is not installed.
    """
    try:
        return importlib.import_module("cryptography.fernet")
    except ImportError as exc:
        raise ImportError(install_hint) from exc
