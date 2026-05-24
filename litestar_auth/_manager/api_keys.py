"""Compatibility exports for API-key manager operations."""

from __future__ import annotations

from litestar_auth._manager.api_key_config import (
    ApiKeyConfigProtocol,
    ApiKeyLastUsedWriteStrategy,
    ApiKeyManagerConfig,
)
from litestar_auth._manager.api_key_row import ApiKeyRowProtocol, _ApiKeyManagerHooks, _ApiKeyManagerProtocol
from litestar_auth._manager.api_key_secrets import ApiKeyCreateResult, ApiKeySecret, secrets
from litestar_auth._manager.api_key_service import ApiKeyManagerService

__all__ = (
    "ApiKeyConfigProtocol",
    "ApiKeyCreateResult",
    "ApiKeyLastUsedWriteStrategy",
    "ApiKeyManagerConfig",
    "ApiKeyManagerService",
    "ApiKeyRowProtocol",
    "ApiKeySecret",
    "_ApiKeyManagerHooks",
    "_ApiKeyManagerProtocol",
    "secrets",
)
