"""Backward-compatible API-key validation import shim."""

from __future__ import annotations

from litestar_auth._plugin.validation.api_key import (
    _validate_api_key_signing_secret_distinctness,
    validate_api_key_config,
)

__all__ = (
    "_validate_api_key_signing_secret_distinctness",
    "validate_api_key_config",
)
