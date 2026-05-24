"""Backward-compatible TOTP validation import shim."""

from __future__ import annotations

from litestar_auth._plugin.validation.totp import (
    _validate_totp_encryption_key,
    _validate_totp_pending_secret_config,
    validate_totp_config,
    validate_totp_encryption_config,
    validate_totp_secret_config,
    validate_totp_sub_config,
)

__all__ = (
    "_validate_totp_encryption_key",
    "_validate_totp_pending_secret_config",
    "validate_totp_config",
    "validate_totp_encryption_config",
    "validate_totp_secret_config",
    "validate_totp_sub_config",
)
