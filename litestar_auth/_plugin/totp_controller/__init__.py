"""Plugin-managed TOTP controller assembly."""

from __future__ import annotations

from litestar_auth._plugin.totp_controller import _core as _core
from litestar_auth._plugin.totp_controller._core import (
    PluginTotpControllerOptions,
    _resolve_request_backend,
    build_totp_controller,
    create_totp_controller,
    totp_backend,
    totp_path,
)

__all__ = (
    "PluginTotpControllerOptions",
    "_resolve_request_backend",
    "build_totp_controller",
    "create_totp_controller",
    "totp_backend",
    "totp_path",
)
