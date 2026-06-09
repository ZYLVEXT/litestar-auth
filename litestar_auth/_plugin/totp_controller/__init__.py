"""Plugin-managed TOTP controller assembly."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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


def __getattr__(name: str) -> object:
    """Lazily resolve plugin-managed TOTP controller helpers.

    Returns:
        Requested helper from the controller assembly module.

    Raises:
        AttributeError: If ``name`` is not a supported export.
    """
    if name not in __all__:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    value = getattr(import_module("litestar_auth._plugin.totp_controller._core"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return the public helper inventory."""
    return sorted(__all__)
