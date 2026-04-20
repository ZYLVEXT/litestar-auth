"""Opt-in public surface for HTTP role-administration controllers."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.contrib.role_admin._controller import create_role_admin_controller

__all__ = ("create_role_admin_controller",)


def __getattr__(name: str) -> Callable[..., object]:
    """Lazily resolve the public role-admin controller factory.

    Returns:
        The requested public role-admin factory.

    Raises:
        AttributeError: If ``name`` is not part of the public package surface.
    """
    if name == "create_role_admin_controller":
        controller_module = import_module("litestar_auth.contrib.role_admin._controller")
        return controller_module.create_role_admin_controller
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
