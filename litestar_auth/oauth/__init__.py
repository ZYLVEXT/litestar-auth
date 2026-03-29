"""OAuth package."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.oauth.router import create_provider_oauth_controller, load_httpx_oauth_client

__all__ = ("create_provider_oauth_controller", "load_httpx_oauth_client")


def __getattr__(name: str) -> Callable[..., object]:
    """Lazily resolve public OAuth router helpers.

    Returns:
        Requested public OAuth router helper.

    Raises:
        AttributeError: If ``name`` is not a supported public export.
    """
    router = import_module("litestar_auth.oauth.router")
    if name == "create_provider_oauth_controller":
        return router.create_provider_oauth_controller
    if name == "load_httpx_oauth_client":
        return router.load_httpx_oauth_client
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
