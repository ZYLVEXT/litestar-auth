"""Stable public OAuth helpers.

Use ``create_provider_oauth_controller`` from this package for the canonical
provider-login route-registration path, typically with
``auth_path=config.auth_path``. ``OAuthConfig.oauth_providers`` remains
declarative inventory only; the plugin never auto-mounts login routes from it.
Plugin-owned OAuth auto-mounting is limited to associate routes configured with
``include_oauth_associate=True`` plus ``oauth_associate_providers``.

Advanced custom route tables still use ``litestar_auth.controllers`` directly.
"""

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
