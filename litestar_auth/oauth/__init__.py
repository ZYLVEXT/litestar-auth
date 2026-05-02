"""Stable public OAuth helpers.

Use ``create_provider_oauth_controller`` from this package when you need a
manual OAuth login controller, typically with ``auth_path=config.auth_path``.
Plugin-managed apps can instead declare ``OAuthConfig.oauth_providers`` plus
``oauth_redirect_base_url`` to auto-mount login routes, and
``include_oauth_associate=True`` extends that same provider inventory with
associate routes.

Advanced custom route tables still use ``litestar_auth.controllers`` directly.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.oauth.client_adapter import (
        OAuthEmailVerificationAsyncClientProtocol,
        OAuthEmailVerificationSyncClientProtocol,
        make_async_email_verification_client,
    )
    from litestar_auth.oauth.router import (
        ProviderOAuthControllerConfig,
        create_provider_oauth_controller,
        load_httpx_oauth_client,
    )

__all__ = (
    "OAuthEmailVerificationAsyncClientProtocol",
    "OAuthEmailVerificationSyncClientProtocol",
    "ProviderOAuthControllerConfig",
    "create_provider_oauth_controller",
    "load_httpx_oauth_client",
    "make_async_email_verification_client",
)


def __getattr__(name: str) -> Callable[..., object]:
    """Lazily resolve public OAuth router helpers.

    Returns:
        Requested public OAuth router helper.

    Raises:
        AttributeError: If ``name`` is not a supported public export.
    """
    if name == "create_provider_oauth_controller":
        router = import_module("litestar_auth.oauth.router")
        return router.create_provider_oauth_controller
    if name == "ProviderOAuthControllerConfig":
        router = import_module("litestar_auth.oauth.router")
        return router.ProviderOAuthControllerConfig
    if name == "load_httpx_oauth_client":
        router = import_module("litestar_auth.oauth.router")
        return router.load_httpx_oauth_client
    if name == "OAuthEmailVerificationAsyncClientProtocol":
        client_adapter = import_module("litestar_auth.oauth.client_adapter")
        return client_adapter.OAuthEmailVerificationAsyncClientProtocol
    if name == "OAuthEmailVerificationSyncClientProtocol":
        client_adapter = import_module("litestar_auth.oauth.client_adapter")
        return client_adapter.OAuthEmailVerificationSyncClientProtocol
    if name == "make_async_email_verification_client":
        client_adapter = import_module("litestar_auth.oauth.client_adapter")
        return client_adapter.make_async_email_verification_client
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
