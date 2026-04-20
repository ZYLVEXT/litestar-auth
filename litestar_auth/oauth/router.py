"""Helpers for constructing provider-specific OAuth controllers."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

from litestar_auth.controllers.oauth import (
    OAuthControllerUserManagerProtocol,
    _create_login_oauth_controller,
    _validate_manual_oauth_redirect_base_url,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.oauth.client_adapter import _build_oauth_client_adapter
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar import Controller

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.oauth.client_adapter import OAuthClientConstructor, OAuthClientFactory, OAuthClientProtocol


def create_provider_oauth_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    backend: AuthenticationBackend[UP, ID],
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
    oauth_client: OAuthClientProtocol | None = None,
    oauth_client_factory: OAuthClientFactory | None = None,
    oauth_client_class: str | None = None,
    oauth_client_kwargs: Mapping[str, object] | None = None,
    redirect_base_url: str,
    auth_path: str = "/auth",
    path: str | None = None,
    cookie_secure: bool = True,
    oauth_scopes: Sequence[str] | None = None,
    associate_by_email: bool = False,
    trust_provider_email_verified: bool = False,
) -> type[Controller]:
    """Build a provider-specific OAuth controller from a client or lazy factory.

    The authorize endpoint uses only server-configured ``oauth_scopes``. Runtime
    scope-query overrides are rejected. ``redirect_base_url`` must use a
    non-loopback ``https://`` origin; the manual controller API does not expose
    a debug or testing override for insecure callback origins.

    Returns:
        Generated controller class mounted under the provider-specific path.
    """
    _validate_manual_oauth_redirect_base_url(redirect_base_url)
    oauth_client_adapter = _build_oauth_client_adapter(
        oauth_client=oauth_client,
        oauth_client_factory=oauth_client_factory,
        oauth_client_class=oauth_client_class,
        oauth_client_kwargs=oauth_client_kwargs,
        oauth_client_class_loader=load_httpx_oauth_client,
    )
    resolved_path = path if path is not None else _build_oauth_login_path(auth_path)

    return _create_login_oauth_controller(
        provider_name=provider_name,
        backend=backend,
        user_manager=user_manager,
        oauth_client_adapter=oauth_client_adapter,
        redirect_base_url=redirect_base_url,
        path=resolved_path,
        cookie_secure=cookie_secure,
        oauth_scopes=oauth_scopes,
        associate_by_email=associate_by_email,
        trust_provider_email_verified=trust_provider_email_verified,
        validate_redirect_base_url=False,
    )


def _build_oauth_login_path(auth_path: str) -> str:
    """Return the login-controller prefix for a given auth base path."""
    base_path = auth_path.rstrip("/") or "/"
    return f"{base_path}/oauth" if base_path != "/" else "/oauth"


def load_httpx_oauth_client(oauth_client_class: str, /, **client_kwargs: object) -> OAuthClientProtocol:
    """Import and instantiate an ``httpx-oauth`` client lazily.

    Returns:
        Instantiated OAuth client.

    Raises:
        ImportError: If the optional `httpx-oauth` dependency is not installed.
        ModuleNotFoundError: If a non-`httpx-oauth` import required by the client cannot be resolved.
        ConfigurationError: If the client path is invalid or the class cannot be imported.
    """
    module_name, _, class_name = oauth_client_class.rpartition(".")
    if not module_name or not class_name:
        msg = "oauth_client_class must be a fully qualified module path."
        raise ConfigurationError(msg)

    try:
        module = import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name is not None and exc.name.startswith("httpx_oauth"):
            msg = "Install litestar-auth[oauth] to use OAuth controllers."
            raise ImportError(msg) from exc
        raise

    oauth_client_type: OAuthClientConstructor | None = getattr(module, class_name, None)
    if oauth_client_type is None:
        msg = f"OAuth client class {oauth_client_class!r} could not be imported."
        raise ConfigurationError(msg)

    return oauth_client_type(**client_kwargs)
