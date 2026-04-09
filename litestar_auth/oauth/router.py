"""Helpers for constructing provider-specific OAuth controllers."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

from litestar_auth.controllers.oauth import (
    OAuthControllerUserManagerProtocol,
    _validate_manual_oauth_redirect_base_url,
    create_oauth_controller,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from litestar import Controller

    from litestar_auth.authentication.backend import AuthenticationBackend


def create_provider_oauth_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    backend: AuthenticationBackend[UP, ID],
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
    oauth_client: object | None = None,
    oauth_client_factory: Callable[[], object] | None = None,
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
    a debug or testing escape hatch for insecure callback origins.

    Returns:
        Generated controller class mounted under the provider-specific path.

    Raises:
        ConfigurationError: If no OAuth client configuration is provided or
            ``redirect_base_url`` is not a public HTTPS origin.
    """
    _validate_manual_oauth_redirect_base_url(redirect_base_url)
    client = oauth_client
    if client is None and oauth_client_factory is not None:
        client = oauth_client_factory()
    if client is None and oauth_client_class is not None:
        client = load_httpx_oauth_client(oauth_client_class, **dict(oauth_client_kwargs or {}))
    if client is None:
        msg = "Provide oauth_client, oauth_client_factory, or oauth_client_class."
        raise ConfigurationError(msg)

    resolved_path = path if path is not None else _build_oauth_login_path(auth_path)

    return create_oauth_controller(
        provider_name=provider_name,
        backend=backend,
        user_manager=user_manager,
        oauth_client=client,
        redirect_base_url=redirect_base_url,
        path=resolved_path,
        cookie_secure=cookie_secure,
        oauth_scopes=oauth_scopes,
        associate_by_email=associate_by_email,
        trust_provider_email_verified=trust_provider_email_verified,
    )


def _build_oauth_login_path(auth_path: str) -> str:
    """Return the canonical login-controller prefix for a given auth base path."""
    base_path = auth_path.rstrip("/") or "/"
    return f"{base_path}/oauth" if base_path != "/" else "/oauth"


def load_httpx_oauth_client(oauth_client_class: str, /, **client_kwargs: object) -> object:
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

    oauth_client_type = getattr(module, class_name, None)
    if oauth_client_type is None:
        msg = f"OAuth client class {oauth_client_class!r} could not be imported."
        raise ConfigurationError(msg)

    return oauth_client_type(**client_kwargs)
