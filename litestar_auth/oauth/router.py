"""Helpers for constructing provider-specific OAuth controllers."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, Unpack, overload

from litestar_auth.controllers.oauth import (
    OAuthControllerUserManagerProtocol,
    _create_login_oauth_controller,
    _OAuthLoginControllerSettings,
    _validate_manual_oauth_redirect_base_url,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.oauth.client_adapter import _build_oauth_client_adapter
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar import Controller

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.oauth._client_contracts import OAuthClientConstructor, OAuthClientFactory, OAuthClientProtocol


@dataclass(frozen=True, slots=True)
class ProviderOAuthControllerConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :func:`create_provider_oauth_controller`."""

    provider_name: str
    backend: AuthenticationBackend[UP, ID]
    user_manager: OAuthControllerUserManagerProtocol[UP, ID]
    redirect_base_url: str
    oauth_flow_cookie_secret: str
    oauth_client: OAuthClientProtocol | None = None
    oauth_client_factory: OAuthClientFactory | None = None
    oauth_client_class: str | None = None
    oauth_client_kwargs: Mapping[str, object] | None = None
    auth_path: str = "/auth"
    path: str | None = None
    cookie_secure: bool = True
    oauth_scopes: Sequence[str] | None = None
    associate_by_email: bool = False
    trust_provider_email_verified: bool = False


class ProviderOAuthControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :func:`create_provider_oauth_controller`."""

    provider_name: Required[str]
    backend: Required[AuthenticationBackend[UP, ID]]
    user_manager: Required[OAuthControllerUserManagerProtocol[UP, ID]]
    oauth_client: NotRequired[OAuthClientProtocol | None]
    oauth_client_factory: NotRequired[OAuthClientFactory | None]
    oauth_client_class: NotRequired[str | None]
    oauth_client_kwargs: NotRequired[Mapping[str, object] | None]
    redirect_base_url: Required[str]
    oauth_flow_cookie_secret: Required[str]
    auth_path: NotRequired[str]
    path: NotRequired[str | None]
    cookie_secure: NotRequired[bool]
    oauth_scopes: NotRequired[Sequence[str] | None]
    associate_by_email: NotRequired[bool]
    trust_provider_email_verified: NotRequired[bool]


@overload
def create_provider_oauth_controller[UP: UserProtocol[Any], ID](  # noqa: D418
    *,
    config: ProviderOAuthControllerConfig[UP, ID],
) -> type[Controller]:
    """Build a provider OAuth controller from grouped settings."""
    # pragma: no cover


@overload
def create_provider_oauth_controller[UP: UserProtocol[Any], ID](  # noqa: D418
    **options: Unpack[ProviderOAuthControllerOptions[UP, ID]],
) -> type[Controller]:
    """Build a provider OAuth controller from keyword settings."""
    # pragma: no cover


def create_provider_oauth_controller[UP: UserProtocol[Any], ID](
    *,
    config: ProviderOAuthControllerConfig[UP, ID] | None = None,
    **options: Unpack[ProviderOAuthControllerOptions[UP, ID]],
) -> type[Controller]:
    """Build a provider-specific OAuth controller from a client or lazy factory.

    The authorize endpoint uses only server-configured ``oauth_scopes``. Runtime
    scope-query overrides are rejected. ``redirect_base_url`` must use a
    non-loopback ``https://`` origin; the manual controller API does not expose
    a debug or testing override for insecure callback origins. The generated
    flow encrypts transient state + PKCE verifier material with
    ``oauth_flow_cookie_secret`` and enforces RFC 7636 PKCE S256, so manual
    clients must accept ``code_challenge`` / ``code_challenge_method`` on
    authorization and ``code_verifier`` on token exchange.

    Returns:
        Generated controller class mounted under the provider-specific path.

    Raises:
        ValueError: If ``config`` and keyword options are combined.
    """
    if config is not None and options:
        msg = "Pass either ProviderOAuthControllerConfig or keyword options, not both."
        raise ValueError(msg)
    settings = ProviderOAuthControllerConfig(**options) if config is None else config

    _validate_manual_oauth_redirect_base_url(settings.redirect_base_url)
    oauth_client_adapter = _build_oauth_client_adapter(
        oauth_client=settings.oauth_client,
        oauth_client_factory=settings.oauth_client_factory,
        oauth_client_class=settings.oauth_client_class,
        oauth_client_kwargs=settings.oauth_client_kwargs,
        oauth_client_class_loader=load_httpx_oauth_client,
    )
    resolved_path = settings.path if settings.path is not None else _build_oauth_login_path(settings.auth_path)

    return _create_login_oauth_controller(
        _OAuthLoginControllerSettings(
            provider_name=settings.provider_name,
            backend=settings.backend,
            user_manager=settings.user_manager,
            oauth_client_adapter=oauth_client_adapter,
            redirect_base_url=settings.redirect_base_url,
            oauth_flow_cookie_secret=settings.oauth_flow_cookie_secret,
            path=resolved_path,
            cookie_secure=settings.cookie_secure,
            oauth_scopes=settings.oauth_scopes,
            associate_by_email=settings.associate_by_email,
            trust_provider_email_verified=settings.trust_provider_email_verified,
            validate_redirect_base_url=False,
        ),
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
