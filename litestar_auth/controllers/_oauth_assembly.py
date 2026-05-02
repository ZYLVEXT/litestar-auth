"""Assembly helpers for generated OAuth controllers."""

from __future__ import annotations

import keyword
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from litestar_auth.config import validate_oauth_provider_name
from litestar_auth.controllers._oauth_helpers import (
    _build_callback_url_from_base,
    _build_cookie_path,
    _normalize_oauth_scopes,
    _validate_manual_oauth_redirect_base_url,
)
from litestar_auth.controllers._utils import _build_controller_name
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.oauth._flow_cookie import _OAuthFlowCookieCipher
from litestar_auth.oauth.client_adapter import (
    OAuthClientAdapter,
    OAuthClientProtocol,
    _build_oauth_client_adapter,
)
from litestar_auth.oauth.service import OAuthService
from litestar_auth.oauth.service import (
    OAuthServiceUserManagerProtocol as OAuthControllerUserManagerProtocol,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar import Request

    from litestar_auth.authentication.backend import AuthenticationBackend


@dataclass(frozen=True, slots=True)
class _OAuthUserManagerBinding[UP: UserProtocol[Any], ID]:
    """Manager binding used by generated OAuth callback handlers."""

    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None
    dependency_parameter_name: str | None = None


@dataclass(frozen=True, slots=True)
class _OAuthControllerAssembly[UP: UserProtocol[Any], ID]:
    """Shared provider-scoped controller assembly details."""

    controller_name: str
    controller_path: str
    callback_url: str
    cookie_name: str
    cookie_path: str
    cookie_secure: bool
    oauth_scopes: tuple[str, ...] | None
    flow_cookie_cipher: _OAuthFlowCookieCipher
    oauth_service: OAuthService[UP, ID]
    user_manager_binding: _OAuthUserManagerBinding[UP, ID]


@dataclass(frozen=True, slots=True)
class _OAuthControllerAssemblySettings:
    """Static settings used to build a provider-scoped OAuth controller."""

    provider_name: str
    redirect_base_url: str
    path: str
    cookie_secure: bool
    oauth_flow_cookie_secret: str
    state_cookie_prefix: str
    controller_name_suffix: str
    validate_redirect_base_url: bool = True


@dataclass(frozen=True, slots=True)
class _OAuthServiceSettings:
    """OAuth service behavior toggles for a provider controller."""

    oauth_scopes: Sequence[str] | None = None
    associate_by_email: bool = False
    trust_provider_email_verified: bool = False


@dataclass(frozen=True, slots=True)
class _OAuthClientBinding:
    """Exactly one resolved or raw OAuth client input for controller assembly."""

    oauth_client: OAuthClientProtocol | None = None
    oauth_client_adapter: OAuthClientAdapter | None = None


@dataclass(frozen=True, slots=True)
class _OAuthLoginControllerSettings[UP: UserProtocol[Any], ID]:
    """Resolved inputs for a provider-specific OAuth login controller."""

    provider_name: str
    backend: AuthenticationBackend[UP, ID]
    user_manager: OAuthControllerUserManagerProtocol[UP, ID]
    oauth_client_adapter: OAuthClientAdapter
    redirect_base_url: str
    oauth_flow_cookie_secret: str
    path: str = "/auth/oauth"
    cookie_secure: bool = True
    oauth_scopes: Sequence[str] | None = None
    associate_by_email: bool = False
    trust_provider_email_verified: bool = False
    validate_redirect_base_url: bool = True


@dataclass(frozen=True, slots=True)
class _OAuthAssociateControllerSettings[UP: UserProtocol[Any], ID]:
    """Resolved inputs for a provider-specific OAuth association controller."""

    provider_name: str
    oauth_client: OAuthClientProtocol
    redirect_base_url: str
    oauth_flow_cookie_secret: str
    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None = None
    user_manager_dependency_key: str | None = None
    path: str = "/auth/associate"
    cookie_secure: bool = True
    validate_redirect_base_url: bool = True
    security: Sequence[Any] | None = None


@dataclass(frozen=True, slots=True)
class _OAuthLoginCallbackInputs[UP: UserProtocol[Any], ID]:
    """Runtime inputs needed to complete an OAuth login callback."""

    request: Request[Any, Any, Any]
    code: str
    oauth_state: str
    user_manager: OAuthControllerUserManagerProtocol[UP, ID]
    backend: AuthenticationBackend[UP, ID]


def _build_direct_user_manager_binding[UP: UserProtocol[Any], ID](
    user_manager: OAuthControllerUserManagerProtocol[UP, ID],
) -> _OAuthUserManagerBinding[UP, ID]:
    """Return a binding for a directly supplied user manager."""
    return _OAuthUserManagerBinding(user_manager=user_manager)


def _build_associate_user_manager_binding[UP: UserProtocol[Any], ID](
    *,
    user_manager: OAuthControllerUserManagerProtocol[UP, ID] | None,
    user_manager_dependency_key: str | None,
) -> _OAuthUserManagerBinding[UP, ID]:
    """Return the manager binding for OAuth account-association controllers.

    Raises:
        ConfigurationError: If neither or both user-manager inputs are provided.
    """
    if (user_manager is None) == (user_manager_dependency_key is None):
        msg = "Provide exactly one of user_manager or user_manager_dependency_key."
        raise ConfigurationError(msg)

    if user_manager is not None:
        return _OAuthUserManagerBinding(user_manager=user_manager)

    dependency_parameter_name = cast("str", user_manager_dependency_key)
    if not dependency_parameter_name.isidentifier() or keyword.iskeyword(dependency_parameter_name):
        msg = (
            "user_manager_dependency_key must be a valid Python identifier because Litestar matches dependency "
            "keys to callback parameter names."
        )
        raise ConfigurationError(msg)

    return _OAuthUserManagerBinding(
        user_manager=None,
        dependency_parameter_name=dependency_parameter_name,
    )


def _build_oauth_controller_assembly[UP: UserProtocol[Any], ID](
    *,
    settings: _OAuthControllerAssemblySettings,
    client_binding: _OAuthClientBinding,
    user_manager_binding: _OAuthUserManagerBinding[UP, ID],
    service_settings: _OAuthServiceSettings | None = None,
) -> _OAuthControllerAssembly[UP, ID]:
    """Build the shared provider-scoped OAuth controller assembly state.

    Returns:
        Shared controller metadata, callback details, cookie scope, and manager binding.

    Raises:
        ValueError: If internal callers provide neither or both client inputs.
    """
    oauth_client = client_binding.oauth_client
    oauth_client_adapter = client_binding.oauth_client_adapter
    if oauth_client is None and oauth_client_adapter is None:
        msg = "Provide oauth_client or oauth_client_adapter."
        raise ValueError(msg)
    if oauth_client is not None and oauth_client_adapter is not None:
        msg = "Provide only one of oauth_client or oauth_client_adapter."
        raise ValueError(msg)

    if oauth_client_adapter is None:
        oauth_client_adapter = _build_oauth_client_adapter(oauth_client=oauth_client)
    resolved_service_settings = _OAuthServiceSettings() if service_settings is None else service_settings

    validate_oauth_provider_name(settings.provider_name)
    if settings.validate_redirect_base_url:
        _validate_manual_oauth_redirect_base_url(settings.redirect_base_url)
    controller_path = _build_cookie_path(path=settings.path, provider_name=settings.provider_name)
    return _OAuthControllerAssembly(
        controller_name=f"{_build_controller_name(settings.provider_name)}{settings.controller_name_suffix}",
        controller_path=controller_path,
        callback_url=_build_callback_url_from_base(settings.redirect_base_url, settings.provider_name),
        cookie_name=f"{settings.state_cookie_prefix}{settings.provider_name}",
        cookie_path=controller_path,
        cookie_secure=settings.cookie_secure,
        oauth_scopes=_normalize_oauth_scopes(resolved_service_settings.oauth_scopes),
        flow_cookie_cipher=_OAuthFlowCookieCipher.from_secret(settings.oauth_flow_cookie_secret),
        oauth_service=OAuthService(
            provider_name=settings.provider_name,
            client=oauth_client_adapter,
            associate_by_email=resolved_service_settings.associate_by_email,
            trust_provider_email_verified=resolved_service_settings.trust_provider_email_verified,
        ),
        user_manager_binding=user_manager_binding,
    )
