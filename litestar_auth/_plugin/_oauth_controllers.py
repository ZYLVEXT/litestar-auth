"""Plugin-managed OAuth controller assembly."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from litestar import Controller, Request, get
from litestar.params import Parameter
from litestar.response import Response  # noqa: TC002

from litestar_auth._plugin.config import (
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
    StartupBackendInventory,
    resolve_backend_inventory,
)
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth.controllers.oauth import (
    _build_direct_user_manager_binding as _build_oauth_direct_user_manager_binding,
)
from litestar_auth.controllers.oauth import (
    _build_oauth_controller_assembly as _build_plugin_oauth_controller_assembly,
)
from litestar_auth.controllers.oauth import _complete_login_callback as _complete_oauth_login_callback
from litestar_auth.controllers.oauth import (
    _create_authorize_handler as _create_plugin_oauth_authorize_handler,
)
from litestar_auth.controllers.oauth import (
    _create_oauth_associate_controller as _create_plugin_oauth_associate_controller,
)
from litestar_auth.controllers.oauth import (
    _create_oauth_controller_type as _create_plugin_oauth_controller_type,
)
from litestar_auth.controllers.oauth import (
    _OAuthAssociateControllerSettings,
    _OAuthClientBinding,
    _OAuthControllerAssembly,
    _OAuthControllerAssemblySettings,
    _OAuthLoginCallbackInputs,
    _OAuthServiceSettings,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import ControllerRouterHandler

    from litestar_auth.oauth.client_adapter import OAuthClientProtocol


@dataclass(frozen=True, slots=True)
class _PluginOAuthAssociateControllerSettings:
    """Static settings for a plugin-owned OAuth associate controller."""

    provider_name: str
    user_manager_dependency_key: str
    oauth_client: OAuthClientProtocol
    redirect_base_url: str
    oauth_flow_cookie_secret: str
    path: str = "/auth/associate"
    cookie_secure: bool = True
    security: Sequence[SecurityRequirement] | None = None


@dataclass(frozen=True, slots=True)
class _PluginOAuthLoginControllerSettings[UP: UserProtocol[Any], ID]:
    """Static settings for a plugin-owned OAuth login controller."""

    provider_name: str
    oauth_client: OAuthClientProtocol
    backend_inventory: StartupBackendInventory[UP, ID]
    backend_index: int
    redirect_base_url: str
    oauth_flow_cookie_secret: str
    cookie_secure: bool = True
    oauth_scopes: Sequence[str] | None = None
    associate_by_email: bool = False
    trust_provider_email_verified: bool = False
    path: str = "/auth/oauth"


def create_oauth_associate_controller(
    settings: _PluginOAuthAssociateControllerSettings,
) -> type[Controller]:
    """Return a plugin-owned OAuth associate controller bound to request DI."""
    return _create_plugin_oauth_associate_controller(
        _OAuthAssociateControllerSettings(
            provider_name=settings.provider_name,
            user_manager=None,
            user_manager_dependency_key=settings.user_manager_dependency_key,
            oauth_client=settings.oauth_client,
            redirect_base_url=settings.redirect_base_url,
            oauth_flow_cookie_secret=settings.oauth_flow_cookie_secret,
            path=settings.path,
            cookie_secure=settings.cookie_secure,
            validate_redirect_base_url=False,
            security=settings.security,
        ),
    )


def create_oauth_login_controller[UP: UserProtocol[Any], ID](
    settings: _PluginOAuthLoginControllerSettings[UP, ID],
) -> type[Controller]:
    """Return a plugin-owned OAuth login controller bound to request DI."""
    assembly = _build_plugin_oauth_login_assembly(settings)
    return _create_plugin_oauth_controller_type(
        assembly=assembly,
        authorize_handler=_create_plugin_oauth_authorize_handler(
            assembly=assembly,
        ),
        callback_handler=_create_plugin_oauth_login_callback(settings=settings, assembly=assembly),
        docstring="Provider-specific OAuth authorize/callback endpoints.",
    )


def _build_plugin_oauth_login_assembly[UP: UserProtocol[Any], ID](
    settings: _PluginOAuthLoginControllerSettings[UP, ID],
) -> _OAuthControllerAssembly[UP, ID]:
    """Build shared assembly state for a plugin-owned OAuth login controller.

    Returns:
        Provider-scoped controller assembly state.
    """
    return _build_plugin_oauth_controller_assembly(
        settings=_OAuthControllerAssemblySettings(
            provider_name=settings.provider_name,
            redirect_base_url=settings.redirect_base_url,
            oauth_flow_cookie_secret=settings.oauth_flow_cookie_secret,
            path=settings.path,
            cookie_secure=settings.cookie_secure,
            state_cookie_prefix="__oauth_state_",
            controller_name_suffix="OAuthController",
            validate_redirect_base_url=False,
        ),
        client_binding=_OAuthClientBinding(oauth_client=settings.oauth_client),
        # The plugin resolves the request-scoped manager inside the callback handler.
        user_manager_binding=_build_oauth_direct_user_manager_binding(cast("Any", object())),
        service_settings=_OAuthServiceSettings(
            oauth_scopes=settings.oauth_scopes,
            associate_by_email=settings.associate_by_email,
            trust_provider_email_verified=settings.trust_provider_email_verified,
        ),
    )


def _create_plugin_oauth_login_callback[UP: UserProtocol[Any], ID](
    *,
    settings: _PluginOAuthLoginControllerSettings[UP, ID],
    assembly: _OAuthControllerAssembly[UP, ID],
) -> object:
    """Create the request-DI callback handler for plugin-owned OAuth login.

    Returns:
        Decorated Litestar route handler for the provider callback endpoint.
    """

    @get("/callback")
    async def callback(  # noqa: PLR0913, PLR0917
        self: object,
        request: Request[Any, Any, Any],
        code: str,
        litestar_auth_user_manager: Any,  # noqa: ANN401
        litestar_auth_backends: Any,  # noqa: ANN401
        oauth_state: str = Parameter(query="state"),
    ) -> Response[Any]:
        del self
        request_backend = settings.backend_inventory.resolve_request_backend(
            litestar_auth_backends,
            backend_index=settings.backend_index,
        )
        return await _complete_oauth_login_callback(
            assembly=assembly,
            callback_inputs=_OAuthLoginCallbackInputs(
                request=request,
                code=code,
                oauth_state=oauth_state,
                user_manager=litestar_auth_user_manager,
                backend=request_backend,
            ),
        )

    return callback


def _append_oauth_login_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: StartupBackendInventory[UP, ID] | None = None,
) -> None:
    """Append plugin-owned OAuth login controllers for configured providers."""
    contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=config.oauth_config,
    )
    if not contract.has_plugin_owned_login_routes:
        return

    redirect_base_url = contract.login_redirect_base_url
    if redirect_base_url is None:  # pragma: no cover - validation guarantees this when providers exist
        return
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    primary_backend_index, _primary_backend = inventory.primary()
    controllers.extend(
        create_oauth_login_controller(
            _PluginOAuthLoginControllerSettings(
                provider_name=entry.name,
                oauth_client=cast("OAuthClientProtocol", entry.client),
                backend_inventory=inventory,
                backend_index=primary_backend_index,
                redirect_base_url=redirect_base_url,
                oauth_flow_cookie_secret=cast("str", contract.oauth_flow_cookie_secret),
                cookie_secure=contract.oauth_cookie_secure,
                oauth_scopes=contract.oauth_provider_scopes.get(entry.name),
                associate_by_email=contract.oauth_associate_by_email,
                trust_provider_email_verified=contract.oauth_trust_provider_email_verified,
                path=contract.login_path,
            ),
        )
        for entry in contract.providers
    )


def _append_oauth_associate_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
    security: Sequence[SecurityRequirement] | None = None,
) -> None:
    """Append OAuth-associate controllers for configured providers."""
    contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=config.oauth_config,
    )
    if not contract.has_plugin_owned_associate_routes:
        return

    redirect_base_url = contract.associate_redirect_base_url
    if redirect_base_url is None:  # pragma: no cover - validation guarantees this when routes exist
        return
    controllers.extend(
        create_oauth_associate_controller(
            _PluginOAuthAssociateControllerSettings(
                provider_name=entry.name,
                user_manager_dependency_key=OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
                oauth_client=cast("OAuthClientProtocol", entry.client),
                redirect_base_url=redirect_base_url,
                oauth_flow_cookie_secret=cast("str", contract.oauth_flow_cookie_secret),
                path=contract.associate_path,
                cookie_secure=contract.oauth_cookie_secure,
                security=security,
            ),
        )
        for entry in contract.providers
    )
