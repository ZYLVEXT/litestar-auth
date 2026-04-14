"""Controller assembly helpers for the auth plugin façade."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any, TypedDict, cast

import msgspec  # noqa: TC002
from litestar import Controller, Request, get, post
from litestar.params import Parameter
from litestar.response import Response  # noqa: TC002

from litestar_auth._plugin.config import (
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
    StartupBackendTemplate,
    _BackendSlot,
    _StartupBackendInventory,
    require_session_maker,
    resolve_backend_inventory,
)
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth.config import validate_secret_length
from litestar_auth.controllers import (
    create_register_controller,
    create_reset_password_controller,
    create_users_controller,
    create_verify_controller,
)
from litestar_auth.controllers._utils import (
    _build_controller_name,
    _configure_request_body_handler,
    _create_before_request_handler,
    _create_request_body_exception_handlers,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.controllers.auth import (
    _handle_auth_login,
    _handle_auth_logout,
    _handle_auth_refresh,
    _make_auth_controller_context,
)
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
from litestar_auth.controllers.totp import (
    _totp_handle_confirm_enable,
    _totp_handle_disable,
    _totp_handle_enable,
    _totp_handle_verify,
    _totp_resolve_pending_jti_store,
    _totp_validate_replay_and_password,
    _TotpControllerContext,
)
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import (
    LoginCredentials,
    RefreshTokenRequest,
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpEnableResponse,
    TotpVerifyRequest,
)
from litestar_auth.ratelimit import TotpRateLimitOrchestrator
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import ControllerRouterHandler

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.oauth.client_adapter import OAuthClientProtocol
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, UsedTotpCodeStore
    from litestar_auth.types import LoginIdentifier


class _UserReadSchemaKwargs(TypedDict, total=False):
    """Optional read-schema kwargs accepted by controller factories."""

    user_read_schema: type[msgspec.Struct]


class _RegisterSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the register controller factory."""

    user_create_schema: type[msgspec.Struct]


class _UsersSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the users controller factory."""

    user_update_schema: type[msgspec.Struct]


def _resolve_request_backend[UP: UserProtocol[Any], ID](
    request_backends: object,
    *,
    backend_index: int,
    backend_name: str,
) -> AuthenticationBackend[UP, ID]:
    """Return the request-scoped backend matching the startup controller slot.

    Returns:
        Request-scoped backend aligned with the startup controller slot.
    """
    return _BackendSlot(index=backend_index, name=backend_name).resolve_request_backend(request_backends)


def create_auth_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    backend: StartupBackendTemplate[UP, ID],
    backend_index: int,
    rate_limit_config: AuthRateLimitConfig | None = None,
    enable_refresh: bool = False,
    requires_verification: bool = False,
    login_identifier: LoginIdentifier = "email",
    totp_pending_secret: str | None = None,
    totp_pending_lifetime: timedelta = timedelta(minutes=5),
    path: str = "/auth",
    unsafe_testing: bool = False,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Return a plugin auth controller bound to request-scoped backends via DI."""
    if totp_pending_secret is not None and not unsafe_testing:
        validate_secret_length(totp_pending_secret, label="totp_pending_secret")
    login_before = _create_before_request_handler(rate_limit_config.login if rate_limit_config else None)
    refresh_before = _create_before_request_handler(rate_limit_config.refresh if rate_limit_config else None)
    login_exception_handlers = _create_request_body_exception_handlers(
        validation_detail="Invalid login payload.",
        validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
    )

    def _build_runtime_context(litestar_auth_backends: object) -> object:
        request_backend = _resolve_request_backend(
            litestar_auth_backends,
            backend_index=backend_index,
            backend_name=backend.name,
        )
        return _make_auth_controller_context(
            backend=request_backend,
            rate_limit_config=rate_limit_config,
            enable_refresh=enable_refresh,
            requires_verification=requires_verification,
            login_identifier=login_identifier,
            totp_pending_secret=totp_pending_secret,
            totp_pending_lifetime=totp_pending_lifetime,
        )

    class AuthController(Controller):
        """Backend-bound authentication endpoints."""

        @post(
            "/login",
            before_request=login_before,
            exception_handlers=login_exception_handlers,
        )
        async def login(
            self,
            request: Request[Any, Any, Any],
            data: LoginCredentials,
            litestar_auth_user_manager: Any,  # noqa: ANN401
            litestar_auth_backends: Any,  # noqa: ANN401
        ) -> object:
            del self
            return await _handle_auth_login(
                request,
                data,
                ctx=cast("Any", _build_runtime_context(litestar_auth_backends)),
                user_manager=litestar_auth_user_manager,
            )

        @post("/logout", guards=[is_authenticated], security=security)
        async def logout(
            self,
            request: Request[Any, Any, Any],
            litestar_auth_backends: Any,  # noqa: ANN401
        ) -> object:
            del self
            return await _handle_auth_logout(
                request,
                ctx=cast("Any", _build_runtime_context(litestar_auth_backends)),
            )

    generated_controller: type[Controller] = AuthController
    if enable_refresh:

        class RefreshAuthController(AuthController):
            """Backend-bound authentication endpoints with refresh-token rotation."""

            @post("/refresh", before_request=refresh_before)
            async def refresh(
                self,
                request: Request[Any, Any, Any],
                data: RefreshTokenRequest,
                litestar_auth_user_manager: Any,  # noqa: ANN401
                litestar_auth_backends: Any,  # noqa: ANN401
            ) -> Response[Any]:
                del self
                return await _handle_auth_refresh(
                    request,
                    ctx=cast("Any", _build_runtime_context(litestar_auth_backends)),
                    data=data,
                    user_manager=litestar_auth_user_manager,
                )

        generated_controller = RefreshAuthController

    generated_controller.__module__ = __name__
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.__name__ = f"{_build_controller_name(backend.name)}AuthController"
    generated_controller.__qualname__ = generated_controller.__name__
    generated_controller.path = path
    return _mark_litestar_auth_route_handler(generated_controller)


def create_oauth_associate_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    user_manager_dependency_key: str,
    oauth_client: OAuthClientProtocol,
    redirect_base_url: str,
    path: str = "/auth/associate",
    cookie_secure: bool = True,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Return a plugin-owned OAuth associate controller bound to request DI."""
    return _create_plugin_oauth_associate_controller(
        provider_name=provider_name,
        user_manager=None,
        user_manager_dependency_key=user_manager_dependency_key,
        oauth_client=oauth_client,
        redirect_base_url=redirect_base_url,
        path=path,
        cookie_secure=cookie_secure,
        validate_redirect_base_url=False,
        security=security,
    )


def create_oauth_login_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    provider_name: str,
    oauth_client: OAuthClientProtocol,
    backend: StartupBackendTemplate[UP, ID],
    backend_index: int,
    redirect_base_url: str,
    cookie_secure: bool = True,
    oauth_scopes: Sequence[str] | None = None,
    associate_by_email: bool = False,
    trust_provider_email_verified: bool = False,
    path: str = "/auth/oauth",
) -> type[Controller]:
    """Return a plugin-owned OAuth login controller bound to request DI."""
    assembly = _build_plugin_oauth_controller_assembly(
        provider_name=provider_name,
        oauth_client=oauth_client,
        redirect_base_url=redirect_base_url,
        path=path,
        cookie_secure=cookie_secure,
        state_cookie_prefix="__oauth_state_",
        controller_name_suffix="OAuthController",
        # The plugin resolves the request-scoped manager inside the callback handler.
        user_manager_binding=_build_oauth_direct_user_manager_binding(cast("Any", object())),
        oauth_scopes=oauth_scopes,
        associate_by_email=associate_by_email,
        trust_provider_email_verified=trust_provider_email_verified,
        # Plugin-owned routes keep their debug/unsafe_testing escape hatch in startup validation.
        validate_redirect_base_url=False,
    )

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
        request_backend = _resolve_request_backend(
            litestar_auth_backends,
            backend_index=backend_index,
            backend_name=backend.name,
        )
        return await _complete_oauth_login_callback(
            assembly=assembly,
            request=request,
            code=code,
            oauth_state=oauth_state,
            user_manager=litestar_auth_user_manager,
            backend=request_backend,
        )

    return _create_plugin_oauth_controller_type(
        assembly=assembly,
        authorize_handler=_create_plugin_oauth_authorize_handler(
            assembly=assembly,
        ),
        callback_handler=callback,
        docstring="Provider-specific OAuth authorize/callback endpoints.",
    )


def _define_plugin_totp_controller_class_di[UP: UserProtocol[Any], ID](
    startup_ctx: _TotpControllerContext[UP, ID],
    *,
    backend_index: int,
    backend_name: str,
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], object] | None,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Build the plugin TOTP controller with request-scoped backend resolution.

    Returns:
        Controller subclass whose verify route resolves the request-scoped backend from DI.
    """

    def _runtime_context(litestar_auth_backends: object) -> _TotpControllerContext[UP, ID]:
        return replace(
            startup_ctx,
            backend=_resolve_request_backend(
                litestar_auth_backends,
                backend_index=backend_index,
                backend_name=backend_name,
            ),
        )

    class _TotpControllerBase(Controller):
        """TOTP 2FA management endpoints."""

        @post("/enable/confirm", guards=[is_authenticated], security=security)
        async def confirm_enable(
            self,
            request: Request[Any, Any, Any],
            data: TotpConfirmEnableRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> TotpConfirmEnableResponse:
            del self
            return await _totp_handle_confirm_enable(
                request,
                ctx=startup_ctx,
                data=data,
                user_manager=litestar_auth_user_manager,
            )

        @post("/verify", before_request=totp_verify_before_request)
        async def verify(
            self,
            request: Request[Any, Any, Any],
            data: TotpVerifyRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
            litestar_auth_backends: Any,  # noqa: ANN401
        ) -> object:
            del self
            return await _totp_handle_verify(
                request,
                ctx=_runtime_context(litestar_auth_backends),
                data=data,
                user_manager=litestar_auth_user_manager,
            )

        @post("/disable", guards=[is_authenticated], security=security)
        async def disable(
            self,
            request: Request[Any, Any, Any],
            data: TotpDisableRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> None:
            del self
            await _totp_handle_disable(
                request,
                ctx=startup_ctx,
                data=data,
                user_manager=litestar_auth_user_manager,
            )

    if startup_ctx.totp_enable_requires_password:

        async def _on_enable_request_body_error(request: Request[Any, Any, Any]) -> None:
            await startup_ctx.totp_rate_limit.on_invalid_attempt("enable", request)

        class TotpController(_TotpControllerBase):
            """TOTP 2FA management endpoints."""

            @post("/enable", guards=[is_authenticated], security=security)
            async def enable(
                self,
                request: Request[Any, Any, Any],
                litestar_auth_user_manager: Any,  # noqa: ANN401
                data: msgspec.Struct | None = None,
            ) -> TotpEnableResponse:
                del self
                return await _totp_handle_enable(
                    request,
                    ctx=startup_ctx,
                    data=cast("TotpEnableRequest | None", data),
                    user_manager=litestar_auth_user_manager,
                )

        _configure_request_body_handler(
            TotpController.enable,
            schema=TotpEnableRequest,
            validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
            on_validation_error=_on_enable_request_body_error,
            on_decode_error=_on_enable_request_body_error,
        )
    else:

        class TotpController(_TotpControllerBase):
            """TOTP 2FA management endpoints."""

            @post("/enable", guards=[is_authenticated], security=security)
            async def enable(
                self,
                request: Request[Any, Any, Any],
                litestar_auth_user_manager: Any,  # noqa: ANN401
            ) -> TotpEnableResponse:
                del self
                return await _totp_handle_enable(
                    request,
                    ctx=startup_ctx,
                    user_manager=litestar_auth_user_manager,
                )

    TotpController.__module__ = __name__
    TotpController.__qualname__ = TotpController.__name__
    return TotpController


def create_totp_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    backend: StartupBackendTemplate[UP, ID],
    backend_index: int,
    user_manager_dependency_key: str,
    used_tokens_store: UsedTotpCodeStore | None = None,
    pending_jti_store: JWTDenylistStore | None = None,
    require_replay_protection: bool = True,
    rate_limit_config: AuthRateLimitConfig | None = None,
    requires_verification: bool = False,
    totp_pending_secret: str,
    totp_enable_requires_password: bool = True,
    totp_issuer: str = "litestar-auth",
    totp_algorithm: TotpAlgorithm = "SHA256",
    totp_pending_lifetime: timedelta | None = None,
    id_parser: Callable[[str], ID] | None = None,
    path: str = "/auth/2fa",
    unsafe_testing: bool = False,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Return a plugin TOTP controller that resolves its backend from request DI."""
    del user_manager_dependency_key
    del totp_pending_lifetime
    if not unsafe_testing:
        validate_secret_length(totp_pending_secret, label="totp_pending_secret")
    _totp_validate_replay_and_password(
        used_tokens_store=used_tokens_store,
        require_replay_protection=require_replay_protection,
        totp_enable_requires_password=totp_enable_requires_password,
        user_manager=None,
        unsafe_testing=unsafe_testing,
    )
    effective_pending_jti_store = _totp_resolve_pending_jti_store(
        pending_jti_store,
        unsafe_testing=unsafe_testing,
    )
    totp_rate_limit = TotpRateLimitOrchestrator(
        enable=rate_limit_config.totp_enable if rate_limit_config else None,
        confirm_enable=rate_limit_config.totp_confirm_enable if rate_limit_config else None,
        verify=rate_limit_config.totp_verify if rate_limit_config else None,
        disable=rate_limit_config.totp_disable if rate_limit_config else None,
    )
    startup_ctx = _TotpControllerContext(
        backend=cast("Any", backend),
        used_tokens_store=used_tokens_store,
        require_replay_protection=require_replay_protection,
        requires_verification=requires_verification,
        totp_enable_requires_password=totp_enable_requires_password,
        totp_issuer=totp_issuer,
        totp_algorithm=totp_algorithm,
        totp_rate_limit=totp_rate_limit,
        totp_pending_secret=totp_pending_secret,
        effective_pending_jti_store=effective_pending_jti_store,
        id_parser=id_parser,
        unsafe_testing=unsafe_testing,
    )

    async def totp_verify_before_request(request: Request[Any, Any, Any]) -> None:
        await totp_rate_limit.before_request("verify", request)

    before = totp_verify_before_request if totp_rate_limit.verify is not None else None
    totp_controller_cls = _define_plugin_totp_controller_class_di(
        startup_ctx,
        backend_index=backend_index,
        backend_name=backend.name,
        totp_verify_before_request=before,
        security=security,
    )
    totp_controller_cls.__name__ = "TotpController"
    totp_controller_cls.__qualname__ = "TotpController"
    totp_controller_cls.path = path
    return totp_controller_cls


def build_controllers[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    security: Sequence[SecurityRequirement] | None = None,
) -> list[ControllerRouterHandler]:
    """Build the controller set for the configured plugin surface.

    Returns:
        Controllers matching the enabled auth features.
    """
    backend_inventory = resolve_backend_inventory(config)
    controllers = _build_auth_controllers(config=config, backend_inventory=backend_inventory, security=security)
    _append_optional_feature_controllers(
        controllers=controllers,
        config=config,
        backend_inventory=backend_inventory,
        security=security,
    )
    return controllers


def _build_auth_controllers[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: _StartupBackendInventory[UP, ID] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> list[ControllerRouterHandler]:
    """Build mandatory auth controllers per configured backend.

    Returns:
        Auth controllers corresponding to configured backends.
    """
    controllers: list[ControllerRouterHandler] = []
    require_session_maker(config)
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    for backend_entry in inventory.entries:
        totp_pending_secret = config.totp_config.totp_pending_secret if config.totp_config is not None else None
        controllers.append(
            create_auth_controller(
                backend=backend_entry.startup_backend,
                backend_index=backend_entry.index,
                rate_limit_config=config.rate_limit_config,
                enable_refresh=config.enable_refresh,
                requires_verification=config.requires_verification,
                login_identifier=config.login_identifier,
                totp_pending_secret=totp_pending_secret,
                path=backend_auth_path(
                    auth_path=config.auth_path,
                    backend_name=backend_entry.name,
                    index=backend_entry.index,
                ),
                unsafe_testing=config.unsafe_testing,
                security=security,
            ),
        )
    return controllers


def _append_optional_feature_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: _StartupBackendInventory[UP, ID] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> None:
    """Append optional controllers enabled by plugin flags."""
    if config.include_register:
        controllers.append(
            create_register_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                unsafe_testing=config.unsafe_testing,
                **register_schema_kwargs(config),
            ),
        )
    if config.include_verify:
        controllers.append(
            create_verify_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                unsafe_testing=config.unsafe_testing,
                **user_read_schema_kwargs(config),
            ),
        )
    if config.include_reset_password:
        controllers.append(
            create_reset_password_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                unsafe_testing=config.unsafe_testing,
                **user_read_schema_kwargs(config),
            ),
        )
    if config.include_users:
        controllers.append(
            create_users_controller(
                id_parser=config.id_parser,
                path=config.users_path,
                hard_delete=config.hard_delete,
                unsafe_testing=config.unsafe_testing,
                security=security,
                **users_schema_kwargs(config),
            ),
        )
    if config.totp_config is not None:
        controllers.append(build_totp_controller(config, backend_inventory=backend_inventory, security=security))
    _append_oauth_login_controllers(
        controllers=controllers,
        config=config,
        backend_inventory=backend_inventory,
    )
    _append_oauth_associate_controllers(controllers=controllers, config=config, security=security)


def _append_oauth_login_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
    backend_inventory: _StartupBackendInventory[UP, ID] | None = None,
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
    primary_backend = inventory.primary()
    controllers.extend(
        create_oauth_login_controller(
            provider_name=entry.name,
            oauth_client=cast("OAuthClientProtocol", entry.client),
            backend=primary_backend.startup_backend,
            backend_index=primary_backend.index,
            redirect_base_url=redirect_base_url,
            cookie_secure=contract.oauth_cookie_secure,
            oauth_scopes=contract.oauth_provider_scopes.get(entry.name),
            associate_by_email=contract.oauth_associate_by_email,
            trust_provider_email_verified=contract.oauth_trust_provider_email_verified,
            path=contract.login_path,
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
            provider_name=entry.name,
            user_manager_dependency_key=OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
            oauth_client=cast("OAuthClientProtocol", entry.client),
            redirect_base_url=redirect_base_url,
            path=contract.associate_path,
            cookie_secure=contract.oauth_cookie_secure,
            security=security,
        )
        for entry in contract.providers
    )


def build_totp_controller[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backend_inventory: _StartupBackendInventory[UP, ID] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> ControllerRouterHandler:
    """Build the configured TOTP controller surface.

    Returns:
        The mounted TOTP controller.

    Raises:
        ValueError: If ``totp_config`` is not configured.
    """
    totp_config = config.totp_config
    if totp_config is None:
        msg = "totp_config must be configured to build TOTP controller."
        raise ValueError(msg)
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    totp_backend_entry = inventory.resolve_totp(backend_name=totp_config.totp_backend_name)
    return create_totp_controller(
        backend=totp_backend_entry.startup_backend,
        backend_index=totp_backend_entry.index,
        user_manager_dependency_key=DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        used_tokens_store=totp_config.totp_used_tokens_store,
        pending_jti_store=totp_config.totp_pending_jti_store,
        require_replay_protection=totp_config.totp_require_replay_protection,
        rate_limit_config=config.rate_limit_config,
        requires_verification=config.requires_verification,
        totp_pending_secret=totp_config.totp_pending_secret,
        totp_enable_requires_password=totp_config.totp_enable_requires_password,
        totp_issuer=totp_config.totp_issuer,
        totp_algorithm=totp_config.totp_algorithm,
        id_parser=config.id_parser,
        path=totp_path(config.auth_path),
        unsafe_testing=config.unsafe_testing,
        security=security,
    )


def user_read_schema_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _UserReadSchemaKwargs:
    """Return non-null read-schema kwargs for controller factories."""
    result: _UserReadSchemaKwargs = {}
    if config.user_read_schema is not None:
        result["user_read_schema"] = config.user_read_schema
    return result


def register_schema_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _RegisterSchemaKwargs:
    """Return non-null register-schema kwargs for controller factories."""
    result: _RegisterSchemaKwargs = {}
    if config.user_read_schema is not None:
        result["user_read_schema"] = config.user_read_schema
    if config.user_create_schema is not None:
        result["user_create_schema"] = config.user_create_schema
    return result


def users_schema_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _UsersSchemaKwargs:
    """Return non-null users-schema kwargs for controller factories."""
    result: _UsersSchemaKwargs = {}
    if config.user_read_schema is not None:
        result["user_read_schema"] = config.user_read_schema
    if config.user_update_schema is not None:
        result["user_update_schema"] = config.user_update_schema
    return result


def backend_auth_path(*, auth_path: str, backend_name: str, index: int) -> str:
    """Return the public auth path for a backend-specific controller."""
    base_path = auth_path.rstrip("/") or "/"
    if index == 0:
        return base_path

    return f"{base_path}/{backend_name}"


def totp_backend[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backend_inventory: _StartupBackendInventory[UP, ID] | None = None,
) -> StartupBackendTemplate[UP, ID]:
    """Return the configured TOTP backend or the primary backend.

    Returns:
        The backend that should service TOTP flows.
    """
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    backend_name = None if config.totp_config is None else config.totp_config.totp_backend_name
    return inventory.resolve_totp(backend_name=backend_name).startup_backend


def totp_path(auth_path: str) -> str:
    """Return the mounted TOTP controller path."""
    base_path = auth_path.rstrip("/") or "/"
    return f"{base_path}/2fa"
