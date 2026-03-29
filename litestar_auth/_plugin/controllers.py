"""Controller assembly helpers for the auth plugin façade."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypedDict

import msgspec

from litestar_auth._plugin.config import (
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
    require_session_maker,
)
from litestar_auth.controllers import (
    create_auth_controller,
    create_oauth_associate_controller,
    create_register_controller,
    create_reset_password_controller,
    create_totp_controller,
    create_users_controller,
    create_verify_controller,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    import msgspec
    from litestar.types import ControllerRouterHandler

    from litestar_auth.authentication.backend import AuthenticationBackend


class _UserReadSchemaKwargs(TypedDict, total=False):
    """Optional read-schema kwargs accepted by controller factories."""

    user_read_schema: type[msgspec.Struct]


class _RegisterSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the register controller factory."""

    user_create_schema: type[msgspec.Struct]


class _UsersSchemaKwargs(_UserReadSchemaKwargs, total=False):
    """Optional schema kwargs accepted by the users controller factory."""

    user_update_schema: type[msgspec.Struct]


def build_controllers[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> list[ControllerRouterHandler]:
    """Build the controller set for the configured plugin surface.

    Returns:
        Controllers matching the enabled auth features.
    """
    controllers = _build_auth_controllers(config=config)
    _append_optional_feature_controllers(controllers=controllers, config=config)
    return controllers


def _build_auth_controllers[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
) -> list[ControllerRouterHandler]:
    """Build mandatory auth controllers per configured backend.

    Returns:
        Auth controllers corresponding to configured backends.
    """
    controllers: list[ControllerRouterHandler] = []
    require_session_maker(config)
    for index, backend in enumerate(config.backends):
        totp_pending_secret = config.totp_config.totp_pending_secret if config.totp_config is not None else None
        controllers.append(
            create_auth_controller(
                backend=backend,
                rate_limit_config=config.rate_limit_config,
                enable_refresh=config.enable_refresh,
                requires_verification=config.requires_verification,
                login_identifier=config.login_identifier,
                totp_pending_secret=totp_pending_secret,
                path=backend_auth_path(auth_path=config.auth_path, backend_name=backend.name, index=index),
            ),
        )
    return controllers


def _append_optional_feature_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Append optional controllers enabled by plugin flags."""
    if config.include_register:
        controllers.append(
            create_register_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                **register_schema_kwargs(config),
            ),
        )
    if config.include_verify:
        controllers.append(
            create_verify_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                **user_read_schema_kwargs(config),
            ),
        )
    if config.include_reset_password:
        controllers.append(
            create_reset_password_controller(
                rate_limit_config=config.rate_limit_config,
                path=config.auth_path,
                **user_read_schema_kwargs(config),
            ),
        )
    if config.include_users:
        controllers.append(
            create_users_controller(
                id_parser=config.id_parser,
                path=config.users_path,
                hard_delete=config.hard_delete,
                **users_schema_kwargs(config),
            ),
        )
    if config.totp_config is not None:
        controllers.append(build_totp_controller(config))
    _append_oauth_associate_controllers(controllers=controllers, config=config)


def _append_oauth_associate_controllers[UP: UserProtocol[Any], ID](
    *,
    controllers: list[ControllerRouterHandler],
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Append OAuth-associate controllers for configured providers."""
    oauth_config = config.oauth_config
    if oauth_config is None:
        return
    if not (oauth_config.include_oauth_associate and oauth_config.oauth_associate_providers):
        return

    associate_path = f"{config.auth_path.rstrip('/')}/associate"
    redirect_base_url = oauth_config.oauth_associate_redirect_base_url or f"http://localhost{associate_path}"
    for provider_name, oauth_client in oauth_config.oauth_associate_providers:
        controllers.append(
            create_oauth_associate_controller(
                provider_name=provider_name,
                user_manager_dependency_key=OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
                oauth_client=oauth_client,
                redirect_base_url=redirect_base_url,
                path=associate_path,
                cookie_secure=oauth_config.oauth_cookie_secure,
            ),
        )


def build_totp_controller[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
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
    return create_totp_controller(
        backend=totp_backend(config),
        user_manager_dependency_key=DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        used_tokens_store=totp_config.totp_used_tokens_store,
        require_replay_protection=totp_config.totp_require_replay_protection,
        rate_limit_config=config.rate_limit_config,
        requires_verification=config.requires_verification,
        totp_pending_secret=totp_config.totp_pending_secret,
        totp_enable_requires_password=totp_config.totp_enable_requires_password,
        totp_issuer=totp_config.totp_issuer,
        totp_algorithm=totp_config.totp_algorithm,
        id_parser=config.id_parser,
        path=totp_path(config.auth_path),
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
) -> AuthenticationBackend[UP, ID]:
    """Return the configured TOTP backend or the primary backend.

    Returns:
        The backend that should service TOTP flows.

    Raises:
        ValueError: If ``totp_backend_name`` does not match any configured backend.
    """
    if config.totp_config is None or config.totp_config.totp_backend_name is None:
        return config.backends[0]

    for backend in config.backends:
        if backend.name == config.totp_config.totp_backend_name:
            return backend

    msg = f"Unknown TOTP backend: {config.totp_config.totp_backend_name}"
    raise ValueError(msg)


def totp_path(auth_path: str) -> str:
    """Return the mounted TOTP controller path."""
    base_path = auth_path.rstrip("/") or "/"
    return f"{base_path}/2fa"
