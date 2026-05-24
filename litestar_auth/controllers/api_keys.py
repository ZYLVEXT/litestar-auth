"""API-key management controller factories."""

from __future__ import annotations

from typing import TYPE_CHECKING, Unpack, overload

from litestar_auth.controllers._api_key_admin import define_admin_api_keys_controller
from litestar_auth.controllers._api_key_common import (
    ApiKeysControllerConfig,
    ApiKeysControllerContext,
    ApiKeysControllerOptions,
    ApiKeysControllerUserManagerProtocol,
)
from litestar_auth.controllers._api_key_self import define_self_api_keys_controller
from litestar_auth.controllers._utils import (
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _mark_litestar_auth_route_handler,
)

if TYPE_CHECKING:
    from litestar import Controller


@overload
def create_api_keys_controllers[ID](
    *,
    config: ApiKeysControllerConfig[ID],
) -> list[type[Controller]]:
    pass  # pragma: no cover


@overload
def create_api_keys_controllers[ID](**options: Unpack[ApiKeysControllerOptions[ID]]) -> list[type[Controller]]:
    pass  # pragma: no cover


def create_api_keys_controllers[ID](
    *,
    config: ApiKeysControllerConfig[ID] | None = None,
    **options: Unpack[ApiKeysControllerOptions[ID]],
) -> list[type[Controller]]:
    """Return self-service and admin API-key controller classes.

    Returns:
        Generated self-service and admin controller classes.

    Raises:
        ValueError: If ``config`` and keyword options are combined.
    """
    if config is not None and options:
        msg = "Pass either ApiKeysControllerConfig or keyword options, not both."
        raise ValueError(msg)
    settings = ApiKeysControllerConfig(**options) if config is None else config
    create_rate_limit = settings.rate_limit_config.api_key_create if settings.rate_limit_config else None
    update_rate_limit = settings.rate_limit_config.api_key_update if settings.rate_limit_config else None
    create_rate_limit_increment, create_rate_limit_reset = _create_rate_limit_handlers(create_rate_limit)
    update_rate_limit_increment, update_rate_limit_reset = _create_rate_limit_handlers(update_rate_limit)
    ctx = ApiKeysControllerContext(
        id_parser=settings.id_parser,
        create_before_request=_create_before_request_handler(create_rate_limit),
        create_rate_limit_increment=create_rate_limit_increment,
        create_rate_limit_reset=create_rate_limit_reset,
        update_before_request=_create_before_request_handler(update_rate_limit),
        update_rate_limit_increment=update_rate_limit_increment,
        update_rate_limit_reset=update_rate_limit_reset,
        security=settings.security,
        require_step_up_on_create=settings.require_step_up_on_create,
        signing_enabled=settings.signing_enabled,
        totp_stepup_policy=dict(settings.totp_stepup_policy),
    )
    self_controller = define_self_api_keys_controller(ctx)
    admin_controller = define_admin_api_keys_controller(ctx)
    self_controller.path = settings.path
    admin_controller.path = settings.users_path
    return [_mark_litestar_auth_route_handler(self_controller), _mark_litestar_auth_route_handler(admin_controller)]


__all__ = (
    "ApiKeysControllerConfig",
    "ApiKeysControllerOptions",
    "ApiKeysControllerUserManagerProtocol",
    "create_api_keys_controllers",
)
