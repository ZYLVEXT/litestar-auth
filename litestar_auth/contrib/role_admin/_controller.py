"""Opt-in factory for the contrib role-administration controller surface."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypedDict, Unpack, cast, overload

import msgspec

from litestar_auth._plugin.role_admin import (
    RoleModelFamily,
    resolve_role_model_family,
)
from litestar_auth.contrib.role_admin._controller_handler_utils import (
    RoleAdminControllerBase,
    RoleAdminControllerContext,
)
from litestar_auth.contrib.role_admin._controller_handlers import (
    create_assign_role_handler,
    create_create_role_handler,
    create_delete_role_handler,
    create_get_role_handler,
    create_list_role_users_handler,
    create_list_roles_handler,
    create_unassign_role_handler,
    create_update_role_handler,
)
from litestar_auth.contrib.role_admin._schemas import RoleCreate, RoleRead, RoleUpdate, UserBrief
from litestar_auth.controllers._utils import (
    _build_controller_name,
    _configure_request_body_handler,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.guards import is_superuser
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar import Controller
    from litestar.types import Guard

    from litestar_auth._plugin.config import LitestarAuthConfig


@dataclass(frozen=True, slots=True)
class RoleAdminControllerConfig[UP: UserProtocol[Any]]:
    """Configuration for :func:`create_role_admin_controller`."""

    config: LitestarAuthConfig[UP, Any] | None = None
    user_model: type[UP] | None = None
    role_model: type[Any] | None = None
    user_role_model: type[Any] | None = None
    route_prefix: str = "roles"
    guards: Sequence[Guard] | None = None


class RoleAdminControllerOptions[UP: UserProtocol[Any]](TypedDict, total=False):
    """Keyword options accepted by :func:`create_role_admin_controller`."""

    config: LitestarAuthConfig[UP, Any] | None
    user_model: type[UP] | None
    role_model: type[Any] | None
    user_role_model: type[Any] | None
    route_prefix: str
    guards: Sequence[Guard] | None


def _normalize_route_prefix(route_prefix: str) -> str:
    """Return a normalized controller path fragment for the supplied route prefix.

    Raises:
        ConfigurationError: If the normalized route prefix would be empty.
    """
    normalized_route_prefix = route_prefix.strip("/")
    if normalized_route_prefix:
        return normalized_route_prefix

    msg = "create_role_admin_controller route_prefix must not be empty."
    raise ConfigurationError(msg)


def _resolve_model_family[UP: UserProtocol[Any]](
    *,
    config: LitestarAuthConfig[UP, Any] | None,
    user_model: type[UP] | None,
    role_model: type[Any] | None,
    user_role_model: type[Any] | None,
) -> RoleModelFamily[UP]:
    """Return the explicit-or-configured role-admin model family.

    Raises:
        ConfigurationError: If config-driven resolution is requested without
            enough explicit model overrides to fill the gaps.
    """
    if config is None:
        if user_model is None or role_model is None or user_role_model is None:
            msg = (
                "create_role_admin_controller requires either explicit user_model, role_model, and "
                "user_role_model arguments or a LitestarAuthConfig for config-driven resolution."
            )
            raise ConfigurationError(msg)
        return RoleModelFamily(
            user_model=user_model,
            role_model=role_model,
            user_role_model=user_role_model,
        )

    resolved_family = resolve_role_model_family(config.user_model)
    return RoleModelFamily(
        user_model=user_model or resolved_family.user_model,
        role_model=role_model or resolved_family.role_model,
        user_role_model=user_role_model or resolved_family.user_role_model,
    )


def _set_dependency_parameter_name(
    handler_fn: object,
    *,
    current_name: str,
    parameter_name: str,
) -> None:
    """Rename one dependency parameter in the Litestar-visible handler signature.

    The rename is a no-op when the handler does not declare ``current_name``: the
    config+session_maker branch opens its own sessions and therefore never binds
    the request-scoped ``db_session`` dependency. Guarding on ``signature.parameters``
    keeps the factory safe for that branch even when the configured
    ``db_session_dependency_key`` differs from the default.
    """
    signature = inspect.signature(cast("Any", handler_fn))
    if current_name not in signature.parameters:
        return
    parameters: list[inspect.Parameter] = []
    for parameter in signature.parameters.values():
        if parameter.name == current_name:
            parameters.append(parameter.replace(name=parameter_name))
            continue
        parameters.append(parameter)

    adapted_handler = cast("Any", handler_fn)
    adapted_handler.__signature__ = inspect.Signature(
        parameters=parameters,
        return_annotation=signature.return_annotation,
    )
    adapted_handler.__annotations__ = {
        **getattr(handler_fn, "__annotations__", {}),
        parameter_name: adapted_handler.__annotations__.pop(current_name),
    }


def _configure_request_session_dependency(
    controller_cls: type[Controller],
    *,
    parameter_name: str,
) -> None:
    """Rename the request-scoped session dependency for all generated handlers."""
    if parameter_name == "db_session":
        return

    for handler_name in (
        "list_roles",
        "create_role",
        "get_role",
        "update_role",
        "delete_role",
        "assign_role",
        "unassign_role",
        "list_role_users",
    ):
        _set_dependency_parameter_name(
            getattr(controller_cls, handler_name).fn,
            current_name="db_session",
            parameter_name=parameter_name,
        )


def _remove_handler_parameters(handler_fn: object, *, parameter_names: frozenset[str]) -> None:
    """Remove request-scoped dependency parameters from the Litestar-visible handler signature."""
    signature = inspect.signature(cast("Any", handler_fn))
    adapted_handler = cast("Any", handler_fn)
    adapted_handler.__signature__ = inspect.Signature(
        parameters=[parameter for parameter in signature.parameters.values() if parameter.name not in parameter_names],
        return_annotation=signature.return_annotation,
    )
    adapted_handler.__annotations__ = {
        key: value for key, value in getattr(handler_fn, "__annotations__", {}).items() if key not in parameter_names
    }


def _remove_request_session_dependency(controller_cls: type[Controller]) -> None:
    """Remove request-scoped role-admin dependencies for config-driven controllers."""
    parameter_names = frozenset(("db_session", "litestar_auth_user_manager"))
    for handler_name in (
        "list_roles",
        "create_role",
        "get_role",
        "update_role",
        "delete_role",
        "assign_role",
        "unassign_role",
        "list_role_users",
    ):
        _remove_handler_parameters(getattr(controller_cls, handler_name).fn, parameter_names=parameter_names)


def _resolve_role_admin_controller_settings[UP: UserProtocol[Any]](
    *,
    controller_config: RoleAdminControllerConfig[UP] | None,
    options: RoleAdminControllerOptions[UP],
) -> RoleAdminControllerConfig[UP]:
    """Return the grouped role-admin controller settings.

    Raises:
        ValueError: If ``controller_config`` and keyword options are combined.
    """
    if controller_config is not None and options:
        msg = "Pass either RoleAdminControllerConfig or keyword options, not both."
        raise ValueError(msg)
    return RoleAdminControllerConfig(**options) if controller_config is None else controller_config


def _create_role_page_schema_type() -> type[msgspec.Struct]:
    return msgspec.defstruct(
        "RolePageSchema",
        [
            ("items", list[RoleRead]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )


def _create_role_user_page_schema_type() -> type[msgspec.Struct]:
    return msgspec.defstruct(
        "RoleUserPageSchema",
        [
            ("items", list[UserBrief]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )


def _create_role_admin_controller_type(controller_name: str) -> type[RoleAdminControllerBase]:
    controller_cls = type(
        controller_name,
        (RoleAdminControllerBase,),
        {
            "__module__": __name__,
            "__doc__": "Generated contrib role-administration controller.",
            "list_roles": create_list_roles_handler(),
            "create_role": create_create_role_handler(),
            "get_role": create_get_role_handler(),
            "update_role": create_update_role_handler(),
            "delete_role": create_delete_role_handler(),
            "assign_role": create_assign_role_handler(),
            "unassign_role": create_unassign_role_handler(),
            "list_role_users": create_list_role_users_handler(),
        },
    )
    controller_cls.__qualname__ = controller_name
    return cast("type[RoleAdminControllerBase]", controller_cls)


def _build_role_admin_controller_context[UP: UserProtocol[Any]](
    *,
    settings: RoleAdminControllerConfig[UP],
    normalized_route_prefix: str,
    resolved_guards: tuple[Guard, ...],
) -> RoleAdminControllerContext[UP]:
    model_family = _resolve_model_family(
        config=settings.config,
        user_model=settings.user_model,
        role_model=settings.role_model,
        user_role_model=settings.user_role_model,
    )
    return RoleAdminControllerContext(
        config=settings.config,
        model_family=model_family,
        route_prefix=normalized_route_prefix,
        guards=resolved_guards,
        role_page_schema_type=_create_role_page_schema_type(),
        role_user_page_schema_type=_create_role_user_page_schema_type(),
        db_session_dependency_key="db_session"
        if settings.config is None
        else settings.config.db_session_dependency_key,
    )


def _finalize_role_admin_controller[UP: UserProtocol[Any]](
    controller_cls: type[RoleAdminControllerBase],
    *,
    settings: RoleAdminControllerConfig[UP],
    normalized_route_prefix: str,
    resolved_guards: tuple[Guard, ...],
    controller_context: RoleAdminControllerContext[UP],
) -> type[Controller]:
    controller_cls.path = f"/{normalized_route_prefix}"
    controller_cls.guards = list(resolved_guards)
    controller_cls.role_admin_context = controller_context
    controller_for_body_config = cast("Any", controller_cls)
    _configure_request_body_handler(controller_for_body_config.create_role, schema=RoleCreate)
    _configure_request_body_handler(controller_for_body_config.update_role, schema=RoleUpdate)
    if settings.config is not None and settings.config.session_maker is not None:
        _remove_request_session_dependency(controller_cls)
    else:
        _configure_request_session_dependency(
            controller_cls,
            parameter_name=controller_context.db_session_dependency_key,
        )
    return _mark_litestar_auth_route_handler(cast("type[Controller]", controller_cls))


@overload
def create_role_admin_controller[UP: UserProtocol[Any]](  # noqa: D418
    *,
    controller_config: RoleAdminControllerConfig[UP],
) -> type[Controller]:
    """Build a role-admin controller from grouped settings."""
    # pragma: no cover


@overload
def create_role_admin_controller[UP: UserProtocol[Any]](  # noqa: D418
    **options: Unpack[RoleAdminControllerOptions[UP]],
) -> type[Controller]:
    """Build a role-admin controller from keyword settings."""
    # pragma: no cover


def create_role_admin_controller[UP: UserProtocol[Any]](
    *,
    controller_config: RoleAdminControllerConfig[UP] | None = None,
    **options: Unpack[RoleAdminControllerOptions[UP]],
) -> type[Controller]:
    """Return a controller subclass scaffold for contrib role administration.

    Args:
        controller_config: Optional grouped role-admin controller settings.
        **options: Individual role-admin controller settings. ``config`` inside
            these options is the existing plugin configuration input. Other
            keyword options are ``user_model``, ``role_model``,
            ``user_role_model``, ``route_prefix``, and ``guards``.

    Returns:
        Controller subclass carrying the resolved role-admin assembly metadata.
    """
    settings = _resolve_role_admin_controller_settings(controller_config=controller_config, options=options)

    normalized_route_prefix = _normalize_route_prefix(settings.route_prefix)
    resolved_guards = tuple((is_superuser,) if settings.guards is None else settings.guards)
    typed_guards = cast("tuple[Guard, ...]", resolved_guards)
    controller_context = _build_role_admin_controller_context(
        settings=settings,
        normalized_route_prefix=normalized_route_prefix,
        resolved_guards=typed_guards,
    )
    controller_name = f"{_build_controller_name(normalized_route_prefix)}RoleAdminController"
    return _finalize_role_admin_controller(
        _create_role_admin_controller_type(controller_name),
        settings=settings,
        normalized_route_prefix=normalized_route_prefix,
        resolved_guards=typed_guards,
        controller_context=controller_context,
    )
