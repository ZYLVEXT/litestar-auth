"""User CRUD controller factory for profile and admin management endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, TypedDict, Unpack, cast, overload, runtime_checkable

import msgspec
from litestar import Controller, Request
from litestar.exceptions import ClientException, NotFoundException

from litestar_auth.controllers._users_helpers import (
    SELF_UPDATE_FORBIDDEN_FIELDS as _USERS_SELF_UPDATE_FORBIDDEN_FIELDS,
)
from litestar_auth.controllers._users_helpers import (
    _build_safe_self_update,
    _create_change_password_rate_limit_handlers,
)
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    _configure_request_body_handler,
    _map_domain_exceptions,
    _mark_litestar_auth_route_handler,
    _require_account_state,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.schemas import AdminUserUpdate, ChangePasswordRequest, UserRead, UserUpdate
from litestar_auth.types import RoleCapableUserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.controllers._utils import RequestHandler
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.types import LoginIdentifier

SELF_UPDATE_FORBIDDEN_FIELDS = _USERS_SELF_UPDATE_FORBIDDEN_FIELDS


class UsersControllerUserProtocol[ID](RoleCapableUserProtocol[ID], Protocol):
    """Protocol describing the public user fields returned by the users controller."""

    email: str
    is_active: bool
    is_verified: bool


@runtime_checkable
class UsersControllerUserManagerProtocol[UP: UsersControllerUserProtocol[Any], ID](
    AccountStateValidatorProvider[UP],
    Protocol,
):
    """User-manager behavior required by the users controller."""

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: LoginIdentifier | None = None,
    ) -> UP | None:
        """Return the authenticated user for valid credentials."""

    async def get(self, user_id: ID) -> UP | None:
        """Return a user by identifier."""

    async def update(
        self,
        user_update: msgspec.Struct | Mapping[str, Any],
        user: UP,
        *,
        allow_privileged: bool = False,
    ) -> UP:
        """Update and return a user."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[Sequence[UP], int]:
        """Return paginated users and the total available count."""

    async def delete(self, user_id: ID) -> None:
        """Delete a user permanently."""


@dataclass(frozen=True, slots=True)
class UsersControllerConfig[ID]:
    """Configuration for :func:`create_users_controller`."""

    id_parser: Callable[[str], ID] | None = None
    rate_limit_config: AuthRateLimitConfig | None = None
    path: str = "/users"
    default_limit: int = 50
    max_limit: int = 100
    hard_delete: bool = False
    user_read_schema: type[msgspec.Struct] = UserRead
    user_update_schema: type[msgspec.Struct] = UserUpdate
    admin_user_update_schema: type[msgspec.Struct] = AdminUserUpdate
    unsafe_testing: bool = False
    security: Sequence[SecurityRequirement] | None = None


class UsersControllerOptions[ID](TypedDict, total=False):
    """Keyword options accepted by :func:`create_users_controller`."""

    id_parser: Callable[[str], ID] | None
    rate_limit_config: AuthRateLimitConfig | None
    path: str
    default_limit: int
    max_limit: int
    hard_delete: bool
    user_read_schema: type[msgspec.Struct]
    user_update_schema: type[msgspec.Struct]
    admin_user_update_schema: type[msgspec.Struct]
    unsafe_testing: bool
    security: Sequence[SecurityRequirement] | None


@dataclass(slots=True)
class _UsersControllerContext[UP: UsersControllerUserProtocol[Any], ID]:
    """Runtime dependencies for generated users controller handlers."""

    id_parser: Callable[[str], ID] | None
    user_read_schema_type: type[msgspec.Struct]
    user_update_schema_type: type[msgspec.Struct]
    admin_user_update_schema_type: type[msgspec.Struct]
    users_page_schema_type: type[msgspec.Struct]
    hard_delete: bool
    default_limit: int
    max_limit: int
    change_password_before_request: RequestHandler | None
    change_password_rate_limit_increment: RequestHandler
    change_password_rate_limit_reset: RequestHandler
    unsafe_testing: bool


async def _users_get_user_or_404[UP: UsersControllerUserProtocol[Any], ID](
    user_id: str,
    *,
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
    id_parser: Callable[[str], ID] | None,
) -> UP:
    """Load a user by identifier or raise a 404 response.

    Returns:
        Loaded user instance.

    Raises:
        NotFoundException: If the requested user does not exist.
    """
    try:
        parsed_user_id = id_parser(user_id) if id_parser is not None else cast("ID", user_id)
    except (ValueError, TypeError) as exc:
        raise NotFoundException(detail="User not found.") from exc
    user = await user_manager.get(parsed_user_id)
    if user is not None:
        return user

    msg = "User not found."
    raise NotFoundException(detail=msg)


async def _users_handle_get_me[UP: UsersControllerUserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> msgspec.Struct:
    """Return the current authenticated user as a public schema payload.

    Returns:
        Public payload for the authenticated user.

    """
    # Litestar does not narrow ``Request.user`` to ``UP``; this handler is mounted behind ``is_authenticated``.
    user = cast("UP", request.user)
    await _require_account_state(user, user_manager=user_manager, require_verified=False)
    return _to_user_schema(user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


async def _users_handle_update_me[UP: UsersControllerUserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    data: msgspec.Struct,
    *,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> msgspec.Struct:
    """Apply a self-service profile update after blocking credential and privileged fields.

    ``PATCH /users/me`` is a non-credential update path. Password rotation is
    handled by ``POST /users/me/change-password`` so the current password can
    be re-verified before the manager receives the replacement password.

    Returns:
        Public payload for the updated authenticated user.

    """
    # Litestar does not narrow ``Request.user`` to ``UP``; this handler is mounted behind ``is_authenticated``.
    user = cast("UP", request.user)
    await _require_account_state(user, user_manager=user_manager, require_verified=False)
    async with _map_domain_exceptions(
        {
            UserAlreadyExistsError: (400, ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS),
            InvalidPasswordError: (400, ErrorCode.UPDATE_USER_INVALID_PASSWORD),
            AuthorizationError: (400, ErrorCode.REQUEST_BODY_INVALID),
        },
    ):
        updated_user = await user_manager.update(_build_safe_self_update(data), user)
    return _to_user_schema(updated_user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


async def _users_handle_change_password[UP: UsersControllerUserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    data: msgspec.Struct,
    *,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> None:
    """Rotate the authenticated user's password after current-password re-verification.

    The authenticated user's email is used for the re-verification lookup,
    independent of the app's public login identifier. Wrong current passwords
    reuse the login ``LOGIN_BAD_CREDENTIALS`` failure contract. Accepted
    replacement passwords are delegated through ``user_manager.update(...,
    allow_privileged=True)`` so manager-level password validation and session
    invalidation stay authoritative.

    Raises:
        ClientException: If the current password is invalid or the new password fails validation.
    """
    user = cast("UP", request.user)
    payload = cast("ChangePasswordRequest", data)
    await _require_account_state(user, user_manager=user_manager, require_verified=False)

    authenticated = await user_manager.authenticate(
        user.email,
        payload.current_password,
        login_identifier="email",
    )
    if authenticated is None or getattr(authenticated, "id", None) != getattr(user, "id", None):
        await ctx.change_password_rate_limit_increment(request)
        raise ClientException(
            status_code=400,
            detail=INVALID_CREDENTIALS_DETAIL,
            extra={"code": ErrorCode.LOGIN_BAD_CREDENTIALS},
        )

    async with _map_domain_exceptions({InvalidPasswordError: (400, ErrorCode.UPDATE_USER_INVALID_PASSWORD)}):
        await user_manager.update(
            {"password": payload.new_password},
            user,
            allow_privileged=True,
        )
    await ctx.change_password_rate_limit_reset(request)


async def _users_handle_delete_user[UP: UsersControllerUserProtocol[Any], ID](
    user_id: str,
    request: Request[Any, Any, Any],
    *,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> msgspec.Struct:
    """Soft- or hard-delete a user for superusers.

    Returns:
        Public payload for the affected user.

    Raises:
        ClientException: If a superuser attempts to delete their own account.
    """
    user = await _users_get_user_or_404(
        user_id,
        user_manager=user_manager,
        id_parser=ctx.id_parser,
    )
    request_user: UP | None = request.user
    if request_user is not None and request_user.id == user.id:
        msg = "Superusers cannot delete their own account."
        raise ClientException(
            status_code=403,
            detail=msg,
            extra={"code": ErrorCode.SUPERUSER_CANNOT_DELETE_SELF},
        )
    if ctx.hard_delete:
        await user_manager.delete(user.id)
        return _to_user_schema(user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)
    updated_user = await user_manager.update(UserUpdate(is_active=False), user, allow_privileged=True)
    return _to_user_schema(updated_user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


async def _users_handle_get_user[UP: UsersControllerUserProtocol[Any], ID](
    user_id: str,
    *,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> msgspec.Struct:
    """Return a superuser-visible user payload."""
    loaded = await _users_get_user_or_404(
        user_id,
        user_manager=user_manager,
        id_parser=ctx.id_parser,
    )
    return _to_user_schema(loaded, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


async def _users_handle_update_user[UP: UsersControllerUserProtocol[Any], ID](
    user_id: str,
    data: msgspec.Struct,
    *,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> msgspec.Struct:
    """Apply a privileged admin user update.

    Returns:
        Public payload for the updated user.
    """
    user = await _users_get_user_or_404(
        user_id,
        user_manager=user_manager,
        id_parser=ctx.id_parser,
    )
    async with _map_domain_exceptions(
        {
            UserAlreadyExistsError: (400, ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS),
            InvalidPasswordError: (400, ErrorCode.UPDATE_USER_INVALID_PASSWORD),
            AuthorizationError: (400, ErrorCode.REQUEST_BODY_INVALID),
        },
    ):
        updated_user = await user_manager.update(data, user, allow_privileged=True)
    return _to_user_schema(updated_user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


async def _users_handle_list_users[UP: UsersControllerUserProtocol[Any], ID](
    *,
    limit: int,
    offset: int,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> msgspec.Struct:
    """Return a paginated superuser-visible user list."""
    users, total = await user_manager.list_users(offset=offset, limit=limit)
    return ctx.users_page_schema_type(
        items=[_to_user_schema(user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing) for user in users],
        total=total,
        limit=limit,
        offset=offset,
    )


from litestar_auth.controllers._users_routes import (  # noqa: E402
    _create_change_password_handler,
    _create_delete_user_handler,
    _create_get_me_handler,
    _create_get_user_handler,
    _create_list_users_handler,
    _create_update_me_handler,
    _create_update_user_handler,
)


def _define_users_controller_class_di[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> type[Controller]:
    """Build the users controller with profile and admin routes (DI user manager).

    Returns:
        Controller subclass with ``/me`` and admin CRUD routes.
    """
    users_cls = type(
        "UsersController",
        (Controller,),
        {
            "__module__": __name__,
            "__doc__": ("Endpoints for profile updates, reverified password rotation, and admin user CRUD."),
            "get_me": _create_get_me_handler(ctx),
            "update_me": _create_update_me_handler(ctx),
            "change_password": _create_change_password_handler(ctx),
            "get_user": _create_get_user_handler(ctx),
            "update_user": _create_update_user_handler(ctx),
            "delete_user": _create_delete_user_handler(ctx),
            "list_users": _create_list_users_handler(ctx),
        },
    )
    _configure_request_body_handler(users_cls.update_me, schema=ctx.user_update_schema_type)
    _configure_request_body_handler(users_cls.change_password, schema=ChangePasswordRequest)
    _configure_request_body_handler(users_cls.update_user, schema=ctx.admin_user_update_schema_type)
    users_cls.__module__ = __name__
    users_cls.__qualname__ = users_cls.__name__
    return users_cls


def _create_users_page_schema_type() -> type[msgspec.Struct]:
    """Create the generated users page response schema.

    Returns:
        Dynamic msgspec struct type for paginated users responses.
    """
    return msgspec.defstruct(
        "UsersPageSchema",
        [
            ("items", list[Any]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )


@overload
def create_users_controller[UP: UsersControllerUserProtocol[Any], ID](
    *,
    config: UsersControllerConfig[ID],
) -> type[Controller]: ...  # pragma: no cover


@overload
def create_users_controller[UP: UsersControllerUserProtocol[Any], ID](
    **options: Unpack[UsersControllerOptions[ID]],
) -> type[Controller]: ...  # pragma: no cover


def create_users_controller[UP: UsersControllerUserProtocol[Any], ID](
    *,
    config: UsersControllerConfig[ID] | None = None,
    **options: Unpack[UsersControllerOptions[ID]],
) -> type[Controller]:
    """Return the users controller subclass wired for Litestar DI.

    Returns:
        Controller subclass exposing self-service profile, reverified password rotation,
        and admin user endpoints.

    Raises:
        ValueError: If ``config`` and keyword options are combined.
    """
    if config is not None and options:
        msg = "Pass either UsersControllerConfig or keyword options, not both."
        raise ValueError(msg)
    settings = UsersControllerConfig(**options) if config is None else config

    _require_msgspec_struct(settings.user_read_schema, parameter_name="user_read_schema")
    _require_msgspec_struct(
        settings.user_update_schema,
        parameter_name="user_update_schema",
        require_forbid_unknown_fields=True,
    )
    _require_msgspec_struct(
        settings.admin_user_update_schema,
        parameter_name="admin_user_update_schema",
        require_forbid_unknown_fields=True,
    )
    change_password_rate_limit = settings.rate_limit_config.change_password if settings.rate_limit_config else None
    (
        change_password_before_request,
        change_password_rate_limit_increment,
        change_password_rate_limit_reset,
    ) = _create_change_password_rate_limit_handlers(change_password_rate_limit)
    ctx = _UsersControllerContext(
        id_parser=settings.id_parser,
        user_read_schema_type=settings.user_read_schema,
        user_update_schema_type=settings.user_update_schema,
        admin_user_update_schema_type=settings.admin_user_update_schema,
        users_page_schema_type=_create_users_page_schema_type(),
        hard_delete=settings.hard_delete,
        default_limit=settings.default_limit,
        max_limit=settings.max_limit,
        change_password_before_request=change_password_before_request,
        change_password_rate_limit_increment=change_password_rate_limit_increment,
        change_password_rate_limit_reset=change_password_rate_limit_reset,
        unsafe_testing=settings.unsafe_testing,
    )
    controller_cls = _define_users_controller_class_di(ctx)
    controller_cls.path = settings.path
    if settings.security is not None:
        controller_cls.security = settings.security
    return _mark_litestar_auth_route_handler(controller_cls)
