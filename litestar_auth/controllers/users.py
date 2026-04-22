"""User CRUD controller factory for profile and admin management endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

import msgspec
from litestar import Controller, Request, delete, get, patch
from litestar.exceptions import ClientException, NotFoundException
from litestar.params import Parameter

from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    _configure_request_body_handler,
    _map_domain_exceptions,
    _mark_litestar_auth_route_handler,
    _require_account_state,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.guards import is_authenticated, is_superuser
from litestar_auth.schemas import UserRead, UserUpdate
from litestar_auth.types import RoleCapableUserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from litestar.openapi.spec import SecurityRequirement

SELF_UPDATE_FORBIDDEN_FIELDS = frozenset({"is_active", "is_verified", "is_superuser", "roles"})
_PRIVILEGED_FIELDS = SELF_UPDATE_FORBIDDEN_FIELDS | frozenset({"hashed_password"})


class UsersControllerUserProtocol[ID](RoleCapableUserProtocol[ID], Protocol):
    """Protocol describing the public user fields returned by the users controller."""

    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool


@runtime_checkable
class UsersControllerUserManagerProtocol[UP: UsersControllerUserProtocol[Any], ID](
    AccountStateValidatorProvider[UP],
    Protocol,
):
    """User-manager behavior required by the users controller."""

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


@dataclass(slots=True)
class _UsersControllerContext[UP: UsersControllerUserProtocol[Any], ID]:
    """Runtime dependencies for generated users controller handlers."""

    id_parser: Callable[[str], ID] | None
    user_read_schema_type: type[msgspec.Struct]
    user_update_schema_type: type[msgspec.Struct]
    users_page_schema_type: type[msgspec.Struct]
    hard_delete: bool
    default_limit: int
    max_limit: int
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
    """Apply a self-service update with privileged fields stripped.

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
        },
    ):
        updated_user = await user_manager.update(_build_safe_self_update(data), user)
    return _to_user_schema(updated_user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


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


def _define_users_controller_class_di[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> type[Controller]:
    """Build the users controller with profile and admin routes (DI user manager).

    Returns:
        Controller subclass with ``/me`` and admin CRUD routes.
    """

    class UsersController(Controller):
        """Endpoints for authenticated user profiles and admin user CRUD."""

        @get("/me", guards=[is_authenticated])
        async def get_me(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            return await _users_handle_get_me(request, ctx=ctx, user_manager=litestar_auth_user_manager)

        @patch("/me", guards=[is_authenticated])
        async def update_me(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: msgspec.Struct,
            litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            return await _users_handle_update_me(
                request,
                data,
                ctx=ctx,
                user_manager=litestar_auth_user_manager,
            )

        @get("/{user_id:str}", guards=[is_superuser])
        async def get_user(  # noqa: PLR6301
            self,
            user_id: str,
            litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            loaded = await _users_get_user_or_404(
                user_id,
                user_manager=litestar_auth_user_manager,
                id_parser=ctx.id_parser,
            )
            return _to_user_schema(loaded, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)

        @patch("/{user_id:str}", guards=[is_superuser])
        async def update_user(  # noqa: PLR6301
            self,
            user_id: str,
            data: msgspec.Struct,
            litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            user = await _users_get_user_or_404(
                user_id,
                user_manager=litestar_auth_user_manager,
                id_parser=ctx.id_parser,
            )
            async with _map_domain_exceptions(
                {
                    UserAlreadyExistsError: (400, ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS),
                    InvalidPasswordError: (400, ErrorCode.UPDATE_USER_INVALID_PASSWORD),
                },
            ):
                updated_user = await litestar_auth_user_manager.update(data, user, allow_privileged=True)
            return _to_user_schema(updated_user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)

        @delete("/{user_id:str}", guards=[is_superuser], status_code=200)
        async def delete_user(  # noqa: PLR6301
            self,
            user_id: str,
            request: Request[Any, Any, Any],
            litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            return await _users_handle_delete_user(
                user_id,
                request,
                ctx=ctx,
                user_manager=litestar_auth_user_manager,
            )

        @get(guards=[is_superuser])
        async def list_users(  # noqa: PLR6301
            self,
            limit: int = Parameter(default=ctx.default_limit, query="limit", ge=1, le=ctx.max_limit),
            offset: int = Parameter(default=0, query="offset", ge=0),
            *,
            litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            users, total = await litestar_auth_user_manager.list_users(offset=offset, limit=limit)
            return ctx.users_page_schema_type(
                items=[
                    _to_user_schema(user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)
                    for user in users
                ],
                total=total,
                limit=limit,
                offset=offset,
            )

    users_cls = UsersController
    _configure_request_body_handler(users_cls.update_me, schema=ctx.user_update_schema_type)
    _configure_request_body_handler(users_cls.update_user, schema=ctx.user_update_schema_type)
    users_cls.__module__ = __name__
    users_cls.__qualname__ = users_cls.__name__
    return users_cls


def create_users_controller[UP: UsersControllerUserProtocol[Any], ID](  # noqa: PLR0913
    *,
    id_parser: Callable[[str], ID] | None = None,
    path: str = "/users",
    default_limit: int = 50,
    max_limit: int = 100,
    hard_delete: bool = False,
    user_read_schema: type[msgspec.Struct] = UserRead,
    user_update_schema: type[msgspec.Struct] = UserUpdate,
    unsafe_testing: bool = False,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Return a controller subclass that resolves the user manager via Litestar DI.

    Args:
        id_parser: Optional callable that converts path IDs into manager IDs.
        path: Base route prefix for the generated controller.
        default_limit: Default page size for list responses.
        max_limit: Maximum allowed page size for list responses.
        hard_delete: When ``True``, admin deletes remove users permanently.
        user_read_schema: Custom msgspec struct used for public user responses.
        user_update_schema: Custom msgspec struct used for update requests.
        unsafe_testing: Explicit test-only override that allows response
            schemas with sensitive fields for isolated fixtures.
        security: Optional OpenAPI security requirements applied at the
            controller level to annotate all routes.

    Returns:
        Controller subclass exposing self-service and admin user endpoints.

    Examples:
        ```python
        class ExtendedUserRead(msgspec.Struct):
            id: uuid.UUID
            email: str
            is_active: bool
            is_verified: bool
            is_superuser: bool
            roles: list[str]
            bio: str

        class ExtendedUserUpdate(msgspec.Struct, omit_defaults=True):
            email: str | None = None
            password: str | None = None
            roles: list[str] | None = None
            bio: str | None = None

        controller = create_users_controller(
            user_read_schema=ExtendedUserRead,
            user_update_schema=ExtendedUserUpdate,
        )
        ```
    """
    _require_msgspec_struct(user_read_schema, parameter_name="user_read_schema")
    _require_msgspec_struct(user_update_schema, parameter_name="user_update_schema")
    users_page_schema_type = msgspec.defstruct(
        "UsersPageSchema",
        [
            ("items", list[Any]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )
    ctx = _UsersControllerContext(
        id_parser=id_parser,
        user_read_schema_type=user_read_schema,
        user_update_schema_type=user_update_schema,
        users_page_schema_type=users_page_schema_type,
        hard_delete=hard_delete,
        default_limit=default_limit,
        max_limit=max_limit,
        unsafe_testing=unsafe_testing,
    )
    controller_cls = _define_users_controller_class_di(ctx)
    controller_cls.path = path
    if security is not None:
        controller_cls.security = security
    return _mark_litestar_auth_route_handler(controller_cls)


def _build_safe_self_update(data: msgspec.Struct) -> dict[str, Any]:
    """Limit self-service updates to non-admin fields from the configured schema.

    Uses a deny-list of privileged fields rather than an allow-list so
    that custom ``UserUpdate`` schemas with extra safe fields work
    out-of-the-box.  The deny-list is intentionally broad to cover
    any field that could grant elevated privileges, including ``roles``.

    Returns:
        A plain update mapping with privileged fields removed.

    Raises:
        TypeError: If ``msgspec.to_builtins`` does not return a mapping (should not occur for structs).
    """
    builtins_payload = msgspec.to_builtins(data)
    if not isinstance(builtins_payload, dict):
        msg = "Expected a mapping from msgspec.to_builtins."
        raise TypeError(msg)
    payload: dict[str, Any] = {str(k): v for k, v in builtins_payload.items()}
    return {field_name: value for field_name, value in payload.items() if field_name not in _PRIVILEGED_FIELDS}
