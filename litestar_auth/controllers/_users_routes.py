"""Generated route handlers for users controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import msgspec  # noqa: TC002
from litestar import Request, delete, get, patch, post
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example
from litestar.params import Parameter

from litestar_auth.controllers._users_helpers import _reject_blocked_self_update_fields
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.controllers.users import (
    UsersControllerUserManagerProtocol,
    _users_handle_change_password,
    _users_handle_delete_user,
    _users_handle_get_me,
    _users_handle_get_user,
    _users_handle_list_users,
    _users_handle_update_me,
    _users_handle_update_user,
)
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError
from litestar_auth.guards import is_authenticated, is_superuser

if TYPE_CHECKING:
    from litestar_auth.controllers._utils import RequestBodyRouteHandler
    from litestar_auth.controllers.users import (
        UsersControllerUserProtocol,
        _UsersControllerContext,
    )

_CHANGE_PASSWORD_OPENAPI_RESPONSES = {
    400: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description=(
            "Wrong current password (`LOGIN_BAD_CREDENTIALS`) or invalid replacement password "
            "(`UPDATE_USER_INVALID_PASSWORD`). Request-body decode and schema failures use "
            "`REQUEST_BODY_INVALID`."
        ),
        examples=[
            Example(
                id="wrong_current_password",
                summary="Wrong current password",
                value={
                    "status_code": 400,
                    "detail": INVALID_CREDENTIALS_DETAIL,
                    "extra": {"code": ErrorCode.LOGIN_BAD_CREDENTIALS.value},
                },
            ),
            Example(
                id="invalid_new_password",
                summary="Invalid replacement password",
                value={
                    "status_code": 400,
                    "detail": InvalidPasswordError.default_message,
                    "extra": {"code": ErrorCode.UPDATE_USER_INVALID_PASSWORD.value},
                },
            ),
        ],
    ),
    401: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description="Unauthenticated requests are rejected before password re-verification runs.",
        examples=[
            Example(
                id="unauthenticated",
                summary="Missing credentials",
                value={
                    "status_code": 401,
                    "detail": "Authentication credentials were not provided.",
                },
            ),
        ],
    ),
    422: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description="Malformed or schema-invalid request bodies use `REQUEST_BODY_INVALID`.",
        examples=[
            Example(
                id="request_body_invalid",
                summary="Invalid request body",
                value={
                    "status_code": 422,
                    "detail": "Invalid request payload.",
                    "extra": {"code": ErrorCode.REQUEST_BODY_INVALID.value},
                },
            ),
        ],
    ),
    429: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description="Rate-limited password-rotation attempts return `Retry-After`.",
        examples=[
            Example(
                id="rate_limited",
                summary="Too many attempts",
                value={
                    "status_code": 429,
                    "detail": "Too many requests.",
                },
            ),
        ],
    ),
}


def _create_get_me_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``GET /me`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @get("/me", guards=[is_authenticated])
    async def get_me(
        self: object,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_get_me(request, ctx=ctx, user_manager=litestar_auth_user_manager)

    return cast("RequestBodyRouteHandler", get_me)


def _create_update_me_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``PATCH /me`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @patch("/me", guards=[is_authenticated], before_request=_reject_blocked_self_update_fields)
    async def update_me(
        self: object,
        request: Request[Any, Any, Any],
        data: msgspec.Struct,
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_update_me(
            request,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", update_me)


def _create_change_password_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``POST /me/change-password`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post(
        "/me/change-password",
        guards=[is_authenticated],
        status_code=204,
        before_request=ctx.change_password_before_request,
        responses=_CHANGE_PASSWORD_OPENAPI_RESPONSES,
    )
    async def change_password(
        self: object,
        request: Request[Any, Any, Any],
        data: msgspec.Struct,
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> None:
        del self
        await _users_handle_change_password(
            request,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", change_password)


def _create_get_user_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``GET /{user_id}`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @get("/{user_id:str}", guards=[is_superuser])
    async def get_user(
        self: object,
        user_id: str,
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_get_user(
            user_id,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", get_user)


def _create_update_user_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``PATCH /{user_id}`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @patch("/{user_id:str}", guards=[is_superuser])
    async def update_user(
        self: object,
        user_id: str,
        data: msgspec.Struct,
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_update_user(
            user_id,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", update_user)


def _create_delete_user_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``DELETE /{user_id}`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @delete("/{user_id:str}", guards=[is_superuser], status_code=200)
    async def delete_user(
        self: object,
        user_id: str,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_delete_user(
            user_id,
            request,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", delete_user)


def _create_list_users_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``GET /`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @get(guards=[is_superuser])
    async def list_users(
        self: object,
        limit: int = Parameter(default=ctx.default_limit, query="limit", ge=1, le=ctx.max_limit),
        offset: int = Parameter(default=0, query="offset", ge=0),
        *,
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_list_users(
            limit=limit,
            offset=offset,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", list_users)
