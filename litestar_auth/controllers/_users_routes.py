"""Generated route handlers for users controllers."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Annotated, Any, cast

import msgspec
from litestar import Request, delete, get, patch, post
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example
from litestar.params import PathParameter, QueryParameter

from litestar_auth.controllers._request_body import _attach_handler_signature
from litestar_auth.controllers._step_up import TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE
from litestar_auth.controllers._users_handlers import (
    _users_handle_change_password,
    _users_handle_delete_user,
    _users_handle_get_me,
    _users_handle_get_user,
    _users_handle_list_users,
    _users_handle_update_me,
    _users_handle_update_user,
)
from litestar_auth.controllers._users_helpers import (
    AdminUserDeleteStepUpRequest,
    _reject_blocked_self_update_fields,
    _self_update_includes_email,
)
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.controllers.users import UsersControllerUserManagerProtocol
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError
from litestar_auth.guards import is_authenticated, is_superuser, requires_password_session

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


_UserIdPath = Annotated[str, PathParameter()]


def _make_list_users_signature(
    *,
    max_limit: int,
    default_limit: int,
) -> inspect.Signature:
    """Build a Litestar-visible signature for paginated user listing.

    Returns:
        Handler signature with dynamic ``limit`` constraints from controller context.
    """
    limit_annotation = Annotated[
        int,
        QueryParameter(name="limit", ge=1, le=max_limit),
    ]
    offset_annotation = Annotated[int, QueryParameter(name="offset", ge=0)]
    return inspect.Signature(
        parameters=[
            inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=object),
            inspect.Parameter(
                "limit",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=limit_annotation,
                default=default_limit,
            ),
            inspect.Parameter(
                "offset",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=offset_annotation,
                default=0,
            ),
            inspect.Parameter(
                "litestar_auth_user_manager",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=UsersControllerUserManagerProtocol[Any, Any],
            ),
        ],
        return_annotation=msgspec.Struct,
    )


def _list_users_handler_annotations(*, max_limit: int) -> dict[str, object]:
    """Return runtime annotations for the generated ``list_users`` handler.

    Returns:
        Annotation mapping assigned to the generated handler.
    """
    return {
        "self": object,
        "limit": Annotated[
            int,
            QueryParameter(name="limit", ge=1, le=max_limit),
        ],
        "offset": Annotated[int, QueryParameter(name="offset", ge=0)],
        "litestar_auth_user_manager": UsersControllerUserManagerProtocol[Any, Any],
        "return": msgspec.Struct,
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

    async def update_me_before_request(request: Request[Any, Any, Any]) -> None:
        await _reject_blocked_self_update_fields(request)
        if ctx.change_password_before_request is not None and await _self_update_includes_email(request):
            await ctx.change_password_before_request(request)

    @patch(
        "/me",
        guards=[is_authenticated],
        before_request=update_me_before_request,
        responses={403: TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE},
    )
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
        guards=[is_authenticated, requires_password_session],
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
        user_id: _UserIdPath,
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
        request: Request[Any, Any, Any],
        user_id: _UserIdPath,
        data: msgspec.Struct,
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_update_user(
            user_id,
            request,
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
        user_id: _UserIdPath,
        request: Request[Any, Any, Any],
        data: AdminUserDeleteStepUpRequest,
        litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        return await _users_handle_delete_user(
            user_id,
            request,
            data,
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
    signature = _make_list_users_signature(
        max_limit=ctx.max_limit,
        default_limit=ctx.default_limit,
    )

    async def list_users(*args: object, **kwargs: object) -> msgspec.Struct:
        bound_arguments = signature.bind(*args, **kwargs)
        bound_arguments.apply_defaults()
        arguments = bound_arguments.arguments
        return await _users_handle_list_users(
            limit=arguments["limit"],
            offset=arguments["offset"],
            ctx=ctx,
            user_manager=arguments["litestar_auth_user_manager"],
        )

    _attach_handler_signature(
        list_users,
        signature=signature,
        annotations=_list_users_handler_annotations(max_limit=ctx.max_limit),
    )
    return cast("RequestBodyRouteHandler", get(guards=[is_superuser])(list_users))
