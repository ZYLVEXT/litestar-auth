"""User CRUD controller factory for profile and admin management endpoints."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, Protocol, TypedDict, Unpack, cast, overload, runtime_checkable

import msgspec
from litestar import Controller, Request, delete, get, patch, post
from litestar.di import NamedDependency
from litestar.exceptions import NotFoundException
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example
from litestar.params import PathParameter, QueryParameter

from litestar_auth.controllers._error_responses import raise_authentication_required, raise_client_error
from litestar_auth.controllers._request_body import _attach_handler_signature
from litestar_auth.controllers._step_up import (
    TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE,
    PasswordStepUpCheck,
    TotpStepUpCheck,
    TotpStepUpEndpoint,
    TotpStepUpPolicyMode,
    TotpStepUpVerifierProtocol,
    require_password_step_up,
    require_totp_stepup,
)
from litestar_auth.controllers._step_up_payloads import AdminUserDeleteStepUpRequest
from litestar_auth.controllers._users_helpers import (
    SELF_UPDATE_FORBIDDEN_FIELDS as _USERS_SELF_UPDATE_FORBIDDEN_FIELDS,
)
from litestar_auth.controllers._users_helpers import (
    _build_safe_self_update,
    _create_change_password_rate_limit_handlers,
    _reject_blocked_self_update_fields,
    _self_update_includes_email,
)
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    _configure_request_body_handler,
    _finalize_route_handler,
    _map_domain_exceptions,
    _mark_litestar_auth_route_handler,
    _require_account_state,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.guards import is_authenticated, is_superuser, requires_password_session
from litestar_auth.schemas import AdminUserUpdate, ChangePasswordRequest, UserRead, UserUpdate
from litestar_auth.types import RoleCapableUserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.controllers._utils import RequestBodyRouteHandler, RequestHandler
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
    TotpStepUpVerifierProtocol[UP],
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


_UserManagerDep = NamedDependency[UsersControllerUserManagerProtocol[Any, Any]]


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
    totp_stepup_policy: dict[str, TotpStepUpPolicyMode] = field(default_factory=dict)


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
    totp_stepup_policy: dict[str, TotpStepUpPolicyMode]


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
    totp_stepup_policy: dict[str, TotpStepUpPolicyMode] = field(default_factory=dict)


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

    Email changes require current-password re-verification. Password rotation
    is handled by ``POST /users/me/change-password`` so the current password
    can be re-verified before the manager receives the replacement password.

    Returns:
        Public payload for the updated authenticated user.

    """
    # Litestar does not narrow ``Request.user`` to ``UP``; this handler is mounted behind ``is_authenticated``.
    user = cast("UP", request.user)
    async with _map_domain_exceptions(
        {
            UserAlreadyExistsError: (400, ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS),
            InvalidPasswordError: (400, ErrorCode.UPDATE_USER_INVALID_PASSWORD),
            AuthorizationError: (400, ErrorCode.REQUEST_BODY_INVALID),
        },
    ):
        safe_update = _build_safe_self_update(data)
        current_password = safe_update.pop("current_password", None)
        totp_code = cast("str | None", safe_update.pop("totp_code", None))
        if "email" in safe_update:
            await _require_sensitive_self_update_reauthentication(
                request,
                user,
                current_password=cast("str | None", current_password),
                ctx=ctx,
                user_manager=user_manager,
            )
            await require_totp_stepup(
                request,
                TotpStepUpCheck(
                    endpoint="users.update_self",
                    policy=ctx.totp_stepup_policy,
                    user_manager=user_manager,
                    totp_code=totp_code,
                ),
            )
        else:
            await _require_account_state(user, user_manager=user_manager, require_verified=False)
        updated_user = await user_manager.update(safe_update, user)
    return _to_user_schema(updated_user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


async def _require_sensitive_self_update_reauthentication[UP: UsersControllerUserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    user: UP,
    *,
    current_password: str | None,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> None:
    """Re-authenticate the current user before sensitive self-service updates."""
    await _require_account_state(user, user_manager=user_manager, require_verified=False)
    await require_password_step_up(
        PasswordStepUpCheck(
            user=user,
            user_manager=user_manager,
            current_password=current_password,
            on_failure=lambda: ctx.change_password_rate_limit_increment(request),
            on_success=lambda: ctx.change_password_rate_limit_reset(request),
        ),
    )


@dataclass(frozen=True, slots=True)
class _AdminMutationStepUpCheck[UP: UsersControllerUserProtocol[Any], ID]:
    """Inputs for admin user mutation step-up enforcement."""

    request: Request[Any, Any, Any]
    admin_user: UP
    current_password: str | None
    totp_code: str | None
    totp_endpoint: TotpStepUpEndpoint
    ctx: _UsersControllerContext[UP, ID]
    user_manager: UsersControllerUserManagerProtocol[UP, ID]


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

    """
    user = cast("UP", request.user)
    payload = cast("ChangePasswordRequest", data)
    await _require_sensitive_self_update_reauthentication(
        request,
        user,
        current_password=payload.current_password,
        ctx=ctx,
        user_manager=user_manager,
    )

    async with _map_domain_exceptions({InvalidPasswordError: (400, ErrorCode.UPDATE_USER_INVALID_PASSWORD)}):
        await user_manager.update(
            {"password": payload.new_password},
            user,
            allow_privileged=True,
        )


async def _users_handle_delete_user[UP: UsersControllerUserProtocol[Any], ID](
    user_id: str,
    request: Request[Any, Any, Any],
    data: AdminUserDeleteStepUpRequest,
    *,
    ctx: _UsersControllerContext[UP, ID],
    user_manager: UsersControllerUserManagerProtocol[UP, ID],
) -> msgspec.Struct:
    """Soft- or hard-delete a user for superusers.

    Returns:
        Public payload for the affected user.

    """
    user = await _users_get_user_or_404(
        user_id,
        user_manager=user_manager,
        id_parser=ctx.id_parser,
    )
    request_user: UP | None = request.user
    if request_user is None:
        raise_authentication_required()
    if request_user.id == user.id:
        raise_client_error(
            status_code=403,
            detail="Superusers cannot delete their own account.",
            error_code=ErrorCode.SUPERUSER_CANNOT_DELETE_SELF,
        )
    await _require_admin_mutation_step_up(
        _AdminMutationStepUpCheck(
            request=request,
            admin_user=request_user,
            current_password=data.current_password,
            totp_code=data.totp_code,
            totp_endpoint="users.delete",
            ctx=ctx,
            user_manager=user_manager,
        ),
    )
    if ctx.hard_delete:
        await user_manager.delete(user.id)
        return _to_user_schema(user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)
    # Soft-delete is an admin path: ``is_active`` is a privileged field that
    # belongs on AdminUserUpdate, not on the self-service UserUpdate contract.
    updated_user = await user_manager.update(AdminUserUpdate(is_active=False), user, allow_privileged=True)
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
    request: Request[Any, Any, Any],
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
        update_payload = _build_admin_update_payload(data)
        admin_user: UP | None = request.user
        if admin_user is None:
            raise_authentication_required()
        await _require_admin_mutation_step_up(
            _AdminMutationStepUpCheck(
                request=request,
                admin_user=admin_user,
                current_password=cast("str | None", getattr(data, "current_password", None)),
                totp_code=cast("str | None", getattr(data, "totp_code", None)),
                totp_endpoint="users.update",
                ctx=ctx,
                user_manager=user_manager,
            ),
        )
        updated_user = await user_manager.update(update_payload, user, allow_privileged=True)
    return _to_user_schema(updated_user, ctx.user_read_schema_type, unsafe_testing=ctx.unsafe_testing)


async def _require_admin_mutation_step_up[UP: UsersControllerUserProtocol[Any], ID](
    check: _AdminMutationStepUpCheck[UP, ID],
) -> None:
    """Require the authenticated admin's own password and TOTP proof before privileged mutation."""
    await _require_account_state(check.admin_user, user_manager=check.user_manager, require_verified=False)
    await require_password_step_up(
        PasswordStepUpCheck(
            user=check.admin_user,
            user_manager=check.user_manager,
            current_password=check.current_password,
            on_failure=lambda: check.ctx.change_password_rate_limit_increment(check.request),
            on_success=lambda: check.ctx.change_password_rate_limit_reset(check.request),
        ),
    )
    await require_totp_stepup(
        check.request,
        TotpStepUpCheck(
            endpoint=check.totp_endpoint,
            policy=check.ctx.totp_stepup_policy,
            user_manager=cast("TotpStepUpVerifierProtocol[UP]", check.user_manager),
            totp_code=check.totp_code,
        ),
    )


def _build_admin_update_payload(data: msgspec.Struct) -> dict[str, Any]:
    """Return privileged update fields after removing admin step-up credentials.

    Raises:
        TypeError: If ``msgspec.to_builtins`` does not return a mapping.
    """
    builtins_payload = msgspec.to_builtins(data)
    if not isinstance(builtins_payload, dict):
        msg = "Expected a mapping from msgspec.to_builtins."
        raise TypeError(msg)
    return {str(key): value for key, value in builtins_payload.items() if key not in {"current_password", "totp_code"}}


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
                annotation=_UserManagerDep,
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
        "litestar_auth_user_manager": _UserManagerDep,
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
        self: object,  # noqa: ARG001
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: _UserManagerDep,
    ) -> msgspec.Struct:
        return await _users_handle_get_me(request, ctx=ctx, user_manager=litestar_auth_user_manager)

    return _finalize_route_handler(get_me)


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
        self: object,  # noqa: ARG001
        request: Request[Any, Any, Any],
        data: msgspec.Struct,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> msgspec.Struct:
        return await _users_handle_update_me(
            request,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return _finalize_route_handler(update_me)


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
        self: object,  # noqa: ARG001
        request: Request[Any, Any, Any],
        data: msgspec.Struct,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> None:
        await _users_handle_change_password(
            request,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return _finalize_route_handler(change_password)


def _create_get_user_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``GET /{user_id}`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @get("/{user_id:str}", guards=[is_superuser])
    async def get_user(
        self: object,  # noqa: ARG001
        user_id: _UserIdPath,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> msgspec.Struct:
        return await _users_handle_get_user(
            user_id,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return _finalize_route_handler(get_user)


def _create_update_user_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``PATCH /{user_id}`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @patch("/{user_id:str}", guards=[is_superuser])
    async def update_user(
        self: object,  # noqa: ARG001
        request: Request[Any, Any, Any],
        user_id: _UserIdPath,
        data: msgspec.Struct,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> msgspec.Struct:
        return await _users_handle_update_user(
            user_id,
            request,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return _finalize_route_handler(update_user)


def _create_delete_user_handler[UP: UsersControllerUserProtocol[Any], ID](
    ctx: _UsersControllerContext[UP, ID],
) -> RequestBodyRouteHandler:
    """Create the generated ``DELETE /{user_id}`` route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @delete("/{user_id:str}", guards=[is_superuser], status_code=200)
    async def delete_user(
        self: object,  # noqa: ARG001
        user_id: _UserIdPath,
        request: Request[Any, Any, Any],
        data: AdminUserDeleteStepUpRequest,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> msgspec.Struct:
        return await _users_handle_delete_user(
            user_id,
            request,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return _finalize_route_handler(delete_user)


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
    return _finalize_route_handler(get(guards=[is_superuser])(list_users))


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
    _configure_request_body_handler(users_cls.delete_user, schema=AdminUserDeleteStepUpRequest)
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
) -> type[Controller]: ...


@overload
def create_users_controller[UP: UsersControllerUserProtocol[Any], ID](
    **options: Unpack[UsersControllerOptions[ID]],
) -> type[Controller]: ...


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
        totp_stepup_policy=dict(settings.totp_stepup_policy),
    )
    controller_cls = _define_users_controller_class_di(ctx)
    controller_cls.path = settings.path
    if settings.security is not None:
        controller_cls.security = settings.security
    return _mark_litestar_auth_route_handler(controller_cls)
