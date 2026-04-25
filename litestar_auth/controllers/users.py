"""User CRUD controller factory for profile and admin management endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

import msgspec
from litestar import Controller, Request, delete, get, patch, post
from litestar.exceptions import ClientException, NotFoundException, TooManyRequestsException
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example
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
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.guards import is_authenticated, is_superuser
from litestar_auth.ratelimit._helpers import _client_host, _safe_key_part, logger
from litestar_auth.schemas import AdminUserUpdate, ChangePasswordRequest, UserRead, UserUpdate
from litestar_auth.types import RoleCapableUserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.controllers._utils import RequestHandler
    from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit
    from litestar_auth.types import LoginIdentifier

SELF_UPDATE_FORBIDDEN_FIELDS = frozenset({"is_active", "is_verified", "roles"})
_SELF_UPDATE_BLOCKED_FIELDS = SELF_UPDATE_FORBIDDEN_FIELDS | frozenset({"hashed_password", "password"})
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


async def _build_change_password_rate_limit_key(
    rate_limit: EndpointRateLimit,
    request: Request[Any, Any, Any],
) -> str:
    """Build the rate-limit key for password rotation attempts.

    ``ChangePasswordRequest`` intentionally does not carry an email field. For
    the default ``ip_email`` scope, use the authenticated user email so this
    post-auth re-verification endpoint keeps the same principal granularity as
    login without widening the request schema.

    Returns:
        Namespaced backend key for the password-rotation attempt.
    """
    if rate_limit.scope != "ip_email":
        return await rate_limit.build_key(request)

    user_email = getattr(request.user, "email", None)
    if not isinstance(user_email, str) or not user_email:
        return await rate_limit.build_key(request)

    host = _client_host(
        request,
        trusted_proxy=rate_limit.trusted_proxy,
        trusted_headers=rate_limit.trusted_headers,
    )
    return ":".join(
        (
            rate_limit.namespace,
            _safe_key_part(host),
            _safe_key_part(user_email.strip().casefold()),
        ),
    )


def _create_change_password_rate_limit_handlers(
    rate_limit: EndpointRateLimit | None,
) -> tuple[RequestHandler | None, RequestHandler, RequestHandler]:
    """Return before/increment/reset handlers for the authenticated password-rotation limiter."""

    async def increment(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await rate_limit.backend.increment(await _build_change_password_rate_limit_key(rate_limit, request))

    async def reset(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await rate_limit.backend.reset(await _build_change_password_rate_limit_key(rate_limit, request))

    if rate_limit is None:
        return None, increment, reset

    async def before_request(request: Request[Any, Any, Any]) -> None:
        key = await _build_change_password_rate_limit_key(rate_limit, request)
        if await rate_limit.backend.check(key):
            return

        retry_after = await rate_limit.backend.retry_after(key)
        logger.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate_limit_triggered",
                "namespace": rate_limit.namespace,
                "scope": rate_limit.scope,
                "trusted_proxy": rate_limit.trusted_proxy,
            },
        )
        msg = "Too many requests."
        raise TooManyRequestsException(
            detail=msg,
            headers={"Retry-After": str(max(retry_after, 1))},
        )

    return before_request, increment, reset


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


def _build_blocked_self_update_detail(blocked_fields: frozenset[str]) -> str:
    """Return a deterministic error message for blocked self-update fields."""
    field_list = ", ".join(sorted(blocked_fields))
    return f"Self-service updates cannot set the following fields: {field_list}."


async def _reject_blocked_self_update_fields(request: Request[Any, Any, Any]) -> None:
    """Reject blocked self-update fields before schema validation can silently diverge.

    Raises:
        ClientException: If the request body includes blocked self-update fields.
    """
    try:
        decoded_body = msgspec.json.decode(await request.body())
    except msgspec.DecodeError:
        return
    if not isinstance(decoded_body, dict):
        return
    blocked_fields = frozenset(str(key) for key in decoded_body) & _SELF_UPDATE_BLOCKED_FIELDS
    if not blocked_fields:
        return
    detail = _build_blocked_self_update_detail(blocked_fields)
    raise ClientException(
        status_code=400,
        detail=detail,
        extra={"code": ErrorCode.REQUEST_BODY_INVALID},
    ) from AuthorizationError(detail)


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
        """Endpoints for profile updates, reverified password rotation, and admin user CRUD.

        Self-service ``PATCH /me`` handles non-credential profile updates only.
        Authenticated password rotation is split to ``POST /me/change-password``
        with ``ChangePasswordRequest`` so the current password is verified
        before the new password reaches the manager lifecycle. Superuser
        ``PATCH /{user_id}`` uses ``AdminUserUpdate`` and remains the admin
        path for operator-initiated password rotation.
        """

        @get("/me", guards=[is_authenticated])
        async def get_me(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            litestar_auth_user_manager: UsersControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            return await _users_handle_get_me(request, ctx=ctx, user_manager=litestar_auth_user_manager)

        @patch("/me", guards=[is_authenticated], before_request=_reject_blocked_self_update_fields)
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

        @post(
            "/me/change-password",
            guards=[is_authenticated],
            status_code=204,
            before_request=ctx.change_password_before_request,
            responses=_CHANGE_PASSWORD_OPENAPI_RESPONSES,
        )
        async def change_password(
            self,
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
                    AuthorizationError: (400, ErrorCode.REQUEST_BODY_INVALID),
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
    _configure_request_body_handler(users_cls.change_password, schema=ChangePasswordRequest)
    _configure_request_body_handler(users_cls.update_user, schema=ctx.admin_user_update_schema_type)
    users_cls.__module__ = __name__
    users_cls.__qualname__ = users_cls.__name__
    return users_cls


def create_users_controller[UP: UsersControllerUserProtocol[Any], ID](  # noqa: PLR0913
    *,
    id_parser: Callable[[str], ID] | None = None,
    rate_limit_config: AuthRateLimitConfig | None = None,
    path: str = "/users",
    default_limit: int = 50,
    max_limit: int = 100,
    hard_delete: bool = False,
    user_read_schema: type[msgspec.Struct] = UserRead,
    user_update_schema: type[msgspec.Struct] = UserUpdate,
    admin_user_update_schema: type[msgspec.Struct] = AdminUserUpdate,
    unsafe_testing: bool = False,
    security: Sequence[SecurityRequirement] | None = None,
) -> type[Controller]:
    """Return a controller subclass that resolves the user manager via Litestar DI.

    Args:
        id_parser: Optional callable that converts path IDs into manager IDs.
        rate_limit_config: Optional auth-endpoint rate-limiter configuration.
        path: Base route prefix for the generated controller.
        default_limit: Default page size for list responses.
        max_limit: Maximum allowed page size for list responses.
        hard_delete: When ``True``, admin deletes remove users permanently.
        user_read_schema: Custom msgspec struct used for public user responses.
        user_update_schema: Custom msgspec struct used for self-service update requests.
        admin_user_update_schema: Custom msgspec struct used for privileged admin update requests.
        unsafe_testing: Explicit test-only override that allows response
            schemas with sensitive fields for isolated fixtures.
        security: Optional OpenAPI security requirements applied at the
            controller level to annotate all routes.

    Returns:
        Controller subclass exposing self-service profile, reverified password rotation,
        and admin user endpoints.

    Examples:
        ```python
        class ExtendedUserRead(msgspec.Struct):
            id: uuid.UUID
            email: str
            is_active: bool
            is_verified: bool
            roles: list[str]
            bio: str

        class ExtendedUserUpdate(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
            email: str | None = None
            bio: str | None = None

        class ExtendedAdminUserUpdate(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
            email: str | None = None
            password: str | None = None
            roles: list[str] | None = None
            bio: str | None = None

        controller = create_users_controller(
            user_read_schema=ExtendedUserRead,
            user_update_schema=ExtendedUserUpdate,
            admin_user_update_schema=ExtendedAdminUserUpdate,
        )
        ```
    """
    _require_msgspec_struct(user_read_schema, parameter_name="user_read_schema")
    _require_msgspec_struct(
        user_update_schema,
        parameter_name="user_update_schema",
        require_forbid_unknown_fields=True,
    )
    _require_msgspec_struct(
        admin_user_update_schema,
        parameter_name="admin_user_update_schema",
        require_forbid_unknown_fields=True,
    )
    change_password_rate_limit = rate_limit_config.change_password if rate_limit_config else None
    (
        change_password_before_request,
        change_password_rate_limit_increment,
        change_password_rate_limit_reset,
    ) = _create_change_password_rate_limit_handlers(change_password_rate_limit)
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
        admin_user_update_schema_type=admin_user_update_schema,
        users_page_schema_type=users_page_schema_type,
        hard_delete=hard_delete,
        default_limit=default_limit,
        max_limit=max_limit,
        change_password_before_request=change_password_before_request,
        change_password_rate_limit_increment=change_password_rate_limit_increment,
        change_password_rate_limit_reset=change_password_rate_limit_reset,
        unsafe_testing=unsafe_testing,
    )
    controller_cls = _define_users_controller_class_di(ctx)
    controller_cls.path = path
    if security is not None:
        controller_cls.security = security
    return _mark_litestar_auth_route_handler(controller_cls)


def _build_safe_self_update(data: msgspec.Struct) -> dict[str, Any]:
    """Reject blocked self-update fields and return the remaining payload mapping.

    ``PATCH /users/me`` must not rotate credentials or mutate authorization
    state. Password changes belong to ``POST /users/me/change-password``, and
    admin-initiated rotation belongs to ``PATCH /users/{user_id}`` with
    ``AdminUserUpdate``.

    Uses a deny-list of privileged fields rather than an allow-list so
    that custom ``UserUpdate`` schemas with extra safe fields work
    out-of-the-box. The deny-list covers fields that could grant elevated
    privileges (``is_active``, ``is_verified``, ``roles``), password
    rotation without re-verification, and the sensitive
    ``hashed_password`` shadow.

    Generated request schemas use ``forbid_unknown_fields=True``, so undeclared
    fields fail request decoding before this helper runs unless the route's
    preflight blocked-field check intercepts them first. Custom self-update
    schemas that still declare blocked fields are rejected here fail-closed.

    Returns:
        A plain update mapping when no blocked self-update fields were supplied.

    Raises:
        AuthorizationError: If the payload attempts to set blocked self-update fields.
        TypeError: If ``msgspec.to_builtins`` does not return a mapping (should not occur for structs).
    """
    builtins_payload = msgspec.to_builtins(data)
    if not isinstance(builtins_payload, dict):
        msg = "Expected a mapping from msgspec.to_builtins."
        raise TypeError(msg)
    payload: dict[str, Any] = {str(k): v for k, v in builtins_payload.items()}
    blocked_fields = frozenset(payload) & _SELF_UPDATE_BLOCKED_FIELDS
    if blocked_fields:
        detail = _build_blocked_self_update_detail(blocked_fields)
        raise AuthorizationError(detail)
    return payload
