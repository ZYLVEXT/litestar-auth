"""Business handlers for generated users controllers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import msgspec
from litestar.exceptions import NotFoundException

from litestar_auth.controllers._error_responses import raise_authentication_required, raise_client_error
from litestar_auth.controllers._step_up import (
    PasswordStepUpCheck,
    TotpStepUpCheck,
    TotpStepUpEndpoint,
    TotpStepUpVerifierProtocol,
    require_password_step_up,
    require_totp_stepup,
)
from litestar_auth.controllers._users_helpers import AdminUserDeleteStepUpRequest, _build_safe_self_update
from litestar_auth.controllers._utils import _map_domain_exceptions, _require_account_state, _to_user_schema
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.schemas import AdminUserUpdate, ChangePasswordRequest

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar import Request

    from litestar_auth.controllers.users import (
        UsersControllerUserManagerProtocol,
        UsersControllerUserProtocol,
        _UsersControllerContext,
    )


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
