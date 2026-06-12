"""Admin API-key controller assembly."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, cast

from litestar import Controller, Request, delete, get, post
from litestar.di import NamedDependency
from litestar.params import PathParameter

from litestar_auth.controllers._api_key_common import (
    ApiKeysControllerContext,
    ApiKeysControllerUserManagerProtocol,
    create_api_key_for_user,
    load_user_or_404,
    raise_api_key_not_found,
    to_api_key_read,
)
from litestar_auth.controllers._step_up import (
    TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE,
    TotpStepUpCheck,
    TotpStepUpVerifierProtocol,
    require_totp_stepup,
)
from litestar_auth.controllers._utils import _configure_request_body_handler
from litestar_auth.exceptions import ApiKeyNotFoundError
from litestar_auth.guards import is_superuser, requires_password_session
from litestar_auth.payloads import ApiKeyAdminCreateRequest, ApiKeyCreateResponse, ApiKeyListResponse, ApiKeyRead

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.controllers._utils import RequestBodyRouteHandler

_UserManagerDep = NamedDependency[ApiKeysControllerUserManagerProtocol[Any, Any]]


_UserIdPath = Annotated[str, PathParameter()]
_KeyIdPath = Annotated[str, PathParameter()]


def _create_admin_api_key_create_handler[ID](ctx: ApiKeysControllerContext[ID]) -> RequestBodyRouteHandler:
    """Return the admin API-key create handler."""

    @post(
        "/{user_id:str}/api-keys",
        status_code=201,
        guards=[is_superuser, requires_password_session],
        security=ctx.security,
        responses={403: TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE},
    )
    async def create_user_api_key(
        self: Controller,  # noqa: ARG001
        request: Request[Any, Any, Any],
        user_id: _UserIdPath,
        data: ApiKeyAdminCreateRequest,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> ApiKeyCreateResponse:
        await require_totp_stepup(
            request,
            TotpStepUpCheck(
                endpoint="api_keys.create",
                policy=ctx.totp_stepup_policy,
                user_manager=cast("TotpStepUpVerifierProtocol[Any]", litestar_auth_user_manager),
                totp_code=data.totp_code,
            ),
        )
        user = await load_user_or_404(user_id, ctx=ctx, user_manager=litestar_auth_user_manager)
        return await create_api_key_for_user(
            request,
            user,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", create_user_api_key)


def _create_admin_api_key_list_handler[ID](ctx: ApiKeysControllerContext[ID]) -> Callable[..., object]:
    """Return the admin API-key list handler."""

    @get("/{user_id:str}/api-keys", guards=[is_superuser, requires_password_session], security=ctx.security)
    async def list_user_api_keys(
        self: Controller,  # noqa: ARG001
        user_id: _UserIdPath,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> ApiKeyListResponse:
        user = await load_user_or_404(user_id, ctx=ctx, user_manager=litestar_auth_user_manager)
        api_keys = await litestar_auth_user_manager.list_api_keys(user)
        return ApiKeyListResponse(api_keys=[to_api_key_read(api_key) for api_key in api_keys])

    return list_user_api_keys


def _create_admin_api_key_revoke_handler[ID](ctx: ApiKeysControllerContext[ID]) -> Callable[..., object]:
    """Return the admin API-key revoke handler."""

    @delete(
        "/{user_id:str}/api-keys/{key_id:str}",
        guards=[is_superuser, requires_password_session],
        security=ctx.security,
        status_code=200,
        responses={403: TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE},
    )
    async def revoke_user_api_key(
        self: Controller,  # noqa: ARG001
        request: Request[Any, Any, Any],
        user_id: _UserIdPath,
        key_id: _KeyIdPath,
        litestar_auth_user_manager: _UserManagerDep,
    ) -> ApiKeyRead:
        await require_totp_stepup(
            request,
            TotpStepUpCheck(
                endpoint="api_keys.revoke",
                policy=ctx.totp_stepup_policy,
                user_manager=cast("TotpStepUpVerifierProtocol[Any]", litestar_auth_user_manager),
            ),
        )
        user = await load_user_or_404(user_id, ctx=ctx, user_manager=litestar_auth_user_manager)
        try:
            api_key = await litestar_auth_user_manager.revoke_api_key(user, key_id)
        except ApiKeyNotFoundError as exc:
            raise_api_key_not_found(exc)
        return to_api_key_read(api_key)

    return revoke_user_api_key


def define_admin_api_keys_controller[ID](ctx: ApiKeysControllerContext[ID]) -> type[Controller]:
    """Define superuser API-key routes nested under ``/users``.

    Returns:
        Generated admin controller class.
    """

    class AdminApiKeysController(Controller):
        """Admin API-key management endpoints."""

        create_user_api_key = _create_admin_api_key_create_handler(ctx)
        list_user_api_keys = _create_admin_api_key_list_handler(ctx)
        revoke_user_api_key = _create_admin_api_key_revoke_handler(ctx)

    _configure_request_body_handler(AdminApiKeysController.create_user_api_key, schema=ApiKeyAdminCreateRequest)
    return AdminApiKeysController
