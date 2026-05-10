"""Self-service API-key controller assembly."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar import Controller, Request, delete, get, patch, post

from litestar_auth.controllers._api_key_common import (
    ApiKeysControllerContext,
    ApiKeysControllerUserManagerProtocol,
    create_api_key_for_user,
    raise_api_key_not_found,
    to_api_key_read,
    update_api_key_for_request,
)
from litestar_auth.controllers._utils import (
    RequestBodyErrorConfig,
    _configure_request_body_handler,
    _create_request_body_exception_handlers,
)
from litestar_auth.exceptions import ApiKeyNotFoundError, ErrorCode
from litestar_auth.guards import is_authenticated, requires_password_session
from litestar_auth.payloads import ApiKeyCreateRequest, ApiKeyListResponse, ApiKeyRead, ApiKeyUpdateRequest

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.controllers._utils import RequestBodyRouteHandler


def _create_self_api_key_create_handler[ID](ctx: ApiKeysControllerContext[ID]) -> RequestBodyRouteHandler:
    """Return the self-service API-key create handler."""

    @post(
        status_code=201,
        guards=[is_authenticated, requires_password_session],
        security=ctx.security,
        before_request=ctx.create_before_request,
        exception_handlers=_create_request_body_exception_handlers(
            RequestBodyErrorConfig(
                validation_detail="Invalid API-key create payload.",
                validation_code=ErrorCode.REQUEST_BODY_INVALID,
            ),
        ),
    )
    async def create_api_key(
        self: Controller,
        request: Request[Any, Any, Any],
        data: ApiKeyCreateRequest,
        litestar_auth_user_manager: ApiKeysControllerUserManagerProtocol[Any, Any],
    ) -> object:
        del self
        return await create_api_key_for_user(
            request,
            request.user,
            data,
            ctx=ctx,
            user_manager=litestar_auth_user_manager,
        )

    return cast("RequestBodyRouteHandler", create_api_key)


def _create_self_api_key_list_handler[ID](ctx: ApiKeysControllerContext[ID]) -> Callable[..., object]:
    """Return the self-service API-key list handler."""

    @get(guards=[is_authenticated, requires_password_session], security=ctx.security)
    async def list_api_keys(
        self: Controller,
        request: Request[Any, Any, Any],
        litestar_auth_user_manager: ApiKeysControllerUserManagerProtocol[Any, Any],
    ) -> ApiKeyListResponse:
        del self
        api_keys = await litestar_auth_user_manager.list_api_keys(request.user)
        return ApiKeyListResponse(api_keys=[to_api_key_read(api_key) for api_key in api_keys])

    return list_api_keys


def _create_self_api_key_get_handler[ID](ctx: ApiKeysControllerContext[ID]) -> Callable[..., object]:
    """Return the self-service API-key read handler."""

    @get("/{key_id:str}", guards=[is_authenticated, requires_password_session], security=ctx.security)
    async def get_api_key(
        self: Controller,
        request: Request[Any, Any, Any],
        key_id: str,
        litestar_auth_user_manager: ApiKeysControllerUserManagerProtocol[Any, Any],
    ) -> ApiKeyRead:
        del self
        try:
            api_key = await litestar_auth_user_manager.get_api_key(request.user, key_id)
        except ApiKeyNotFoundError as exc:
            raise_api_key_not_found(exc)
        return to_api_key_read(api_key)

    return get_api_key


def _create_self_api_key_update_handler[ID](ctx: ApiKeysControllerContext[ID]) -> RequestBodyRouteHandler:
    """Return the self-service API-key update handler."""

    @patch(
        "/{key_id:str}",
        guards=[is_authenticated, requires_password_session],
        security=ctx.security,
        before_request=ctx.update_before_request,
        exception_handlers=_create_request_body_exception_handlers(
            RequestBodyErrorConfig(
                validation_detail="Invalid API-key update payload.",
                validation_code=ErrorCode.REQUEST_BODY_INVALID,
            ),
        ),
    )
    async def update_api_key(
        self: Controller,
        request: Request[Any, Any, Any],
        key_id: str,
        data: ApiKeyUpdateRequest,
        litestar_auth_user_manager: ApiKeysControllerUserManagerProtocol[Any, Any],
    ) -> ApiKeyRead:
        del self
        try:
            api_key = await update_api_key_for_request(
                request,
                key_id,
                data,
                ctx=ctx,
                user_manager=litestar_auth_user_manager,
            )
        except ApiKeyNotFoundError as exc:
            raise_api_key_not_found(exc)
        await ctx.update_rate_limit_reset(request)
        return to_api_key_read(api_key)

    return cast("RequestBodyRouteHandler", update_api_key)


def _create_self_api_key_revoke_handler[ID](ctx: ApiKeysControllerContext[ID]) -> Callable[..., object]:
    """Return the self-service API-key revoke handler."""

    @delete(
        "/{key_id:str}",
        guards=[is_authenticated, requires_password_session],
        security=ctx.security,
        status_code=200,
    )
    async def revoke_api_key(
        self: Controller,
        request: Request[Any, Any, Any],
        key_id: str,
        litestar_auth_user_manager: ApiKeysControllerUserManagerProtocol[Any, Any],
    ) -> ApiKeyRead:
        del self
        try:
            api_key = await litestar_auth_user_manager.revoke_api_key(request.user, key_id)
        except ApiKeyNotFoundError as exc:
            raise_api_key_not_found(exc)
        return to_api_key_read(api_key)

    return revoke_api_key


def define_self_api_keys_controller[ID](ctx: ApiKeysControllerContext[ID]) -> type[Controller]:
    """Define self-service API-key routes.

    Returns:
        Generated self-service controller class.
    """

    class ApiKeysController(Controller):
        """Self-service API-key management endpoints."""

        create_api_key = _create_self_api_key_create_handler(ctx)
        list_api_keys = _create_self_api_key_list_handler(ctx)
        get_api_key = _create_self_api_key_get_handler(ctx)
        update_api_key = _create_self_api_key_update_handler(ctx)
        revoke_api_key = _create_self_api_key_revoke_handler(ctx)

    _configure_request_body_handler(ApiKeysController.create_api_key, schema=ApiKeyCreateRequest)
    _configure_request_body_handler(ApiKeysController.update_api_key, schema=ApiKeyUpdateRequest)
    return ApiKeysController
