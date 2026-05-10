"""Shared API-key controller contracts and helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Never, Protocol, TypedDict, Unpack, cast, runtime_checkable

from litestar.exceptions import ClientException, NotFoundException

from litestar_auth.controllers._utils import _map_domain_exceptions
from litestar_auth.exceptions import (
    ApiKeyLimitReachedError,
    ApiKeyNotFoundError,
    ApiKeyScopeDeniedError,
    ErrorCode,
    InvalidPasswordError,
)
from litestar_auth.payloads import (
    ApiKeyAdminCreateRequest,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyRead,
    ApiKeyUpdateRequest,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import datetime

    from litestar import Request
    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth._manager.api_key_creation import ApiKeyCreateOptions
    from litestar_auth._manager.api_keys import ApiKeyRowProtocol
    from litestar_auth.controllers._utils import RequestHandler
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.types import UserProtocol

_API_KEY_NOT_FOUND_DETAIL = "API key not found."


@runtime_checkable
class ApiKeysControllerUserManagerProtocol[UP: UserProtocol[Any], ID](Protocol):
    """User-manager behavior required by API-key controllers."""

    async def get(self, user_id: ID) -> UP | None:
        """Return a user by identifier."""

    async def create_api_key(
        self,
        user: UP,
        **options: Unpack[ApiKeyCreateOptions],
    ) -> object:
        """Create an API key and return the manager creation result."""

    async def list_api_keys(self, user: UP, *, include_inactive: bool = False) -> list[ApiKeyRowProtocol]:
        """Return API-key rows owned by a user."""

    async def get_api_key(self, user: UP, key_id: str, *, include_inactive: bool = False) -> ApiKeyRowProtocol:
        """Return one API-key row owned by a user."""

    async def update_api_key(
        self,
        user: UP,
        key_id: str,
        *,
        name: str | None = None,
        scopes: list[str] | None = None,
        current_password: str | None = None,
    ) -> ApiKeyRowProtocol:
        """Update mutable API-key metadata."""

    async def revoke_api_key(
        self,
        user: UP,
        key_id: str,
    ) -> ApiKeyRowProtocol:
        """Soft-revoke an API key."""


@dataclass(frozen=True, slots=True)
class ApiKeysControllerConfig[ID]:
    """Configuration for :func:`create_api_keys_controllers`."""

    id_parser: Callable[[str], ID] | None = None
    rate_limit_config: AuthRateLimitConfig | None = None
    path: str = "/api-keys"
    users_path: str = "/users"
    security: Sequence[SecurityRequirement] | None = None
    require_step_up_on_create: bool = True
    signing_enabled: bool = False


class ApiKeysControllerOptions[ID](TypedDict, total=False):
    """Keyword options accepted by :func:`create_api_keys_controllers`."""

    id_parser: Callable[[str], ID] | None
    rate_limit_config: AuthRateLimitConfig | None
    path: str
    users_path: str
    security: Sequence[SecurityRequirement] | None
    require_step_up_on_create: bool
    signing_enabled: bool


@dataclass(frozen=True, slots=True)
class ApiKeysControllerContext[ID]:
    """Runtime settings shared by generated API-key routes."""

    id_parser: Callable[[str], ID] | None
    create_before_request: RequestHandler | None
    create_rate_limit_increment: RequestHandler
    create_rate_limit_reset: RequestHandler
    update_before_request: RequestHandler | None
    update_rate_limit_increment: RequestHandler
    update_rate_limit_reset: RequestHandler
    security: Sequence[SecurityRequirement] | None
    require_step_up_on_create: bool
    signing_enabled: bool


def to_api_key_read(api_key: ApiKeyRowProtocol) -> ApiKeyRead:
    """Return the safe public representation of an API-key row."""
    return ApiKeyRead(
        key_id=api_key.key_id,
        name=api_key.name,
        scopes=list(api_key.scopes),
        prefix_env=api_key.prefix_env,
        created_at=cast("datetime | None", getattr(api_key, "created_at", None)),
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        revoked_at=api_key.revoked_at,
    )


def raise_invalid_api_key_create_payload(detail: str) -> Never:
    """Raise a normalized API-key request-body error.

    Raises:
        ClientException: Always.
    """
    raise ClientException(status_code=400, detail=detail, extra={"code": ErrorCode.REQUEST_BODY_INVALID})


async def load_user_or_404[UP: UserProtocol[Any], ID](
    user_id: str,
    *,
    ctx: ApiKeysControllerContext[ID],
    user_manager: ApiKeysControllerUserManagerProtocol[UP, ID],
) -> UP:
    """Load a user for an admin API-key route or raise 404.

    Returns:
        Loaded user.

    Raises:
        NotFoundException: If the user id is malformed or no user exists.
    """
    try:
        parsed_user_id = ctx.id_parser(user_id) if ctx.id_parser is not None else cast("ID", user_id)
    except (TypeError, ValueError) as exc:
        raise NotFoundException(detail="User not found.") from exc
    user = await user_manager.get(parsed_user_id)
    if user is not None:
        return user
    raise NotFoundException(detail="User not found.")


async def create_api_key_for_user[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    user: UP,
    data: ApiKeyCreateRequest | ApiKeyAdminCreateRequest,
    *,
    ctx: ApiKeysControllerContext[ID],
    user_manager: ApiKeysControllerUserManagerProtocol[UP, ID],
) -> ApiKeyCreateResponse:
    """Create an API key for ``user`` and return the one-time credential response.

    Returns:
        Creation response containing the raw API key exactly once.
    """
    if isinstance(data, ApiKeyCreateRequest) and ctx.require_step_up_on_create and data.current_password is None:
        raise_invalid_api_key_create_payload("API-key create payload requires current_password.")
    if data.signing_required and not ctx.signing_enabled:
        raise_invalid_api_key_create_payload("API-key request signing is not configured.")
    async with _map_domain_exceptions(
        {
            InvalidPasswordError: (400, ErrorCode.LOGIN_BAD_CREDENTIALS),
            ApiKeyScopeDeniedError: (400, ErrorCode.API_KEY_SCOPE_DENIED),
            ApiKeyLimitReachedError: (400, ErrorCode.API_KEY_LIMIT_REACHED),
        },
        on_error=lambda: ctx.create_rate_limit_increment(request),
    ):
        created = await user_manager.create_api_key(
            user,
            name=data.name,
            scopes=list(data.scopes),
            current_password=current_password_for_create_payload(data),
            expires_at=data.expires_at,
            signing_required=data.signing_required,
            created_via="http",
        )
    await ctx.create_rate_limit_reset(request)
    api_key = cast("Any", created).api_key
    secret = cast("Any", created).secret.get_secret_value()
    return ApiKeyCreateResponse(api_key=secret, key=to_api_key_read(cast("ApiKeyRowProtocol", api_key)))


def current_password_for_create_payload(data: ApiKeyCreateRequest | ApiKeyAdminCreateRequest) -> str | None:
    """Return the self-service step-up password, or ``None`` for admin create payloads."""
    if isinstance(data, ApiKeyCreateRequest):
        return data.current_password
    return None


async def update_api_key_for_request[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    key_id: str,
    data: ApiKeyUpdateRequest,
    *,
    ctx: ApiKeysControllerContext[ID],
    user_manager: ApiKeysControllerUserManagerProtocol[UP, ID],
) -> ApiKeyRowProtocol:
    """Update one API key for the authenticated request user.

    Returns:
        The updated API-key row.
    """
    async with _map_domain_exceptions(
        {
            InvalidPasswordError: (400, ErrorCode.LOGIN_BAD_CREDENTIALS),
            ApiKeyScopeDeniedError: (400, ErrorCode.API_KEY_SCOPE_DENIED),
        },
        on_error=lambda: ctx.update_rate_limit_increment(request),
    ):
        return await user_manager.update_api_key(
            request.user,
            key_id,
            name=data.name,
            scopes=None if data.scopes is None else list(data.scopes),
            current_password=data.current_password,
        )


def raise_api_key_not_found(exc: ApiKeyNotFoundError) -> Never:
    """Raise the non-enumerating API-key not-found response.

    Raises:
        NotFoundException: Always, chained from the domain not-found error.
    """
    raise NotFoundException(
        detail=_API_KEY_NOT_FOUND_DETAIL,
        extra={"code": ErrorCode.API_KEY_INVALID},
    ) from exc
