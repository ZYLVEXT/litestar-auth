"""Registration controller factory for user sign-up endpoints."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, TypedDict, Unpack, cast, overload, runtime_checkable

import msgspec  # noqa: TC002
from litestar import Controller, Request, post
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example

from litestar_auth.controllers._utils import (
    RequestBodyRouteHandler,
    _configure_request_body_handler,
    _create_before_request_handler,
    _map_domain_exceptions,
    _mark_litestar_auth_route_handler,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.schemas import UserCreate, UserRead
from litestar_auth.types import RoleCapableUserProtocol

if TYPE_CHECKING:
    from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit

REGISTER_FAILURE_DETAIL = "Registration could not be completed."
DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS = 0.4
_REGISTER_OPENAPI_RESPONSES = {
    400: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description=(
            "Registration domain failures use the enumeration-resistant `REGISTER_FAILED` code. "
            "Malformed JSON request bodies use `REQUEST_BODY_INVALID`."
        ),
        examples=[
            Example(
                id="register_failed",
                summary="Registration failed",
                value={
                    "status_code": 400,
                    "detail": REGISTER_FAILURE_DETAIL,
                    "extra": {"code": ErrorCode.REGISTER_FAILED.value},
                },
            ),
            Example(
                id="invalid_request_body",
                summary="Invalid request body",
                value={
                    "status_code": 400,
                    "detail": "Invalid request body.",
                    "extra": {"code": ErrorCode.REQUEST_BODY_INVALID.value},
                },
            ),
        ],
    ),
    422: ResponseSpec(
        data_container=dict[str, object],
        generate_examples=False,
        description="Schema-invalid registration request bodies use `REQUEST_BODY_INVALID`.",
        examples=[
            Example(
                id="request_body_invalid",
                summary="Invalid request payload",
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
        description="Rate-limited registration attempts return `Retry-After`.",
        examples=[
            Example(
                id="rate_limited",
                summary="Too many registration attempts",
                value={
                    "status_code": 429,
                    "detail": "Too many requests.",
                },
            ),
        ],
    ),
}


class RegisterControllerUserProtocol[ID](RoleCapableUserProtocol[ID], Protocol):
    """Protocol describing the public user fields returned after registration."""

    email: str
    is_active: bool
    is_verified: bool


@runtime_checkable
class RegisterControllerUserManagerProtocol[UP: RegisterControllerUserProtocol[Any], ID](Protocol):
    """User-manager behavior required by the register controller."""

    async def create(
        self,
        user_create: msgspec.Struct,
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> UP:
        """Create and return a new user."""


@dataclass(frozen=True, slots=True)
class _RegisterControllerSettings:
    """Resolved settings for the generated registration controller."""

    register_rate_limit: EndpointRateLimit | None
    register_before_request: Any
    path: str
    user_read_schema: type[msgspec.Struct]
    user_create_schema: type[msgspec.Struct]
    minimum_response_seconds: float
    unsafe_testing: bool


@dataclass(frozen=True, slots=True)
class RegisterControllerConfig:
    """Configuration for :func:`create_register_controller`."""

    rate_limit_config: AuthRateLimitConfig | None = None
    path: str = "/auth"
    user_read_schema: type[msgspec.Struct] = UserRead
    user_create_schema: type[msgspec.Struct] = UserCreate
    register_minimum_response_seconds: float = DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS
    unsafe_testing: bool = False


class RegisterControllerOptions(TypedDict, total=False):
    """Keyword options accepted by :func:`create_register_controller`."""

    rate_limit_config: AuthRateLimitConfig | None
    path: str
    user_read_schema: type[msgspec.Struct]
    user_create_schema: type[msgspec.Struct]
    register_minimum_response_seconds: float
    unsafe_testing: bool


def _validate_register_minimum_response_seconds(value: float) -> float:
    """Return a non-negative register timing-envelope value.

    Raises:
        ValueError: If ``value`` is negative.
    """
    if value >= 0:
        return value

    msg = "register_minimum_response_seconds must be non-negative."
    raise ValueError(msg)


async def _await_register_minimum_response(
    *,
    started_at: float,
    minimum_seconds: float,
) -> None:
    """Pad registration responses to the configured minimum duration."""
    remaining_seconds = minimum_seconds - (time.perf_counter() - started_at)
    if remaining_seconds > 0:
        await asyncio.sleep(remaining_seconds)


async def _increment_register_rate_limit(
    register_rate_limit: EndpointRateLimit | None,
    request: Request[Any, Any, Any],
) -> None:
    """Increment the registration limiter when one is configured."""
    if register_rate_limit is not None:
        await register_rate_limit.increment(request)


async def _create_user_or_register_failure(
    data: msgspec.Struct,
    *,
    request: Request[Any, Any, Any],
    user_manager: RegisterControllerUserManagerProtocol[Any, Any],
    register_rate_limit: EndpointRateLimit | None,
) -> RegisterControllerUserProtocol[Any]:
    """Create a user while collapsing domain failures to the public register response.

    Returns:
        Newly created user.
    """

    async def _increment_rate_limit() -> None:
        await _increment_register_rate_limit(register_rate_limit, request)

    async with _map_domain_exceptions(
        {
            UserAlreadyExistsError: (400, ErrorCode.REGISTER_FAILED),
            InvalidPasswordError: (400, ErrorCode.REGISTER_FAILED),
            AuthorizationError: (400, ErrorCode.REGISTER_FAILED),
        },
        on_error=_increment_rate_limit,
        detail=REGISTER_FAILURE_DETAIL,
    ):
        return await user_manager.create(data, safe=True)


async def _reset_register_rate_limit(
    register_rate_limit: EndpointRateLimit | None,
    request: Request[Any, Any, Any],
) -> None:
    """Reset the registration limiter after a successful registration."""
    if register_rate_limit is not None:
        await register_rate_limit.reset(request)


def _create_register_handler(settings: _RegisterControllerSettings) -> RequestBodyRouteHandler:
    """Create the generated registration route handler.

    Returns:
        Decorated Litestar route handler.
    """

    @post("/register", before_request=settings.register_before_request, responses=_REGISTER_OPENAPI_RESPONSES)
    async def register(
        self: object,
        request: Request[Any, Any, Any],
        data: msgspec.Struct,
        litestar_auth_user_manager: RegisterControllerUserManagerProtocol[Any, Any],
    ) -> msgspec.Struct:
        del self
        started_at = time.perf_counter()
        try:
            user = await _create_user_or_register_failure(
                data,
                request=request,
                user_manager=litestar_auth_user_manager,
                register_rate_limit=settings.register_rate_limit,
            )
            await _reset_register_rate_limit(settings.register_rate_limit, request)
            return _to_user_schema(user, settings.user_read_schema, unsafe_testing=settings.unsafe_testing)
        finally:
            await _await_register_minimum_response(
                started_at=started_at,
                minimum_seconds=settings.minimum_response_seconds,
            )

    return cast("RequestBodyRouteHandler", register)


def _create_register_controller_type(settings: _RegisterControllerSettings) -> type[Controller]:
    """Create the generated registration controller type.

    Returns:
        Controller subclass exposing the registration endpoint.
    """
    register_cls = type(
        "RegisterController",
        (Controller,),
        {
            "__module__": __name__,
            "__doc__": "Endpoints for registering a new user with a non-enumerating failure surface.",
            "register": _create_register_handler(settings),
        },
    )
    register_cls.__qualname__ = register_cls.__name__
    _configure_request_body_handler(cast("Any", register_cls).register, schema=settings.user_create_schema)
    register_cls.path = settings.path
    return _mark_litestar_auth_route_handler(cast("type[Controller]", register_cls))


@overload
def create_register_controller[UP: RegisterControllerUserProtocol[Any], ID](
    *,
    config: RegisterControllerConfig,
) -> type[Controller]:
    pass  # pragma: no cover


@overload
def create_register_controller[UP: RegisterControllerUserProtocol[Any], ID](
    **options: Unpack[RegisterControllerOptions],
) -> type[Controller]:
    pass  # pragma: no cover


def create_register_controller[UP: RegisterControllerUserProtocol[Any], ID](
    *,
    config: RegisterControllerConfig | None = None,
    **options: Unpack[RegisterControllerOptions],
) -> type[Controller]:
    """Return a controller subclass for enumeration-resistant public registration.

    Domain failures collapse to HTTP 400 with ``ErrorCode.REGISTER_FAILED`` and
    successful/domain-failed attempts are padded to the configured minimum
    duration.

    Returns:
        Controller subclass exposing the registration endpoint.

    Raises:
        ValueError: If ``config`` and keyword options are combined.
    """
    if config is not None and options:
        msg = "Pass either RegisterControllerConfig or keyword options, not both."
        raise ValueError(msg)
    settings = RegisterControllerConfig(**options) if config is None else config

    _require_msgspec_struct(settings.user_read_schema, parameter_name="user_read_schema")
    _require_msgspec_struct(
        settings.user_create_schema,
        parameter_name="user_create_schema",
        require_forbid_unknown_fields=True,
    )
    register_rate_limit = settings.rate_limit_config.register if settings.rate_limit_config else None
    return _create_register_controller_type(
        _RegisterControllerSettings(
            register_rate_limit=register_rate_limit,
            register_before_request=_create_before_request_handler(register_rate_limit),
            path=settings.path,
            user_read_schema=settings.user_read_schema,
            user_create_schema=settings.user_create_schema,
            minimum_response_seconds=_validate_register_minimum_response_seconds(
                settings.register_minimum_response_seconds,
            ),
            unsafe_testing=settings.unsafe_testing,
        ),
    )
