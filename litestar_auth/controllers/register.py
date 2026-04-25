"""Registration controller factory for user sign-up endpoints."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

import msgspec  # noqa: TC002
from litestar import Controller, Request, post
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example

from litestar_auth.controllers._utils import (
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
    from litestar_auth.ratelimit import AuthRateLimitConfig

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


def create_register_controller[UP: RegisterControllerUserProtocol[Any], ID](  # noqa: PLR0913
    *,
    rate_limit_config: AuthRateLimitConfig | None = None,
    path: str = "/auth",
    user_read_schema: type[msgspec.Struct] = UserRead,
    user_create_schema: type[msgspec.Struct] = UserCreate,
    register_minimum_response_seconds: float = DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS,
    unsafe_testing: bool = False,
) -> type[Controller]:
    """Return a controller subclass for enumeration-resistant public registration.

    Duplicate users, password-policy failures, and authorization rejections raised
    by the manager are collapsed to HTTP 400 with ``ErrorCode.REGISTER_FAILED``
    and the shared ``REGISTER_FAILURE_DETAIL`` text. The underlying exception
    subclasses are not changed, so custom hooks and operator logging can still
    inspect the root cause before it is translated at the HTTP boundary.

    Args:
        rate_limit_config: Optional auth-endpoint rate-limiter configuration.
        path: Base route prefix for the generated controller.
        user_read_schema: Custom msgspec struct used for public registration responses.
        user_create_schema: Custom msgspec struct used for registration requests.
        register_minimum_response_seconds: Minimum wall-clock duration for
            successful and domain-failed registration attempts. This tail wait is
            defense-in-depth against lower-tail timing enumeration and is
            independent of rate limiting.
        unsafe_testing: Explicit test-only override that allows response
            schemas with sensitive fields for isolated fixtures.

    Returns:
        Controller subclass exposing the registration endpoint.

    Examples:
        ```python
        class ExtendedUserCreate(msgspec.Struct, forbid_unknown_fields=True):
            email: str
            password: str
            bio: str

        class ExtendedUserRead(msgspec.Struct):
            id: uuid.UUID
            email: str
            is_active: bool
            is_verified: bool
            roles: list[str]
            bio: str

        controller = create_register_controller(
            user_create_schema=ExtendedUserCreate,
            user_read_schema=ExtendedUserRead,
        )
        ```
    """
    _require_msgspec_struct(user_read_schema, parameter_name="user_read_schema")
    _require_msgspec_struct(
        user_create_schema,
        parameter_name="user_create_schema",
        require_forbid_unknown_fields=True,
    )
    register_rate_limit = rate_limit_config.register if rate_limit_config else None
    register_minimum_response_seconds = _validate_register_minimum_response_seconds(register_minimum_response_seconds)
    user_read_schema_type = user_read_schema
    user_create_schema_type = user_create_schema
    register_before_request = _create_before_request_handler(register_rate_limit)

    class RegisterController(Controller):
        """Endpoints for registering a new user with a non-enumerating failure surface."""

        @post("/register", before_request=register_before_request, responses=_REGISTER_OPENAPI_RESPONSES)
        async def register(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: msgspec.Struct,
            litestar_auth_user_manager: RegisterControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            """Create a user or return the generic ``REGISTER_FAILED`` domain-error contract.

            Returns:
                Configured public user response schema for a successful registration.
            """

            async def _increment_rate_limit() -> None:
                if register_rate_limit is not None:
                    await register_rate_limit.increment(request)

            started_at = time.perf_counter()
            try:
                async with _map_domain_exceptions(
                    {
                        UserAlreadyExistsError: (400, ErrorCode.REGISTER_FAILED),
                        InvalidPasswordError: (400, ErrorCode.REGISTER_FAILED),
                        AuthorizationError: (400, ErrorCode.REGISTER_FAILED),
                    },
                    on_error=_increment_rate_limit,
                    detail=REGISTER_FAILURE_DETAIL,
                ):
                    user = await litestar_auth_user_manager.create(data, safe=True)

                if register_rate_limit is not None:
                    await register_rate_limit.reset(request)

                return _to_user_schema(user, user_read_schema_type, unsafe_testing=unsafe_testing)
            finally:
                await _await_register_minimum_response(
                    started_at=started_at,
                    minimum_seconds=register_minimum_response_seconds,
                )

    register_cls = RegisterController
    _configure_request_body_handler(register_cls.register, schema=user_create_schema_type)
    register_cls.path = path
    return _mark_litestar_auth_route_handler(cast("type[Controller]", register_cls))
