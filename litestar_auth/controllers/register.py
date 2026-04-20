"""Registration controller factory for user sign-up endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

import msgspec  # noqa: TC002
from litestar import Controller, Request, post

from litestar_auth.controllers._utils import (
    _configure_request_body_handler,
    _create_before_request_handler,
    _map_domain_exceptions,
    _mark_litestar_auth_route_handler,
    _require_msgspec_struct,
    _to_user_schema,
)
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.schemas import UserCreate, UserRead
from litestar_auth.types import RoleCapableUserProtocol

if TYPE_CHECKING:
    from litestar_auth.ratelimit import AuthRateLimitConfig


class RegisterControllerUserProtocol[ID](RoleCapableUserProtocol[ID], Protocol):
    """Protocol describing the public user fields returned after registration."""

    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool


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


def create_register_controller[UP: RegisterControllerUserProtocol[Any], ID](
    *,
    rate_limit_config: AuthRateLimitConfig | None = None,
    path: str = "/auth",
    user_read_schema: type[msgspec.Struct] = UserRead,
    user_create_schema: type[msgspec.Struct] = UserCreate,
    unsafe_testing: bool = False,
) -> type[Controller]:
    """Return a controller subclass that resolves the user manager via Litestar DI.

    Args:
        rate_limit_config: Optional auth-endpoint rate-limiter configuration.
        path: Base route prefix for the generated controller.
        user_read_schema: Custom msgspec struct used for public registration responses.
        user_create_schema: Custom msgspec struct used for registration requests.
        unsafe_testing: Explicit test-only override that allows response
            schemas with sensitive fields for isolated fixtures.

    Returns:
        Controller subclass exposing the registration endpoint.

    Examples:
        ```python
        class ExtendedUserCreate(msgspec.Struct):
            email: str
            password: str
            bio: str

        class ExtendedUserRead(msgspec.Struct):
            id: uuid.UUID
            email: str
            is_active: bool
            is_verified: bool
            is_superuser: bool
            roles: list[str]
            bio: str

        controller = create_register_controller(
            user_create_schema=ExtendedUserCreate,
            user_read_schema=ExtendedUserRead,
        )
        ```
    """
    _require_msgspec_struct(user_read_schema, parameter_name="user_read_schema")
    _require_msgspec_struct(user_create_schema, parameter_name="user_create_schema")
    register_rate_limit = rate_limit_config.register if rate_limit_config else None
    user_read_schema_type = user_read_schema
    user_create_schema_type = user_create_schema
    register_before_request = _create_before_request_handler(register_rate_limit)

    class RegisterController(Controller):
        """Endpoints for registering a new user."""

        @post("/register", before_request=register_before_request)
        async def register(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: msgspec.Struct,
            litestar_auth_user_manager: RegisterControllerUserManagerProtocol[Any, Any],
        ) -> msgspec.Struct:
            async def _increment_rate_limit() -> None:
                if register_rate_limit is not None:
                    await register_rate_limit.increment(request)

            async with _map_domain_exceptions(
                {
                    UserAlreadyExistsError: (400, ErrorCode.REGISTER_USER_ALREADY_EXISTS),
                    InvalidPasswordError: (400, ErrorCode.REGISTER_INVALID_PASSWORD),
                },
                on_error=_increment_rate_limit,
            ):
                user = await litestar_auth_user_manager.create(data, safe=True)

            if register_rate_limit is not None:
                await register_rate_limit.reset(request)

            return _to_user_schema(user, user_read_schema_type, unsafe_testing=unsafe_testing)

    register_cls = RegisterController
    _configure_request_body_handler(register_cls.register, schema=user_create_schema_type)
    register_cls.path = path
    return _mark_litestar_auth_route_handler(cast("type[Controller]", register_cls))
