"""Unit tests for reset-controller helper branches and error mapping."""

from __future__ import annotations

import importlib
from types import CellType, FunctionType
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.status_codes import HTTP_200_OK, HTTP_202_ACCEPTED, HTTP_400_BAD_REQUEST
from litestar.testing import AsyncTestClient

import litestar_auth.controllers.reset as reset_module
from litestar_auth.controllers.reset import (
    ResetPassword,
    create_reset_password_controller,
)
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError, InvalidResetPasswordTokenError
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit
from tests._helpers import litestar_app_with_user_manager

if TYPE_CHECKING:
    from litestar import Controller

pytestmark = pytest.mark.unit


def test_reset_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and protocol execution."""
    reloaded_module = importlib.reload(reset_module)

    assert reloaded_module.ResetPassword.__name__ == ResetPassword.__name__
    assert reloaded_module.ResetPasswordControllerUserManagerProtocol.__name__.endswith("Protocol")


class DummyUser(msgspec.Struct):
    """Minimal user struct compatible with the reset-password controller."""

    id: UUID
    email: str
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = msgspec.field(default_factory=lambda: ["member"])


class DummyUserManager:
    """User manager stub that can be configured to raise specific errors."""

    def __init__(self, error: Exception | None = None) -> None:
        """Initialize the stub with an optional error to raise on reset_password."""
        self.error = error
        self.last_forgot_password_email: str | None = None
        self.last_reset_arguments: dict[str, Any] | None = None

    async def forgot_password(self, email: str) -> None:
        """Record the email used to request a reset token."""
        self.last_forgot_password_email = email

    async def reset_password(self, token: str, password: str) -> DummyUser:
        """Return a dummy user or raise the configured error."""
        self.last_reset_arguments = {"token": token, "password": password}
        if self.error is not None:
            raise self.error
        return DummyUser(id=uuid4(), email="user@example.com")


def _make_closure_cell(value: object) -> CellType:
    """Return a closure cell containing ``value`` for function reconstruction."""

    def _cell_factory() -> object:
        return value

    closure = _cell_factory.__closure__
    assert closure is not None
    return closure[0]


async def _invoke_forgot_password(
    controller: type[Controller],
    *,
    email: str,
    user_manager: object,
) -> int:
    """Call the forgot-password endpoint of a generated controller.

    Returns:
        Response status code.
    """
    app = litestar_app_with_user_manager(user_manager, controller)
    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/forgot-password", json={"email": email})
    return response.status_code


async def _invoke_reset_password(
    controller: type[Controller],
    *,
    token: str,
    password: str,
    user_manager: object,
) -> tuple[int, dict[str, Any]]:
    """Call the reset-password endpoint of a generated controller.

    Returns:
        Tuple of HTTP status code and parsed JSON payload.
    """
    app = litestar_app_with_user_manager(user_manager, controller)
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/reset-password",
            json={"token": token, "password": password},
        )
    return response.status_code, cast("dict[str, Any]", response.json())


async def test_reset_password_maps_invalid_reset_token_error_to_client_exception() -> None:
    """Invalid reset token errors are converted into a 400 response with the correct error code."""
    manager = DummyUserManager(error=InvalidResetPasswordTokenError("bad token"))
    controller = create_reset_password_controller()

    status_code, payload = await _invoke_reset_password(
        controller,
        token="invalid-token",
        password="new-password",
        user_manager=manager,
    )

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload.get("extra", {}).get("code") == ErrorCode.RESET_PASSWORD_BAD_TOKEN


async def test_reset_password_maps_invalid_password_error_to_client_exception() -> None:
    """Invalid password errors are converted into a 400 response with the correct error code."""
    manager = DummyUserManager(error=InvalidPasswordError("too weak"))
    controller = create_reset_password_controller()

    status_code, payload = await _invoke_reset_password(
        controller,
        token="valid-token",
        password="weak",
        user_manager=manager,
    )

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload.get("extra", {}).get("code") == ErrorCode.RESET_PASSWORD_INVALID_PASSWORD


async def test_forgot_password_success_increments_rate_limit_and_forwards_email() -> None:
    """Forgot-password increments the limiter only after the manager call succeeds."""
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    manager = DummyUserManager()
    controller = create_reset_password_controller(
        rate_limit_config=AuthRateLimitConfig(
            forgot_password=EndpointRateLimit(
                backend=backend,
                scope="ip_email",
                namespace="forgot-password",
            ),
        ),
    )

    status_code = await _invoke_forgot_password(
        controller,
        email="user@example.com",
        user_manager=manager,
    )

    assert status_code == HTTP_202_ACCEPTED
    assert manager.last_forgot_password_email == "user@example.com"
    backend.increment.assert_awaited_once()
    backend.reset.assert_not_awaited()


async def test_forgot_password_rate_limit_before_request_is_a_noop_when_rate_limit_cell_is_none() -> None:
    """The forgot-password before_request hook exits cleanly when no limiter is configured."""
    rate_limiter_backend = MagicMock()
    rate_limiter_backend.check = AsyncMock(return_value=True)
    rate_limiter_backend.increment = AsyncMock()
    rate_limiter_backend.reset = AsyncMock()
    controller = create_reset_password_controller(
        rate_limit_config=AuthRateLimitConfig(
            forgot_password=EndpointRateLimit(
                backend=rate_limiter_backend,
                scope="ip",
                namespace="forgot-password",
            ),
        ),
    )
    before_request = cast("Any", controller).forgot_password.before_request
    no_limit_before_request = FunctionType(
        before_request.__code__,
        before_request.__globals__,
        name=before_request.__name__,
        closure=(_make_closure_cell(None),),
    )

    await no_limit_before_request(MagicMock())

    rate_limiter_backend.check.assert_not_awaited()


async def test_reset_password_rate_limit_before_request_is_a_noop_when_rate_limit_cell_is_none() -> None:
    """The reset-password before_request hook exits cleanly when no limiter is configured."""
    rate_limiter_backend = MagicMock()
    rate_limiter_backend.check = AsyncMock(return_value=True)
    rate_limiter_backend.increment = AsyncMock()
    rate_limiter_backend.reset = AsyncMock()
    controller = create_reset_password_controller(
        rate_limit_config=AuthRateLimitConfig(
            reset_password=EndpointRateLimit(
                backend=rate_limiter_backend,
                scope="ip",
                namespace="reset-password",
            ),
        ),
    )
    before_request = cast("Any", controller).reset_password.before_request
    no_limit_before_request = FunctionType(
        before_request.__code__,
        before_request.__globals__,
        name=before_request.__name__,
        closure=(_make_closure_cell(None),),
    )

    await no_limit_before_request(MagicMock())

    rate_limiter_backend.check.assert_not_awaited()


async def test_reset_password_invalid_token_increments_rate_limit() -> None:
    """Invalid reset tokens increment the reset-password limiter."""
    manager = DummyUserManager(error=InvalidResetPasswordTokenError("bad token"))
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    controller = create_reset_password_controller(
        rate_limit_config=AuthRateLimitConfig(
            reset_password=EndpointRateLimit(
                backend=backend,
                scope="ip",
                namespace="reset-password",
            ),
        ),
    )

    status_code, payload = await _invoke_reset_password(
        controller,
        token="invalid-token",
        password="new-password",
        user_manager=manager,
    )

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload.get("extra", {}).get("code") == ErrorCode.RESET_PASSWORD_BAD_TOKEN
    backend.increment.assert_awaited_once()
    backend.reset.assert_not_awaited()


async def test_reset_password_success_resets_rate_limit() -> None:
    """Successful password resets clear tracked reset-password failures."""
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    manager = DummyUserManager()
    controller = create_reset_password_controller(
        rate_limit_config=AuthRateLimitConfig(
            reset_password=EndpointRateLimit(
                backend=backend,
                scope="ip",
                namespace="reset-password",
            ),
        ),
    )

    status_code, payload = await _invoke_reset_password(
        controller,
        token="valid-token",
        password="new-password",
        user_manager=manager,
    )

    assert status_code == HTTP_200_OK
    assert payload["email"] == "user@example.com"
    assert payload["roles"] == ["member"]
    backend.increment.assert_not_awaited()
    backend.reset.assert_awaited_once()
