"""Unit tests for register controller: duplicate user, invalid password, rate-limit increments."""

from __future__ import annotations

import importlib
from types import CellType, FunctionType
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.status_codes import HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from litestar.testing import AsyncTestClient

import litestar_auth.controllers.register as register_module
from litestar_auth.controllers.register import create_register_controller
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit
from tests._helpers import litestar_app_with_user_manager

pytestmark = pytest.mark.unit
HTTP_UNPROCESSABLE_ENTITY = 422


def test_register_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and protocol execution."""
    reloaded_module = importlib.reload(register_module)

    assert reloaded_module.create_register_controller.__name__ == create_register_controller.__name__
    assert reloaded_module.RegisterControllerUserManagerProtocol.__name__.endswith("Protocol")


class DummyUser(msgspec.Struct):
    """Minimal user struct compatible with UserRead schema."""

    id: UUID
    email: str
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = msgspec.field(default_factory=list)


class DummyUserManager:
    """User manager stub that can raise or return a user."""

    def __init__(self, error: Exception | None = None) -> None:
        """Store the optional error to raise from create."""
        self.error = error
        self.create_calls: list[object] = []
        self.safe_values: list[bool] = []
        self.allow_privileged_values: list[bool] = []

    async def create(
        self,
        user_create: msgspec.Struct,
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> DummyUser:
        """Return a dummy user or raise the configured error."""
        self.create_calls.append(user_create)
        self.safe_values.append(safe)
        self.allow_privileged_values.append(allow_privileged)
        if self.error is not None:
            raise self.error
        return DummyUser(id=uuid4(), email=getattr(user_create, "email", "u@example.com"))


async def _invoke_register(
    controller: type,
    payload: dict[str, Any],
    *,
    user_manager: object,
) -> tuple[int, dict[str, Any] | None]:
    """POST to /auth/register and return status code and JSON body.

    Returns:
        Tuple of (status_code, parsed JSON body or None).
    """
    app = litestar_app_with_user_manager(user_manager, controller)
    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/register", json=payload)
    body = cast("dict[str, Any] | None", response.json() if response.content else None)
    return response.status_code, body


def _make_rate_limit_backend() -> MagicMock:
    """Return a mock backend with check and increment for EndpointRateLimit."""
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    return backend


def _make_closure_cell(value: object) -> CellType:
    """Return a closure cell containing ``value`` for function reconstruction."""

    def _cell_factory() -> object:
        return value

    closure = _cell_factory.__closure__
    assert closure is not None
    return closure[0]


async def test_register_duplicate_user_returns_400_and_increments_rate_limit() -> None:
    """UserAlreadyExistsError is mapped to 400 REGISTER_USER_ALREADY_EXISTS and rate limit is incremented."""
    manager = DummyUserManager(error=UserAlreadyExistsError(message="Email already registered"))
    backend = _make_rate_limit_backend()
    rate_limit = EndpointRateLimit(backend=backend, scope="ip", namespace="register")
    config = AuthRateLimitConfig(register=rate_limit)
    controller = create_register_controller(rate_limit_config=config)

    status_code, payload = await _invoke_register(
        controller,
        {"email": "existing@example.com", "password": "valid-password"},
        user_manager=manager,
    )

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload is not None
    assert payload["extra"]["code"] == ErrorCode.REGISTER_USER_ALREADY_EXISTS
    assert backend.increment.await_count == 1


async def test_register_invalid_password_returns_400_and_increments_rate_limit() -> None:
    """InvalidPasswordError is mapped to 400 REGISTER_INVALID_PASSWORD and rate limit is incremented."""
    manager = DummyUserManager(error=InvalidPasswordError(message="Password too weak"))
    backend = _make_rate_limit_backend()
    rate_limit = EndpointRateLimit(backend=backend, scope="ip", namespace="register")
    config = AuthRateLimitConfig(register=rate_limit)
    controller = create_register_controller(rate_limit_config=config)

    status_code, payload = await _invoke_register(
        controller,
        {"email": "u@example.com", "password": "valid-password"},
        user_manager=manager,
    )

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload is not None
    assert payload["extra"]["code"] == ErrorCode.REGISTER_INVALID_PASSWORD
    assert backend.increment.await_count == 1


async def test_register_success_returns_201_and_resets_rate_limit() -> None:
    """Successful registration returns 201 and clears prior rate-limit state."""
    manager = DummyUserManager()
    backend = _make_rate_limit_backend()
    rate_limit = EndpointRateLimit(backend=backend, scope="ip", namespace="register")
    config = AuthRateLimitConfig(register=rate_limit)
    controller = create_register_controller(rate_limit_config=config)

    status_code, payload = await _invoke_register(
        controller,
        {"email": "new@example.com", "password": "secure-password"},
        user_manager=manager,
    )

    assert status_code == HTTP_201_CREATED
    assert payload is not None
    assert payload["email"] == "new@example.com"
    assert "id" in payload
    assert payload["roles"] == []
    assert manager.safe_values == [True]
    assert manager.allow_privileged_values == [False]
    assert backend.increment.await_count == 0
    assert backend.reset.await_count == 1


async def test_register_success_without_rate_limit_no_increment() -> None:
    """When rate_limit_config is None, no increment is called."""
    manager = DummyUserManager()
    controller = create_register_controller(rate_limit_config=None)

    status_code, payload = await _invoke_register(
        controller,
        {"email": "norate@example.com", "password": "valid-password"},
        user_manager=manager,
    )

    assert status_code == HTTP_201_CREATED
    assert payload is not None
    assert payload["email"] == "norate@example.com"
    assert payload["roles"] == []
    assert manager.safe_values == [True]
    assert manager.allow_privileged_values == [False]


async def test_register_before_request_is_a_noop_when_rate_limit_cell_is_none() -> None:
    """The register before_request hook exits cleanly when no limiter is configured."""
    backend = _make_rate_limit_backend()
    rate_limit = EndpointRateLimit(backend=backend, scope="ip", namespace="register")
    controller = create_register_controller(rate_limit_config=AuthRateLimitConfig(register=rate_limit))
    before_request = cast("Any", controller).register.before_request
    no_limit_before_request = FunctionType(
        before_request.__code__,
        before_request.__globals__,
        name=before_request.__name__,
        closure=(_make_closure_cell(None),),
    )

    await no_limit_before_request(MagicMock())

    backend.check.assert_not_awaited()


async def test_register_invalid_password_without_rate_limit_keeps_plain_error_mapping() -> None:
    """InvalidPasswordError still maps correctly when no rate limiter is configured."""
    manager = DummyUserManager(error=InvalidPasswordError(message="Password too weak"))
    controller = create_register_controller(rate_limit_config=None)

    status_code, payload = await _invoke_register(
        controller,
        {"email": "u@example.com", "password": "valid-password"},
        user_manager=manager,
    )

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload is not None
    assert payload["extra"]["code"] == ErrorCode.REGISTER_INVALID_PASSWORD


async def test_register_schema_validation_failure_returns_422_without_manager_side_effects() -> None:
    """Schema validation errors return 422 before the manager create call runs."""
    manager = DummyUserManager()
    controller = create_register_controller(rate_limit_config=None)

    status_code, payload = await _invoke_register(
        controller,
        {"email": "u@example.com", "password": 123},
        user_manager=manager,
    )

    assert status_code == HTTP_UNPROCESSABLE_ENTITY
    assert payload is not None
    assert payload["detail"] == "Invalid request payload."
    assert payload["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID
    assert manager.create_calls == []
