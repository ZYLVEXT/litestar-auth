"""Unit tests for small verify-controller helper branches."""

from __future__ import annotations

from types import CellType, FunctionType
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock

import msgspec
import pytest
from litestar.status_codes import HTTP_200_OK, HTTP_400_BAD_REQUEST
from litestar.testing import AsyncTestClient

from litestar_auth.controllers.verify import create_verify_controller
from litestar_auth.exceptions import ErrorCode, InvalidVerifyTokenError
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit
from tests._helpers import litestar_app_with_user_manager

if TYPE_CHECKING:
    from uuid import UUID

    from litestar import Controller
else:
    from uuid import uuid4

pytestmark = pytest.mark.unit


class DummyUser(msgspec.Struct):
    """Minimal user struct compatible with the verify controller."""

    id: UUID
    email: str
    is_active: bool = True
    is_verified: bool = False
    roles: list[str] = msgspec.field(default_factory=lambda: ["member"])


class DummyUserManager:
    """User manager stub satisfying the verify-controller protocol."""

    def __init__(self, error: Exception | None = None) -> None:
        """Initialize the stub with an optional error to raise on verify."""
        self.error = error

    async def verify(self, token: str) -> DummyUser:
        """Return a verified user or raise the configured error."""
        del token
        if self.error is not None:
            raise self.error
        return DummyUser(id=uuid4(), email="verified@example.com", is_verified=True)

    async def request_verify_token(self, email: str) -> None:
        """Accept a verify-token request without side effects."""
        del email


def _make_closure_cell(value: object) -> CellType:
    """Return a closure cell containing ``value`` for function reconstruction."""

    def _cell_factory() -> object:
        return value

    closure = _cell_factory.__closure__
    assert closure is not None
    return closure[0]


async def _invoke_verify(
    controller: type[Controller],
    *,
    token: str,
    user_manager: object,
) -> tuple[int, dict[str, Any]]:
    """Call the verify endpoint of a generated controller.

    Returns:
        Tuple of HTTP status code and parsed JSON payload.
    """
    app = litestar_app_with_user_manager(user_manager, controller)
    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/verify", json={"token": token})
    return response.status_code, cast("dict[str, Any]", response.json())


async def test_request_verify_rate_limit_before_request_is_a_noop_when_rate_limit_cell_is_none() -> None:
    """The request-verify before_request hook exits cleanly when no limiter is configured."""
    rate_limiter_backend = MagicMock()
    rate_limiter_backend.check = AsyncMock(return_value=True)
    rate_limiter_backend.increment = AsyncMock()
    rate_limiter_backend.reset = AsyncMock()
    controller = create_verify_controller(
        rate_limit_config=AuthRateLimitConfig(
            request_verify_token=EndpointRateLimit(
                backend=rate_limiter_backend,
                scope="ip",
                namespace="verify-request",
            ),
        ),
    )
    before_request = cast("Any", controller).request_verify_token.before_request
    no_limit_before_request = FunctionType(
        before_request.__code__,
        before_request.__globals__,
        name=before_request.__name__,
        closure=(_make_closure_cell(None),),
    )

    await no_limit_before_request(MagicMock())

    rate_limiter_backend.check.assert_not_awaited()


async def test_verify_rate_limit_before_request_is_a_noop_when_rate_limit_cell_is_none() -> None:
    """The verify before_request hook exits cleanly when no limiter is configured."""
    rate_limiter_backend = MagicMock()
    rate_limiter_backend.check = AsyncMock(return_value=True)
    rate_limiter_backend.increment = AsyncMock()
    rate_limiter_backend.reset = AsyncMock()
    controller = create_verify_controller(
        rate_limit_config=AuthRateLimitConfig(
            verify_token=EndpointRateLimit(
                backend=rate_limiter_backend,
                scope="ip",
                namespace="verify-token",
            ),
        ),
    )
    before_request = cast("Any", controller).verify.before_request
    no_limit_before_request = FunctionType(
        before_request.__code__,
        before_request.__globals__,
        name=before_request.__name__,
        closure=(_make_closure_cell(None),),
    )

    await no_limit_before_request(MagicMock())

    rate_limiter_backend.check.assert_not_awaited()


async def test_verify_invalid_token_increments_rate_limit() -> None:
    """Invalid verify tokens increment the verify-token limiter."""
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    manager = DummyUserManager(error=InvalidVerifyTokenError("bad token"))
    controller = create_verify_controller(
        rate_limit_config=AuthRateLimitConfig(
            verify_token=EndpointRateLimit(
                backend=backend,
                scope="ip",
                namespace="verify-token",
            ),
        ),
    )

    status_code, payload = await _invoke_verify(controller, token="invalid-token", user_manager=manager)

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload.get("extra", {}).get("code") == ErrorCode.VERIFY_USER_BAD_TOKEN
    backend.increment.assert_awaited_once()
    backend.reset.assert_not_awaited()


async def test_verify_success_resets_rate_limit() -> None:
    """Successful verification clears tracked verify-token failures."""
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    manager = DummyUserManager()
    controller = create_verify_controller(
        rate_limit_config=AuthRateLimitConfig(
            verify_token=EndpointRateLimit(
                backend=backend,
                scope="ip",
                namespace="verify-token",
            ),
        ),
    )

    status_code, payload = await _invoke_verify(controller, token="valid-token", user_manager=manager)

    assert status_code == HTTP_200_OK
    assert payload["email"] == "verified@example.com"
    assert payload["roles"] == ["member"]
    backend.increment.assert_not_awaited()
    backend.reset.assert_awaited_once()
