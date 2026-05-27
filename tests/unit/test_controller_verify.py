"""Unit tests for small verify-controller helper branches."""

from __future__ import annotations

import time
from types import CellType, FunctionType
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock

import msgspec
import pytest
from litestar.status_codes import HTTP_200_OK, HTTP_202_ACCEPTED, HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR
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
MINIMUM_RESPONSE_SECONDS = 0.01
TIMING_TOLERANCE_SECONDS = 0.003


class DummyUser(msgspec.Struct):
    """Minimal user struct compatible with the verify controller."""

    id: UUID
    email: str
    is_active: bool = True
    is_verified: bool = False
    roles: list[str] = msgspec.field(default_factory=lambda: ["member"])


class DummyUserManager:
    """User manager stub satisfying the verify-controller protocol."""

    def __init__(
        self,
        error: Exception | None = None,
        *,
        request_verify_error: Exception | None = None,
    ) -> None:
        """Initialize the stub with optional errors to raise on verify or request_verify_token."""
        self.error = error
        self.request_verify_error = request_verify_error
        self.last_request_verify_email: str | None = None

    async def verify(self, token: str) -> DummyUser:
        """Return a verified user or raise the configured error."""
        if self.error is not None:
            raise self.error
        return DummyUser(id=uuid4(), email="verified@example.com", is_verified=True)

    async def request_verify_token(self, email: str) -> None:
        """Accept a verify-token request, or raise the configured error."""
        self.last_request_verify_email = email
        if self.request_verify_error is not None:
            raise self.request_verify_error


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


async def _timed_invoke_verify(
    controller: type[Controller],
    *,
    token: str,
    user_manager: object,
) -> tuple[int, dict[str, Any], float]:
    """Call the verify endpoint and return the elapsed wall-clock duration.

    Returns:
        Tuple of HTTP status code, parsed JSON payload, and elapsed seconds.
    """
    app = litestar_app_with_user_manager(user_manager, controller)
    async with AsyncTestClient(app=app) as client:
        started_at = time.perf_counter()
        response = await client.post("/auth/verify", json={"token": token})
        elapsed = time.perf_counter() - started_at
    return response.status_code, cast("dict[str, Any]", response.json()), elapsed


async def _invoke_request_verify_token(
    controller: type[Controller],
    *,
    email: str,
    user_manager: object,
) -> int:
    """Call the request-verify-token endpoint of a generated controller.

    Returns:
        Response status code.
    """
    app = litestar_app_with_user_manager(user_manager, controller)
    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/request-verify-token", json={"email": email})
    return response.status_code


async def _timed_invoke_request_verify_token(
    controller: type[Controller],
    *,
    email: str,
    user_manager: object,
) -> tuple[int, float]:
    """Call the request-verify-token endpoint and return the elapsed wall-clock duration.

    Returns:
        Tuple of HTTP status code and elapsed seconds.
    """
    app = litestar_app_with_user_manager(user_manager, controller)
    async with AsyncTestClient(app=app) as client:
        started_at = time.perf_counter()
        response = await client.post("/auth/request-verify-token", json={"email": email})
        elapsed = time.perf_counter() - started_at
    return response.status_code, elapsed


def test_verify_controller_rejects_negative_minimum_response_seconds() -> None:
    """Negative verification timing envelopes fail during controller construction."""
    with pytest.raises(ValueError, match="verify_minimum_response_seconds must be non-negative"):
        create_verify_controller(verify_minimum_response_seconds=-0.001)

    with pytest.raises(ValueError, match="request_verify_minimum_response_seconds must be non-negative"):
        create_verify_controller(request_verify_minimum_response_seconds=-0.001)


async def test_request_verify_token_increments_rate_limit_even_when_manager_raises() -> None:
    """Rate-limit must increment via `finally` so transient manager failures are still counted."""
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    manager = DummyUserManager(request_verify_error=RuntimeError("transient SMTP failure"))
    controller = create_verify_controller(
        rate_limit_config=AuthRateLimitConfig(
            request_verify_token=EndpointRateLimit(
                backend=backend,
                scope="ip_email",
                namespace="verify-request",
            ),
        ),
    )

    status_code = await _invoke_request_verify_token(
        controller,
        email="user@example.com",
        user_manager=manager,
    )

    # The exact 5xx code does not matter — the contract is that the limiter still
    # incremented despite the failure, closing the abuse window.
    assert status_code >= HTTP_500_INTERNAL_SERVER_ERROR
    assert manager.last_request_verify_email == "user@example.com"
    backend.increment.assert_awaited_once()


async def test_request_verify_token_failure_increments_rate_limit_once_after_minimum_response() -> None:
    """request-verify-token manager failures keep the timing floor and limiter increment contract."""
    backend = MagicMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock()
    backend.reset = AsyncMock()
    manager = DummyUserManager(request_verify_error=RuntimeError("transient SMTP failure"))
    controller = create_verify_controller(
        rate_limit_config=AuthRateLimitConfig(
            request_verify_token=EndpointRateLimit(
                backend=backend,
                scope="ip_email",
                namespace="verify-request",
            ),
        ),
        request_verify_minimum_response_seconds=MINIMUM_RESPONSE_SECONDS,
    )

    status_code, elapsed = await _timed_invoke_request_verify_token(
        controller,
        email="user@example.com",
        user_manager=manager,
    )

    assert status_code >= HTTP_500_INTERNAL_SERVER_ERROR
    assert elapsed >= MINIMUM_RESPONSE_SECONDS - TIMING_TOLERANCE_SECONDS
    backend.increment.assert_awaited_once()


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


async def test_verify_invalid_token_increments_rate_limit_once_after_minimum_response() -> None:
    """Invalid verify-token requests keep the timing floor and limiter increment contract."""
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
        verify_minimum_response_seconds=MINIMUM_RESPONSE_SECONDS,
    )

    status_code, payload, elapsed = await _timed_invoke_verify(
        controller,
        token="invalid-token",
        user_manager=manager,
    )

    assert status_code == HTTP_400_BAD_REQUEST
    assert payload.get("extra", {}).get("code") == ErrorCode.VERIFY_USER_BAD_TOKEN
    assert elapsed >= MINIMUM_RESPONSE_SECONDS - TIMING_TOLERANCE_SECONDS
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


async def test_verify_success_observes_minimum_response_duration() -> None:
    """Successful verify responses meet the configured lower bound."""
    manager = DummyUserManager()
    controller = create_verify_controller(verify_minimum_response_seconds=MINIMUM_RESPONSE_SECONDS)

    status_code, payload, elapsed = await _timed_invoke_verify(
        controller,
        token="valid-token",
        user_manager=manager,
    )

    assert status_code == HTTP_200_OK
    assert payload["email"] == "verified@example.com"
    assert elapsed >= MINIMUM_RESPONSE_SECONDS - TIMING_TOLERANCE_SECONDS


async def test_request_verify_token_success_observes_minimum_response_duration() -> None:
    """Successful request-verify-token responses meet the configured lower bound."""
    manager = DummyUserManager()
    controller = create_verify_controller(request_verify_minimum_response_seconds=MINIMUM_RESPONSE_SECONDS)

    status_code, elapsed = await _timed_invoke_request_verify_token(
        controller,
        email="user@example.com",
        user_manager=manager,
    )

    assert status_code == HTTP_202_ACCEPTED
    assert elapsed >= MINIMUM_RESPONSE_SECONDS - TIMING_TOLERANCE_SECONDS
