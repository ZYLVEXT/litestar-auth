"""Unit tests for TOTP controller configuration hardening."""

from __future__ import annotations

import inspect
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from litestar import Litestar
from litestar.openapi.config import OpenAPIConfig

from litestar_auth._plugin.config import TotpConfig
from litestar_auth.controllers.totp import (
    TOTP_RATE_LIMITED_ENDPOINTS,
    TOTP_SENSITIVE_ENDPOINTS,
    _totp_validate_replay_and_password,
    create_totp_controller,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.plugin import LitestarAuthConfig

pytestmark = pytest.mark.unit


@pytest.mark.unit
def test_create_totp_controller_requires_replay_store_by_default() -> None:
    """TOTP controller requires a replay store by default outside explicit unsafe testing."""
    backend = AsyncMock()
    with pytest.raises(ConfigurationError, match=r"used_tokens_store is required"):
        create_totp_controller(
            backend=backend,
            user_manager_dependency_key="litestar_auth_user_manager",
            used_tokens_store=None,
            totp_pending_secret="test-totp-pending-secret-thirty-two!",
        )


@pytest.mark.unit
def test_create_totp_controller_step_up_requires_authenticate() -> None:
    """Step-up enrollment requires user_manager.authenticate."""

    class _NoAuthManager:  # pragma: no cover - shape-only for validation
        async def get(self, _user_id: object) -> object: ...

        async def on_after_login(self, _user: object) -> None: ...

        async def set_totp_secret(self, _user: object, _secret: str | None) -> object: ...

        async def read_totp_secret(self, _secret: str | None) -> str | None: ...

    with pytest.raises(ConfigurationError, match=r"totp_enable_requires_password=True"):
        _totp_validate_replay_and_password(
            used_tokens_store=AsyncMock(),
            require_replay_protection=False,
            totp_enable_requires_password=True,
            user_manager=_NoAuthManager(),
            unsafe_testing=True,
        )


@pytest.mark.unit
def test_create_totp_controller_requires_pending_jti_store_outside_testing() -> None:
    """Production mode requires an explicit pending-token replay store."""
    backend = AsyncMock()

    with pytest.raises(ConfigurationError, match="pending_jti_store is required"):
        create_totp_controller(
            backend=backend,
            user_manager_dependency_key="litestar_auth_user_manager",
            used_tokens_store=AsyncMock(),
            pending_jti_store=None,
            totp_pending_secret="test-totp-pending-secret-thirty-two!",
            require_replay_protection=False,
        )


@pytest.mark.unit
def test_create_totp_controller_allows_missing_pending_jti_store_in_testing() -> None:
    """Testing mode preserves the no-store behavior explicitly."""
    backend = AsyncMock()

    controller = create_totp_controller(
        backend=backend,
        user_manager_dependency_key="litestar_auth_user_manager",
        used_tokens_store=AsyncMock(),
        pending_jti_store=None,
        totp_pending_secret="test-totp-pending-secret-thirty-two!",
        require_replay_protection=False,
        unsafe_testing=True,
    )

    assert controller is not None


@pytest.mark.unit
def test_totp_controller_endpoint_contract_is_explicit() -> None:
    """Controller-level endpoint coverage and verify-only limiter scope stay explicit."""
    assert TOTP_SENSITIVE_ENDPOINTS == ("enable", "confirm_enable", "verify", "disable")
    assert TOTP_RATE_LIMITED_ENDPOINTS == ("verify", "confirm_enable")


@pytest.mark.unit
def test_totp_defaults_use_sha256() -> None:
    """Plugin and controller defaults use SHA256 for new enrollments."""
    assert TotpConfig.__dataclass_fields__["totp_algorithm"].default == "SHA256"
    assert LitestarAuthConfig.__dataclass_fields__["totp_config"].default is None
    signature = inspect.signature(create_totp_controller)
    assert signature.parameters["totp_algorithm"].default == "SHA256"


@pytest.mark.unit
def test_create_totp_controller_applies_openapi_security_to_guarded_routes() -> None:
    """Manual TOTP controllers expose security metadata on authenticated routes."""
    controller = create_totp_controller(
        backend=AsyncMock(),
        user_manager_dependency_key="litestar_auth_user_manager",
        used_tokens_store=AsyncMock(),
        pending_jti_store=AsyncMock(),
        totp_pending_secret="test-totp-pending-secret-thirty-two!",
        require_replay_protection=False,
        unsafe_testing=True,
        security=[{"BearerToken": []}],
    )
    app = Litestar(
        route_handlers=[controller],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )
    paths = cast("Any", app.openapi_schema.paths)

    assert paths["/auth/2fa/enable"].post.security == [{"BearerToken": []}]
    assert paths["/auth/2fa/enable/confirm"].post.security == [{"BearerToken": []}]
    assert paths["/auth/2fa/disable"].post.security == [{"BearerToken": []}]
    assert paths["/auth/2fa/verify"].post.security is None
