"""Reload-based coverage tests for re-export ``__init__`` modules."""

from __future__ import annotations

from typing import TYPE_CHECKING, get_args

import pytest

import litestar_auth as litestar_auth_module
import litestar_auth._plugin.totp_controller as totp_controller_module
import litestar_auth.controllers as controllers_module
import litestar_auth.models as models_module
import litestar_auth.payloads as payloads_module
import litestar_auth.ratelimit as ratelimit_module
import litestar_auth.ratelimit._endpoint as ratelimit_endpoint_module
import litestar_auth.ratelimit._slot_catalog as ratelimit_slot_catalog_module

AuthRateLimitEndpointGroup = ratelimit_module.AuthRateLimitEndpointGroup
AuthRateLimitSlot = ratelimit_module.AuthRateLimitSlot

pytestmark = [pytest.mark.unit, pytest.mark.imports]

if TYPE_CHECKING:
    import logging
    from collections.abc import Iterable
    from types import ModuleType


class _CapturingLogger:
    """Collect handlers added during reload."""

    def __init__(self) -> None:
        self.handlers: list[logging.Handler] = []

    def addHandler(self, handler: logging.Handler) -> None:
        """Record the attached handler."""
        self.handlers.append(handler)


def _assert_exported_symbols(module: ModuleType, *, expected_names: Iterable[str] | None = None) -> None:
    """Assert that the module exposes the expected public names."""
    export_names = tuple(expected_names or getattr(module, "__all__", ()))

    assert export_names

    for name in export_names:
        assert hasattr(module, name)


def test_session_device_payloads_stay_on_explicit_payloads_surface() -> None:
    """Session/device DTOs are public via payloads without widening package root exports."""
    assert set(payloads_module.__all__) >= {
        "RefreshSessionRead",
        "RefreshSessionListResponse",
    }
    assert hasattr(payloads_module, "RefreshSessionRead")
    assert hasattr(payloads_module, "RefreshSessionListResponse")
    assert not hasattr(litestar_auth_module, "RefreshSessionRead")
    assert not hasattr(litestar_auth_module, "RefreshSessionListResponse")
    assert not hasattr(controllers_module, "RefreshSessionRead")
    assert not hasattr(controllers_module, "RefreshSessionListResponse")


def test_lazy_public_modules_report_their_export_inventory() -> None:
    """Lazy re-export modules expose stable names to interactive discovery."""
    assert set(controllers_module.__all__) <= set(dir(controllers_module))
    assert set(models_module.__all__) <= set(dir(models_module))
    assert set(totp_controller_module.__all__) <= set(dir(totp_controller_module))


def test_ratelimit_reexport_module_keeps_private_helpers_internal() -> None:
    """The public ratelimit module keeps helper internals off the package surface."""
    _assert_exported_symbols(
        ratelimit_module,
        expected_names=(
            "AuthRateLimitConfig",
            "AuthRateLimitEndpointGroup",
            "AuthRateLimitSlot",
            "EndpointRateLimit",
            "InMemoryRateLimiter",
            "RateLimitScope",
            "RedisRateLimiter",
            "TotpRateLimitOrchestrator",
            "TotpSensitiveEndpoint",
        ),
    )
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES")
    assert hasattr(ratelimit_slot_catalog_module, "_build_auth_rate_limit_endpoint_catalog")
    assert ratelimit_endpoint_module.EndpointRateLimit is ratelimit_module.EndpointRateLimit
    assert ratelimit_endpoint_module.RateLimitScope is ratelimit_module.RateLimitScope
    assert get_args(ratelimit_module.AuthRateLimitEndpointGroup.__value__) == get_args(
        AuthRateLimitEndpointGroup.__value__,
    )
    assert tuple(ratelimit_module.AuthRateLimitSlot) == tuple(AuthRateLimitSlot)
    assert not hasattr(ratelimit_module, "AuthRateLimitEndpointSlot")
    assert not hasattr(ratelimit_module, "_DEFAULT_TRUSTED_HEADERS")
    assert not hasattr(ratelimit_module, "_extract_email")
    assert not hasattr(ratelimit_module, "_load_redis_asyncio")
    assert not hasattr(ratelimit_module, "_safe_key_part")
    assert not hasattr(ratelimit_module, "_validate_configuration")
    assert not hasattr(ratelimit_module, "importlib")
    assert not hasattr(ratelimit_module, "logger")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES")
    assert not hasattr(ratelimit_module, "_build_auth_rate_limit_endpoint_catalog")
