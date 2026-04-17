"""Focused tests for auth rate-limit preset factories."""

from __future__ import annotations

from dataclasses import fields

import pytest

from litestar_auth.ratelimit import AuthRateLimitConfig, AuthRateLimitSlot, EndpointRateLimit, InMemoryRateLimiter

pytestmark = pytest.mark.unit

STRICT_MAX_ATTEMPTS = 3
LENIENT_MAX_ATTEMPTS = 12
LENIENT_STRICT_CAP = 5
WINDOW_SECONDS = 300
STRICT_SLOTS = ("login", "register", "totp_verify")
LENIENT_SHARED_SLOTS = ("login", "refresh", "register")
LENIENT_STRICT_SLOTS = (
    "forgot_password",
    "reset_password",
    "totp_enable",
    "totp_confirm_enable",
    "totp_verify",
    "totp_disable",
    "verify_token",
    "request_verify_token",
)


def test_auth_rate_limit_presets_instantiate_with_minimal_supported_arguments() -> None:
    """Each preset factory can be called with only its documented required inputs."""
    strict_backend = InMemoryRateLimiter(max_attempts=STRICT_MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS)
    lenient_backend = InMemoryRateLimiter(max_attempts=LENIENT_MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS)

    assert isinstance(AuthRateLimitConfig.strict(backend=strict_backend), AuthRateLimitConfig)
    assert isinstance(AuthRateLimitConfig.lenient(backend=lenient_backend), AuthRateLimitConfig)
    assert isinstance(AuthRateLimitConfig.disabled(), AuthRateLimitConfig)


def test_auth_rate_limit_preset_strict_routes_keep_lower_login_and_register_budgets() -> None:
    """The strict preset wires the supplied lower-budget backend to the public sign-in routes."""
    strict_backend = InMemoryRateLimiter(max_attempts=STRICT_MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS)
    config = AuthRateLimitConfig.strict(backend=strict_backend)

    assert config.login == EndpointRateLimit(backend=strict_backend, scope="ip_email", namespace="login")
    assert config.register == EndpointRateLimit(backend=strict_backend, scope="ip", namespace="register")
    assert config.totp_verify == EndpointRateLimit(backend=strict_backend, scope="ip", namespace="totp-verify")
    assert config.login is not None
    assert config.register is not None
    assert isinstance(config.login.backend, InMemoryRateLimiter)
    assert isinstance(config.register.backend, InMemoryRateLimiter)
    assert config.login.backend.max_attempts == STRICT_MAX_ATTEMPTS
    assert config.register.backend.max_attempts == STRICT_MAX_ATTEMPTS

    for field in fields(AuthRateLimitConfig):
        if field.name not in STRICT_SLOTS:
            assert getattr(config, field.name) is None


def test_auth_rate_limit_preset_lenient_routes_keep_higher_login_and_register_budgets() -> None:
    """The lenient preset preserves the higher shared budget on login-family routes."""
    strict_backend = InMemoryRateLimiter(max_attempts=STRICT_MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS)
    lenient_backend = InMemoryRateLimiter(max_attempts=LENIENT_MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS)

    strict_config = AuthRateLimitConfig.strict(backend=strict_backend)
    lenient_config = AuthRateLimitConfig.lenient(backend=lenient_backend)

    for slot_name in LENIENT_SHARED_SLOTS:
        limiter = getattr(lenient_config, slot_name)

        assert limiter == EndpointRateLimit(
            backend=lenient_backend,
            scope="ip_email" if slot_name == "login" else "ip",
            namespace=slot_name,
        )
        assert limiter.backend.max_attempts == LENIENT_MAX_ATTEMPTS

    assert strict_config.login is not None
    assert strict_config.register is not None
    assert lenient_config.login is not None
    assert lenient_config.register is not None
    assert isinstance(strict_config.login.backend, InMemoryRateLimiter)
    assert isinstance(lenient_config.login.backend, InMemoryRateLimiter)
    assert isinstance(strict_config.register.backend, InMemoryRateLimiter)
    assert isinstance(lenient_config.register.backend, InMemoryRateLimiter)
    assert strict_config.login.backend.max_attempts < lenient_config.login.backend.max_attempts
    assert strict_config.register.backend.max_attempts < lenient_config.register.backend.max_attempts

    for slot_name in LENIENT_STRICT_SLOTS:
        limiter = getattr(lenient_config, slot_name)

        assert limiter is not None
        assert limiter.backend is not lenient_backend
        assert limiter.backend.max_attempts == LENIENT_STRICT_CAP


def test_auth_rate_limit_preset_disabled_leaves_every_slot_unset() -> None:
    """The disabled preset returns an all-None auth rate-limit config."""
    config = AuthRateLimitConfig.disabled()

    assert all(getattr(config, field.name) is None for field in fields(AuthRateLimitConfig))


def test_auth_rate_limit_from_shared_backend_uses_endpoint_overrides_for_customized_slots() -> None:
    """Canonical endpoint overrides replace the removed namespace and scope builder shims."""
    shared_backend = InMemoryRateLimiter(max_attempts=STRICT_MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS)
    forgot_password_override = EndpointRateLimit(
        backend=shared_backend,
        scope="ip",
        namespace="forgot_password",
    )
    request_verify_override = EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="verify-request",
    )
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        enabled=("forgot_password", "request_verify_token"),
        endpoint_overrides={
            AuthRateLimitSlot.FORGOT_PASSWORD: forgot_password_override,
            AuthRateLimitSlot.REQUEST_VERIFY_TOKEN: request_verify_override,
        },
    )

    assert config.forgot_password is forgot_password_override
    assert config.request_verify_token is request_verify_override


def test_auth_rate_limit_from_shared_backend_keeps_canonical_route_namespaces() -> None:
    """The shared-backend builder keeps the package-owned route-style namespace defaults."""
    shared_backend = InMemoryRateLimiter(max_attempts=STRICT_MAX_ATTEMPTS, window_seconds=WINDOW_SECONDS)
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        enabled=("forgot_password", "request_verify_token"),
    )

    assert config.forgot_password == EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="forgot-password",
    )
    assert config.request_verify_token == EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="request-verify-token",
    )
