"""Unit tests for shared configuration helpers."""

from __future__ import annotations

import importlib
import re
import warnings

import pytest

import litestar_auth.authentication.strategy.jwt as jwt_strategy_module
import litestar_auth.config as config_module
import litestar_auth.controllers.totp as totp_controller_module
import litestar_auth.manager as manager_module
import litestar_auth.totp_flow as totp_flow_module
from litestar_auth.config import (
    JWT_ACCESS_TOKEN_AUDIENCE,
    MINIMUM_SECRET_LENGTH,
    RESET_PASSWORD_TOKEN_AUDIENCE,
    TOTP_ENROLL_AUDIENCE,
    TOTP_PENDING_AUDIENCE,
    VERIFY_TOKEN_AUDIENCE,
    _resolve_token_secret,
    plugin_owns_secret_role_reuse_warning,
    plugin_secret_role_warning_matches_manager_surface,
    plugin_secret_role_warning_owner,
    resolve_trusted_proxy_setting,
    validate_secret_length,
    validate_testing_mode_for_startup,
)
from litestar_auth.exceptions import ConfigurationError

pytestmark = pytest.mark.unit
GENERATED_SECRET_HEX_LENGTH = 64


def test_config_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(config_module)

    assert reloaded_module.MINIMUM_SECRET_LENGTH == MINIMUM_SECRET_LENGTH
    assert reloaded_module.validate_testing_mode_for_startup is config_module.validate_testing_mode_for_startup


def test_config_defines_canonical_token_audiences() -> None:
    """Shared token audiences are defined once in the config module."""
    assert VERIFY_TOKEN_AUDIENCE == "litestar-auth:verify"
    assert RESET_PASSWORD_TOKEN_AUDIENCE == "litestar-auth:reset-password"
    assert JWT_ACCESS_TOKEN_AUDIENCE == "litestar-auth:access"
    assert TOTP_PENDING_AUDIENCE == "litestar-auth:2fa-pending"
    assert TOTP_ENROLL_AUDIENCE == "litestar-auth:2fa-enroll"


@pytest.mark.parametrize(
    ("module", "attribute", "expected"),
    [
        pytest.param(manager_module, "VERIFY_TOKEN_AUDIENCE", VERIFY_TOKEN_AUDIENCE, id="manager-verify"),
        pytest.param(
            manager_module,
            "RESET_PASSWORD_TOKEN_AUDIENCE",
            RESET_PASSWORD_TOKEN_AUDIENCE,
            id="manager-reset-password",
        ),
        pytest.param(
            jwt_strategy_module,
            "JWT_ACCESS_TOKEN_AUDIENCE",
            JWT_ACCESS_TOKEN_AUDIENCE,
            id="jwt-access",
        ),
        pytest.param(totp_flow_module, "TOTP_PENDING_AUDIENCE", TOTP_PENDING_AUDIENCE, id="totp-pending"),
        pytest.param(
            totp_controller_module,
            "TOTP_ENROLL_AUDIENCE",
            TOTP_ENROLL_AUDIENCE,
            id="totp-enroll",
        ),
    ],
)
def test_existing_modules_export_canonical_token_audiences(
    module: object,
    attribute: str,
    expected: str,
) -> None:
    """Compatibility import paths stay aligned with the canonical config constants."""
    assert getattr(module, attribute) == getattr(config_module, attribute) == expected


def test_resolve_token_secret_generates_testing_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode allows an ephemeral secret when none is configured."""
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        secret = _resolve_token_secret(None, label="JWT secret", warning_stacklevel=1)

    assert len(secret) == GENERATED_SECRET_HEX_LENGTH
    assert re.fullmatch(rf"[0-9a-f]{{{GENERATED_SECRET_HEX_LENGTH}}}", secret) is not None
    assert len(records) == 1
    assert "JWT secret not provided" in str(records[0].message)


def test_resolve_token_secret_raises_without_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production mode requires explicit token secrets."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)

    with pytest.raises(ConfigurationError, match="JWT secret not provided"):
        _resolve_token_secret(None, label="JWT secret")


def test_resolve_token_secret_validates_short_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production mode rejects secrets shorter than the configured minimum."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)

    with pytest.raises(
        ConfigurationError,
        match=rf"JWT secret must be at least {MINIMUM_SECRET_LENGTH} characters\.",
    ):
        _resolve_token_secret("short-secret", label="JWT secret")


def test_validate_secret_length_raises_for_short_secret() -> None:
    """Shared secret validation reports the configured minimum length."""
    with pytest.raises(ConfigurationError, match="token secret must be at least 10 characters\\."):
        validate_secret_length("short", label="token secret", minimum_length=10)


def test_validate_secret_length_accepts_secret_at_minimum_length() -> None:
    """Secrets meeting the minimum length pass validation."""
    validate_secret_length("a" * 10, label="token secret", minimum_length=10)


def test_validate_testing_mode_for_startup_raises_outside_pytest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode is rejected when startup is not running under pytest."""
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    with pytest.raises(ConfigurationError, match="automated tests only"):
        validate_testing_mode_for_startup()


def test_validate_testing_mode_for_startup_returns_inside_pytest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode remains valid when the runtime is pytest."""
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/unit/test_config.py::test_case")

    validate_testing_mode_for_startup()


def test_resolve_token_secret_returns_explicit_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configured production secrets are returned unchanged."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)
    secret = "s" * MINIMUM_SECRET_LENGTH

    assert _resolve_token_secret(secret, label="JWT secret") == secret


def test_plugin_secret_role_warning_matcher_returns_false_without_active_owner() -> None:
    """The secret-role baseline matcher is false when no plugin-owned warning scope is active."""
    assert not plugin_owns_secret_role_reuse_warning()
    assert not plugin_secret_role_warning_matches_manager_surface(
        verification_token_secret="verify-secret",
        reset_password_token_secret="reset-secret",
        totp_secret_key="totp-secret",
    )


def test_plugin_secret_role_warning_matcher_tracks_active_owner() -> None:
    """The secret-role baseline matcher follows the active plugin-owned warning scope."""
    with plugin_secret_role_warning_owner(
        verification_token_secret="verify-secret",
        reset_password_token_secret="reset-secret",
        totp_secret_key="totp-secret",
    ):
        assert plugin_owns_secret_role_reuse_warning()
        assert plugin_secret_role_warning_matches_manager_surface(
            verification_token_secret="verify-secret",
            reset_password_token_secret="reset-secret",
            totp_secret_key="totp-secret",
        )
        assert not plugin_secret_role_warning_matches_manager_surface(
            verification_token_secret="verify-secret",
            reset_password_token_secret="reset-secret",
            totp_secret_key="other-secret",
        )

    assert not plugin_owns_secret_role_reuse_warning()


@pytest.mark.parametrize("trusted_proxy", [True, False])
def test_resolve_trusted_proxy_setting_returns_boolean(trusted_proxy: object) -> None:
    """Boolean trusted-proxy settings are preserved."""
    assert resolve_trusted_proxy_setting(trusted_proxy=trusted_proxy) is trusted_proxy


def test_resolve_trusted_proxy_setting_rejects_non_boolean() -> None:
    """Non-boolean trusted-proxy settings raise a configuration error."""
    with pytest.raises(ConfigurationError, match="trusted_proxy must be a boolean\\."):
        resolve_trusted_proxy_setting(trusted_proxy="yes")
