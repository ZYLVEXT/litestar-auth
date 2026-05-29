"""Unit tests for shared configuration helpers."""

from __future__ import annotations

import re
import secrets as _secrets
import warnings

import pytest

import litestar_auth._secret_roles as secret_roles_module
import litestar_auth.authentication.strategy.jwt as jwt_strategy_module
import litestar_auth.config as config_module
import litestar_auth.controllers.totp as totp_controller_module
import litestar_auth.manager as manager_module
import litestar_auth.totp_flow as totp_flow_module
from litestar_auth.exceptions import ConfigurationError

JWT_ACCESS_TOKEN_AUDIENCE = config_module.JWT_ACCESS_TOKEN_AUDIENCE
MINIMUM_SECRET_ENTROPY_BITS = config_module.MINIMUM_SECRET_ENTROPY_BITS
MINIMUM_SECRET_LENGTH = config_module.MINIMUM_SECRET_LENGTH
_MAX_SEQUENTIAL_PAIR_FRACTION = config_module._MAX_SEQUENTIAL_PAIR_FRACTION
RESET_PASSWORD_TOKEN_AUDIENCE = config_module.RESET_PASSWORD_TOKEN_AUDIENCE
TOTP_ENROLL_AUDIENCE = config_module.TOTP_ENROLL_AUDIENCE
TOTP_PENDING_AUDIENCE = config_module.TOTP_PENDING_AUDIENCE
VERIFY_TOKEN_AUDIENCE = config_module.VERIFY_TOKEN_AUDIENCE
_resolve_token_secret = config_module._resolve_token_secret
_estimated_secret_entropy_bits = config_module._estimated_secret_entropy_bits
_sequential_pair_fraction = config_module._sequential_pair_fraction
_shannon_entropy_bits = config_module._shannon_entropy_bits
resolve_trusted_proxy_hops = config_module.resolve_trusted_proxy_hops
resolve_trusted_proxy_setting = config_module.resolve_trusted_proxy_setting
validate_production_secret = config_module.validate_production_secret
validate_secret_length = config_module.validate_secret_length
validate_secret_strength = config_module.validate_secret_strength

pytestmark = pytest.mark.unit
GENERATED_SECRET_HEX_LENGTH = 64
MULTI_PROXY_HOPS = 2


def test_config_defines_canonical_token_audiences() -> None:
    """Shared token audiences are defined once in the config module."""
    assert VERIFY_TOKEN_AUDIENCE == "litestar-auth:verify"
    assert RESET_PASSWORD_TOKEN_AUDIENCE == "litestar-auth:reset-password"
    assert JWT_ACCESS_TOKEN_AUDIENCE == "litestar-auth:access"
    assert TOTP_PENDING_AUDIENCE == "litestar-auth:2fa-pending"
    assert TOTP_ENROLL_AUDIENCE == "litestar-auth:2fa-enroll"


def test_config_reexports_secret_role_catalog_helpers() -> None:
    """Secret-role helpers remain available through the historical config module path."""
    role_values = config_module.SecretRoleValues(
        verification_token_secret="verify",
        reset_password_token_secret="reset",
        login_identifier_telemetry_secret="telemetry",
        totp_secret_key="totp-key",
        totp_pending_secret="totp-pending",
        api_key_hash_secret="api-key-hash",
        oauth_flow_cookie_secret="oauth-flow",
    )

    assert config_module.SecretRoleValues is secret_roles_module.SecretRoleValues
    assert config_module.validate_secret_roles_are_distinct is secret_roles_module.validate_secret_roles_are_distinct
    assert [role.setting_name for role, _secret in role_values.as_role_pairs()] == [
        "verification_token_secret",
        "reset_password_token_secret",
        "login_identifier_telemetry_secret",
        "totp_secret_key",
        "totp_pending_secret",
        "totp_recovery_code_lookup_secret",
        "oauth_flow_cookie_secret",
        "api_key_hash_secret",
        "api_key_secret_encryption_keyring",
    ]


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


def test_resolve_token_secret_generates_unsafe_testing_secret() -> None:
    """Explicit unsafe testing allows an ephemeral secret when none is configured."""
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        secret = _resolve_token_secret(None, label="JWT secret", warning_stacklevel=1, unsafe_testing=True)

    assert len(secret) == GENERATED_SECRET_HEX_LENGTH
    assert re.fullmatch(rf"[0-9a-f]{{{GENERATED_SECRET_HEX_LENGTH}}}", secret) is not None
    assert len(records) == 1
    assert "JWT secret not provided" in str(records[0].message)


def test_resolve_token_secret_raises_without_secret_in_production() -> None:
    """Production mode requires explicit token secrets."""
    with pytest.raises(ConfigurationError, match="JWT secret not provided"):
        _resolve_token_secret(None, label="JWT secret")


def test_resolve_token_secret_validates_short_secret_in_production() -> None:
    """Production mode rejects secrets shorter than the configured minimum."""
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


def test_resolve_token_secret_skips_length_validation_under_explicit_unsafe_testing() -> None:
    """Explicit unsafe testing skips production minimum-length enforcement."""
    assert _resolve_token_secret("short-secret", label="JWT secret", unsafe_testing=True) == "short-secret"


def test_resolve_token_secret_returns_explicit_secret_in_production() -> None:
    """Configured production secrets are returned unchanged."""
    secret = "c1e8f42a79b035d6a9f03c2e81d4765bf2a70e6c9d1348b5ad02f7c6e9b4183a"

    assert _resolve_token_secret(secret, label="JWT secret") == secret


def test_resolve_token_secret_rejects_low_entropy_secret_in_production() -> None:
    """Production token-secret resolution rejects repeated strings."""
    with pytest.raises(ConfigurationError, match="insufficient entropy"):
        _resolve_token_secret("a" * MINIMUM_SECRET_LENGTH, label="JWT secret")


def test_shannon_entropy_bits_returns_zero_for_empty_string() -> None:
    """The empty string carries no entropy."""
    assert _shannon_entropy_bits("") == pytest.approx(0.0, abs=0.0)


def test_shannon_entropy_bits_returns_zero_for_repeated_character() -> None:
    """Single-symbol strings collapse to zero bits regardless of length."""
    assert _shannon_entropy_bits("a" * 32) == pytest.approx(0.0, abs=0.0)


def test_shannon_entropy_bits_grows_with_alphabet_size() -> None:
    """Uniformly drawn high-alphabet strings score near the theoretical maximum."""
    # ``secrets.token_hex(32)`` yields 64 chars over 16 hex symbols; the
    # observed-frequency estimate sits comfortably above 128 bits.
    assert _shannon_entropy_bits(_secrets.token_hex(32)) > MINIMUM_SECRET_ENTROPY_BITS


def test_estimated_secret_entropy_caps_repeated_structured_pattern() -> None:
    """Repeated phrases score as the phrase, not as the expanded copy."""
    weak_secret = "abc123" * 22

    assert _shannon_entropy_bits(weak_secret) > MINIMUM_SECRET_ENTROPY_BITS
    assert _estimated_secret_entropy_bits(weak_secret) < MINIMUM_SECRET_ENTROPY_BITS


def test_validate_secret_strength_accepts_high_entropy_secret() -> None:
    """Cryptographically random secrets clear both length and entropy floors."""
    validate_secret_strength(_secrets.token_hex(32), label="JWT secret")
    validate_secret_strength(_secrets.token_urlsafe(32), label="JWT secret")


def test_validate_secret_strength_rejects_low_entropy_secret() -> None:
    """Repeated-character secrets are rejected even when long enough.

    Without an entropy gate, ``"a" * MINIMUM_SECRET_LENGTH`` would slip past
    the chars-count floor and silently weaken JWT signing or Fernet keys.
    """
    with pytest.raises(ConfigurationError, match="insufficient entropy"):
        validate_secret_strength("a" * MINIMUM_SECRET_LENGTH, label="JWT secret")


def test_validate_secret_strength_rejects_weak_but_long_repeated_secret() -> None:
    """Pattern repetition cannot satisfy the production entropy floor."""
    with pytest.raises(ConfigurationError, match="insufficient entropy"):
        validate_secret_strength("abc123" * 22, label="JWT secret")


def test_sequential_pair_fraction_returns_zero_for_short_value() -> None:
    """Values shorter than two characters have no adjacent pairs to score."""
    assert _sequential_pair_fraction("") == pytest.approx(0.0)
    assert _sequential_pair_fraction("a") == pytest.approx(0.0)


def test_sequential_pair_fraction_separates_walks_from_random_tokens() -> None:
    """A strict codepoint walk scores above the ceiling while random tokens stay below it."""
    assert _sequential_pair_fraction("abcdefghijklmnopqrstuvwxyz123456") >= _MAX_SEQUENTIAL_PAIR_FRACTION
    assert _sequential_pair_fraction(_secrets.token_hex(32)) < _MAX_SEQUENTIAL_PAIR_FRACTION


def test_validate_secret_strength_rejects_sequential_codepoint_walk() -> None:
    """A sequential pattern clears the frequency entropy floor but is still rejected.

    ``"abc...xyz123"`` has 32 distinct characters, so raw Shannon entropy
    over-credits it well past the 128-bit floor; the adjacent-transition check
    rejects it as trivially guessable.
    """
    sequential_secret = "abcdefghijklmnopqrstuvwxyz123456"

    assert len(sequential_secret) >= MINIMUM_SECRET_LENGTH
    assert _estimated_secret_entropy_bits(sequential_secret) > MINIMUM_SECRET_ENTROPY_BITS
    with pytest.raises(ConfigurationError, match="low-complexity sequential pattern"):
        validate_secret_strength(sequential_secret, label="JWT secret")


def test_validate_secret_strength_scopes_sequential_check_to_single_span() -> None:
    """A repeated floor-length unit is judged by the full string, not the sequential gate.

    ``"0123456789abcdef" * 4`` has a high adjacent-sequential fraction, but it is a
    repeated 16-character unit rather than one uninterrupted walk. The repeat-unit
    entropy cap applies only below the floor, so the full-string entropy estimate
    governs this boundary case and the single-span sequential gate does not fire.
    """
    repeated_unit_secret = "0123456789abcdef" * 4

    assert _sequential_pair_fraction(repeated_unit_secret) >= _MAX_SEQUENTIAL_PAIR_FRACTION
    validate_secret_strength(repeated_unit_secret, label="JWT secret")


def test_validate_secret_strength_rejects_short_secret_before_entropy_check() -> None:
    """Length validation runs first so the error wording remains stable."""
    with pytest.raises(ConfigurationError, match=rf"must be at least {MINIMUM_SECRET_LENGTH} characters"):
        validate_secret_strength("short", label="JWT secret")


def test_validate_secret_strength_skips_entropy_when_floor_is_zero() -> None:
    """Setting ``minimum_entropy_bits=0`` disables the entropy gate."""
    validate_secret_strength(
        "a" * MINIMUM_SECRET_LENGTH,
        label="JWT secret",
        minimum_entropy_bits=0,
    )


def test_validate_secret_strength_exposes_minimum_in_error_message() -> None:
    """Operators get a generation hint and explicit threshold in the failure."""
    with pytest.raises(ConfigurationError) as exc_info:
        validate_secret_strength("a" * MINIMUM_SECRET_LENGTH, label="JWT secret")
    message = str(exc_info.value)
    assert "JWT secret" in message
    assert f"required {MINIMUM_SECRET_ENTROPY_BITS:.0f}" in message
    assert "secrets.token_hex" in message


def test_validate_production_secret_rejects_low_entropy_secret() -> None:
    """Production validation closes the length-only low-entropy gap."""
    with pytest.raises(ConfigurationError, match="insufficient entropy"):
        validate_production_secret("a" * MINIMUM_SECRET_LENGTH, label="JWT secret")


def test_validate_production_secret_preserves_explicit_unsafe_testing_shortcut() -> None:
    """Unsafe-testing mode keeps existing short-lived fixture shortcuts explicit."""
    validate_production_secret("short", label="JWT secret", unsafe_testing=True)


def test_validate_production_secret_preserves_zero_floor_skip_hatch() -> None:
    """The explicit zero-floor opt-out keeps length validation but skips entropy."""
    validate_production_secret(
        "abc123" * 22,
        label="JWT secret",
        minimum_entropy_bits=0,
    )


@pytest.mark.parametrize("trusted_proxy", [True, False])
def test_resolve_trusted_proxy_setting_returns_boolean(trusted_proxy: object) -> None:
    """Boolean trusted-proxy settings are preserved."""
    assert resolve_trusted_proxy_setting(trusted_proxy=trusted_proxy) is trusted_proxy


def test_resolve_trusted_proxy_setting_rejects_non_boolean() -> None:
    """Non-boolean trusted-proxy settings raise a configuration error."""
    with pytest.raises(ConfigurationError, match="trusted_proxy must be a boolean\\."):
        resolve_trusted_proxy_setting(trusted_proxy="yes")


def test_resolve_trusted_proxy_hops_returns_positive_integer() -> None:
    """Positive integer trusted-proxy hop counts are preserved."""
    assert resolve_trusted_proxy_hops(trusted_proxy_hops=MULTI_PROXY_HOPS) == MULTI_PROXY_HOPS


@pytest.mark.parametrize("trusted_proxy_hops", [0, -1, True, "2"])
def test_resolve_trusted_proxy_hops_rejects_invalid_values(trusted_proxy_hops: object) -> None:
    """Invalid trusted-proxy hop counts raise a configuration error."""
    with pytest.raises(ConfigurationError, match="trusted_proxy_hops must be a positive integer\\."):
        resolve_trusted_proxy_hops(trusted_proxy_hops=trusted_proxy_hops)
