"""Tests for the centralised UserPolicy object."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest

import litestar_auth._manager.user_policy as user_policy_module
from litestar_auth.password import PasswordHelper

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.unit


def _user_policy_cls() -> type[user_policy_module.UserPolicy]:
    """Import the runtime class lazily so coverage records module definitions.

    Returns:
        The runtime ``UserPolicy`` class from ``litestar_auth._manager.user_policy``.
    """
    module = importlib.import_module("litestar_auth._manager.user_policy")
    return module.UserPolicy


def _invalid_password_error_cls() -> type[Exception]:
    """Return the ``InvalidPasswordError`` bound in ``user_policy`` (matches ``UserPolicy`` raises)."""
    return cast("type[Exception]", user_policy_module.InvalidPasswordError)


def _inactive_user_error_cls() -> type[Exception]:
    """Return the ``InactiveUserError`` bound in ``user_policy`` (matches ``UserPolicy`` raises)."""
    return cast("type[Exception]", user_policy_module.InactiveUserError)


def _unverified_user_error_cls() -> type[Exception]:
    """Return the ``UnverifiedUserError`` bound in ``user_policy`` (matches ``UserPolicy`` raises)."""
    return cast("type[Exception]", user_policy_module.UnverifiedUserError)


@dataclass
class _StubUser:
    is_active: bool = True
    is_verified: bool = False


def _make_policy(
    *,
    password_validator: Callable[[str], None] | None = None,
) -> user_policy_module.UserPolicy:
    return _user_policy_cls()(
        password_helper=PasswordHelper(),
        password_validator=password_validator,
    )


def test_user_policy_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records class and helper definitions."""
    reloaded_module = importlib.reload(user_policy_module)

    assert reloaded_module.UserPolicy.__name__ == _user_policy_cls().__name__
    assert reloaded_module._require_password_length.__name__ == "_require_password_length"


def test_normalize_email_strips_and_lowercases() -> None:
    """Whitespace and mixed case are normalised."""
    assert _user_policy_cls().normalize_email("  Alice@Example.COM  ") == "alice@example.com"


def test_normalize_email_applies_nfkc_normalization() -> None:
    """Compatibility characters are normalized before validation."""
    assert _user_policy_cls().normalize_email("\uff21lice@Example.com") == "alice@example.com"


def test_normalize_email_rejects_invalid() -> None:
    """Missing '@' or dot after domain rejects with ValueError."""
    with pytest.raises(ValueError, match="Invalid email"):
        _user_policy_cls().normalize_email("not-an-email")


def test_normalize_email_rejects_exceeding_max_length() -> None:
    """Emails longer than 320 characters are rejected."""
    long_local = "a" * 310
    with pytest.raises(ValueError, match="Invalid email"):
        _user_policy_cls().normalize_email(f"{long_local}@example.com")


def test_normalize_username_strips_and_lowercases() -> None:
    """Whitespace and mixed case are normalised."""
    assert _user_policy_cls().normalize_username_lookup("  Alice  ") == "alice"


def test_normalize_username_empty_returns_empty() -> None:
    """Whitespace-only usernames normalise to empty string."""
    assert not _user_policy_cls().normalize_username_lookup("   ")


def test_validate_password_rejects_empty() -> None:
    """Zero-length passwords are rejected."""
    policy = _make_policy()
    with pytest.raises(_invalid_password_error_cls()):
        policy.validate_password("")


def test_validate_password_accepts_valid() -> None:
    """A reasonable-length password passes without error."""
    policy = _make_policy()
    policy.validate_password("a-valid-password")


def test_validate_password_rejects_oversized() -> None:
    """Passwords exceeding 128 characters are rejected."""
    policy = _make_policy()
    with pytest.raises(_invalid_password_error_cls()):
        policy.validate_password("x" * 200)


def test_validate_password_custom_validator_called() -> None:
    """Custom validators receive the password and may reject it."""
    min_len = 20

    def reject_short(password: str) -> None:
        if len(password) < min_len:
            msg = "too short"
            raise _invalid_password_error_cls()(msg)

    policy = _make_policy(password_validator=reject_short)
    # Password meets baseline (12+) but fails custom validator (20+)
    with pytest.raises(_invalid_password_error_cls(), match="too short"):
        policy.validate_password("a]b]c]d]e]f]g]")


def test_validate_password_wraps_value_error() -> None:
    """ValueError from custom validators is wrapped in InvalidPasswordError."""

    def reject_all(_password: str) -> None:
        msg = "nope"
        raise ValueError(msg)

    policy = _make_policy(password_validator=reject_all)
    with pytest.raises(_invalid_password_error_cls(), match="nope"):
        policy.validate_password("anything-valid-length")


def test_validate_password_wraps_baseline_length_error_message() -> None:
    """Baseline password-length failures are normalized into InvalidPasswordError."""
    policy = _make_policy()

    with pytest.raises(_invalid_password_error_cls(), match="at least 12 characters long"):
        policy.validate_password("short-pass")


def test_require_account_state_active_passes() -> None:
    """An active user passes without error."""
    _user_policy_cls().require_account_state(_StubUser(is_active=True))


def test_require_account_state_inactive_raises() -> None:
    """An inactive user raises InactiveUserError."""
    with pytest.raises(_inactive_user_error_cls()):
        _user_policy_cls().require_account_state(_StubUser(is_active=False))


def test_require_account_state_unverified_passes_by_default() -> None:
    """Without require_verified, unverified users pass."""
    _user_policy_cls().require_account_state(_StubUser(is_active=True, is_verified=False))


def test_require_account_state_unverified_raises_when_required() -> None:
    """With require_verified=True, unverified users raise UnverifiedUserError."""
    with pytest.raises(_unverified_user_error_cls()):
        _user_policy_cls().require_account_state(
            _StubUser(is_active=True, is_verified=False),
            require_verified=True,
        )


def test_require_account_state_verified_passes_when_required() -> None:
    """A verified, active user passes even with require_verified=True."""
    _user_policy_cls().require_account_state(
        _StubUser(is_active=True, is_verified=True),
        require_verified=True,
    )


def test_require_account_state_requires_account_state_attributes() -> None:
    """Objects missing the protocol fields fail when account-state checks access them."""

    class MissingAccountState:
        """Deliberately lacks the account-state protocol attributes."""

    with pytest.raises(AttributeError, match="is_active"):
        _user_policy_cls().require_account_state(MissingAccountState())
