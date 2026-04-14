"""Tests for the exception hierarchy."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import pytest

import litestar_auth.exceptions as exceptions_module
from litestar_auth.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ErrorCode,
    InactiveUserError,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    LitestarAuthError,
    OAuthAccountAlreadyLinkedError,
    TokenError,
    UnverifiedUserError,
    UserAlreadyExistsError,
    UserNotExistsError,
)
from tests.unit.test_definition_file_coverage import load_reloaded_test_alias

pytestmark = pytest.mark.unit

type ExceptionCase = tuple[type[LitestarAuthError], str, str | ErrorCode, type[BaseException]]

EXCEPTION_CASES: tuple[ExceptionCase, ...] = (
    (
        LitestarAuthError,
        "An unexpected litestar-auth error occurred.",
        ErrorCode.UNKNOWN,
        Exception,
    ),
    (
        AuthenticationError,
        "Authentication failed.",
        ErrorCode.AUTHENTICATION_FAILED,
        LitestarAuthError,
    ),
    (
        AuthorizationError,
        "Authorization failed.",
        ErrorCode.AUTHORIZATION_DENIED,
        LitestarAuthError,
    ),
    (
        TokenError,
        "Token processing failed.",
        ErrorCode.TOKEN_PROCESSING_FAILED,
        LitestarAuthError,
    ),
    (
        ConfigurationError,
        "litestar-auth is configured incorrectly.",
        ErrorCode.CONFIGURATION_INVALID,
        LitestarAuthError,
    ),
    (
        UserAlreadyExistsError,
        "A user with the provided credentials already exists.",
        ErrorCode.REGISTER_USER_ALREADY_EXISTS,
        AuthenticationError,
    ),
    (
        UserNotExistsError,
        "The requested user does not exist.",
        ErrorCode.USER_NOT_FOUND,
        AuthenticationError,
    ),
    (
        InvalidPasswordError,
        "The provided password is invalid.",
        ErrorCode.LOGIN_BAD_CREDENTIALS,
        AuthenticationError,
    ),
    (
        InactiveUserError,
        "The user account is inactive.",
        ErrorCode.LOGIN_USER_INACTIVE,
        AuthenticationError,
    ),
    (
        UnverifiedUserError,
        "The user account is not verified.",
        ErrorCode.LOGIN_USER_NOT_VERIFIED,
        AuthenticationError,
    ),
    (
        InvalidVerifyTokenError,
        "The email verification token is invalid.",
        ErrorCode.VERIFY_USER_BAD_TOKEN,
        TokenError,
    ),
    (
        InvalidResetPasswordTokenError,
        "The password reset token is invalid.",
        ErrorCode.RESET_PASSWORD_BAD_TOKEN,
        TokenError,
    ),
    (
        OAuthAccountAlreadyLinkedError,
        (
            "This provider account is already linked to another user. "
            "One provider identity can only be linked to a single local account."
        ),
        ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED,
        AuthenticationError,
    ),
)

EXPECTED_ERROR_CODES = {
    "UNKNOWN": "UNKNOWN",
    "AUTHENTICATION_FAILED": "AUTHENTICATION_FAILED",
    "TOKEN_PROCESSING_FAILED": "TOKEN_PROCESSING_FAILED",
    "CONFIGURATION_INVALID": "CONFIGURATION_INVALID",
    "USER_NOT_FOUND": "USER_NOT_FOUND",
    "REGISTER_USER_ALREADY_EXISTS": "REGISTER_USER_ALREADY_EXISTS",
    "REGISTER_INVALID_PASSWORD": "REGISTER_INVALID_PASSWORD",
    "LOGIN_BAD_CREDENTIALS": "LOGIN_BAD_CREDENTIALS",
    "LOGIN_USER_INACTIVE": "LOGIN_USER_INACTIVE",
    "LOGIN_USER_NOT_VERIFIED": "LOGIN_USER_NOT_VERIFIED",
    "AUTHORIZATION_DENIED": "AUTHORIZATION_DENIED",
    "RESET_PASSWORD_BAD_TOKEN": "RESET_PASSWORD_BAD_TOKEN",
    "RESET_PASSWORD_INVALID_PASSWORD": "RESET_PASSWORD_INVALID_PASSWORD",
    "VERIFY_USER_BAD_TOKEN": "VERIFY_USER_BAD_TOKEN",
    "VERIFY_USER_ALREADY_VERIFIED": "VERIFY_USER_ALREADY_VERIFIED",
    "UPDATE_USER_EMAIL_ALREADY_EXISTS": "UPDATE_USER_EMAIL_ALREADY_EXISTS",
    "UPDATE_USER_INVALID_PASSWORD": "UPDATE_USER_INVALID_PASSWORD",
    "SUPERUSER_CANNOT_DELETE_SELF": "SUPERUSER_CANNOT_DELETE_SELF",
    "OAUTH_NOT_AVAILABLE_EMAIL": "OAUTH_NOT_AVAILABLE_EMAIL",
    "OAUTH_STATE_INVALID": "OAUTH_STATE_INVALID",
    "OAUTH_EMAIL_NOT_VERIFIED": "OAUTH_EMAIL_NOT_VERIFIED",
    "OAUTH_USER_ALREADY_EXISTS": "OAUTH_USER_ALREADY_EXISTS",
    "OAUTH_ACCOUNT_ALREADY_LINKED": "OAUTH_ACCOUNT_ALREADY_LINKED",
    "REQUEST_BODY_INVALID": "REQUEST_BODY_INVALID",
    "LOGIN_PAYLOAD_INVALID": "LOGIN_PAYLOAD_INVALID",
    "REFRESH_TOKEN_INVALID": "REFRESH_TOKEN_INVALID",
    "TOTP_PENDING_BAD_TOKEN": "TOTP_PENDING_BAD_TOKEN",
    "TOTP_CODE_INVALID": "TOTP_CODE_INVALID",
    "TOTP_ALREADY_ENABLED": "TOTP_ALREADY_ENABLED",
    "TOTP_ENROLL_BAD_TOKEN": "TOTP_ENROLL_BAD_TOKEN",
}


def _error_code_members() -> dict[str, str]:
    """Return member names and string values for ``ErrorCode``."""
    return {member.name: member.value for member in ErrorCode}


def test_exception_module_reload_preserves_default_message_and_code_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload coverage keeps exception defaults stable even when class identity changes."""
    assert exceptions_module.__file__ is not None
    reloaded_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_exceptions",
        source_path=Path(exceptions_module.__file__).resolve(),
        monkeypatch=monkeypatch,
    )
    reloaded_configuration_error = reloaded_module.ConfigurationError()
    reloaded_link_error = reloaded_module.OAuthAccountAlreadyLinkedError()

    assert reloaded_module.LitestarAuthError.default_code == LitestarAuthError.default_code
    assert reloaded_module.ConfigurationError is not ConfigurationError
    assert reloaded_module.OAuthAccountAlreadyLinkedError is not OAuthAccountAlreadyLinkedError
    assert str(reloaded_configuration_error) == ConfigurationError.default_message
    assert reloaded_configuration_error.code == ErrorCode.CONFIGURATION_INVALID
    assert str(reloaded_link_error) == OAuthAccountAlreadyLinkedError.default_message
    assert reloaded_link_error.code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED


@pytest.mark.parametrize(("exception_type", "expected_message", "expected_code", "expected_base"), EXCEPTION_CASES)
def test_exception_defaults(
    exception_type: type[LitestarAuthError],
    expected_message: str,
    expected_code: str | ErrorCode,
    expected_base: type[BaseException],
) -> None:
    """Each exception exposes its default message, code, and inheritance."""
    error = exception_type()

    assert isinstance(error, expected_base)
    assert str(error) == expected_message
    assert error.code == expected_code


@pytest.mark.parametrize(("exception_type", "expected_message", "expected_code", "_"), EXCEPTION_CASES)
def test_exception_none_arguments_fall_back_to_defaults(
    exception_type: type[LitestarAuthError],
    expected_message: str,
    expected_code: str | ErrorCode,
    _: type[BaseException],
) -> None:
    """Passing ``None`` preserves the class defaults."""
    error = exception_type(message=None, code=None)

    assert str(error) == expected_message
    assert error.code == expected_code


@pytest.mark.parametrize(("exception_type", "expected_message", "expected_code", "_"), EXCEPTION_CASES)
def test_exception_custom_message_and_code_override_defaults(
    exception_type: type[LitestarAuthError],
    expected_message: str,
    expected_code: str | ErrorCode,
    _: type[BaseException],
) -> None:
    """Every exception accepts custom message and code overrides."""
    custom_message = f"custom message for {exception_type.__name__}"
    custom_code = f"CUSTOM_{exception_type.__name__.upper()}"

    error = exception_type(message=custom_message, code=custom_code)

    assert str(error) != expected_message
    assert error.code != expected_code
    assert str(error) == custom_message
    assert error.code == custom_code


def test_litestar_auth_error_inherits_base_unknown_code_via_mro_when_subclass_omits_default_code() -> None:
    """Subclasses that omit ``default_code`` inherit ``LitestarAuthError.default_code`` via normal MRO."""

    class MissingDefaultCodeError(LitestarAuthError):
        default_message = "missing default code"

    error = MissingDefaultCodeError(message=None, code=None)

    assert str(error) == MissingDefaultCodeError.default_message
    assert error.code == LitestarAuthError.default_code


def test_exception_inheritance_hierarchy() -> None:
    """Concrete exception types keep the documented inheritance chains."""
    assert issubclass(AuthenticationError, LitestarAuthError)
    assert issubclass(AuthorizationError, LitestarAuthError)
    assert issubclass(TokenError, LitestarAuthError)
    assert issubclass(ConfigurationError, LitestarAuthError)
    assert issubclass(UserAlreadyExistsError, AuthenticationError)
    assert issubclass(UserNotExistsError, AuthenticationError)
    assert issubclass(InvalidPasswordError, AuthenticationError)
    assert issubclass(InactiveUserError, AuthenticationError)
    assert issubclass(UnverifiedUserError, AuthenticationError)
    assert issubclass(InvalidVerifyTokenError, TokenError)
    assert issubclass(InvalidResetPasswordTokenError, TokenError)
    assert issubclass(OAuthAccountAlreadyLinkedError, AuthenticationError)


def test_error_code_constants_match_string_values() -> None:
    """Every ``ErrorCode`` constant matches its machine-readable string value."""
    assert _error_code_members() == EXPECTED_ERROR_CODES


def test_error_code_is_strenum_with_stable_public_surface() -> None:
    """``ErrorCode`` is a StrEnum with iterable members and value-based construction."""
    assert issubclass(ErrorCode, StrEnum)
    members = list(ErrorCode)
    assert len(members) == len(EXPECTED_ERROR_CODES)
    assert ErrorCode("UNKNOWN") is ErrorCode.UNKNOWN
    assert ErrorCode("AUTHENTICATION_FAILED") is ErrorCode.AUTHENTICATION_FAILED
    assert ErrorCode("LOGIN_BAD_CREDENTIALS") is ErrorCode.LOGIN_BAD_CREDENTIALS
    assert isinstance(ErrorCode.LOGIN_BAD_CREDENTIALS, str)
    assert ErrorCode.LOGIN_BAD_CREDENTIALS == "LOGIN_BAD_CREDENTIALS"
