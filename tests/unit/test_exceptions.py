"""Tests for the exception hierarchy."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import pytest

import litestar_auth._error_codes as error_codes_module
import litestar_auth.exceptions as exceptions_module
from litestar_auth.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ErrorCode,
    InactiveUserError,
    InsufficientRolesError,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    LitestarAuthError,
    OAuthAccountAlreadyLinkedError,
    TokenError,
    UnverifiedUserError,
    UserAlreadyExistsError,
    UserIdentifier,
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
        ErrorCode.USER_ALREADY_EXISTS,
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
)

EXPECTED_ERROR_CODES = {
    "UNKNOWN": "UNKNOWN",
    "AUTHENTICATION_FAILED": "AUTHENTICATION_FAILED",
    "TOKEN_PROCESSING_FAILED": "TOKEN_PROCESSING_FAILED",
    "CONFIGURATION_INVALID": "CONFIGURATION_INVALID",
    "USER_NOT_FOUND": "USER_NOT_FOUND",
    "USER_ALREADY_EXISTS": "USER_ALREADY_EXISTS",
    "REGISTER_FAILED": "REGISTER_FAILED",
    "LOGIN_BAD_CREDENTIALS": "LOGIN_BAD_CREDENTIALS",
    "LOGIN_USER_INACTIVE": "LOGIN_USER_INACTIVE",
    "LOGIN_USER_NOT_VERIFIED": "LOGIN_USER_NOT_VERIFIED",
    "AUTHORIZATION_DENIED": "AUTHORIZATION_DENIED",
    "INSUFFICIENT_ROLES": "INSUFFICIENT_ROLES",
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
    "ROLE_ALREADY_EXISTS": "ROLE_ALREADY_EXISTS",
    "ROLE_NOT_FOUND": "ROLE_NOT_FOUND",
    "ROLE_STILL_ASSIGNED": "ROLE_STILL_ASSIGNED",
    "ROLE_ASSIGNMENT_USER_NOT_FOUND": "ROLE_ASSIGNMENT_USER_NOT_FOUND",
    "ROLE_NAME_INVALID": "ROLE_NAME_INVALID",
    "TOTP_PENDING_BAD_TOKEN": "TOTP_PENDING_BAD_TOKEN",
    "TOTP_CODE_INVALID": "TOTP_CODE_INVALID",
    "TOTP_ALREADY_ENABLED": "TOTP_ALREADY_ENABLED",
    "TOTP_ENROLL_BAD_TOKEN": "TOTP_ENROLL_BAD_TOKEN",
}


def _error_code_members() -> dict[str, str]:
    """Return member names and string values for ``ErrorCode``."""
    return {member.name: member.value for member in ErrorCode}


def test_error_code_module_reload_preserves_error_code_and_identifier_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload coverage keeps relocated error-code contracts stable."""
    assert error_codes_module.__file__ is not None
    reloaded_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_error_codes",
        source_path=Path(error_codes_module.__file__).resolve(),
        monkeypatch=monkeypatch,
    )

    assert reloaded_module.ErrorCode is not ErrorCode
    assert reloaded_module.UserIdentifier is not UserIdentifier
    assert {member.name: member.value for member in reloaded_module.ErrorCode} == EXPECTED_ERROR_CODES
    assert reloaded_module.UserIdentifier(identifier_type="email", identifier_value="user@example.com") == (
        reloaded_module.UserIdentifier(identifier_type="email", identifier_value="user@example.com")
    )


def test_exception_module_reload_preserves_default_message_and_code_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload coverage keeps exception defaults stable even when class identity changes."""
    assert exceptions_module.__file__ is not None
    reloaded_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_exceptions",
        source_path=Path(exceptions_module.__file__).resolve(),
        monkeypatch=monkeypatch,
    )
    reloaded_configuration_error = reloaded_module.ConfigurationError()
    reloaded_user_exists_error = reloaded_module.UserAlreadyExistsError(
        identifier=reloaded_module.UserIdentifier(
            identifier_type="email",
            identifier_value="user@example.com",
        ),
    )
    reloaded_invalid_password_error = reloaded_module.InvalidPasswordError(user_id="user-123")
    reloaded_role_error = reloaded_module.InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"viewer"}),
        require_all=False,
    )
    reloaded_link_error = reloaded_module.OAuthAccountAlreadyLinkedError(
        provider="github",
        account_id="provider-user",
        existing_user_id="user-123",
    )

    assert reloaded_module.LitestarAuthError.default_code == LitestarAuthError.default_code
    assert reloaded_module.ErrorCode is ErrorCode
    assert reloaded_module.ConfigurationError is not ConfigurationError
    assert reloaded_module.UserAlreadyExistsError is not UserAlreadyExistsError
    assert reloaded_module.UserIdentifier is UserIdentifier
    assert reloaded_module.InvalidPasswordError is not InvalidPasswordError
    assert reloaded_module.InsufficientRolesError is not InsufficientRolesError
    assert reloaded_module.OAuthAccountAlreadyLinkedError is not OAuthAccountAlreadyLinkedError
    assert str(reloaded_configuration_error) == ConfigurationError.default_message
    assert reloaded_configuration_error.code == ErrorCode.CONFIGURATION_INVALID
    assert str(reloaded_user_exists_error) == UserAlreadyExistsError.default_message
    assert reloaded_user_exists_error.code == ErrorCode.USER_ALREADY_EXISTS
    assert reloaded_user_exists_error.identifier_type == "email"
    assert reloaded_user_exists_error.identifier_value == "user@example.com"
    assert str(reloaded_invalid_password_error) == InvalidPasswordError.default_message
    assert reloaded_invalid_password_error.code == ErrorCode.LOGIN_BAD_CREDENTIALS
    assert reloaded_invalid_password_error.user_id == "user-123"
    assert str(reloaded_role_error) == "The authenticated user does not have any of the required roles."
    assert reloaded_role_error.code == ErrorCode.INSUFFICIENT_ROLES
    assert reloaded_role_error.required_roles == frozenset({"admin", "billing"})
    assert reloaded_role_error.user_roles == frozenset({"viewer"})
    assert reloaded_role_error.require_all is False
    assert str(reloaded_link_error) == "OAuth account github:provider-user is already linked to user user-123"
    assert reloaded_link_error.code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
    assert reloaded_link_error.provider == "github"
    assert reloaded_link_error.account_id == "provider-user"
    assert reloaded_link_error.existing_user_id == "user-123"


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
def test_exception_none_message_and_omitted_code_fall_back_to_defaults(
    exception_type: type[LitestarAuthError],
    expected_message: str,
    expected_code: str | ErrorCode,
    _: type[BaseException],
) -> None:
    """Passing ``message=None`` while omitting ``code`` preserves the class defaults."""
    error = exception_type(message=None)

    assert str(error) == expected_message
    assert error.code == expected_code


@pytest.mark.parametrize(("exception_type", "expected_message", "expected_code", "_"), EXCEPTION_CASES)
def test_exception_none_code_argument_uses_default_code(
    exception_type: type[LitestarAuthError],
    expected_message: str,
    expected_code: str | ErrorCode,
    _: type[BaseException],
) -> None:
    """Passing ``code=None`` falls back to the class default code."""
    error = exception_type(code=None)

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

    error = MissingDefaultCodeError(message=None)

    assert str(error) == MissingDefaultCodeError.default_message
    assert error.code == LitestarAuthError.default_code


def test_oauth_account_already_linked_error_exposes_context_and_default_message() -> None:
    """OAuth link conflicts expose the provider identity and linked user context."""
    error = OAuthAccountAlreadyLinkedError(
        provider="github",
        account_id="provider-user",
        existing_user_id="user-123",
    )

    assert str(error) == "OAuth account github:provider-user is already linked to user user-123"
    assert error.code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
    assert error.provider == "github"
    assert error.account_id == "provider-user"
    assert error.existing_user_id == "user-123"


def test_oauth_account_already_linked_error_none_message_and_omitted_code_use_context_message() -> None:
    """Explicit ``message=None`` still derives the message from the required context."""
    error = OAuthAccountAlreadyLinkedError(
        provider="google",
        account_id="acct-42",
        existing_user_id=123,
        message=None,
    )

    assert str(error) == "OAuth account google:acct-42 is already linked to user 123"
    assert error.code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED


def test_oauth_account_already_linked_error_none_code_argument_uses_default_code() -> None:
    """OAuth link conflicts resolve explicit ``code=None`` to the default code."""
    error = OAuthAccountAlreadyLinkedError(
        provider="google",
        account_id="acct-42",
        existing_user_id=123,
        code=None,
    )

    assert str(error) == "OAuth account google:acct-42 is already linked to user 123"
    assert error.code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED


def test_oauth_account_already_linked_error_preserves_blank_context_without_runtime_validation() -> None:
    """Linked-account conflicts store provider context as provided instead of raising ``ValueError``."""
    error = OAuthAccountAlreadyLinkedError(
        provider=" \t ",
        account_id="",
        existing_user_id=None,
    )

    assert error.provider == " \t "
    assert not error.account_id
    assert error.existing_user_id is None
    assert str(error) == "OAuth account  \t : is already linked to user None"


def test_oauth_account_already_linked_error_custom_message_and_code_override_defaults() -> None:
    """OAuth link conflicts still accept explicit message and code overrides."""
    error = OAuthAccountAlreadyLinkedError(
        provider="github",
        account_id="provider-user",
        existing_user_id="user-123",
        message="custom linked account message",
        code="CUSTOM_OAUTH_ACCOUNT_ALREADY_LINKED",
    )

    assert str(error) == "custom linked account message"
    assert error.code == "CUSTOM_OAUTH_ACCOUNT_ALREADY_LINKED"
    assert error.provider == "github"
    assert error.account_id == "provider-user"
    assert error.existing_user_id == "user-123"


def test_insufficient_roles_error_exposes_context_and_generic_default_message() -> None:
    """Role-denial errors keep structured context off the default message."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"viewer"}),
        require_all=False,
    )

    assert str(error) == "The authenticated user does not have any of the required roles."
    assert error.code == ErrorCode.INSUFFICIENT_ROLES
    assert error.required_roles == frozenset({"admin", "billing"})
    assert error.user_roles == frozenset({"viewer"})
    assert error.require_all is False


def test_insufficient_roles_error_require_all_message_uses_all_role_wording() -> None:
    """The default message reflects whether the guard requires every configured role."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"admin"}),
        require_all=True,
    )

    assert str(error) == "The authenticated user does not have all of the required roles."
    assert error.code == ErrorCode.INSUFFICIENT_ROLES
    assert error.require_all is True


def test_insufficient_roles_error_none_code_argument_uses_default_code() -> None:
    """Role-denial errors resolve explicit ``code=None`` to the default code."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin"}),
        user_roles=frozenset({"viewer"}),
        require_all=False,
        code=None,
    )

    assert str(error) == "The authenticated user does not have any of the required roles."
    assert error.code == ErrorCode.INSUFFICIENT_ROLES


def test_insufficient_roles_error_preserves_blank_role_names_without_runtime_validation() -> None:
    """Role-denial errors store role context as provided without echoing it in messages."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin", ""}),
        user_roles=frozenset({" \n ", "viewer"}),
        require_all=False,
    )

    assert error.required_roles == frozenset({"admin", ""})
    assert error.user_roles == frozenset({" \n ", "viewer"})
    assert error.require_all is False
    assert str(error) == "The authenticated user does not have any of the required roles."


def test_insufficient_roles_error_custom_message_and_code_override_defaults() -> None:
    """Role-denial errors still accept explicit message and code overrides."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin"}),
        user_roles=frozenset({"viewer"}),
        require_all=False,
        message="custom insufficient roles message",
        code="CUSTOM_INSUFFICIENT_ROLES",
    )

    assert str(error) == "custom insufficient roles message"
    assert error.code == "CUSTOM_INSUFFICIENT_ROLES"
    assert error.required_roles == frozenset({"admin"})
    assert error.user_roles == frozenset({"viewer"})
    assert error.require_all is False


def test_user_already_exists_error_exposes_identifier_context_and_default_message() -> None:
    """Duplicate-user errors expose operator context without leaking it in the default message."""
    error = UserAlreadyExistsError(
        identifier=UserIdentifier(
            identifier_type="username",
            identifier_value="existing-user",
        ),
    )

    assert str(error) == UserAlreadyExistsError.default_message
    assert error.code == ErrorCode.USER_ALREADY_EXISTS
    assert error.identifier == UserIdentifier(identifier_type="username", identifier_value="existing-user")
    assert error.identifier_type == "username"
    assert error.identifier_value == "existing-user"


def test_user_already_exists_error_none_message_and_none_code_use_generic_defaults() -> None:
    """Explicit ``message=None`` and ``code=None`` keep generic duplicate-user defaults."""
    error = UserAlreadyExistsError(
        identifier=UserIdentifier(
            identifier_type="email",
            identifier_value="user@example.com",
        ),
        message=None,
        code=None,
    )

    assert str(error) == UserAlreadyExistsError.default_message
    assert error.code == ErrorCode.USER_ALREADY_EXISTS


def test_user_already_exists_error_rejects_positional_message_argument() -> None:
    """The duplicate-user constructor is keyword-only to keep structured context explicit."""
    call_class = type.__call__
    with pytest.raises(TypeError):
        call_class(UserAlreadyExistsError, "duplicate")


def test_user_already_exists_error_preserves_blank_context_without_runtime_validation() -> None:
    """Duplicate-user identifier context is stored as provided once both fields are present."""
    error = UserAlreadyExistsError(
        identifier=UserIdentifier(
            identifier_type="email",
            identifier_value="\n",
        ),
    )

    assert error.identifier == UserIdentifier(identifier_type="email", identifier_value="\n")
    assert error.identifier_type == "email"
    assert error.identifier_value == "\n"
    assert str(error) == UserAlreadyExistsError.default_message


def test_user_already_exists_error_custom_message_and_code_override_defaults() -> None:
    """Duplicate-user errors still accept explicit message and code overrides."""
    error = UserAlreadyExistsError(
        identifier=UserIdentifier(
            identifier_type="email",
            identifier_value="user@example.com",
        ),
        message="custom user exists message",
        code="CUSTOM_USER_ALREADY_EXISTS",
    )

    assert str(error) == "custom user exists message"
    assert error.code == "CUSTOM_USER_ALREADY_EXISTS"
    assert error.identifier == UserIdentifier(identifier_type="email", identifier_value="user@example.com")
    assert error.identifier_type == "email"
    assert error.identifier_value == "user@example.com"


def test_invalid_password_error_none_code_stores_optional_user_id_without_leaking_it() -> None:
    """Invalid-password errors keep operator-only context while resolving ``code=None`` to default."""
    error = InvalidPasswordError(user_id="user-123", code=None)

    assert str(error) == InvalidPasswordError.default_message
    assert error.code == ErrorCode.LOGIN_BAD_CREDENTIALS
    assert error.user_id == "user-123"


def test_invalid_password_error_custom_message_and_code_preserve_user_id_context() -> None:
    """Custom invalid-password overrides still retain the operator-only context field."""
    user_id = "user-123"
    error = InvalidPasswordError(
        user_id=user_id,
        message="custom invalid password message",
        code="CUSTOM_LOGIN_BAD_CREDENTIALS",
    )

    assert str(error) == "custom invalid password message"
    assert error.code == "CUSTOM_LOGIN_BAD_CREDENTIALS"
    assert error.user_id == user_id


def test_invalid_password_error_rejects_positional_message_argument() -> None:
    """The invalid-password constructor is keyword-only so operator context stays unambiguous."""
    call_class = type.__call__
    with pytest.raises(TypeError):
        call_class(InvalidPasswordError, "custom invalid password message")


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
    assert issubclass(InsufficientRolesError, AuthorizationError)
    assert issubclass(OAuthAccountAlreadyLinkedError, AuthenticationError)


def test_error_code_constants_match_string_values() -> None:
    """Every ``ErrorCode`` constant matches its machine-readable string value."""
    assert _error_code_members() == EXPECTED_ERROR_CODES


def test_register_failed_error_code_is_available_for_register_response_collapse() -> None:
    """``REGISTER_FAILED`` remains available for the register response collapse."""
    assert ErrorCode.REGISTER_FAILED.value == "REGISTER_FAILED"


def test_obsolete_register_error_codes_are_removed() -> None:
    """Register-specific duplicate and password policy codes are no longer public enum members."""
    removed_member_names = (
        "REGISTER_" + "USER_ALREADY_EXISTS",
        "REGISTER_" + "INVALID_PASSWORD",
    )

    for removed_member_name in removed_member_names:
        with pytest.raises(AttributeError):
            getattr(ErrorCode, removed_member_name)


def test_error_code_is_strenum_with_stable_public_surface() -> None:
    """``ErrorCode`` is a StrEnum with iterable members and value-based construction."""
    assert issubclass(ErrorCode, StrEnum)
    members = list(ErrorCode)
    assert len(members) == len(EXPECTED_ERROR_CODES)
    assert ErrorCode("UNKNOWN") is ErrorCode.UNKNOWN
    assert ErrorCode("AUTHENTICATION_FAILED") is ErrorCode.AUTHENTICATION_FAILED
    assert ErrorCode("LOGIN_BAD_CREDENTIALS") is ErrorCode.LOGIN_BAD_CREDENTIALS
    assert ErrorCode("INSUFFICIENT_ROLES") is ErrorCode.INSUFFICIENT_ROLES
    assert isinstance(ErrorCode.LOGIN_BAD_CREDENTIALS, str)
    assert ErrorCode.LOGIN_BAD_CREDENTIALS == "LOGIN_BAD_CREDENTIALS"
