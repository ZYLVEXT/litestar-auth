"""Tests for the exception hierarchy."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import pytest

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
    reloaded_user_exists_error = reloaded_module.UserAlreadyExistsError(
        identifier_type="email",
        identifier_value="user@example.com",
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
    assert reloaded_module.ConfigurationError is not ConfigurationError
    assert reloaded_module.UserAlreadyExistsError is not UserAlreadyExistsError
    assert reloaded_module.InvalidPasswordError is not InvalidPasswordError
    assert reloaded_module.InsufficientRolesError is not InsufficientRolesError
    assert reloaded_module.OAuthAccountAlreadyLinkedError is not OAuthAccountAlreadyLinkedError
    assert str(reloaded_configuration_error) == ConfigurationError.default_message
    assert reloaded_configuration_error.code == ErrorCode.CONFIGURATION_INVALID
    assert str(reloaded_user_exists_error) == "User with email='user@example.com' already exists"
    assert reloaded_user_exists_error.code == ErrorCode.REGISTER_USER_ALREADY_EXISTS
    assert reloaded_user_exists_error.identifier_type == "email"
    assert reloaded_user_exists_error.identifier_value == "user@example.com"
    assert str(reloaded_invalid_password_error) == InvalidPasswordError.default_message
    assert reloaded_invalid_password_error.code == ErrorCode.LOGIN_BAD_CREDENTIALS
    assert reloaded_invalid_password_error.user_id == "user-123"
    assert (
        str(reloaded_role_error) == "The authenticated user does not have any of the required roles. "
        "required_roles=['admin', 'billing']; user_roles=['viewer']"
    )
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


@pytest.mark.parametrize("exception_type", tuple(case[0] for case in EXCEPTION_CASES))
def test_exception_none_code_argument_is_rejected(exception_type: type[LitestarAuthError]) -> None:
    """Passing ``code=None`` is rejected; callers must omit it to use the default."""
    exc_factory = cast("Any", exception_type)
    with pytest.raises(TypeError, match="code cannot be None"):
        exc_factory(code=None)


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


def test_oauth_account_already_linked_error_none_code_argument_is_rejected() -> None:
    """OAuth link conflicts inherit the base exception's concrete-code requirement."""
    exc_factory = cast("Any", OAuthAccountAlreadyLinkedError)

    with pytest.raises(TypeError, match="code cannot be None"):
        exc_factory(
            provider="google",
            account_id="acct-42",
            existing_user_id=123,
            code=None,
        )


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("provider", ""),
        ("provider", " \t "),
        ("account_id", ""),
        ("account_id", "\n"),
    ],
)
def test_oauth_account_already_linked_error_blank_string_context_is_rejected(
    field_name: str,
    field_value: str,
) -> None:
    """Provider identity context must fail fast when a required string field is blank."""
    exc_factory = cast("Any", OAuthAccountAlreadyLinkedError)
    kwargs = {
        "provider": "github",
        "account_id": "provider-user",
        "existing_user_id": "user-123",
    }
    kwargs[field_name] = field_value

    with pytest.raises(ValueError, match=rf"{field_name} cannot be empty or whitespace-only"):
        exc_factory(**kwargs)


def test_oauth_account_already_linked_error_none_existing_user_id_is_rejected() -> None:
    """Linked-account conflicts require the existing local user identifier."""
    exc_factory = cast("Any", OAuthAccountAlreadyLinkedError)

    with pytest.raises(ValueError, match="existing_user_id cannot be None"):
        exc_factory(
            provider="github",
            account_id="provider-user",
            existing_user_id=None,
        )


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


def test_insufficient_roles_error_exposes_context_and_default_message() -> None:
    """Role-denial errors expose the required and actual role membership."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"viewer"}),
        require_all=False,
    )

    assert (
        str(error) == "The authenticated user does not have any of the required roles. "
        "required_roles=['admin', 'billing']; user_roles=['viewer']"
    )
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

    assert (
        str(error) == "The authenticated user does not have all of the required roles. "
        "required_roles=['admin', 'billing']; user_roles=['admin']"
    )
    assert error.code == ErrorCode.INSUFFICIENT_ROLES
    assert error.require_all is True


def test_insufficient_roles_error_none_code_argument_is_rejected() -> None:
    """Role-denial errors inherit the concrete-code requirement."""
    exc_factory = cast("Any", InsufficientRolesError)

    with pytest.raises(TypeError, match="code cannot be None"):
        exc_factory(
            required_roles=frozenset({"admin"}),
            user_roles=frozenset({"viewer"}),
            require_all=False,
            code=None,
        )


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("required_roles", frozenset({"", "admin"})),
        ("required_roles", frozenset({" \t ", "admin"})),
        ("user_roles", frozenset({"", "viewer"})),
        ("user_roles", frozenset({" \n ", "viewer"})),
    ],
)
def test_insufficient_roles_error_blank_role_names_are_rejected(
    field_name: str,
    field_value: frozenset[str],
) -> None:
    """Structured role context must not carry blank role names."""
    exc_factory = cast("Any", InsufficientRolesError)
    kwargs = {
        "required_roles": frozenset({"admin"}),
        "user_roles": frozenset({"viewer"}),
        "require_all": False,
    }
    kwargs[field_name] = field_value

    with pytest.raises(ValueError, match=rf"{field_name} cannot contain empty or whitespace-only role names"):
        exc_factory(**kwargs)


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
    """Duplicate-user errors expose the colliding identifier details."""
    error = UserAlreadyExistsError(
        identifier_type="username",
        identifier_value="existing-user",
    )

    assert str(error) == "User with username='existing-user' already exists"
    assert error.code == ErrorCode.REGISTER_USER_ALREADY_EXISTS
    assert error.identifier_type == "username"
    assert error.identifier_value == "existing-user"


def test_user_already_exists_error_none_message_and_omitted_code_use_context_message() -> None:
    """Explicit ``message=None`` still derives the message from identifier context."""
    error = UserAlreadyExistsError(
        identifier_type="email",
        identifier_value="user@example.com",
        message=None,
    )

    assert str(error) == "User with email='user@example.com' already exists"
    assert error.code == ErrorCode.REGISTER_USER_ALREADY_EXISTS


def test_user_already_exists_error_partial_context_is_rejected() -> None:
    """Context fields must be supplied together so the error remains coherent."""
    exc_factory = cast("Any", UserAlreadyExistsError)

    with pytest.raises(TypeError, match="identifier_type and identifier_value must be provided together"):
        exc_factory(identifier_type="email")


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("identifier_type", ""),
        ("identifier_type", " \t "),
        ("identifier_value", ""),
        ("identifier_value", "\n"),
    ],
)
def test_user_already_exists_error_blank_context_is_rejected(field_name: str, field_value: str) -> None:
    """Duplicate-user context must fail fast when any required string field is blank."""
    exc_factory = cast("Any", UserAlreadyExistsError)
    kwargs = {
        "identifier_type": "email",
        "identifier_value": "user@example.com",
    }
    kwargs[field_name] = field_value

    with pytest.raises(ValueError, match=rf"{field_name} cannot be empty or whitespace-only"):
        exc_factory(**kwargs)


def test_user_already_exists_error_custom_message_and_code_override_defaults() -> None:
    """Duplicate-user errors still accept explicit message and code overrides."""
    error = UserAlreadyExistsError(
        message="custom user exists message",
        code="CUSTOM_REGISTER_USER_ALREADY_EXISTS",
        identifier_type="email",
        identifier_value="user@example.com",
    )

    assert str(error) == "custom user exists message"
    assert error.code == "CUSTOM_REGISTER_USER_ALREADY_EXISTS"
    assert error.identifier_type == "email"
    assert error.identifier_value == "user@example.com"


def test_invalid_password_error_stores_optional_user_id_without_leaking_it_in_default_message() -> None:
    """Invalid-password errors keep operator-only user context off the client-facing detail."""
    error = InvalidPasswordError(user_id="user-123")

    assert str(error) == InvalidPasswordError.default_message
    assert error.code == ErrorCode.LOGIN_BAD_CREDENTIALS
    assert error.user_id == "user-123"


def test_invalid_password_error_custom_message_and_code_preserve_user_id_context() -> None:
    """Custom invalid-password overrides still retain the operator-only context field."""
    user_id = "user-123"
    error = InvalidPasswordError(
        "custom invalid password message",
        "CUSTOM_LOGIN_BAD_CREDENTIALS",
        user_id=user_id,
    )

    assert str(error) == "custom invalid password message"
    assert error.code == "CUSTOM_LOGIN_BAD_CREDENTIALS"
    assert error.user_id == user_id


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
