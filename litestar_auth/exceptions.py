"""Custom exception hierarchy for litestar-auth."""

from __future__ import annotations


class ErrorCode:
    """String constants for machine-readable error responses."""

    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    TOKEN_PROCESSING_FAILED = "TOKEN_PROCESSING_FAILED"
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    REGISTER_USER_ALREADY_EXISTS = "REGISTER_USER_ALREADY_EXISTS"
    REGISTER_INVALID_PASSWORD = "REGISTER_INVALID_PASSWORD"
    LOGIN_BAD_CREDENTIALS = "LOGIN_BAD_CREDENTIALS"
    LOGIN_USER_INACTIVE = "LOGIN_USER_INACTIVE"
    LOGIN_USER_NOT_VERIFIED = "LOGIN_USER_NOT_VERIFIED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    RESET_PASSWORD_BAD_TOKEN = "RESET_PASSWORD_BAD_TOKEN"
    RESET_PASSWORD_INVALID_PASSWORD = "RESET_PASSWORD_INVALID_PASSWORD"
    VERIFY_USER_BAD_TOKEN = "VERIFY_USER_BAD_TOKEN"
    VERIFY_USER_ALREADY_VERIFIED = "VERIFY_USER_ALREADY_VERIFIED"
    UPDATE_USER_EMAIL_ALREADY_EXISTS = "UPDATE_USER_EMAIL_ALREADY_EXISTS"
    UPDATE_USER_INVALID_PASSWORD = "UPDATE_USER_INVALID_PASSWORD"
    SUPERUSER_CANNOT_DELETE_SELF = "SUPERUSER_CANNOT_DELETE_SELF"
    OAUTH_NOT_AVAILABLE_EMAIL = "OAUTH_NOT_AVAILABLE_EMAIL"
    OAUTH_STATE_INVALID = "OAUTH_STATE_INVALID"
    OAUTH_EMAIL_NOT_VERIFIED = "OAUTH_EMAIL_NOT_VERIFIED"
    OAUTH_USER_ALREADY_EXISTS = "OAUTH_USER_ALREADY_EXISTS"
    OAUTH_ACCOUNT_ALREADY_LINKED = "OAUTH_ACCOUNT_ALREADY_LINKED"
    REQUEST_BODY_INVALID = "REQUEST_BODY_INVALID"
    LOGIN_PAYLOAD_INVALID = "LOGIN_PAYLOAD_INVALID"
    REFRESH_TOKEN_INVALID = "REFRESH_TOKEN_INVALID"
    TOTP_PENDING_BAD_TOKEN = "TOTP_PENDING_BAD_TOKEN"
    TOTP_CODE_INVALID = "TOTP_CODE_INVALID"
    TOTP_ALREADY_ENABLED = "TOTP_ALREADY_ENABLED"
    TOTP_ENROLL_BAD_TOKEN = "TOTP_ENROLL_BAD_TOKEN"


class LitestarAuthError(Exception):
    """Base exception for all library-specific errors."""

    default_message = "An unexpected litestar-auth error occurred."
    default_code = "UNKNOWN"

    def __init__(self, message: str | None = None, code: str | None = None) -> None:
        """Initialize the exception with a default or custom message and optional code."""
        msg = message or self.default_message
        self.code = code if code is not None else getattr(type(self), "default_code", LitestarAuthError.default_code)
        super().__init__(msg)


class AuthenticationError(LitestarAuthError):
    """Raised when authentication fails."""

    default_message = "Authentication failed."
    default_code = ErrorCode.AUTHENTICATION_FAILED


class AuthorizationError(LitestarAuthError):
    """Raised when an authenticated user is not allowed to perform an action."""

    default_message = "Authorization failed."
    default_code = ErrorCode.AUTHORIZATION_DENIED


class TokenError(LitestarAuthError):
    """Raised when token operations fail."""

    default_message = "Token processing failed."
    default_code = ErrorCode.TOKEN_PROCESSING_FAILED


class ConfigurationError(LitestarAuthError):
    """Raised when the library is configured incorrectly."""

    default_message = "litestar-auth is configured incorrectly."
    default_code = ErrorCode.CONFIGURATION_INVALID


class UserAlreadyExistsError(AuthenticationError):
    """Raised when creating a user that already exists."""

    default_message = "A user with the provided credentials already exists."
    default_code = ErrorCode.REGISTER_USER_ALREADY_EXISTS


class UserNotExistsError(AuthenticationError):
    """Raised when a requested user cannot be found."""

    default_message = "The requested user does not exist."
    default_code = ErrorCode.USER_NOT_FOUND


class InvalidPasswordError(AuthenticationError):
    """Raised when a password does not match the stored credentials."""

    default_message = "The provided password is invalid."
    default_code = ErrorCode.LOGIN_BAD_CREDENTIALS


class InactiveUserError(AuthenticationError):
    """Raised when an operation requires an active account."""

    default_message = "The user account is inactive."
    default_code = ErrorCode.LOGIN_USER_INACTIVE


class UnverifiedUserError(AuthenticationError):
    """Raised when an operation requires a verified account."""

    default_message = "The user account is not verified."
    default_code = ErrorCode.LOGIN_USER_NOT_VERIFIED


class InvalidVerifyTokenError(TokenError):
    """Raised when an email verification token is invalid or expired."""

    default_message = "The email verification token is invalid."
    default_code = ErrorCode.VERIFY_USER_BAD_TOKEN


class InvalidResetPasswordTokenError(TokenError):
    """Raised when a password reset token is invalid or expired."""

    default_message = "The password reset token is invalid."
    default_code = ErrorCode.RESET_PASSWORD_BAD_TOKEN


class OAuthAccountAlreadyLinkedError(AuthenticationError):
    """Raised when an OAuth provider identity is already linked to another user.

    Persistence layer refuses cross-user rebinding: one provider identity
    (oauth_name, account_id) can only be linked to a single local user.
    """

    default_message = (
        "This provider account is already linked to another user. "
        "One provider identity can only be linked to a single local account."
    )
    default_code = ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
