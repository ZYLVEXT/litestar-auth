"""Custom exception hierarchy for litestar-auth."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

type UserIdentifierType = Literal["email", "username"]


@dataclass(frozen=True, slots=True)
class UserIdentifier:
    """Structured duplicate-user identifier context."""

    identifier_type: UserIdentifierType
    identifier_value: str


class ErrorCode(StrEnum):
    """Machine-readable error codes (``StrEnum``); values match member names."""

    UNKNOWN = "UNKNOWN"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    TOKEN_PROCESSING_FAILED = "TOKEN_PROCESSING_FAILED"
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS"
    REGISTER_FAILED = "REGISTER_FAILED"
    LOGIN_BAD_CREDENTIALS = "LOGIN_BAD_CREDENTIALS"
    LOGIN_USER_INACTIVE = "LOGIN_USER_INACTIVE"
    LOGIN_USER_NOT_VERIFIED = "LOGIN_USER_NOT_VERIFIED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    INSUFFICIENT_ROLES = "INSUFFICIENT_ROLES"
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
    ROLE_ALREADY_EXISTS = "ROLE_ALREADY_EXISTS"
    ROLE_NOT_FOUND = "ROLE_NOT_FOUND"
    ROLE_STILL_ASSIGNED = "ROLE_STILL_ASSIGNED"
    ROLE_ASSIGNMENT_USER_NOT_FOUND = "ROLE_ASSIGNMENT_USER_NOT_FOUND"
    ROLE_NAME_INVALID = "ROLE_NAME_INVALID"
    TOTP_PENDING_BAD_TOKEN = "TOTP_PENDING_BAD_TOKEN"
    TOTP_CODE_INVALID = "TOTP_CODE_INVALID"
    TOTP_ALREADY_ENABLED = "TOTP_ALREADY_ENABLED"
    TOTP_ENROLL_BAD_TOKEN = "TOTP_ENROLL_BAD_TOKEN"


class LitestarAuthError(Exception):
    """Base exception for all library-specific errors."""

    default_message = "An unexpected litestar-auth error occurred."
    default_code = ErrorCode.UNKNOWN

    def __init__(
        self,
        message: str | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize the exception with a default or custom message and explicit or inherited code."""
        resolved_message = message or self.default_message
        resolved_code = code if code is not None else self.default_code
        self.code = resolved_code
        super().__init__(resolved_message)


class AuthenticationError(LitestarAuthError):
    """Raised when authentication fails."""

    default_message = "Authentication failed."
    default_code = ErrorCode.AUTHENTICATION_FAILED


class AuthorizationError(LitestarAuthError):
    """Raised when an authenticated user is not allowed to perform an action."""

    default_message = "Authorization failed."
    default_code = ErrorCode.AUTHORIZATION_DENIED


class InsufficientRolesError(AuthorizationError):
    """Raised when a user does not satisfy a role-based authorization check."""

    default_message = "The authenticated user does not satisfy the required roles."
    default_code = ErrorCode.INSUFFICIENT_ROLES

    def __init__(
        self,
        *,
        required_roles: frozenset[str],
        user_roles: frozenset[str],
        require_all: bool,
        message: str | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize the role-denial error with structured role context."""
        self.required_roles = required_roles
        self.user_roles = user_roles
        self.require_all = require_all
        required_role_phrase = "all of the required roles" if require_all else "any of the required roles"
        # Security: keep structured role context on the exception instance for
        # operators and custom hooks, but do not leak role names in the
        # default human-readable message.
        resolved_message = message or f"The authenticated user does not have {required_role_phrase}."
        super().__init__(message=resolved_message, code=code)


class TokenError(LitestarAuthError):
    """Raised when token operations fail."""

    default_message = "Token processing failed."
    default_code = ErrorCode.TOKEN_PROCESSING_FAILED


class ConfigurationError(LitestarAuthError):
    """Raised when the library is configured incorrectly."""

    default_message = "litestar-auth is configured incorrectly."
    default_code = ErrorCode.CONFIGURATION_INVALID


class UserAlreadyExistsError(AuthenticationError):
    """Raised when creating a user that already exists.

    Duplicate identifier context is stored on the exception instance for
    operator logging, but the generated default message stays generic. The
    public register controller further maps this exception to the shared
    ``REGISTER_FAILED`` response so callers cannot distinguish duplicate
    identifiers from other registration failures.
    """

    default_message = "A user with the provided credentials already exists."
    default_code = ErrorCode.USER_ALREADY_EXISTS

    def __init__(
        self,
        *,
        identifier: UserIdentifier | None = None,
        message: str | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize the duplicate-user error with optional identifier context."""
        self.identifier = identifier
        self.identifier_type = None if identifier is None else identifier.identifier_type
        self.identifier_value = None if identifier is None else identifier.identifier_value
        super().__init__(message=message, code=code)


class UserNotExistsError(AuthenticationError):
    """Raised when a requested user cannot be found."""

    default_message = "The requested user does not exist."
    default_code = ErrorCode.USER_NOT_FOUND


class InvalidPasswordError(AuthenticationError):
    """Raised when a password does not match the stored credentials.

    Optional ``user_id`` context is stored on the instance for operator logging
    without changing the response message sent to clients.
    """

    default_message = "The provided password is invalid."
    default_code = ErrorCode.LOGIN_BAD_CREDENTIALS

    def __init__(
        self,
        *,
        user_id: object | None = None,
        message: str | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize the invalid-password error with optional operator-only context."""
        self.user_id = user_id
        super().__init__(message=message, code=code)


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

    def __init__(
        self,
        *,
        provider: str,
        account_id: str,
        existing_user_id: object,
        message: str | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize the linked-account conflict with provider context."""
        self.provider = provider
        self.account_id = account_id
        self.existing_user_id = existing_user_id
        resolved_message = (
            message
            or f"OAuth account {self.provider}:{self.account_id} is already linked to user {self.existing_user_id}"
        )
        super().__init__(message=resolved_message, code=code)
