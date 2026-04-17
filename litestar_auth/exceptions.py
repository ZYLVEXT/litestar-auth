"""Custom exception hierarchy for litestar-auth."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Literal, overload


class _UseDefaultCode:
    """Sentinel type for omitted exception-code arguments."""

    __slots__ = ()


_USE_DEFAULT_CODE = _UseDefaultCode()


def _require_non_empty_string(value: str, *, field_name: str) -> str:
    """Reject blank exception context strings while preserving the original value.

    Returns:
        The original ``value`` when it contains at least one non-whitespace character.

    Raises:
        ValueError: If ``value`` is empty or whitespace-only.
    """
    if not value.strip():
        msg = f"{field_name} cannot be empty or whitespace-only."
        raise ValueError(msg)
    return value


def _require_present_context(value: object | None, *, field_name: str) -> object:
    """Reject missing exception context values that are required for diagnostics.

    Returns:
        The original ``value`` when it is present.

    Raises:
        ValueError: If ``value`` is ``None``.
    """
    if value is None:
        msg = f"{field_name} cannot be None."
        raise ValueError(msg)
    return value


def _require_non_empty_role_names(role_names: frozenset[str], *, field_name: str) -> frozenset[str]:
    """Reject blank role names in structured authorization context.

    Returns:
        The original role-name set when every item contains a non-whitespace character.

    Raises:
        ValueError: If any role name is empty or whitespace-only.
    """
    if any(not role_name.strip() for role_name in role_names):
        msg = f"{field_name} cannot contain empty or whitespace-only role names."
        raise ValueError(msg)
    return role_names


class ErrorCode(StrEnum):
    """Machine-readable error codes (``StrEnum``); values match member names."""

    UNKNOWN = "UNKNOWN"
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
    TOTP_PENDING_BAD_TOKEN = "TOTP_PENDING_BAD_TOKEN"
    TOTP_CODE_INVALID = "TOTP_CODE_INVALID"
    TOTP_ALREADY_ENABLED = "TOTP_ALREADY_ENABLED"
    TOTP_ENROLL_BAD_TOKEN = "TOTP_ENROLL_BAD_TOKEN"


class LitestarAuthError(Exception):
    """Base exception for all library-specific errors."""

    default_message = "An unexpected litestar-auth error occurred."
    default_code = ErrorCode.UNKNOWN

    if TYPE_CHECKING:

        @overload
        def __init__(self, message: str | None = None) -> None: ...

        @overload
        def __init__(self, message: str | None, code: str) -> None: ...

    def __init__(
        self,
        message: str | None = None,
        code: str | _UseDefaultCode | None = _USE_DEFAULT_CODE,
    ) -> None:
        """Initialize the exception with a default or custom message and explicit or inherited code.

        Raises:
            TypeError: If ``code=None`` is passed instead of omitting the argument.
        """
        resolved_message = message or self.default_message
        if isinstance(code, _UseDefaultCode):
            resolved_code = self.default_code
        elif code is None:
            msg = "code cannot be None; omit it to use the class default."
            raise TypeError(msg)
        else:
            resolved_code = code
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

    if TYPE_CHECKING:

        @overload
        def __init__(
            self,
            *,
            required_roles: frozenset[str],
            user_roles: frozenset[str],
            require_all: bool,
            message: str | None = None,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            required_roles: frozenset[str],
            user_roles: frozenset[str],
            require_all: bool,
            message: str | None = None,
            code: _UseDefaultCode = _USE_DEFAULT_CODE,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            required_roles: frozenset[str],
            user_roles: frozenset[str],
            require_all: bool,
            message: str | None,
            code: str,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            required_roles: frozenset[str],
            user_roles: frozenset[str],
            require_all: bool,
            message: str | None,
            code: None,
        ) -> None: ...

    def __init__(
        self,
        *,
        required_roles: frozenset[str],
        user_roles: frozenset[str],
        require_all: bool,
        message: str | None = None,
        code: str | _UseDefaultCode | None = _USE_DEFAULT_CODE,
    ) -> None:
        """Initialize the role-denial error with structured role context.

        Raises:
            TypeError: If ``code=None`` is passed instead of omitting the argument.
        """
        self.required_roles = _require_non_empty_role_names(required_roles, field_name="required_roles")
        self.user_roles = _require_non_empty_role_names(user_roles, field_name="user_roles")
        self.require_all = require_all
        required_role_phrase = "all of the required roles" if require_all else "any of the required roles"
        resolved_message = (
            message
            or f"The authenticated user does not have {required_role_phrase}. "
            f"required_roles={sorted(self.required_roles)!r}; user_roles={sorted(self.user_roles)!r}"
        )
        if isinstance(code, _UseDefaultCode):
            super().__init__(message=resolved_message)
            return
        if code is None:
            msg = "code cannot be None; omit it to use the class default."
            raise TypeError(msg)
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
    """Raised when creating a user that already exists."""

    default_message = "A user with the provided credentials already exists."
    default_code = ErrorCode.REGISTER_USER_ALREADY_EXISTS

    if TYPE_CHECKING:

        @overload
        def __init__(self, message: str | None = None) -> None: ...

        @overload
        def __init__(self, message: str | None, code: str) -> None: ...

        @overload
        def __init__(
            self,
            *,
            identifier_type: Literal["email", "username"],
            identifier_value: str,
            message: str | None = None,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            identifier_type: Literal["email", "username"],
            identifier_value: str,
            message: str | None = None,
            code: _UseDefaultCode = _USE_DEFAULT_CODE,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            identifier_type: Literal["email", "username"],
            identifier_value: str,
            message: str | None,
            code: str,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            identifier_type: Literal["email", "username"],
            identifier_value: str,
            message: str | None,
            code: None,
        ) -> None: ...

    def __init__(
        self,
        message: str | None = None,
        code: str | _UseDefaultCode | None = _USE_DEFAULT_CODE,
        *,
        identifier_type: Literal["email", "username"] | None = None,
        identifier_value: str | None = None,
    ) -> None:
        """Initialize the duplicate-user error with optional identifier context.

        Raises:
            TypeError: If ``code=None`` is passed or only one context field is supplied.
        """
        if (identifier_type is None) != (identifier_value is None):
            msg = "identifier_type and identifier_value must be provided together."
            raise TypeError(msg)
        if identifier_type is not None and identifier_value is not None:
            self.identifier_type = _require_non_empty_string(identifier_type, field_name="identifier_type")
            self.identifier_value = _require_non_empty_string(identifier_value, field_name="identifier_value")
        else:
            self.identifier_type = None
            self.identifier_value = None
        resolved_message = message or (
            f"User with {self.identifier_type}={self.identifier_value!r} already exists"
            if self.identifier_type is not None and self.identifier_value is not None
            else None
        )
        if isinstance(code, _UseDefaultCode):
            super().__init__(message=resolved_message)
            return
        if code is None:
            msg = "code cannot be None; omit it to use the class default."
            raise TypeError(msg)
        super().__init__(message=resolved_message, code=code)


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

    if TYPE_CHECKING:

        @overload
        def __init__(self, message: str | None = None, *, user_id: object | None = None) -> None: ...

        @overload
        def __init__(self, message: str | None, code: str, *, user_id: object | None = None) -> None: ...

        @overload
        def __init__(self, message: str | None, code: None, *, user_id: object | None = None) -> None: ...

    def __init__(
        self,
        message: str | None = None,
        code: str | _UseDefaultCode | None = _USE_DEFAULT_CODE,
        *,
        user_id: object | None = None,
    ) -> None:
        """Initialize the invalid-password error with optional operator-only context.

        Raises:
            TypeError: If ``code=None`` is passed instead of omitting the argument.
        """
        self.user_id = user_id
        if isinstance(code, _UseDefaultCode):
            super().__init__(message=message)
            return
        if code is None:
            msg = "code cannot be None; omit it to use the class default."
            raise TypeError(msg)
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

    if TYPE_CHECKING:

        @overload
        def __init__(
            self,
            *,
            provider: str,
            account_id: str,
            existing_user_id: object,
            message: str | None = None,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            provider: str,
            account_id: str,
            existing_user_id: object,
            message: str | None = None,
            code: _UseDefaultCode = _USE_DEFAULT_CODE,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            provider: str,
            account_id: str,
            existing_user_id: object,
            message: str | None,
            code: str,
        ) -> None: ...

        @overload
        def __init__(
            self,
            *,
            provider: str,
            account_id: str,
            existing_user_id: object,
            message: str | None,
            code: None,
        ) -> None: ...

    def __init__(
        self,
        *,
        provider: str,
        account_id: str,
        existing_user_id: object,
        message: str | None = None,
        code: str | _UseDefaultCode | None = _USE_DEFAULT_CODE,
    ) -> None:
        """Initialize the linked-account conflict with provider context.

        Raises:
            TypeError: If ``code=None`` is passed instead of omitting the argument.
        """
        self.provider = _require_non_empty_string(provider, field_name="provider")
        self.account_id = _require_non_empty_string(account_id, field_name="account_id")
        self.existing_user_id = _require_present_context(existing_user_id, field_name="existing_user_id")
        resolved_message = (
            message
            or f"OAuth account {self.provider}:{self.account_id} is already linked to user {self.existing_user_id}"
        )
        if isinstance(code, _UseDefaultCode):
            super().__init__(message=resolved_message)
            return
        if code is None:
            msg = "code cannot be None; omit it to use the class default."
            raise TypeError(msg)
        super().__init__(message=resolved_message, code=code)
