"""Custom exception hierarchy for litestar-auth."""

from __future__ import annotations

from litestar.exceptions import ClientException

from litestar_auth._error_codes import ErrorCode, UserIdentifier


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


def totp_stepup_required_exception() -> ClientException:
    """Return the stable 403 client response for missing recent TOTP verification."""
    msg = "Recent TOTP verification is required."
    return ClientException(status_code=403, detail=msg, extra={"code": ErrorCode.TOTP_STEPUP_REQUIRED})


class TokenError(LitestarAuthError):
    """Raised when token operations fail."""

    default_message = "Token processing failed."
    default_code = ErrorCode.TOKEN_PROCESSING_FAILED


class SessionManagementUnsupportedError(TokenError):
    """Raised when a strategy cannot manage refresh sessions."""

    default_message = "The configured auth strategy does not support refresh-session management."
    default_code = ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED


class RefreshSessionNotFoundError(TokenError):
    """Raised when a user-scoped refresh session cannot be found."""

    default_message = "Refresh session not found."
    default_code = ErrorCode.REFRESH_SESSION_NOT_FOUND


class ConfigurationError(LitestarAuthError):
    """Raised when the library is configured incorrectly."""

    default_message = "litestar-auth is configured incorrectly."
    default_code = ErrorCode.CONFIGURATION_INVALID


class ApiKeyError(LitestarAuthError):
    """Raised when an API-key manager operation fails."""

    default_message = "API-key operation failed."
    default_code = ErrorCode.AUTHORIZATION_DENIED


class ApiKeyNotFoundError(ApiKeyError):
    """Raised when an API key cannot be found in the caller's ownership scope."""

    default_message = "API key not found."


class ApiKeyScopeDeniedError(ApiKeyError):
    """Raised when requested API-key scopes are outside the configured whitelist."""

    default_message = "One or more requested API-key scopes are not allowed."

    def __init__(
        self,
        *,
        denied_scopes: frozenset[str],
        message: str | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize the scope-denial error with structured scope context."""
        self.denied_scopes = denied_scopes
        super().__init__(message=message, code=code)


class ApiKeyLimitReachedError(ApiKeyError):
    """Raised when a user has reached the configured active API-key limit."""

    default_message = "API-key limit reached."

    def __init__(
        self,
        *,
        max_keys_per_user: int,
        message: str | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize the limit error with structured policy context."""
        self.max_keys_per_user = max_keys_per_user
        super().__init__(message=message, code=code)


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
    default_code = ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE


class UnverifiedUserError(AuthenticationError):
    """Raised when an operation requires a verified account."""

    default_message = "The user account is not verified."
    default_code = ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE


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
