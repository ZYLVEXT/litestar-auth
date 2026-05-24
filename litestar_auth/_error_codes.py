"""Machine-readable error codes and structured error context."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, auto
from typing import Literal, Self

type UserIdentifierType = Literal["email", "username"]


@dataclass(frozen=True, slots=True)
class UserIdentifier:
    """Structured duplicate-user identifier context."""

    identifier_type: UserIdentifierType
    identifier_value: str


class _DocumentedErrorCode(StrEnum):
    """Base ``StrEnum`` for documented machine-readable error-code groups."""

    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: list[str]) -> str:
        del start, count, last_values
        return name

    def __new__(cls, value: str, doc: str = "") -> Self:
        """Create an error-code member with an optional emission-site docstring."""
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.__doc__ = doc
        return obj


class AuthErrorCode(_DocumentedErrorCode):
    """Authentication, authorization, account, request-validation, and configuration error codes."""

    UNKNOWN = auto()
    AUTHENTICATION_FAILED = auto()
    CONFIGURATION_INVALID = auto()
    USER_NOT_FOUND = auto()
    USER_ALREADY_EXISTS = ("USER_ALREADY_EXISTS", "Emitted by UserAlreadyExistsError.")
    REGISTER_FAILED = ("REGISTER_FAILED", "Emitted by bundled register controller domain-error collapse.")
    LOGIN_BAD_CREDENTIALS = ("LOGIN_BAD_CREDENTIALS", "Emitted by InvalidPasswordError and login credential failures.")
    LOGIN_ACCOUNT_UNAVAILABLE = (
        "LOGIN_ACCOUNT_UNAVAILABLE",
        "Emitted by InactiveUserError, UnverifiedUserError, and account-state HTTP guards.",
    )
    AUTHORIZATION_DENIED = ("AUTHORIZATION_DENIED", "Emitted by AuthorizationError and bearer-auth guards.")
    REQUEST_BODY_INVALID = ("REQUEST_BODY_INVALID", "Emitted by request-body decoding and validation helpers.")
    LOGIN_PAYLOAD_INVALID = ("LOGIN_PAYLOAD_INVALID", "Emitted by login payload validation helpers.")
    UPDATE_USER_EMAIL_ALREADY_EXISTS = (
        "UPDATE_USER_EMAIL_ALREADY_EXISTS",
        "Emitted by user-update email conflict mapping.",
    )
    UPDATE_USER_INVALID_PASSWORD = (
        "UPDATE_USER_INVALID_PASSWORD",
        "Emitted by user-update password validation mapping.",
    )
    SUPERUSER_CANNOT_DELETE_SELF = (
        "SUPERUSER_CANNOT_DELETE_SELF",
        "Emitted by user-delete self-protection checks.",
    )


class TokenErrorCode(_DocumentedErrorCode):
    """Token, password-reset, email-verification, and refresh-session error codes."""

    TOKEN_PROCESSING_FAILED = auto()
    RESET_PASSWORD_BAD_TOKEN = ("RESET_PASSWORD_BAD_TOKEN", "Emitted by InvalidResetPasswordTokenError.")
    RESET_PASSWORD_INVALID_PASSWORD = (
        "RESET_PASSWORD_INVALID_PASSWORD",
        "Emitted by reset-password password-policy mapping.",
    )
    VERIFY_USER_BAD_TOKEN = ("VERIFY_USER_BAD_TOKEN", "Emitted by InvalidVerifyTokenError.")
    VERIFY_USER_ALREADY_VERIFIED = (
        "VERIFY_USER_ALREADY_VERIFIED",
        "Emitted by verify-user route when the account is already verified.",
    )
    REFRESH_TOKEN_INVALID = ("REFRESH_TOKEN_INVALID", "Emitted by refresh-token validation and replay checks.")
    SESSION_MANAGEMENT_UNSUPPORTED = (
        "SESSION_MANAGEMENT_UNSUPPORTED",
        "Emitted by SessionManagementUnsupportedError and session-device routes.",
    )
    REFRESH_SESSION_NOT_FOUND = (
        "REFRESH_SESSION_NOT_FOUND",
        "Emitted by RefreshSessionNotFoundError and session-device routes.",
    )


class RoleErrorCode(_DocumentedErrorCode):
    """Role guard and bundled role-admin route error codes."""

    INSUFFICIENT_ROLES = ("INSUFFICIENT_ROLES", "Emitted by InsufficientRolesError.")
    ROLE_ALREADY_EXISTS = ("ROLE_ALREADY_EXISTS", "Emitted by role-admin create conflicts.")
    ROLE_NOT_FOUND = ("ROLE_NOT_FOUND", "Emitted by role-admin lookup failures.")
    ROLE_STILL_ASSIGNED = ("ROLE_STILL_ASSIGNED", "Emitted by role-admin delete protection.")
    ROLE_ASSIGNMENT_USER_NOT_FOUND = (
        "ROLE_ASSIGNMENT_USER_NOT_FOUND",
        "Emitted by role-admin user-assignment lookup failures.",
    )
    ROLE_NAME_INVALID = ("ROLE_NAME_INVALID", "Emitted by role-admin role-name validation.")


class TotpErrorCode(_DocumentedErrorCode):
    """TOTP enrollment, verification, and step-up error codes."""

    TOTP_PENDING_BAD_TOKEN = ("TOTP_PENDING_BAD_TOKEN", "Emitted by pending TOTP session-token validation.")
    TOTP_CODE_INVALID = ("TOTP_CODE_INVALID", "Emitted by TOTP code verification failures.")
    TOTP_ALREADY_ENABLED = ("TOTP_ALREADY_ENABLED", "Emitted by TOTP enablement guards.")
    TOTP_ENROLL_BAD_TOKEN = ("TOTP_ENROLL_BAD_TOKEN", "Emitted by TOTP enrollment-token validation.")
    TOTP_STEPUP_REQUIRED = ("TOTP_STEPUP_REQUIRED", "Emitted by TOTP step-up guard failures.")


class OAuthErrorCode(_DocumentedErrorCode):
    """OAuth callback, linking, and provider-account error codes."""

    OAUTH_NOT_AVAILABLE_EMAIL = (
        "OAUTH_NOT_AVAILABLE_EMAIL",
        "Emitted by OAuth callbacks when a provider does not return an email.",
    )
    OAUTH_STATE_INVALID = ("OAUTH_STATE_INVALID", "Emitted by OAuth flow-cookie and callback state validation.")
    OAUTH_EMAIL_NOT_VERIFIED = (
        "OAUTH_EMAIL_NOT_VERIFIED",
        "Emitted by OAuth callbacks requiring a verified provider email.",
    )
    OAUTH_USER_ALREADY_EXISTS = ("OAUTH_USER_ALREADY_EXISTS", "Emitted by OAuth local-account conflict mapping.")
    OAUTH_ACCOUNT_ALREADY_LINKED = (
        "OAUTH_ACCOUNT_ALREADY_LINKED",
        "Emitted by OAuthAccountAlreadyLinkedError.",
    )


class ApiKeyErrorCode(_DocumentedErrorCode):
    """API-key bearer, scope, quota, and request-signature error codes."""

    # See docs/security.md#bearer-failure-code-taxonomy for the API-key disclosure trade-off.
    API_KEY_INVALID = ("API_KEY_INVALID", "Emitted by API-key credential validation and non-enumerating lookups.")
    # See docs/security.md#bearer-failure-code-taxonomy for the API-key disclosure trade-off.
    API_KEY_REVOKED = ("API_KEY_REVOKED", "Emitted by API-key strategy revoked-key classification.")
    # See docs/security.md#bearer-failure-code-taxonomy for the API-key disclosure trade-off.
    API_KEY_EXPIRED = ("API_KEY_EXPIRED", "Emitted by API-key strategy expiry classification.")
    API_KEY_SCOPE_DENIED = ("API_KEY_SCOPE_DENIED", "Emitted by ApiKeyScopeDeniedError and API-key scope guards.")
    API_KEY_LIMIT_REACHED = ("API_KEY_LIMIT_REACHED", "Emitted by ApiKeyLimitReachedError.")
    API_KEY_SIGNATURE_INVALID = (
        "API_KEY_SIGNATURE_INVALID",
        "Emitted by signed API-key request validation failures.",
    )
    API_KEY_SIGNATURE_TIMESTAMP_SKEW = (
        "API_KEY_SIGNATURE_TIMESTAMP_SKEW",
        "Emitted by signed API-key timestamp-window validation.",
    )
    API_KEY_SIGNATURE_NONCE_REPLAY = (
        "API_KEY_SIGNATURE_NONCE_REPLAY",
        "Emitted by signed API-key nonce replay detection.",
    )


def _documented_member(member: _DocumentedErrorCode) -> tuple[str, str]:
    """Return a value/doc tuple for the aggregate ``ErrorCode`` registry."""
    return member.value, member.__doc__ or ""


class ErrorCode(_DocumentedErrorCode):
    """Aggregate machine-readable error-code registry; values match member names."""

    UNKNOWN = _documented_member(AuthErrorCode.UNKNOWN)
    AUTHENTICATION_FAILED = _documented_member(AuthErrorCode.AUTHENTICATION_FAILED)
    TOKEN_PROCESSING_FAILED = _documented_member(TokenErrorCode.TOKEN_PROCESSING_FAILED)
    CONFIGURATION_INVALID = _documented_member(AuthErrorCode.CONFIGURATION_INVALID)
    USER_NOT_FOUND = _documented_member(AuthErrorCode.USER_NOT_FOUND)
    USER_ALREADY_EXISTS = _documented_member(AuthErrorCode.USER_ALREADY_EXISTS)
    REGISTER_FAILED = _documented_member(AuthErrorCode.REGISTER_FAILED)
    LOGIN_BAD_CREDENTIALS = _documented_member(AuthErrorCode.LOGIN_BAD_CREDENTIALS)
    LOGIN_ACCOUNT_UNAVAILABLE = _documented_member(AuthErrorCode.LOGIN_ACCOUNT_UNAVAILABLE)
    AUTHORIZATION_DENIED = _documented_member(AuthErrorCode.AUTHORIZATION_DENIED)
    INSUFFICIENT_ROLES = _documented_member(RoleErrorCode.INSUFFICIENT_ROLES)
    RESET_PASSWORD_BAD_TOKEN = _documented_member(TokenErrorCode.RESET_PASSWORD_BAD_TOKEN)
    RESET_PASSWORD_INVALID_PASSWORD = _documented_member(TokenErrorCode.RESET_PASSWORD_INVALID_PASSWORD)
    VERIFY_USER_BAD_TOKEN = _documented_member(TokenErrorCode.VERIFY_USER_BAD_TOKEN)
    VERIFY_USER_ALREADY_VERIFIED = _documented_member(TokenErrorCode.VERIFY_USER_ALREADY_VERIFIED)
    UPDATE_USER_EMAIL_ALREADY_EXISTS = _documented_member(AuthErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS)
    UPDATE_USER_INVALID_PASSWORD = _documented_member(AuthErrorCode.UPDATE_USER_INVALID_PASSWORD)
    SUPERUSER_CANNOT_DELETE_SELF = _documented_member(AuthErrorCode.SUPERUSER_CANNOT_DELETE_SELF)
    OAUTH_NOT_AVAILABLE_EMAIL = _documented_member(OAuthErrorCode.OAUTH_NOT_AVAILABLE_EMAIL)
    OAUTH_STATE_INVALID = _documented_member(OAuthErrorCode.OAUTH_STATE_INVALID)
    OAUTH_EMAIL_NOT_VERIFIED = _documented_member(OAuthErrorCode.OAUTH_EMAIL_NOT_VERIFIED)
    OAUTH_USER_ALREADY_EXISTS = _documented_member(OAuthErrorCode.OAUTH_USER_ALREADY_EXISTS)
    OAUTH_ACCOUNT_ALREADY_LINKED = _documented_member(OAuthErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED)
    REQUEST_BODY_INVALID = _documented_member(AuthErrorCode.REQUEST_BODY_INVALID)
    LOGIN_PAYLOAD_INVALID = _documented_member(AuthErrorCode.LOGIN_PAYLOAD_INVALID)
    REFRESH_TOKEN_INVALID = _documented_member(TokenErrorCode.REFRESH_TOKEN_INVALID)
    SESSION_MANAGEMENT_UNSUPPORTED = _documented_member(TokenErrorCode.SESSION_MANAGEMENT_UNSUPPORTED)
    REFRESH_SESSION_NOT_FOUND = _documented_member(TokenErrorCode.REFRESH_SESSION_NOT_FOUND)
    ROLE_ALREADY_EXISTS = _documented_member(RoleErrorCode.ROLE_ALREADY_EXISTS)
    ROLE_NOT_FOUND = _documented_member(RoleErrorCode.ROLE_NOT_FOUND)
    ROLE_STILL_ASSIGNED = _documented_member(RoleErrorCode.ROLE_STILL_ASSIGNED)
    ROLE_ASSIGNMENT_USER_NOT_FOUND = _documented_member(RoleErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND)
    ROLE_NAME_INVALID = _documented_member(RoleErrorCode.ROLE_NAME_INVALID)
    TOTP_PENDING_BAD_TOKEN = _documented_member(TotpErrorCode.TOTP_PENDING_BAD_TOKEN)
    TOTP_CODE_INVALID = _documented_member(TotpErrorCode.TOTP_CODE_INVALID)
    TOTP_ALREADY_ENABLED = _documented_member(TotpErrorCode.TOTP_ALREADY_ENABLED)
    TOTP_ENROLL_BAD_TOKEN = _documented_member(TotpErrorCode.TOTP_ENROLL_BAD_TOKEN)
    TOTP_STEPUP_REQUIRED = _documented_member(TotpErrorCode.TOTP_STEPUP_REQUIRED)
    API_KEY_INVALID = _documented_member(ApiKeyErrorCode.API_KEY_INVALID)
    API_KEY_REVOKED = _documented_member(ApiKeyErrorCode.API_KEY_REVOKED)
    API_KEY_EXPIRED = _documented_member(ApiKeyErrorCode.API_KEY_EXPIRED)
    API_KEY_SCOPE_DENIED = _documented_member(ApiKeyErrorCode.API_KEY_SCOPE_DENIED)
    API_KEY_LIMIT_REACHED = _documented_member(ApiKeyErrorCode.API_KEY_LIMIT_REACHED)
    API_KEY_SIGNATURE_INVALID = _documented_member(ApiKeyErrorCode.API_KEY_SIGNATURE_INVALID)
    API_KEY_SIGNATURE_TIMESTAMP_SKEW = _documented_member(ApiKeyErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW)
    API_KEY_SIGNATURE_NONCE_REPLAY = _documented_member(ApiKeyErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY)


ERROR_CODE_REGISTRY: dict[ErrorCode, _DocumentedErrorCode] = {
    ErrorCode.UNKNOWN: AuthErrorCode.UNKNOWN,
    ErrorCode.AUTHENTICATION_FAILED: AuthErrorCode.AUTHENTICATION_FAILED,
    ErrorCode.TOKEN_PROCESSING_FAILED: TokenErrorCode.TOKEN_PROCESSING_FAILED,
    ErrorCode.CONFIGURATION_INVALID: AuthErrorCode.CONFIGURATION_INVALID,
    ErrorCode.USER_NOT_FOUND: AuthErrorCode.USER_NOT_FOUND,
    ErrorCode.USER_ALREADY_EXISTS: AuthErrorCode.USER_ALREADY_EXISTS,
    ErrorCode.REGISTER_FAILED: AuthErrorCode.REGISTER_FAILED,
    ErrorCode.LOGIN_BAD_CREDENTIALS: AuthErrorCode.LOGIN_BAD_CREDENTIALS,
    ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE: AuthErrorCode.LOGIN_ACCOUNT_UNAVAILABLE,
    ErrorCode.AUTHORIZATION_DENIED: AuthErrorCode.AUTHORIZATION_DENIED,
    ErrorCode.INSUFFICIENT_ROLES: RoleErrorCode.INSUFFICIENT_ROLES,
    ErrorCode.RESET_PASSWORD_BAD_TOKEN: TokenErrorCode.RESET_PASSWORD_BAD_TOKEN,
    ErrorCode.RESET_PASSWORD_INVALID_PASSWORD: TokenErrorCode.RESET_PASSWORD_INVALID_PASSWORD,
    ErrorCode.VERIFY_USER_BAD_TOKEN: TokenErrorCode.VERIFY_USER_BAD_TOKEN,
    ErrorCode.VERIFY_USER_ALREADY_VERIFIED: TokenErrorCode.VERIFY_USER_ALREADY_VERIFIED,
    ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS: AuthErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS,
    ErrorCode.UPDATE_USER_INVALID_PASSWORD: AuthErrorCode.UPDATE_USER_INVALID_PASSWORD,
    ErrorCode.SUPERUSER_CANNOT_DELETE_SELF: AuthErrorCode.SUPERUSER_CANNOT_DELETE_SELF,
    ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL: OAuthErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
    ErrorCode.OAUTH_STATE_INVALID: OAuthErrorCode.OAUTH_STATE_INVALID,
    ErrorCode.OAUTH_EMAIL_NOT_VERIFIED: OAuthErrorCode.OAUTH_EMAIL_NOT_VERIFIED,
    ErrorCode.OAUTH_USER_ALREADY_EXISTS: OAuthErrorCode.OAUTH_USER_ALREADY_EXISTS,
    ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED: OAuthErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED,
    ErrorCode.REQUEST_BODY_INVALID: AuthErrorCode.REQUEST_BODY_INVALID,
    ErrorCode.LOGIN_PAYLOAD_INVALID: AuthErrorCode.LOGIN_PAYLOAD_INVALID,
    ErrorCode.REFRESH_TOKEN_INVALID: TokenErrorCode.REFRESH_TOKEN_INVALID,
    ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED: TokenErrorCode.SESSION_MANAGEMENT_UNSUPPORTED,
    ErrorCode.REFRESH_SESSION_NOT_FOUND: TokenErrorCode.REFRESH_SESSION_NOT_FOUND,
    ErrorCode.ROLE_ALREADY_EXISTS: RoleErrorCode.ROLE_ALREADY_EXISTS,
    ErrorCode.ROLE_NOT_FOUND: RoleErrorCode.ROLE_NOT_FOUND,
    ErrorCode.ROLE_STILL_ASSIGNED: RoleErrorCode.ROLE_STILL_ASSIGNED,
    ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND: RoleErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND,
    ErrorCode.ROLE_NAME_INVALID: RoleErrorCode.ROLE_NAME_INVALID,
    ErrorCode.TOTP_PENDING_BAD_TOKEN: TotpErrorCode.TOTP_PENDING_BAD_TOKEN,
    ErrorCode.TOTP_CODE_INVALID: TotpErrorCode.TOTP_CODE_INVALID,
    ErrorCode.TOTP_ALREADY_ENABLED: TotpErrorCode.TOTP_ALREADY_ENABLED,
    ErrorCode.TOTP_ENROLL_BAD_TOKEN: TotpErrorCode.TOTP_ENROLL_BAD_TOKEN,
    ErrorCode.TOTP_STEPUP_REQUIRED: TotpErrorCode.TOTP_STEPUP_REQUIRED,
    ErrorCode.API_KEY_INVALID: ApiKeyErrorCode.API_KEY_INVALID,
    ErrorCode.API_KEY_REVOKED: ApiKeyErrorCode.API_KEY_REVOKED,
    ErrorCode.API_KEY_EXPIRED: ApiKeyErrorCode.API_KEY_EXPIRED,
    ErrorCode.API_KEY_SCOPE_DENIED: ApiKeyErrorCode.API_KEY_SCOPE_DENIED,
    ErrorCode.API_KEY_LIMIT_REACHED: ApiKeyErrorCode.API_KEY_LIMIT_REACHED,
    ErrorCode.API_KEY_SIGNATURE_INVALID: ApiKeyErrorCode.API_KEY_SIGNATURE_INVALID,
    ErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW: ApiKeyErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW,
    ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY: ApiKeyErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY,
}


__all__ = (
    "ERROR_CODE_REGISTRY",
    "ApiKeyErrorCode",
    "AuthErrorCode",
    "ErrorCode",
    "OAuthErrorCode",
    "RoleErrorCode",
    "TokenErrorCode",
    "TotpErrorCode",
    "UserIdentifier",
    "UserIdentifierType",
)
