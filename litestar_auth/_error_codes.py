"""Machine-readable error codes and structured error context."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, auto
from typing import Literal

type UserIdentifierType = Literal["email", "username"]


@dataclass(frozen=True, slots=True)
class UserIdentifier:
    """Structured duplicate-user identifier context."""

    identifier_type: UserIdentifierType
    identifier_value: str


class ErrorCode(StrEnum):
    """Machine-readable error codes (``StrEnum``); values match member names."""

    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: list[str]) -> str:
        del start, count, last_values
        return name

    UNKNOWN = auto()
    AUTHENTICATION_FAILED = auto()
    TOKEN_PROCESSING_FAILED = auto()
    CONFIGURATION_INVALID = auto()
    USER_NOT_FOUND = auto()
    USER_ALREADY_EXISTS = auto()
    REGISTER_FAILED = auto()
    LOGIN_BAD_CREDENTIALS = auto()
    LOGIN_USER_INACTIVE = auto()
    LOGIN_USER_NOT_VERIFIED = auto()
    AUTHORIZATION_DENIED = auto()
    INSUFFICIENT_ROLES = auto()
    RESET_PASSWORD_BAD_TOKEN = auto()
    RESET_PASSWORD_INVALID_PASSWORD = auto()
    VERIFY_USER_BAD_TOKEN = auto()
    VERIFY_USER_ALREADY_VERIFIED = auto()
    UPDATE_USER_EMAIL_ALREADY_EXISTS = auto()
    UPDATE_USER_INVALID_PASSWORD = auto()
    SUPERUSER_CANNOT_DELETE_SELF = auto()
    OAUTH_NOT_AVAILABLE_EMAIL = auto()
    OAUTH_STATE_INVALID = auto()
    OAUTH_EMAIL_NOT_VERIFIED = auto()
    OAUTH_USER_ALREADY_EXISTS = auto()
    OAUTH_ACCOUNT_ALREADY_LINKED = auto()
    REQUEST_BODY_INVALID = auto()
    LOGIN_PAYLOAD_INVALID = auto()
    REFRESH_TOKEN_INVALID = auto()
    ROLE_ALREADY_EXISTS = auto()
    ROLE_NOT_FOUND = auto()
    ROLE_STILL_ASSIGNED = auto()
    ROLE_ASSIGNMENT_USER_NOT_FOUND = auto()
    ROLE_NAME_INVALID = auto()
    TOTP_PENDING_BAD_TOKEN = auto()
    TOTP_CODE_INVALID = auto()
    TOTP_ALREADY_ENABLED = auto()
    TOTP_ENROLL_BAD_TOKEN = auto()


__all__ = ("ErrorCode", "UserIdentifier", "UserIdentifierType")
