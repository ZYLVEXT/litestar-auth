"""Shared account-state validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, NoReturn, Protocol, cast

from litestar.exceptions import ClientException, PermissionDeniedException

from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards._guards import _ACCOUNT_STATE_DETAIL
from litestar_auth.types import GuardedUserProtocol

_HTTP_BAD_REQUEST = 400

type AccountStateFailure = Literal["inactive", "unverified"]


@dataclass(frozen=True, slots=True)
class AccountStateErrorTypes:
    """Caller-provided domain exceptions used for account-state failures."""

    inactive_error: type[BaseException]
    unverified_error: type[BaseException]


class AccountStateValidator(Protocol):
    """Callable account-state validator contract used across auth flows."""

    def __call__(self, user: object, *, require_verified: bool) -> None:
        """Validate the given user account state."""


def resolve_account_state_validator(
    user_manager: object | None,
) -> AccountStateValidator | None:
    """Return an optional account-state validator exposed by a manager."""
    if user_manager is None:
        return None

    validator = getattr(user_manager, "require_account_state", None)
    if callable(validator):
        return cast("AccountStateValidator", validator)

    return None


def resolve_account_state_attribute_failure(
    user: object,
    *,
    require_verified: bool,
    prioritize_unverified: bool,
) -> AccountStateFailure | None:
    """Return the account-state failure implied by guarded user attributes.

    Raises:
        PermissionDeniedException: If the user is not a guarded-user protocol instance.
    """
    if not isinstance(user, GuardedUserProtocol):
        raise PermissionDeniedException(detail=_ACCOUNT_STATE_DETAIL)
    is_active = user.is_active
    is_verified = user.is_verified

    if prioritize_unverified and require_verified and not is_verified:
        return "unverified"
    if not is_active:
        return "inactive"
    if require_verified and not is_verified:
        return "unverified"
    return None


def resolve_account_state_failure(
    user: object,
    *,
    require_verified: bool,
    prioritize_unverified: bool,
    user_manager: object | None,
) -> AccountStateFailure | None:
    """Return the current account-state failure from manager seam or attribute fallback."""
    validator = resolve_account_state_validator(user_manager)
    if validator is not None:
        validator(user, require_verified=require_verified)
        return None

    return resolve_account_state_attribute_failure(
        user,
        require_verified=require_verified,
        prioritize_unverified=prioritize_unverified,
    )


def require_account_state(
    user: object,
    *,
    require_verified: bool,
    prioritize_unverified: bool,
    user_manager: object | None,
    error_types: AccountStateErrorTypes,
) -> None:
    """Enforce account-state policy via manager validator or guarded-user attributes."""
    failure = resolve_account_state_failure(
        user,
        require_verified=require_verified,
        prioritize_unverified=prioritize_unverified,
        user_manager=user_manager,
    )
    if failure is not None:
        raise_account_state_failure(
            failure,
            inactive_error=error_types.inactive_error,
            unverified_error=error_types.unverified_error,
        )


def resolve_account_state_client_error(
    failure: AccountStateFailure,
) -> tuple[int, str]:
    """Map account-state failures to the stable client response payload.

    Returns:
        Stable status code and error code for the internal account-state failure.
    """
    error_code = ErrorCode.LOGIN_USER_INACTIVE if failure == "inactive" else ErrorCode.LOGIN_USER_NOT_VERIFIED
    return _HTTP_BAD_REQUEST, error_code


def raise_account_state_client_exception(
    failure: AccountStateFailure,
    *,
    detail: str,
    cause: BaseException,
) -> NoReturn:
    """Raise the stable client-facing payload for an account-state failure.

    Raises:
        ClientException: Always raised with the stable login account-state payload.
    """
    status_code, error_code = resolve_account_state_client_error(failure)
    raise ClientException(status_code=status_code, detail=detail, extra={"code": error_code}) from cause


def require_account_state_with_client_error(
    user: object,
    *,
    require_verified: bool,
    prioritize_unverified: bool,
    user_manager: object | None,
    error_types: AccountStateErrorTypes,
) -> None:
    """Enforce account-state policy and translate domain failures to ``ClientException``."""
    try:
        require_account_state(
            user,
            require_verified=require_verified,
            prioritize_unverified=prioritize_unverified,
            user_manager=user_manager,
            error_types=error_types,
        )
    except error_types.inactive_error as exc:
        raise_account_state_client_exception("inactive", detail=str(exc), cause=exc)
    except error_types.unverified_error as exc:
        raise_account_state_client_exception("unverified", detail=str(exc), cause=exc)


def raise_account_state_failure(
    failure: AccountStateFailure,
    *,
    inactive_error: type[BaseException],
    unverified_error: type[BaseException],
) -> NoReturn:
    """Raise the caller-provided domain exception for the given account-state failure."""
    if failure == "inactive":
        raise inactive_error
    raise unverified_error
