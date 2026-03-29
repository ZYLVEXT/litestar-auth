"""Shared internal helpers for controller classes."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Protocol, cast

import msgspec
from litestar import Request
from litestar.exceptions import ClientException, PermissionDeniedException

from litestar_auth.config import is_testing
from litestar_auth.exceptions import ConfigurationError, ErrorCode, InactiveUserError, UnverifiedUserError
from litestar_auth.guards._guards import _ACCOUNT_STATE_DETAIL
from litestar_auth.types import GuardedUserProtocol

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from litestar_auth.ratelimit import EndpointRateLimit

type RequestHandler = Callable[[Request[Any, Any, Any]], Awaitable[None]]
type ErrorCallback = Callable[[Request[Any, Any, Any]], Awaitable[None]]
type AccountStateFailureCallback = Callable[[], Awaitable[None]]
type DomainErrorMap = Mapping[type[Exception], tuple[int, str]]


class AccountStateValidator(Protocol):
    """Callable account-state validator contract used by controller helpers."""

    def __call__(self, user: object, *, require_verified: bool) -> None:
        """Validate the given user account state."""


class AccountStateValidatorProvider[UP](Protocol):
    """Explicit manager seam for controller account-state validation."""

    def require_account_state(self, user: UP, *, require_verified: bool = False) -> None:
        """Validate active and optionally verified account state."""


async def _decode_request_body(  # noqa: PLR0913
    request: Request[Any, Any, Any],
    *,
    schema: type[msgspec.Struct],
    on_error: ErrorCallback | None = None,
    validation_detail: str = "Invalid request payload.",
    validation_code: str = ErrorCode.REQUEST_BODY_INVALID,
    decode_detail: str = "Invalid request body.",
    decode_code: str = ErrorCode.REQUEST_BODY_INVALID,
) -> msgspec.Struct:
    """Decode a JSON request body into the configured msgspec schema.

    Returns:
        The decoded request-body struct.

    Raises:
        ClientException: If the request body cannot be decoded into ``schema``.
    """
    try:
        return msgspec.json.decode(await request.body(), type=cast("Any", schema))
    except msgspec.ValidationError as exc:
        if on_error is not None:
            await on_error(request)
        raise ClientException(
            status_code=422,
            detail=validation_detail,
            extra={"code": validation_code},
        ) from exc
    except msgspec.DecodeError as exc:
        if on_error is not None:
            await on_error(request)
        raise ClientException(status_code=400, detail=decode_detail, extra={"code": decode_code}) from exc


@asynccontextmanager
async def _map_domain_exceptions(
    mapping: DomainErrorMap,
    *,
    on_error: AccountStateFailureCallback | None = None,
) -> AsyncIterator[None]:
    """Map configured domain exceptions into ``ClientException`` responses.

    Raises:
        ClientException: If a configured domain exception is raised in the context.
    """
    try:
        yield
    except tuple(mapping) as exc:
        if on_error is not None:
            await on_error()
        status_code, error_code = _resolve_domain_error_response(exc, mapping)
        raise ClientException(status_code=status_code, detail=str(exc), extra={"code": error_code}) from exc


def _require_msgspec_struct(schema: type[object], *, parameter_name: str) -> None:
    """Validate that a configurable schema is a msgspec struct type.

    Raises:
        TypeError: If ``schema`` is not a ``msgspec.Struct`` subclass.
    """
    if issubclass(schema, msgspec.Struct):
        return

    msg = f"{parameter_name} must be a msgspec.Struct subclass."
    raise TypeError(msg)


_SENSITIVE_FIELD_BLOCKLIST: frozenset[str] = frozenset(
    {
        "hashed_password",
        "totp_secret",
        "password",
    },
)


def _to_user_schema(user: object, schema: type[msgspec.Struct]) -> msgspec.Struct:
    """Build the configured public response struct from a user object.

    Returns:
        The configured response struct populated from ``user`` attributes.

    Raises:
        ConfigurationError: If the schema includes sensitive fields in production.
    """
    leaked = _SENSITIVE_FIELD_BLOCKLIST & frozenset(schema.__struct_fields__)
    if leaked:
        if not is_testing():
            msg = (
                f"UserRead schema includes sensitive fields {sorted(leaked)}; "
                "remove them from the response schema to prevent data leakage."
            )
            raise ConfigurationError(msg)
        logger.warning(
            "UserRead schema includes sensitive fields %s; these will appear in API responses",
            sorted(leaked),
        )
    payload = {field_name: getattr(user, field_name) for field_name in schema.__struct_fields__}
    return schema(**payload)


def _build_controller_name(name: str) -> str:
    """Return a class-name-safe prefix derived from a backend or provider name.

    Returns:
        Title-cased alphanumeric name suitable for generated controller classes.
    """
    normalized_name = "".join(part.capitalize() for part in name.replace("_", "-").split("-") if part)
    return normalized_name or "Generated"


def _resolve_domain_error_response(
    exc: Exception,
    mapping: DomainErrorMap,
) -> tuple[int, str]:
    """Return the first mapped client response for the raised domain exception.

    Raises:
        LookupError: If ``exc`` does not match any configured exception type.
    """
    for exception_type, response in mapping.items():
        if isinstance(exc, exception_type):
            return response

    msg = f"Unmapped domain exception: {type(exc).__name__}"
    raise LookupError(msg)


def _create_rate_limit_handlers(rate_limit: EndpointRateLimit | None) -> tuple[RequestHandler, RequestHandler]:
    """Return increment/reset request handlers for an optional rate limit."""

    async def increment(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await rate_limit.increment(request)

    async def reset(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await rate_limit.reset(request)

    return increment, reset


def _create_before_request_handler(rate_limit: EndpointRateLimit | None) -> RequestHandler | None:
    """Return a ``before_request`` handler for an optional rate limit."""
    if rate_limit is None:
        return None

    async def before_request(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await rate_limit.before_request(request)

    return before_request


async def _require_account_state[UP](
    user: UP,
    *,
    require_verified: bool = False,
    user_manager: AccountStateValidatorProvider[UP] | None = None,
    on_failure: AccountStateFailureCallback | None = None,
    prioritize_unverified: bool = False,
) -> None:
    """Validate controller account-state policy and map failures to client errors.

    Args:
        user: User object to validate.
        require_verified: When ``True``, also reject unverified users.
        user_manager: Optional manager exposing ``require_account_state()``.
        on_failure: Optional async callback invoked before raising a client error.
        prioritize_unverified: Preserve legacy flows that reject unverified users
            before inactive ones when both checks fail.

    Raises:
        ClientException: If the account is inactive or unverified.
    """
    try:
        validator = _resolve_account_state_validator(user_manager)
        if validator is not None:
            validator(user, require_verified=require_verified)
        else:
            _require_account_state_from_attributes(
                user,
                require_verified=require_verified,
                prioritize_unverified=prioritize_unverified,
            )
    except InactiveUserError as exc:
        if on_failure is not None:
            await on_failure()
        raise ClientException(
            status_code=400,
            detail=str(exc),
            extra={"code": ErrorCode.LOGIN_USER_INACTIVE},
        ) from exc
    except UnverifiedUserError as exc:
        if on_failure is not None:
            await on_failure()
        raise ClientException(
            status_code=400,
            detail=str(exc),
            extra={"code": ErrorCode.LOGIN_USER_NOT_VERIFIED},
        ) from exc


def _resolve_account_state_validator[UP](
    user_manager: AccountStateValidatorProvider[UP] | None,
) -> AccountStateValidator | None:
    """Return an optional account-state validator exposed by a manager."""
    if user_manager is None:
        return None

    validator = getattr(user_manager, "require_account_state", None)
    if callable(validator):
        return cast("AccountStateValidator", validator)

    return None


def _require_account_state_from_attributes(
    user: object,
    *,
    require_verified: bool,
    prioritize_unverified: bool,
) -> None:
    """Apply controller account-state validation from user attributes only.

    Raises:
        PermissionDeniedException: When the user is not a guarded-user protocol instance.
        InactiveUserError: If the account is inactive.
        UnverifiedUserError: If verification is required and missing.
    """
    if not isinstance(user, GuardedUserProtocol):
        raise PermissionDeniedException(detail=_ACCOUNT_STATE_DETAIL)
    is_active = user.is_active
    is_verified = user.is_verified

    if prioritize_unverified and require_verified and not is_verified:
        raise UnverifiedUserError
    if not is_active:
        raise InactiveUserError
    if require_verified and not is_verified:
        raise UnverifiedUserError
