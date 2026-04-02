"""Shared internal helpers for controller classes."""

from __future__ import annotations

import inspect
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Protocol, cast

import msgspec
from litestar import Request
from litestar.background_tasks import BackgroundTask
from litestar.enums import MediaType
from litestar.exceptions import ClientException, PermissionDeniedException, ValidationException
from litestar.response import Response

from litestar_auth.config import is_testing
from litestar_auth.exceptions import ConfigurationError, ErrorCode, InactiveUserError, UnverifiedUserError
from litestar_auth.guards._guards import _ACCOUNT_STATE_DETAIL
from litestar_auth.types import GuardedUserProtocol

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from litestar.types import ExceptionHandlersMap

    from litestar_auth.ratelimit import EndpointRateLimit

_HTTP_BAD_REQUEST = 400

type RequestHandler = Callable[[Request[Any, Any, Any]], Awaitable[None]]
type ErrorCallback = Callable[[Request[Any, Any, Any]], Awaitable[None]]
type AccountStateFailureCallback = Callable[[], Awaitable[None]]
type DomainErrorMap = Mapping[type[Exception], tuple[int, str]]


class RequestBodyRouteHandler(Protocol):
    """Minimal route-handler surface needed for request-body signature adaptation."""

    fn: Callable[..., Any]
    exception_handlers: ExceptionHandlersMap | None


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


def _create_error_response(
    *,
    status_code: int,
    detail: str,
    extra: Mapping[str, Any] | None = None,
    background: BackgroundTask | None = None,
    headers: Mapping[str, str] | None = None,
) -> Response[dict[str, object]]:
    """Return the JSON error payload shape used by controller request-body failures."""
    payload: dict[str, object] = {
        "status_code": status_code,
        "detail": detail,
    }
    if extra is not None:
        payload["extra"] = dict(extra)
    return Response(
        content=payload,
        status_code=status_code,
        media_type=MediaType.JSON,
        background=background,
        headers=dict(headers) if headers is not None else None,
    )


def _create_request_body_exception_handlers(  # noqa: PLR0913
    *,
    validation_detail: str = "Invalid request payload.",
    validation_code: str = ErrorCode.REQUEST_BODY_INVALID,
    decode_detail: str = "Invalid request body.",
    decode_code: str = ErrorCode.REQUEST_BODY_INVALID,
    on_validation_error: ErrorCallback | None = None,
    on_decode_error: ErrorCallback | None = None,
) -> ExceptionHandlersMap:
    """Create route-local handlers that preserve legacy body-error payloads with typed ``data`` params.

    Returns:
        Mapping of body-related exceptions to route-local response adapters.
    """

    def _background(callback: ErrorCallback | None, request: Request[Any, Any, Any]) -> BackgroundTask | None:
        return BackgroundTask(callback, request) if callback is not None else None

    def handle_validation(
        request: Request[Any, Any, Any],
        exc: ValidationException,
    ) -> Response[dict[str, object]]:
        del exc
        return _create_error_response(
            status_code=422,
            detail=validation_detail,
            extra={"code": validation_code},
            background=_background(on_validation_error, request),
        )

    def handle_client(
        request: Request[Any, Any, Any],
        exc: ClientException,
    ) -> Response[dict[str, object]]:
        if exc.extra is None and exc.status_code == _HTTP_BAD_REQUEST:
            return _create_error_response(
                status_code=_HTTP_BAD_REQUEST,
                detail=decode_detail,
                extra={"code": decode_code},
                background=_background(on_decode_error, request),
            )

        return _create_error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            extra=cast("Mapping[str, Any] | None", exc.extra),
            headers=cast("Mapping[str, str] | None", getattr(exc, "headers", None)),
        )

    return cast(
        "ExceptionHandlersMap",
        {
            ValidationException: handle_validation,
            ClientException: handle_client,
        },
    )


def _configure_request_body_handler(  # noqa: PLR0913
    route_handler: RequestBodyRouteHandler,
    *,
    schema: type[msgspec.Struct],
    validation_detail: str = "Invalid request payload.",
    validation_code: str = ErrorCode.REQUEST_BODY_INVALID,
    decode_detail: str = "Invalid request body.",
    decode_code: str = ErrorCode.REQUEST_BODY_INVALID,
    on_validation_error: ErrorCallback | None = None,
    on_decode_error: ErrorCallback | None = None,
) -> None:
    """Attach a typed ``data`` signature and legacy body-error handlers to a route handler."""
    _set_data_parameter_annotation(route_handler.fn, schema=schema)
    route_handler.exception_handlers = {
        **(route_handler.exception_handlers or {}),
        **_create_request_body_exception_handlers(
            validation_detail=validation_detail,
            validation_code=validation_code,
            decode_detail=decode_detail,
            decode_code=decode_code,
            on_validation_error=on_validation_error,
            on_decode_error=on_decode_error,
        ),
    }


def _set_data_parameter_annotation(
    handler_fn: Callable[..., Any],
    *,
    schema: type[msgspec.Struct],
) -> None:
    """Replace the ``data`` parameter annotation used by Litestar request-body discovery.

    Raises:
        TypeError: If the handler does not declare a ``data`` parameter.
    """
    signature = inspect.signature(handler_fn)
    parameters: list[inspect.Parameter] = []
    has_data_parameter = False

    for parameter in signature.parameters.values():
        if parameter.name == "data":
            parameters.append(parameter.replace(annotation=schema))
            has_data_parameter = True
            continue
        parameters.append(parameter)

    if not has_data_parameter:
        msg = "Request-body handlers must declare a `data` parameter."
        raise TypeError(msg)

    adapted_handler = cast("Any", handler_fn)
    adapted_handler.__signature__ = inspect.Signature(
        parameters=parameters,
        return_annotation=signature.return_annotation,
    )
    adapted_handler.__annotations__ = {
        **getattr(handler_fn, "__annotations__", {}),
        "data": schema,
    }


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
