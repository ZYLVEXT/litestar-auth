"""Request-body helpers for generated controller classes."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast

import msgspec
from litestar import Request
from litestar.background_tasks import BackgroundTask
from litestar.exceptions import ClientException, ValidationException

from litestar_auth.controllers._error_responses import _create_error_response
from litestar_auth.exceptions import ErrorCode

if TYPE_CHECKING:
    from litestar.response import Response
    from litestar.types import ExceptionHandlersMap

_HTTP_BAD_REQUEST = 400

type ErrorCallback = Callable[[Request[Any, Any, Any]], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class RequestBodyErrorConfig:
    """Error metadata and callbacks for generated request-body handlers."""

    validation_detail: str = "Invalid request payload."
    validation_code: str = ErrorCode.REQUEST_BODY_INVALID
    decode_detail: str = "Invalid request body."
    decode_code: str = ErrorCode.REQUEST_BODY_INVALID
    on_validation_error: ErrorCallback | None = None
    on_decode_error: ErrorCallback | None = None


class RequestBodyRouteHandler(Protocol):
    """Minimal route-handler surface needed for request-body signature adaptation."""

    fn: Callable[..., Any]
    exception_handlers: ExceptionHandlersMap | None


async def _decode_request_body(
    request: Request[Any, Any, Any],
    *,
    schema: type[msgspec.Struct],
    error_config: RequestBodyErrorConfig | None = None,
) -> msgspec.Struct:
    """Decode a JSON request body into the configured msgspec schema.

    Returns:
        The decoded request-body struct.

    Raises:
        ClientException: If the request body cannot be decoded into ``schema``.
    """
    config = error_config or RequestBodyErrorConfig()
    try:
        return msgspec.json.decode(await request.body(), type=cast("Any", schema))
    except msgspec.ValidationError as exc:
        if config.on_validation_error is not None:
            await config.on_validation_error(request)
        raise ClientException(
            status_code=422,
            detail=config.validation_detail,
            extra={"code": config.validation_code},
        ) from exc
    except msgspec.DecodeError as exc:
        if config.on_decode_error is not None:
            await config.on_decode_error(request)
        raise ClientException(
            status_code=_HTTP_BAD_REQUEST,
            detail=config.decode_detail,
            extra={"code": config.decode_code},
        ) from exc


def _create_request_body_exception_handlers(
    error_config: RequestBodyErrorConfig | None = None,
) -> ExceptionHandlersMap:
    """Create route-local handlers that preserve the controller body-error contract for typed ``data`` params.

    Returns:
        Mapping of body-related exceptions to route-local response adapters.
    """
    config = error_config or RequestBodyErrorConfig()

    def _background(callback: ErrorCallback | None, request: Request[Any, Any, Any]) -> BackgroundTask | None:
        return BackgroundTask(callback, request) if callback is not None else None

    def handle_validation(
        request: Request[Any, Any, Any],
        exc: ValidationException,
    ) -> Response[dict[str, object]]:
        del exc
        return _create_error_response(
            status_code=422,
            detail=config.validation_detail,
            extra={"code": config.validation_code},
            background=_background(config.on_validation_error, request),
        )

    def handle_client(
        request: Request[Any, Any, Any],
        exc: ClientException,
    ) -> Response[dict[str, object]]:
        if exc.extra is None and exc.status_code == _HTTP_BAD_REQUEST:
            return _create_error_response(
                status_code=_HTTP_BAD_REQUEST,
                detail=config.decode_detail,
                extra={"code": config.decode_code},
                background=_background(config.on_decode_error, request),
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


def _configure_request_body_handler(
    route_handler: RequestBodyRouteHandler,
    *,
    schema: type[msgspec.Struct],
    error_config: RequestBodyErrorConfig | None = None,
) -> None:
    """Attach a typed ``data`` signature and controller body-error handlers to a route handler."""
    _set_data_parameter_annotation(route_handler.fn, schema=schema)
    route_handler.exception_handlers = {
        **(route_handler.exception_handlers or {}),
        **_create_request_body_exception_handlers(error_config),
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
