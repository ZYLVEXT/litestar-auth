"""Error-response helpers for generated controller classes."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.response import Response

from litestar_auth.exceptions import UserAlreadyExistsError

if TYPE_CHECKING:
    from litestar.background_tasks import BackgroundTask

type AccountStateFailureCallback = Callable[[], Awaitable[None]]
type DomainErrorMap = Mapping[type[Exception], tuple[int, str]]


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


@asynccontextmanager
async def _map_domain_exceptions(
    mapping: DomainErrorMap,
    *,
    on_error: AccountStateFailureCallback | None = None,
    detail: str | None = None,
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
        raise ClientException(
            status_code=status_code,
            detail=detail if detail is not None else _domain_error_public_detail(exc),
            extra={"code": error_code},
        ) from exc


def _domain_error_public_detail(exc: Exception) -> str:
    """Return the client-facing detail for a mapped domain exception."""
    if isinstance(exc, UserAlreadyExistsError):
        return UserAlreadyExistsError.default_message
    return str(exc)


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
