"""API-key controller rate-limit hook adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers._utils import RequestHandler


def create_api_key_create_increment(rate_limit: object) -> RequestHandler:
    """Return the create failure increment handler."""

    async def increment(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await cast("Any", rate_limit).increment(request)

    return increment


def create_api_key_create_reset(rate_limit: object) -> RequestHandler:
    """Return the create success reset handler."""

    async def reset(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await cast("Any", rate_limit).reset(request)

    return reset


def create_api_key_update_increment(rate_limit: object) -> RequestHandler:
    """Return the update failure increment handler."""

    async def increment(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await cast("Any", rate_limit).increment(request)

    return increment


def create_api_key_update_reset(rate_limit: object) -> RequestHandler:
    """Return the update success reset handler."""

    async def reset(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await cast("Any", rate_limit).reset(request)

    return reset
