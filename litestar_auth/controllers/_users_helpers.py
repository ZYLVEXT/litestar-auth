"""Internal helpers for generated users controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import msgspec
from litestar.exceptions import ClientException, TooManyRequestsException

from litestar_auth.exceptions import AuthorizationError, ErrorCode
from litestar_auth.ratelimit._helpers import _client_host, _safe_key_part, logger

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers._utils import RequestHandler
    from litestar_auth.ratelimit import EndpointRateLimit

SELF_UPDATE_FORBIDDEN_FIELDS = frozenset({"is_active", "is_verified", "roles"})
_SELF_UPDATE_BLOCKED_FIELDS = SELF_UPDATE_FORBIDDEN_FIELDS | frozenset({"hashed_password", "password"})


async def _build_change_password_rate_limit_key(
    rate_limit: EndpointRateLimit,
    request: Request[Any, Any, Any],
) -> str:
    """Build the rate-limit key for password rotation attempts.

    ``ChangePasswordRequest`` intentionally does not carry an email field. For
    the default ``ip_email`` scope, use the authenticated user email so this
    post-auth re-verification endpoint keeps the same principal granularity as
    login without widening the request schema.

    Returns:
        Namespaced backend key for the password-rotation attempt.
    """
    if rate_limit.scope != "ip_email":
        return await rate_limit.build_key(request)

    user_email = getattr(request.user, "email", None)
    if not isinstance(user_email, str) or not user_email:
        return await rate_limit.build_key(request)

    host = _client_host(
        request,
        trusted_proxy=rate_limit.trusted_proxy,
        trusted_headers=rate_limit.trusted_headers,
    )
    return ":".join(
        (
            rate_limit.namespace,
            _safe_key_part(host),
            _safe_key_part(user_email.strip().casefold()),
        ),
    )


def _create_change_password_rate_limit_handlers(
    rate_limit: EndpointRateLimit | None,
) -> tuple[RequestHandler | None, RequestHandler, RequestHandler]:
    """Return before/increment/reset handlers for the authenticated password-rotation limiter."""

    async def increment(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await rate_limit.backend.increment(await _build_change_password_rate_limit_key(rate_limit, request))

    async def reset(request: Request[Any, Any, Any]) -> None:
        if rate_limit is not None:
            await rate_limit.backend.reset(await _build_change_password_rate_limit_key(rate_limit, request))

    if rate_limit is None:
        return None, increment, reset

    async def before_request(request: Request[Any, Any, Any]) -> None:
        key = await _build_change_password_rate_limit_key(rate_limit, request)
        if await rate_limit.backend.check(key):
            return

        retry_after = await rate_limit.backend.retry_after(key)
        logger.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate_limit_triggered",
                "namespace": rate_limit.namespace,
                "scope": rate_limit.scope,
                "trusted_proxy": rate_limit.trusted_proxy,
            },
        )
        msg = "Too many requests."
        raise TooManyRequestsException(
            detail=msg,
            headers={"Retry-After": str(max(retry_after, 1))},
        )

    return before_request, increment, reset


def _build_blocked_self_update_detail(blocked_fields: frozenset[str]) -> str:
    """Return a deterministic error message for blocked self-update fields."""
    field_list = ", ".join(sorted(blocked_fields))
    return f"Self-service updates cannot set the following fields: {field_list}."


async def _reject_blocked_self_update_fields(request: Request[Any, Any, Any]) -> None:
    """Reject blocked self-update fields before schema validation can silently diverge.

    Raises:
        ClientException: If the request body includes blocked self-update fields.
    """
    try:
        decoded_body = msgspec.json.decode(await request.body())
    except msgspec.DecodeError:
        return
    if not isinstance(decoded_body, dict):
        return
    blocked_fields = frozenset(str(key) for key in decoded_body) & _SELF_UPDATE_BLOCKED_FIELDS
    if not blocked_fields:
        return
    detail = _build_blocked_self_update_detail(blocked_fields)
    raise ClientException(
        status_code=400,
        detail=detail,
        extra={"code": ErrorCode.REQUEST_BODY_INVALID},
    ) from AuthorizationError(detail)


def _build_safe_self_update(data: msgspec.Struct) -> dict[str, Any]:
    """Reject blocked self-update fields and return the remaining payload mapping.

    ``PATCH /users/me`` must not rotate credentials or mutate authorization
    state. Password changes belong to ``POST /users/me/change-password``, and
    admin-initiated rotation belongs to ``PATCH /users/{user_id}`` with
    ``AdminUserUpdate``.

    Uses a deny-list of privileged fields rather than an allow-list so
    that custom ``UserUpdate`` schemas with extra safe fields work
    out-of-the-box. The deny-list covers fields that could grant elevated
    privileges (``is_active``, ``is_verified``, ``roles``), password
    rotation without re-verification, and the sensitive
    ``hashed_password`` shadow.

    Generated request schemas use ``forbid_unknown_fields=True``, so undeclared
    fields fail request decoding before this helper runs unless the route's
    preflight blocked-field check intercepts them first. Custom self-update
    schemas that still declare blocked fields are rejected here fail-closed.

    Returns:
        A plain update mapping when no blocked self-update fields were supplied.

    Raises:
        AuthorizationError: If the payload attempts to set blocked self-update fields.
        TypeError: If ``msgspec.to_builtins`` does not return a mapping (should not occur for structs).
    """
    builtins_payload = msgspec.to_builtins(data)
    if not isinstance(builtins_payload, dict):
        msg = "Expected a mapping from msgspec.to_builtins."
        raise TypeError(msg)
    payload: dict[str, Any] = {str(k): v for k, v in builtins_payload.items()}
    blocked_fields = frozenset(payload) & _SELF_UPDATE_BLOCKED_FIELDS
    if blocked_fields:
        detail = _build_blocked_self_update_detail(blocked_fields)
        raise AuthorizationError(detail)
    return payload
