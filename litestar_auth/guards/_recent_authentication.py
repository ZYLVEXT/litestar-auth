"""Public recent-authentication guard contracts for sensitive application routes."""

from __future__ import annotations

import inspect
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from litestar.exceptions import PermissionDeniedException

from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards._guards import is_human_authenticated

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Guard

_OPERATION_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_MAX_RECENT_AUTHENTICATION_AGE_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class RecentAuthenticationRequirement:
    """Bounded assurance requirement supplied to an application verifier."""

    operation: str
    maximum_age_seconds: int = 300
    phishing_resistant: bool = False

    def __post_init__(self) -> None:
        """Reject ambiguous operation names and unbounded recency windows.

        Raises:
            ValueError: If the operation or maximum age falls outside the public bounds.
        """
        if _OPERATION_PATTERN.fullmatch(self.operation) is None:
            msg = f"operation must match {_OPERATION_PATTERN.pattern!r}"
            raise ValueError(msg)
        if not 1 <= self.maximum_age_seconds <= _MAX_RECENT_AUTHENTICATION_AGE_SECONDS:
            msg = f"maximum_age_seconds must be between 1 and {_MAX_RECENT_AUTHENTICATION_AGE_SECONDS}"
            raise ValueError(msg)


type RecentAuthenticationVerifier = Callable[
    [ASGIConnection[Any, Any, Any, Any], RecentAuthenticationRequirement],
    bool | Awaitable[bool],
]


def requires_recent_authentication(
    verifier: RecentAuthenticationVerifier,
    *,
    requirement: RecentAuthenticationRequirement,
) -> Guard:
    """Build a fail-closed human guard backed by an application-owned assurance verifier.

    Returns:
        An async Litestar guard suitable for ``guards=[...]``.
    """

    async def _guard(
        connection: ASGIConnection[Any, Any, Any, Any],
        handler: BaseRouteHandler,
    ) -> None:
        is_human_authenticated(connection, handler)
        decision = verifier(connection, requirement)
        accepted = await decision if inspect.isawaitable(decision) else decision
        if accepted is True:
            return
        raise PermissionDeniedException(
            detail="Recent authentication with the required assurance is required.",
            extra={"code": ErrorCode.AUTHORIZATION_DENIED},
        )

    _guard.__name__ = f"requires_recent_authentication_{requirement.operation.replace(':', '_').replace('.', '_')}"
    return _guard


__all__ = (
    "RecentAuthenticationRequirement",
    "RecentAuthenticationVerifier",
    "requires_recent_authentication",
)
