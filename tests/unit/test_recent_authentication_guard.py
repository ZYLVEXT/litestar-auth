"""Tests for the public application-level recent-authentication guard."""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest
from authweave_core import AuthenticationContext, AuthenticationEvidence, PrincipalRef
from litestar import Request
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from litestar_auth.guards import RecentAuthenticationRequirement, requires_recent_authentication

pytestmark = pytest.mark.unit


def _request(*, authenticated: bool = True) -> Request[Any, Any, Any]:
    principal = PrincipalRef("urn:test", "operator", "human")
    auth = AuthenticationContext(
        subject=principal,
        actor=principal,
        evidence=AuthenticationEvidence(
            provider="human",
            profile="session",
            method="cookie",
            issuer=principal.issuer,
        ),
    )
    return Request(
        scope=cast(
            "Any",
            {
                "type": "http",
                "path": "/security/users",
                "headers": [],
                "state": {},
                "user": object() if authenticated else None,
                "auth": auth if authenticated else None,
            },
        ),
    )


@pytest.mark.parametrize(
    "options",
    [
        {"operation": "Invalid operation"},
        {"operation": "security.user.update", "maximum_age_seconds": 0},
        {"operation": "security.user.update", "maximum_age_seconds": 3601},
    ],
)
def test_recent_authentication_requirement_rejects_unbounded_values(options: dict[str, object]) -> None:
    """Requirement construction rejects invalid names and recency windows."""
    with pytest.raises(ValueError, match=r"operation|maximum_age_seconds"):
        RecentAuthenticationRequirement(**options)  # ty: ignore[invalid-argument-type]


async def test_recent_authentication_guard_accepts_sync_and_async_verified_decisions() -> None:
    """The guard supports explicit synchronous and asynchronous application verifiers."""
    requirement = RecentAuthenticationRequirement(
        operation="security.user.update",
        phishing_resistant=True,
    )
    seen: list[RecentAuthenticationRequirement] = []

    def sync_verifier(_connection: object, received: RecentAuthenticationRequirement) -> bool:
        seen.append(received)
        return True

    async def async_verifier(_connection: object, received: RecentAuthenticationRequirement) -> bool:
        await asyncio.sleep(0)
        seen.append(received)
        return True

    for verifier in (sync_verifier, async_verifier):
        guard = requires_recent_authentication(cast("Any", verifier), requirement=requirement)
        await cast("Any", guard)(_request(), cast("Any", object()))

    assert seen == [requirement, requirement]


async def test_recent_authentication_guard_denies_missing_human_or_assurance() -> None:
    """Anonymous requests and unsatisfied assurance both fail closed."""
    requirement = RecentAuthenticationRequirement(operation="security.user.delete")
    guard = requires_recent_authentication(lambda _connection, _requirement: False, requirement=requirement)

    with pytest.raises(NotAuthorizedException):
        await cast("Any", guard)(_request(authenticated=False), cast("Any", object()))
    with pytest.raises(PermissionDeniedException, match="Recent authentication") as exc_info:
        await cast("Any", guard)(_request(), cast("Any", object()))

    assert exc_info.value.extra == {"code": "AUTHORIZATION_DENIED"}


async def test_recent_authentication_guard_propagates_verifier_unavailability() -> None:
    """Verifier outages remain terminal instead of bypassing recent authentication."""

    def unavailable(_connection: object, _requirement: RecentAuthenticationRequirement) -> bool:
        msg = "assurance store unavailable"
        raise RuntimeError(msg)

    guard = requires_recent_authentication(
        cast("Any", unavailable),
        requirement=RecentAuthenticationRequirement(operation="security.user.reset_totp"),
    )

    with pytest.raises(RuntimeError, match="assurance store unavailable"):
        await cast("Any", guard)(_request(), cast("Any", object()))
