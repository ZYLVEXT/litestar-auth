"""Behavior tests for deterministic provider coordination."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import anyio
import pytest
from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationCoordinator,
    AuthenticationDecision,
    AuthenticationEvidence,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    InvariantFailure,
    NotApplicable,
    PrincipalRef,
    RequestView,
    RouteProviderPolicy,
    Unavailable,
)

pytestmark = pytest.mark.unit


def _authenticated(*, provider: str = "provider", profile: str = "profile") -> Authenticated:
    principal = PrincipalRef("issuer", "subject", "service")
    evidence = AuthenticationEvidence(provider, profile, "mtls", "issuer")
    return Authenticated(AuthenticationContext(principal, principal, evidence))


@dataclass
class _Provider:
    name: str = "provider"
    profile: str = "profile"
    match_result: CredentialMatch | object = CredentialMatch.OWNED
    decision: AuthenticationDecision | object = field(default_factory=_authenticated)
    delay: float = 0
    calls: int = 0

    def match(self, request: RequestView) -> CredentialMatch:
        return cast("CredentialMatch", self.match_result)

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        self.calls += 1
        if self.delay:
            await anyio.sleep(self.delay)
        return cast("AuthenticationDecision", self.decision)


def test_coordinator_rejects_duplicate_inventory() -> None:
    with pytest.raises(ValueError, match="name"):
        AuthenticationCoordinator((_Provider(), _Provider(profile="other")))
    with pytest.raises(ValueError, match="profile"):
        AuthenticationCoordinator((_Provider(), _Provider(name="other")))
    with pytest.raises(ValueError, match="must match"):
        AuthenticationCoordinator((_Provider(name="Not Valid"),))


async def test_coordinator_returns_not_applicable_without_owned_credentials() -> None:
    provider = _Provider(match_result=CredentialMatch.NOT_APPLICABLE)
    coordinator = AuthenticationCoordinator((provider,))

    result = await coordinator.authenticate(
        RequestView("GET"),
        AuthenticationRuntime(),
        RouteProviderPolicy(("provider",)),
    )

    assert isinstance(result, NotApplicable)
    assert provider.calls == 0


def test_route_policy_rejects_overlapping_provider_profiles() -> None:
    """A route cannot activate two credential owners."""
    with pytest.raises(ValueError, match="at most one"):
        RouteProviderPolicy(("first", "second"))


@pytest.mark.parametrize(
    "match_result",
    [CredentialMatch.AMBIGUOUS, object()],
)
async def test_coordinator_fails_closed_for_invalid_match_result(match_result: CredentialMatch | object) -> None:
    provider = _Provider(match_result=match_result)
    coordinator = AuthenticationCoordinator((provider,))

    result = await coordinator.authenticate(
        RequestView("GET"),
        AuthenticationRuntime(),
        RouteProviderPolicy(("provider",)),
    )

    assert result in {Invalid(FailureCode.AMBIGUOUS_CREDENTIALS), InvariantFailure()}
    assert provider.calls == 0


async def test_coordinator_returns_config_invariant_for_unknown_provider() -> None:
    result = await AuthenticationCoordinator(()).authenticate(
        RequestView("GET"),
        AuthenticationRuntime(),
        RouteProviderPolicy(("missing",)),
    )

    assert isinstance(result, InvariantFailure)


@pytest.mark.parametrize(
    "decision",
    [
        Invalid(FailureCode.INVALID),
        Unavailable(),
        InvariantFailure(),
    ],
)
async def test_coordinator_returns_terminal_provider_decision(decision: AuthenticationDecision) -> None:
    provider = _Provider(decision=decision)
    coordinator = AuthenticationCoordinator((provider,))

    result = await coordinator.authenticate(
        RequestView("GET"),
        AuthenticationRuntime(),
        RouteProviderPolicy(("provider",)),
    )

    assert result == decision
    assert provider.calls == 1


@pytest.mark.parametrize(
    "decision",
    [
        NotApplicable(),
        _authenticated(provider="other"),
        _authenticated(profile="other"),
        object(),
    ],
)
async def test_coordinator_rejects_provider_contract_violations(decision: AuthenticationDecision | object) -> None:
    provider = _Provider(decision=decision)
    coordinator = AuthenticationCoordinator((provider,))

    result = await coordinator.authenticate(
        RequestView("GET"),
        AuthenticationRuntime(),
        RouteProviderPolicy(("provider",)),
    )

    assert isinstance(result, InvariantFailure)


async def test_coordinator_returns_authenticated_context() -> None:
    expected = _authenticated()
    provider = _Provider(decision=expected)
    coordinator = AuthenticationCoordinator((provider,))

    result = await coordinator.authenticate(
        RequestView("GET"),
        AuthenticationRuntime(),
        RouteProviderPolicy(("provider",)),
    )

    assert result == expected


async def test_coordinator_enforces_expired_and_active_deadlines() -> None:
    provider = _Provider(delay=1)
    coordinator = AuthenticationCoordinator((provider,))
    request = RequestView("GET")
    policy = RouteProviderPolicy(("provider",))

    expired = await coordinator.authenticate(request, AuthenticationRuntime(deadline=anyio.current_time()), policy)
    timed_out = await coordinator.authenticate(
        request,
        AuthenticationRuntime(deadline=anyio.current_time() + 0.01),
        policy,
    )

    assert isinstance(expired, Unavailable)
    assert isinstance(timed_out, Unavailable)


async def test_coordinator_does_not_swallow_external_cancellation() -> None:
    provider = _Provider(delay=1)
    coordinator = AuthenticationCoordinator((provider,))

    with anyio.move_on_after(0.01) as scope:
        await coordinator.authenticate(
            RequestView("GET"),
            AuthenticationRuntime(),
            RouteProviderPolicy(("provider",)),
        )

    assert scope.cancel_called
