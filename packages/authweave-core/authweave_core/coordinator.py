"""Fail-closed authentication provider coordination."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

import anyio

from authweave_core.models import (
    Authenticated,
    AuthenticationDecision,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    InvariantFailure,
    NotApplicable,
    RequestView,
    RouteProviderPolicy,
    Unavailable,
    _validate_label,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


@runtime_checkable
class RequestAuthenticationProvider(Protocol):
    """Framework-neutral request authentication provider."""

    name: str
    profile: str

    def match(self, request: RequestView) -> CredentialMatch:
        """Classify credential ownership without performing expensive verification."""
        ...

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Verify an owned credential presentation."""
        ...


class AuthenticationCoordinator:
    """Route providers deterministically and stop on every owned failure."""

    def __init__(self, providers: Iterable[RequestAuthenticationProvider]) -> None:
        """Freeze and validate the provider inventory.

        Raises:
            ValueError: If provider names or profiles are invalid or duplicated.
        """
        inventory = tuple(providers)
        names: set[str] = set()
        profiles: set[str] = set()
        for provider in inventory:
            _validate_label(provider.name, name="provider name")
            _validate_label(provider.profile, name="provider profile")
            if provider.name in names:
                msg = f"duplicate provider name: {provider.name}"
                raise ValueError(msg)
            if provider.profile in profiles:
                msg = f"duplicate provider profile: {provider.profile}"
                raise ValueError(msg)
            names.add(provider.name)
            profiles.add(provider.profile)
        self._providers = {provider.name: provider for provider in inventory}

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
        policy: RouteProviderPolicy,
    ) -> AuthenticationDecision:
        """Authenticate through exactly one credential owner.

        Returns:
            A terminal typed authentication decision.
        """
        selected = self._select_provider(request, policy)
        if not isinstance(selected, RequestAuthenticationProvider):
            return selected

        decision = await self._authenticate_with_deadline(selected, request, runtime)
        return self._validate_decision(selected, decision)

    def _select_provider(
        self,
        request: RequestView,
        policy: RouteProviderPolicy,
    ) -> RequestAuthenticationProvider | AuthenticationDecision:
        allowed: list[RequestAuthenticationProvider] = []
        for name in policy.providers:
            provider = self._providers.get(name)
            if provider is None:
                return InvariantFailure()
            match provider.match(request):
                case CredentialMatch.NOT_APPLICABLE:
                    continue
                case CredentialMatch.OWNED:
                    allowed.append(provider)
                case CredentialMatch.AMBIGUOUS:
                    return Invalid(FailureCode.AMBIGUOUS_CREDENTIALS)
                case _:
                    return InvariantFailure()
        if not allowed:
            return NotApplicable()
        return allowed[0]

    @staticmethod
    def _validate_decision(
        provider: RequestAuthenticationProvider,
        decision: object,
    ) -> AuthenticationDecision:
        if isinstance(decision, NotApplicable):
            return InvariantFailure()
        if isinstance(decision, Authenticated):
            evidence = decision.context.evidence
            if evidence.provider != provider.name or evidence.profile != provider.profile:
                return InvariantFailure()
        if not isinstance(decision, (Authenticated, Invalid, Unavailable, InvariantFailure)):
            return InvariantFailure()
        return decision

    @staticmethod
    async def _authenticate_with_deadline(
        provider: RequestAuthenticationProvider,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Apply the request deadline without swallowing external cancellation.

        Returns:
            Provider decision or unavailable when the deadline expires.
        """
        if runtime.deadline is None:
            return await provider.authenticate(request, runtime)

        remaining = runtime.deadline - anyio.current_time()
        if remaining <= 0:
            return Unavailable()
        with anyio.move_on_after(remaining) as timeout_scope:
            decision = await provider.authenticate(request, runtime)
        return Unavailable() if timeout_scope.cancelled_caught else decision
