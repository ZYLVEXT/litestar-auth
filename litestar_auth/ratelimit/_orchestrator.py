"""TOTP rate-limit orchestration helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from litestar.connection import Request

    from ._config import EndpointRateLimit

type TotpSensitiveEndpoint = Literal["enable", "confirm_enable", "verify", "disable", "regenerate_recovery_codes"]


@dataclass(slots=True, frozen=True)
class TotpRateLimitOrchestrator:
    """Orchestrate TOTP endpoint rate-limit behavior with explicit semantics.

    External behavior stays unchanged:
    - ``verify`` uses before-request checks, increments on invalid attempts, and
      resets on success/account-state failures.
    - ``enable`` and ``disable`` do not consume verify counters.

    Endpoints that should reset on account-state failures are listed in
    ``_ACCOUNT_STATE_RESET_ENDPOINTS`` (currently only ``verify``).
    """

    enable: EndpointRateLimit | None = None
    confirm_enable: EndpointRateLimit | None = None
    verify: EndpointRateLimit | None = None
    disable: EndpointRateLimit | None = None
    regenerate_recovery_codes: EndpointRateLimit | None = None

    _ACCOUNT_STATE_RESET_ENDPOINTS: frozenset[TotpSensitiveEndpoint] = frozenset({"verify"})

    @property
    def _limiters(self) -> dict[TotpSensitiveEndpoint, EndpointRateLimit]:
        return {
            ep: limiter
            for ep, limiter in (
                ("enable", self.enable),
                ("confirm_enable", self.confirm_enable),
                ("verify", self.verify),
                ("disable", self.disable),
                ("regenerate_recovery_codes", self.regenerate_recovery_codes),
            )
            if limiter is not None
        }

    async def before_request(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Run endpoint-specific before-request checks."""
        if limiter := self._limiters.get(endpoint):
            await limiter.before_request(request)

    async def on_invalid_attempt(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Record endpoint-specific invalid attempt failures."""
        if limiter := self._limiters.get(endpoint):
            await limiter.increment(request)

    async def on_account_state_failure(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Apply endpoint-specific account-state failure behavior."""
        if endpoint in self._ACCOUNT_STATE_RESET_ENDPOINTS and (limiter := self._limiters.get(endpoint)):
            await limiter.reset(request)

    async def on_success(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Apply endpoint-specific success behavior."""
        if limiter := self._limiters.get(endpoint):
            await limiter.reset(request)
