"""Per-endpoint auth rate-limit runtime objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from litestar.exceptions import TooManyRequestsException

from litestar_auth._schema_fields import EMAIL_MAX_LENGTH

from ._client_host import _DEFAULT_TRUSTED_HEADERS, _client_host, logger
from ._identifier_extraction import _extract_email
from ._key_derivation import _bounded_hash_part, _safe_key_part
from ._protocol import KnownRateLimitConnection, RateLimiterBackend, RateLimitKey

type RateLimitScope = Literal["ip", "ip_email"]

_DEFAULT_IDENTITY_FIELDS = ("identifier", "username", "email")


@dataclass(slots=True, frozen=True)
class EndpointRateLimit:
    """Per-endpoint rate-limit settings and request hook."""

    backend: RateLimiterBackend
    scope: RateLimitScope
    namespace: str
    trusted_proxy: bool = False
    identity_fields: tuple[str, ...] = _DEFAULT_IDENTITY_FIELDS
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS
    trusted_proxy_hops: int = 1
    reserve_attempts: bool = False
    """Atomically reserve the attempt at admission instead of the default
    check-then-count-on-failure pattern.

    The default pattern counts failures only, but the check and the later
    increment are separate operations, so concurrent failures can exceed
    ``max_attempts`` by the request concurrency. With ``reserve_attempts=True``
    every admitted request is counted up front through the backend's atomic
    ``admit`` (overshoot zero), :meth:`increment` becomes a no-op, and success
    paths that call :meth:`reset` release the budget as before. Semantics
    change: the window then bounds *attempts since the last success*, not
    failures alone. Requires a backend implementing ``admit`` (both built-in
    backends do); backends without it fall back to the non-atomic check.
    """

    async def before_request(self, request: KnownRateLimitConnection) -> None:
        """Reject the request with 429 when its key is over the configured limit.

        Security:
            Only set ``trusted_proxy=True`` when this service is behind a trusted
            proxy or load balancer that overwrites client IP headers. Otherwise,
            attackers can spoof headers like ``X-Forwarded-For`` and evade or
            poison rate-limiting keys.

        Raises:
            TooManyRequestsException: If the request exceeded the configured limit.
        """
        key = await self.build_key(request)
        admit = getattr(self.backend, "admit", None) if self.reserve_attempts else None
        if admit is not None:
            if await admit(key):
                return
        elif await self.backend.check(key):
            return

        retry_after = await self.backend.retry_after(key)
        logger.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate_limit_triggered",
                "namespace": self.namespace,
                "scope": self.scope,
                "trusted_proxy": self.trusted_proxy,
            },
        )
        msg = "Too many requests."
        raise TooManyRequestsException(
            detail=msg,
            headers={"Retry-After": str(max(retry_after, 1))},
        )

    async def increment(self, request: KnownRateLimitConnection) -> None:
        """Record a failed or rate-limited attempt for the current request.

        No-op under ``reserve_attempts`` when the backend supports atomic
        admission: the attempt was already counted in :meth:`before_request`.
        """
        if self.reserve_attempts and getattr(self.backend, "admit", None) is not None:
            return
        await self.backend.increment(await self.build_key(request))

    async def reset(self, request: KnownRateLimitConnection) -> None:
        """Clear stored attempts for the current request key."""
        await self.backend.reset(await self.build_key(request))

    async def build_key(self, request: KnownRateLimitConnection) -> RateLimitKey:
        """Build the backend key for the given request.

        Returns:
            Namespaced rate-limit key for the request.
        """
        host = _client_host(
            request,
            trusted_proxy=self.trusted_proxy,
            trusted_headers=self.trusted_headers,
            trusted_proxy_hops=self.trusted_proxy_hops,
        )
        parts = [self.namespace, _safe_key_part(host)]
        if self.scope == "ip_email":
            email = await _extract_email(request, identity_fields=self.identity_fields)
            if email:
                email_part = _bounded_hash_part(email, max_length=EMAIL_MAX_LENGTH)
                if email_part is not None:
                    parts.append(email_part)
        return RateLimitKey(":".join(parts))
