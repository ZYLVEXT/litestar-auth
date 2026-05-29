"""Per-endpoint auth rate-limit runtime objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from litestar.exceptions import TooManyRequestsException

from litestar_auth._schema_fields import EMAIL_MAX_LENGTH

from ._client_host import _DEFAULT_TRUSTED_HEADERS, _client_host, logger
from ._identifier_extraction import (
    _API_KEY_ID_LENGTH,
    _extract_api_key_id,
    _extract_email,
    _has_hmac_api_key_authorization,
)
from ._key_derivation import _bounded_hash_part, _safe_key_part
from ._protocol import KnownRateLimitConnection, RateLimiterBackend, RateLimitKey

type RateLimitScope = Literal["api_key_id", "ip", "ip_email"]

_DEFAULT_IDENTITY_FIELDS = ("identifier", "username", "email")
_SIGNED_API_KEY_BUCKET_PART = "signed"


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
        if await self.backend.check(key):
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
        """Record a failed or rate-limited attempt for the current request."""
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
        if self.scope == "api_key_id":
            key_id = _extract_api_key_id(request)
            if key_id:
                key_id_part = _bounded_hash_part(key_id, max_length=_API_KEY_ID_LENGTH)
                if key_id_part is not None:
                    parts.append(key_id_part)
            elif _has_hmac_api_key_authorization(request):
                parts.append(_safe_key_part(_SIGNED_API_KEY_BUCKET_PART))

        return RateLimitKey(":".join(parts))
