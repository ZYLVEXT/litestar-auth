"""Bounded explicit-URL JWKS retrieval and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

import anyio

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

type JWKSFetcher = Callable[[str, float, int], Awaitable[Mapping[str, object]]]

_ALLOWED_ALGORITHMS = frozenset({"PS256", "ES256", "EdDSA"})
_MAX_KID_LENGTH = 128
_MIN_RSA_KEY_SIZE = 3072
_HTTP_OK = 200


class JWKSUnavailableError(Exception):
    """Raised when trusted signing keys cannot be obtained safely."""


class JWKSValidationError(ValueError):
    """Raised when a JWKS or key violates the configured profile."""


@dataclass(frozen=True, slots=True)
class JWKSCachePolicy:
    """Bounded network and cache limits for one trusted issuer."""

    ttl_seconds: float = 300.0
    timeout_seconds: float = 3.0
    maximum_response_bytes: int = 262_144
    maximum_keys: int = 32
    refresh_cooldown_seconds: float = 10.0
    """Minimum time between refreshes triggered by unknown ``kid`` lookups.

    Bounds upstream fetch amplification from attacker-chosen kids while still
    letting a freshly rotated key be picked up shortly after publication.
    """

    def __post_init__(self) -> None:
        """Reject non-positive ceilings.

        Raises:
            ValueError: If the call cannot complete.
        """
        if (
            self.ttl_seconds <= 0
            or self.timeout_seconds <= 0
            or self.maximum_response_bytes < 1
            or self.maximum_keys < 1
            or self.refresh_cooldown_seconds < 0
        ):
            msg = "JWKS cache and network ceilings must be positive"
            raise ValueError(msg)


class BoundedJWKSClient:
    """Deduplicate refreshes and expose only validated modern signing keys."""

    def __init__(
        self,
        *,
        url: str | None = None,
        static_jwks: Mapping[str, object] | None = None,
        policy: JWKSCachePolicy | None = None,
        fetcher: JWKSFetcher | None = None,
    ) -> None:
        """Configure exactly one explicit key source.

        Raises:
            ValueError: If the call cannot complete.
        """
        if (url is None) == (static_jwks is None):
            msg = "configure exactly one of url or static_jwks"
            raise ValueError(msg)
        if url is not None:
            _validate_jwks_url(url)
        self.url = url
        self.static_jwks = static_jwks
        self.policy = JWKSCachePolicy() if policy is None else policy
        self.fetcher = _fetch_jwks if fetcher is None else fetcher
        self._keys: dict[str, Any] = {}
        self._last_refresh_at = float("-inf")
        self._expires_at = 0.0
        self._lock = anyio.Lock()

    async def get_key(self, kid: str, algorithm: str) -> object:
        """Return one validated key, rate-limiting refreshes for unknown ``kid`` values.

        Raises:
            JWKSValidationError: If the call cannot complete.
        """
        if not kid or len(kid) > _MAX_KID_LENGTH:
            msg = "JWT kid is missing or oversized"
            raise JWKSValidationError(msg)
        if algorithm not in _ALLOWED_ALGORITHMS:
            msg = "JWT algorithm is not allowed"
            raise JWKSValidationError(msg)
        now = anyio.current_time()
        key = self._keys.get(kid)
        if key is not None and now < self._expires_at:
            _validate_key_algorithm(key, algorithm)
            return key.key
        async with self._lock:
            now = anyio.current_time()
            key = self._keys.get(kid)
            if now >= self._expires_at or not self._keys:
                await self._refresh()
            elif key is None and now - self._last_refresh_at >= self.policy.refresh_cooldown_seconds:
                # Time-based cooldown instead of a one-shot flag: a flood of
                # attacker-chosen kids can no longer consume the single refresh
                # and block a legitimately rotated key until TTL expiry.
                await self._refresh()
            key = self._keys.get(kid)
            if key is None:
                msg = "JWT kid is unknown"
                raise JWKSValidationError(msg)
            _validate_key_algorithm(key, algorithm)
            return key.key

    async def _refresh(self) -> None:
        jwks = (
            self.static_jwks
            if self.static_jwks is not None
            else await self.fetcher(
                cast("str", self.url),
                self.policy.timeout_seconds,
                self.policy.maximum_response_bytes,
            )
        )
        self._keys = _parse_jwks(jwks, maximum_keys=self.policy.maximum_keys)
        self._last_refresh_at = anyio.current_time()
        self._expires_at = self._last_refresh_at + self.policy.ttl_seconds


def _validate_jwks_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        msg = "jwks_url must be an explicit clean HTTPS URL"
        raise ValueError(msg)


def _load_jwt() -> Any:
    try:
        import jwt
    except ImportError as exc:
        msg = "JWT verification requires the 'authweave-workload[jwt]' extra."
        raise ImportError(msg) from exc
    return jwt


def _parse_jwks(value: Mapping[str, object] | None, *, maximum_keys: int) -> dict[str, Any]:
    if value is None or set(value) != {"keys"}:
        msg = "JWKS must contain only a keys array"
        raise JWKSValidationError(msg)
    raw_keys = value["keys"]
    if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > maximum_keys:
        msg = "JWKS key count is invalid"
        raise JWKSValidationError(msg)
    parsed: dict[str, Any] = {}
    jwt = _load_jwt()
    for raw_key in raw_keys:
        if not isinstance(raw_key, dict):
            msg = "JWKS keys must be objects"
            raise JWKSValidationError(msg)
        kid = raw_key.get("kid")
        algorithm = raw_key.get("alg")
        invalid_kid = not isinstance(kid, str) or not kid or len(kid) > _MAX_KID_LENGTH or kid in parsed
        invalid_algorithm = not isinstance(algorithm, str) or algorithm not in _ALLOWED_ALGORITHMS
        if invalid_kid or invalid_algorithm:
            msg = "JWKS key identity or algorithm is invalid"
            raise JWKSValidationError(msg)
        try:
            key = jwt.PyJWK.from_dict(raw_key, algorithm=algorithm)
        except (TypeError, ValueError, jwt.PyJWTError) as exc:
            msg = "JWKS key cannot be parsed"
            raise JWKSValidationError(msg) from exc
        _validate_key_algorithm(key, algorithm)
        parsed[kid] = key
    return parsed


def _validate_key_algorithm(key: Any, algorithm: str) -> None:
    if key.algorithm_name != algorithm:
        msg = "JWK algorithm does not match JWT algorithm"
        raise JWKSValidationError(msg)
    public_key = key.key
    if algorithm == "PS256":
        if key.key_type != "RSA" or getattr(public_key, "key_size", 0) < _MIN_RSA_KEY_SIZE:
            msg = f"PS256 requires an RSA key of at least {_MIN_RSA_KEY_SIZE} bits"
            raise JWKSValidationError(msg)
    elif algorithm == "ES256":
        if key.key_type != "EC" or getattr(getattr(public_key, "curve", None), "name", None) != "secp256r1":
            msg_0 = "ES256 requires a P-256 key"
            raise JWKSValidationError(msg_0)
    elif key.key_type != "OKP" or type(public_key).__name__ != "Ed25519PublicKey":
        msg_0 = "EdDSA requires an Ed25519 key"
        raise JWKSValidationError(msg_0)


async def _fetch_jwks(url: str, timeout_seconds: float, maximum_response_bytes: int) -> Mapping[str, object]:
    try:
        import httpx
    except ImportError as exc:
        msg = "JWKS retrieval requires the 'authweave-workload[jwt]' extra."
        raise ImportError(msg) from exc
    content = bytearray()
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout_seconds) as client:
            async with client.stream("GET", url, headers={"accept": "application/json"}) as response:
                if response.status_code != _HTTP_OK:
                    msg_0 = "trusted JWKS returned a non-success status"
                    raise JWKSUnavailableError(msg_0)
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > maximum_response_bytes:
                        msg_0 = "JWKS response exceeds the configured size limit"
                        raise JWKSValidationError(msg_0)
    except JWKSValidationError:
        raise
    except (httpx.HTTPError, TimeoutError) as exc:
        msg_0 = "trusted JWKS request failed"
        raise JWKSUnavailableError(msg_0) from exc
    try:
        decoded = json.loads(content)
    except (TypeError, ValueError) as exc:
        msg_0 = "JWKS response is not valid JSON"
        raise JWKSValidationError(msg_0) from exc
    if not isinstance(decoded, dict):
        msg_0 = "JWKS response must be an object"
        raise JWKSValidationError(msg_0)
    return decoded


__all__ = (
    "BoundedJWKSClient",
    "JWKSCachePolicy",
    "JWKSUnavailableError",
    "JWKSValidationError",
)
