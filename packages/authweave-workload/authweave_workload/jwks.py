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

    def __post_init__(self) -> None:
        """Reject non-positive ceilings."""
        if (
            self.ttl_seconds <= 0
            or self.timeout_seconds <= 0
            or self.maximum_response_bytes < 1
            or self.maximum_keys < 1
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
        """Configure exactly one explicit key source."""
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
        self._unknown_kid_refresh_used = False
        self._expires_at = 0.0
        self._lock = anyio.Lock()

    async def get_key(self, kid: str, algorithm: str) -> object:
        """Return one validated key, refreshing at most once for an unknown ``kid``."""
        if not kid or len(kid) > _MAX_KID_LENGTH:
            raise JWKSValidationError("JWT kid is missing or oversized")
        if algorithm not in _ALLOWED_ALGORITHMS:
            raise JWKSValidationError("JWT algorithm is not allowed")
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
                self._unknown_kid_refresh_used = False
            elif key is None and not self._unknown_kid_refresh_used:
                self._unknown_kid_refresh_used = True
                await self._refresh()
            key = self._keys.get(kid)
            if key is None:
                self._unknown_kid_refresh_used = True
                raise JWKSValidationError("JWT kid is unknown")
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
        self._expires_at = anyio.current_time() + self.policy.ttl_seconds


def _validate_jwks_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("jwks_url must be an explicit clean HTTPS URL")


def _load_jwt() -> Any:
    try:
        import jwt
    except ImportError as exc:
        msg = "JWT verification requires the 'authweave-workload[jwt]' extra."
        raise ImportError(msg) from exc
    return jwt


def _parse_jwks(value: Mapping[str, object] | None, *, maximum_keys: int) -> dict[str, Any]:
    if value is None or set(value) != {"keys"}:
        raise JWKSValidationError("JWKS must contain only a keys array")
    raw_keys = value["keys"]
    if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > maximum_keys:
        raise JWKSValidationError("JWKS key count is invalid")
    parsed: dict[str, Any] = {}
    jwt = _load_jwt()
    for raw_key in raw_keys:
        if not isinstance(raw_key, dict):
            raise JWKSValidationError("JWKS keys must be objects")
        kid = raw_key.get("kid")
        algorithm = raw_key.get("alg")
        invalid_kid = not isinstance(kid, str) or not kid or len(kid) > _MAX_KID_LENGTH or kid in parsed
        invalid_algorithm = not isinstance(algorithm, str) or algorithm not in _ALLOWED_ALGORITHMS
        if invalid_kid or invalid_algorithm:
            raise JWKSValidationError("JWKS key identity or algorithm is invalid")
        try:
            key = jwt.PyJWK.from_dict(raw_key, algorithm=algorithm)
        except (TypeError, ValueError, jwt.PyJWTError) as exc:
            raise JWKSValidationError("JWKS key cannot be parsed") from exc
        _validate_key_algorithm(key, algorithm)
        parsed[kid] = key
    return parsed


def _validate_key_algorithm(key: Any, algorithm: str) -> None:
    if key.algorithm_name != algorithm:
        raise JWKSValidationError("JWK algorithm does not match JWT algorithm")
    public_key = key.key
    if algorithm == "PS256":
        if key.key_type != "RSA" or getattr(public_key, "key_size", 0) < _MIN_RSA_KEY_SIZE:
            msg = f"PS256 requires an RSA key of at least {_MIN_RSA_KEY_SIZE} bits"
            raise JWKSValidationError(msg)
    elif algorithm == "ES256":
        if key.key_type != "EC" or getattr(getattr(public_key, "curve", None), "name", None) != "secp256r1":
            raise JWKSValidationError("ES256 requires a P-256 key")
    elif key.key_type != "OKP" or type(public_key).__name__ != "Ed25519PublicKey":
        raise JWKSValidationError("EdDSA requires an Ed25519 key")


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
                    raise JWKSUnavailableError("trusted JWKS returned a non-success status")
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > maximum_response_bytes:
                        raise JWKSValidationError("JWKS response exceeds the configured size limit")
    except JWKSValidationError:
        raise
    except (httpx.HTTPError, TimeoutError) as exc:
        raise JWKSUnavailableError("trusted JWKS request failed") from exc
    try:
        decoded = json.loads(content)
    except (TypeError, ValueError) as exc:
        raise JWKSValidationError("JWKS response is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise JWKSValidationError("JWKS response must be an object")
    return decoded


__all__ = (
    "BoundedJWKSClient",
    "JWKSCachePolicy",
    "JWKSUnavailableError",
    "JWKSValidationError",
)
