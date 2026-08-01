"""Strict FAPI 2.0 Message Signing authorization-code client primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from authweave_core import AuthorizationValue, ReplayOutcome, ReplayStore, freeze_authorization_details

if TYPE_CHECKING:
    from jwt.algorithms import AllowedPublicKeys

_ALGORITHMS = frozenset({"PS256", "ES256", "EdDSA"})
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_HTTP_CREATED = 201
_MAX_JWT_BYTES = 16_384
_MAX_RESPONSE_BYTES = 65_536
_MAX_VALUE_LENGTH = 512
_MAX_URI_LENGTH = 2048
_MAX_SCOPES = 64
_MAX_KEY_ID_LENGTH = 128
_MAX_PAR_LIFETIME_SECONDS = 600
_MIN_RANDOM_LENGTH = 32
_MAX_RANDOM_LENGTH = 128
_JWT_SEPARATOR_COUNT = 2
_JAR_TYPE = "oauth-authz-req+jwt"
_JARM_TYPE = "oauth-authz-resp+jwt"
_ID_TOKEN_TYPE = "JWT"  # ruff: ignore[hardcoded-password-string]
_SCOPE_PATTERN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]{1,512}$")

type FAPIPoster = Callable[
    [str, Mapping[str, str], bytes, float, int],
    Awaitable[tuple[int, bytes, str]],
]


class FAPIUnavailableError(Exception):
    """Raised when an exact FAPI dependency is unavailable."""


class FAPIValidationError(ValueError):
    """Raised when a FAPI message violates the configured issuer profile."""


@runtime_checkable
class AsyncJWTSigner(Protocol):
    """External JOSE signer that never exposes private key bytes."""

    async def sign(
        self,
        *,
        protected_headers: Mapping[str, object],
        claims: Mapping[str, object],
    ) -> str:
        """Return one compact signed JWT."""
        ...


@runtime_checkable
class AsyncJWTKeyResolver(Protocol):
    """Resolve one already trusted issuer key by exact key id and algorithm."""

    async def get_key(self, kid: str, algorithm: str) -> AllowedPublicKeys | jwt.PyJWK | str | bytes:
        """Return a verification key or raise a typed dependency error."""
        ...


@dataclass(frozen=True, slots=True)
class FAPIIssuerProfile:
    """One exact FAPI 2.0 Message Signing OIDC client registration."""

    issuer: str
    authorization_endpoint: str
    par_endpoint: str
    client_id: str
    redirect_uri: str
    key_id: str
    algorithm: str
    signer: AsyncJWTSigner
    key_resolver: AsyncJWTKeyResolver
    replay_store: ReplayStore
    response_algorithms: frozenset[str] = _ALGORITHMS
    jar_lifetime: timedelta = timedelta(minutes=5)
    jarm_maximum_lifetime: timedelta = timedelta(minutes=10)
    id_token_maximum_lifetime: timedelta = timedelta(minutes=10)
    clock_skew: timedelta = timedelta(seconds=30)
    par_timeout_seconds: float = 3.0
    par_maximum_response_bytes: int = _MAX_RESPONSE_BYTES
    time_source: Callable[[], datetime] = lambda: datetime.now(UTC)
    random_source: Callable[[], str] = lambda: secrets.token_urlsafe(32)

    def __post_init__(self) -> None:
        """Reject discovery, weak JOSE, ambiguous endpoints, and broad time policy.

        Raises:
            ValueError: If the registration is not an exact supported profile.
        """
        for url in (self.issuer, self.authorization_endpoint, self.par_endpoint, self.redirect_uri):
            _validate_https_url(url)
        identity_invalid = not self.client_id or len(self.client_id) > _MAX_VALUE_LENGTH
        key_invalid = not self.key_id or len(self.key_id) > _MAX_KEY_ID_LENGTH or self.algorithm not in _ALGORITHMS
        response_invalid = not self.response_algorithms or not self.response_algorithms <= _ALGORITHMS
        time_invalid = (
            not timedelta(0) < self.jar_lifetime <= timedelta(hours=1)
            or not timedelta(0) < self.jarm_maximum_lifetime <= timedelta(minutes=10)
            or not timedelta(0) < self.id_token_maximum_lifetime <= timedelta(hours=24)
            or self.clock_skew < timedelta(0)
        )
        network_invalid = self.par_timeout_seconds <= 0 or self.par_maximum_response_bytes < 1
        if any((identity_invalid, key_invalid, response_invalid, time_invalid, network_invalid)):
            msg = "FAPI issuer profile is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class FAPIAuthorization:
    """Persistable browser redirect and protocol-run binding material."""

    authorization_url: str
    request_uri: str
    expires_in: int
    state: str
    nonce: str
    code_verifier: str


@dataclass(frozen=True, slots=True)
class FAPIJARMResult:
    """Verified JARM success or error response."""

    state: str
    code: str | None = None
    error: str | None = None
    error_description: str | None = None

    def require_code(self) -> str:
        """Return the authorization code or raise the verified AS error.

        Returns:
            Verified authorization code.

        Raises:
            FAPIValidationError: If the authorization response is an error.
        """
        if self.code is None:
            msg = f"authorization server returned {self.error or 'an unknown error'}"
            raise FAPIValidationError(msg)
        return self.code


@dataclass(frozen=True, slots=True)
class FAPIIDToken:
    """Minimal verified ID-token identity facts."""

    subject: str
    issued_at: datetime
    expires_at: datetime
    auth_time: datetime | None = None


class FAPIMessageSigningClient:
    """Create signed PAR requests and verify distinct JARM and ID-token schemas."""

    def __init__(self, profile: FAPIIssuerProfile, *, poster: FAPIPoster | None = None) -> None:
        """Bind one exact issuer registration and bounded PAR transport."""
        self.profile = profile
        self.poster = _post_par if poster is None else poster

    async def begin(
        self,
        *,
        scopes: tuple[str, ...],
        authorization_details: tuple[Mapping[str, AuthorizationValue], ...] = (),
    ) -> FAPIAuthorization:
        """Push a signed request object and return browser/persistence material.

        Returns:
            Authorization redirect and values the application must persist.

        Raises:
            ValueError: If scopes or injected clock/random sources are invalid.
            FAPIValidationError: If PAR returns an invalid response.
            FAPIUnavailableError: If signing, transport, or PAR is unavailable.
        """
        _validate_scopes(scopes)
        if "openid" not in scopes:
            msg = "FAPI OIDC profile requires the openid scope"
            raise ValueError(msg)
        now = _aware_now(self.profile.time_source)
        state = _bounded_random(self.profile.random_source)
        nonce = _bounded_random(self.profile.random_source)
        code_verifier = _bounded_random(self.profile.random_source)
        request_claims: dict[str, object] = {
            "iss": self.profile.client_id,
            "aud": self.profile.issuer,
            "nbf": int(now.timestamp()),
            "exp": int(now.timestamp()) + int(self.profile.jar_lifetime.total_seconds()),
            "jti": _bounded_random(self.profile.random_source),
            "response_type": "code",
            "client_id": self.profile.client_id,
            "redirect_uri": self.profile.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": _base64url_sha256(code_verifier),
            "code_challenge_method": "S256",
            "response_mode": "jwt",
        }
        if authorization_details:
            request_claims["authorization_details"] = _json_authorization_details(authorization_details)
        request_object = await self._sign(
            token_type=_JAR_TYPE,
            claims=request_claims,
        )
        assertion = await self._client_assertion(now)
        form = {
            "request": request_object,
            "client_assertion_type": _ASSERTION_TYPE,
            "client_assertion": assertion,
        }
        try:
            status, content, content_type = await self.poster(
                self.profile.par_endpoint,
                {"accept": "application/json", "content-type": "application/x-www-form-urlencoded"},
                urlencode(form).encode("ascii"),
                self.profile.par_timeout_seconds,
                self.profile.par_maximum_response_bytes,
            )
        except (FAPIUnavailableError, FAPIValidationError):
            raise
        except Exception as exc:
            msg = "PAR request failed"
            raise FAPIUnavailableError(msg) from exc
        if status != _HTTP_CREATED:
            msg = "PAR endpoint returned a non-success status"
            raise FAPIUnavailableError(msg)
        if len(content) > self.profile.par_maximum_response_bytes:
            msg = "PAR response exceeds the configured size limit"
            raise FAPIValidationError(msg)
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            msg = "PAR Content-Type must be application/json"
            raise FAPIValidationError(msg)
        request_uri, expires_in = _parse_par_response(content)
        query = urlencode({"client_id": self.profile.client_id, "request_uri": request_uri})
        return FAPIAuthorization(
            authorization_url=f"{self.profile.authorization_endpoint}?{query}",
            request_uri=request_uri,
            expires_in=expires_in,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
        )

    async def verify_jarm(self, response: str, *, expected_state: str) -> FAPIJARMResult:
        """Verify and single-consume a signed JARM response before exposing its code.

        Returns:
            Verified success or error response.

        Raises:
            FAPIValidationError: If the response is invalid, mismatched, or replayed.
        """
        _required_string(expected_state, label="expected state")
        claims = await self._verify_jwt(
            response,
            expected_type=_JARM_TYPE,
            required=("iss", "aud", "exp", "iat", "jti", "state"),
        )
        state = _required_string(claims.get("state"), label="JARM state")
        if not hmac.compare_digest(state.encode(), expected_state.encode()):
            msg = "JARM state mismatch"
            raise FAPIValidationError(msg)
        _issued_at, expires_at = _validate_token_times(
            claims,
            now=_aware_now(self.profile.time_source),
            maximum_lifetime=self.profile.jarm_maximum_lifetime,
            clock_skew=self.profile.clock_skew,
            label="JARM",
        )
        _required_string(claims.get("jti"), label="JARM jti")
        code = _optional_string(claims.get("code"), label="JARM code")
        error = _optional_string(claims.get("error"), label="JARM error")
        if (code is None) == (error is None):
            msg = "JARM must contain exactly one of code or error"
            raise FAPIValidationError(msg)
        await self._consume_once(
            f"fapi:jarm:{_digest(self.profile.issuer, state)}",
            ttl=max(1.0, (expires_at - _aware_now(self.profile.time_source) + self.profile.clock_skew).total_seconds()),
        )
        return FAPIJARMResult(
            state=state,
            code=code,
            error=error,
            error_description=_optional_string(claims.get("error_description"), label="JARM error_description"),
        )

    async def verify_id_token(self, token: str, *, expected_nonce: str) -> FAPIIDToken:
        """Verify and single-consume the OIDC nonce under a distinct JWT schema.

        Returns:
            Minimal verified ID-token identity facts.

        Raises:
            FAPIValidationError: If the token is invalid, mismatched, or replayed.
        """
        _required_string(expected_nonce, label="expected nonce")
        claims = await self._verify_jwt(
            token,
            expected_type=_ID_TOKEN_TYPE,
            required=("iss", "sub", "aud", "exp", "iat", "nonce"),
        )
        if "code" in claims or "state" in claims or "token_introspection" in claims:
            msg = "ID token contains claims from another JWT profile"
            raise FAPIValidationError(msg)
        authorized_party = claims.get("azp")
        if authorized_party is not None and authorized_party != self.profile.client_id:
            msg = "ID token authorized party mismatch"
            raise FAPIValidationError(msg)
        nonce = _required_string(claims.get("nonce"), label="ID token nonce")
        if not hmac.compare_digest(nonce.encode(), expected_nonce.encode()):
            msg = "ID token nonce mismatch"
            raise FAPIValidationError(msg)
        issued_at, expires_at = _validate_token_times(
            claims,
            now=_aware_now(self.profile.time_source),
            maximum_lifetime=self.profile.id_token_maximum_lifetime,
            clock_skew=self.profile.clock_skew,
            label="ID token",
        )
        auth_time = _optional_numeric_date(claims.get("auth_time"), label="ID token auth_time")
        if auth_time is not None and auth_time > issued_at + self.profile.clock_skew:
            msg = "ID token auth_time is invalid"
            raise FAPIValidationError(msg)
        subject = _required_string(claims.get("sub"), label="ID token subject")
        await self._consume_once(
            f"fapi:nonce:{_digest(self.profile.issuer, nonce)}",
            ttl=max(1.0, (expires_at - _aware_now(self.profile.time_source) + self.profile.clock_skew).total_seconds()),
        )
        return FAPIIDToken(
            subject=subject,
            issued_at=issued_at,
            expires_at=expires_at,
            auth_time=auth_time,
        )

    async def _client_assertion(self, now: datetime) -> str:
        issued_at = int(now.timestamp())
        return await self._sign(
            token_type=_ID_TOKEN_TYPE,
            claims={
                "iss": self.profile.client_id,
                "sub": self.profile.client_id,
                "aud": self.profile.issuer,
                "iat": issued_at,
                "exp": issued_at + 60,
                "jti": _bounded_random(self.profile.random_source),
            },
        )

    async def _sign(self, *, token_type: str, claims: Mapping[str, object]) -> str:
        try:
            token = await self.profile.signer.sign(
                protected_headers={"alg": self.profile.algorithm, "kid": self.profile.key_id, "typ": token_type},
                claims=claims,
            )
        except Exception as exc:
            msg = "FAPI signer is unavailable"
            raise FAPIUnavailableError(msg) from exc
        _validate_compact_jwt(token, label=token_type)
        return token

    async def _verify_jwt(
        self,
        token: str,
        *,
        expected_type: str,
        required: tuple[str, ...],
    ) -> Mapping[str, object]:
        _validate_compact_jwt(token, label=expected_type)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            msg = "FAPI response is not a compact JWT"
            raise FAPIValidationError(msg) from exc
        if header.get("typ") != expected_type:
            msg = "FAPI JWT type mismatch"
            raise FAPIValidationError(msg)
        algorithm = header.get("alg")
        kid = header.get("kid")
        if algorithm not in self.profile.response_algorithms:
            msg = "FAPI JWT algorithm mismatch"
            raise FAPIValidationError(msg)
        if not isinstance(kid, str):
            msg = "FAPI JWT kid is missing"
            raise FAPIValidationError(msg)
        try:
            key = await self.profile.key_resolver.get_key(kid, algorithm)
        except FAPIUnavailableError:
            raise
        except Exception as exc:
            msg = "FAPI JWT key is invalid"
            raise FAPIValidationError(msg) from exc
        try:
            decoded = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                audience=self.profile.client_id,
                issuer=self.profile.issuer,
                options={"require": list(required), "verify_exp": False, "verify_iat": False, "verify_nbf": False},
            )
        except jwt.PyJWTError as exc:
            msg = "FAPI JWT signature or claims are invalid"
            raise FAPIValidationError(msg) from exc
        audience = decoded.get("aud")
        if audience not in (self.profile.client_id, [self.profile.client_id]):
            msg = "FAPI JWT audience mismatch"
            raise FAPIValidationError(msg)
        return cast("Mapping[str, object]", decoded)

    async def _consume_once(self, key: str, *, ttl: float) -> None:
        try:
            outcome = await self.profile.replay_store.check_and_store(key, ttl_seconds=ttl)
        except Exception as exc:
            msg = "FAPI replay store is unavailable"
            raise FAPIUnavailableError(msg) from exc
        if outcome is ReplayOutcome.REPLAY:
            msg = "FAPI protocol value was replayed"
            raise FAPIValidationError(msg)
        if outcome is not ReplayOutcome.STORED:
            msg = "FAPI replay store is unavailable"
            raise FAPIUnavailableError(msg)


def _parse_par_response(content: bytes) -> tuple[str, int]:
    try:
        value = json.loads(content)
    except (TypeError, ValueError) as exc:
        msg = "PAR response is not valid JSON"
        raise FAPIValidationError(msg) from exc
    if not isinstance(value, dict) or set(value) != {"request_uri", "expires_in"}:
        msg = "PAR response schema is invalid"
        raise FAPIValidationError(msg)
    request_uri = value.get("request_uri")
    expires_in = value.get("expires_in")
    if not isinstance(request_uri, str) or not request_uri or len(request_uri) > _MAX_URI_LENGTH:
        msg = "PAR request_uri is invalid"
        raise FAPIValidationError(msg)
    if (
        not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or not 0 < expires_in < _MAX_PAR_LIFETIME_SECONDS
    ):
        msg = "PAR expires_in is invalid"
        raise FAPIValidationError(msg)
    return request_uri, expires_in


def _json_authorization_details(
    details: tuple[Mapping[str, AuthorizationValue], ...],
) -> list[object]:
    try:
        frozen = freeze_authorization_details(details)
    except (TypeError, ValueError) as exc:
        msg = "FAPI authorization_details are invalid"
        raise ValueError(msg) from exc
    return [_json_authorization_value(detail) for detail in frozen]


def _json_authorization_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {name: _json_authorization_value(member) for name, member in value.items()}
    if isinstance(value, tuple):
        return [_json_authorization_value(member) for member in value]
    return value


def _validate_token_times(
    claims: Mapping[str, object],
    *,
    now: datetime,
    maximum_lifetime: timedelta,
    clock_skew: timedelta,
    label: str,
) -> tuple[datetime, datetime]:
    issued_at = _required_numeric_date(claims.get("iat"), label=f"{label} iat")
    expires_at = _required_numeric_date(claims.get("exp"), label=f"{label} exp")
    if issued_at > now + clock_skew:
        msg = f"{label} is not yet valid"
        raise FAPIValidationError(msg)
    if expires_at <= now - clock_skew:
        msg = f"{label} is expired"
        raise FAPIValidationError(msg)
    if expires_at <= issued_at or expires_at - issued_at > maximum_lifetime:
        msg = f"{label} lifetime is invalid"
        raise FAPIValidationError(msg)
    return issued_at, expires_at


def _validate_scopes(scopes: tuple[str, ...]) -> None:
    if (
        not scopes
        or len(scopes) > _MAX_SCOPES
        or len(scopes) != len(set(scopes))
        or any(_SCOPE_PATTERN.fullmatch(scope) is None for scope in scopes)
    ):
        msg = "FAPI scopes are invalid"
        raise ValueError(msg)


def _validate_compact_jwt(value: str, *, label: str) -> None:
    if (
        not value
        or len(value.encode("ascii", errors="ignore")) > _MAX_JWT_BYTES
        or value.count(".") != _JWT_SEPARATOR_COUNT
    ):
        msg = f"FAPI {label} is invalid"
        raise FAPIValidationError(msg)


def _validate_https_url(value: str) -> None:
    parsed = urlsplit(value)
    authority_invalid = not parsed.hostname or parsed.username is not None or parsed.password is not None
    suffix_invalid = bool(parsed.fragment or parsed.query)
    if parsed.scheme != "https" or authority_invalid or suffix_invalid:
        msg = "FAPI URLs must be explicit clean HTTPS URLs"
        raise ValueError(msg)


def _bounded_random(source: Callable[[], str]) -> str:
    value = source()
    if not isinstance(value, str) or not _MIN_RANDOM_LENGTH <= len(value) <= _MAX_RANDOM_LENGTH or not value.isascii():
        msg = "FAPI random source returned an invalid value"
        raise ValueError(msg)
    return value


def _aware_now(source: Callable[[], datetime]) -> datetime:
    value = source()
    if value.tzinfo is None:
        msg = "FAPI time source must return an aware datetime"
        raise ValueError(msg)
    return value


def _base64url_sha256(value: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).rstrip(b"=").decode()


def _digest(*values: str) -> str:
    return _base64url_sha256("\0".join(values))


def _required_string(value: object, *, label: str) -> str:
    parsed = _optional_string(value, label=label)
    if parsed is None:
        msg = f"{label} is missing"
        raise FAPIValidationError(msg)
    return parsed


def _optional_string(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > _MAX_VALUE_LENGTH:
        msg = f"{label} is invalid"
        raise FAPIValidationError(msg)
    return value


def _required_numeric_date(value: object, *, label: str) -> datetime:
    parsed = _optional_numeric_date(value, label=label)
    if parsed is None:
        msg = f"{label} is missing"
        raise FAPIValidationError(msg)
    return parsed


def _optional_numeric_date(value: object, *, label: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, int | float) or isinstance(value, bool):
        msg = f"{label} is invalid"
        raise FAPIValidationError(msg)
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OSError, OverflowError, ValueError) as exc:
        msg = f"{label} is invalid"
        raise FAPIValidationError(msg) from exc


async def _post_par(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> tuple[int, bytes, str]:
    content = bytearray()
    try:
        async with (
            httpx.AsyncClient(follow_redirects=False, timeout=timeout_seconds) as client,
            client.stream("POST", url, headers=dict(headers), content=body) as response,
        ):
            content_type = response.headers.get("content-type", "")
            async for chunk in response.aiter_bytes():
                _extend_bounded(content, chunk, maximum_response_bytes)
            status = response.status_code
    except (httpx.HTTPError, TimeoutError) as exc:
        msg = "PAR request failed"
        raise FAPIUnavailableError(msg) from exc
    return status, bytes(content), content_type


def _extend_bounded(content: bytearray, chunk: bytes, maximum_bytes: int) -> None:
    content.extend(chunk)
    if len(content) > maximum_bytes:
        msg = "PAR response exceeds the configured size limit"
        raise FAPIValidationError(msg)


__all__ = (
    "AsyncJWTKeyResolver",
    "AsyncJWTSigner",
    "FAPIAuthorization",
    "FAPIIDToken",
    "FAPIIssuerProfile",
    "FAPIJARMResult",
    "FAPIMessageSigningClient",
    "FAPIPoster",
    "FAPIUnavailableError",
    "FAPIValidationError",
)
