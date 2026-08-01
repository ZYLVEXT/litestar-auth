"""Bounded RFC 7662 introspection and sender-constrained opaque-token providers."""

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

from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationEvidence,
    AuthorizationValue,
    CredentialMatch,
    FailureCode,
    Invalid,
    PrincipalRef,
    ReplayOutcome,
    ReplayStore,
    SecurityOperation,
    SecurityOutcome,
    Unavailable,
    freeze_authorization_details,
    observe_security,
)

from authweave_workload.authorization_details import (
    PaymentAuthorizationError,
    PaymentAuthorizationPolicy,
    payment_authorization_evidence,
)
from authweave_workload.dpop import DPoPPolicy, _extract_presentation, verify_dpop_proof
from authweave_workload.events import (
    EventDeliveryError,
    SecurityEvent,
    SecurityEventType,
    deliver_security_event,
)
from authweave_workload.jwks import BoundedJWKSClient, JWKSUnavailableError, JWKSValidationError
from authweave_workload.jwt import _load_jwt

if TYPE_CHECKING:
    from authweave_core import AuthenticationDecision, AuthenticationRuntime, RequestView, TlsPeerEvidence

    from authweave_workload.provider import DirectMTLSPolicy

_HTTP_OK = 200
_MAX_TOKEN_BYTES = 16_384
_MAX_RESPONSE_BYTES = 65_536
_MAX_SUBJECT_LENGTH = 512
_MAX_CLIENT_ID_LENGTH = 256
_MAX_KEY_ID_LENGTH = 128
_MAX_VALUE_LENGTH = 512
_MAX_AUDIENCES = 64
_MAX_SCOPES = 64
_THUMBPRINT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_INACTIVE_ONLY_KEYS = frozenset({"active"})
_SIGNED_MEDIA_TYPE = "application/token-introspection+jwt"
_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_DPOP_TOKEN_TYPE = "DPoP"  # ruff: ignore[hardcoded-password-string]
_JOSE_ALGORITHMS = frozenset({"PS256", "ES256", "EdDSA"})

type IntrospectionPoster = Callable[
    [str, Mapping[str, str], bytes, float, int],
    Awaitable[tuple[int, bytes, str]],
]


class IntrospectionUnavailableError(Exception):
    """Raised when the introspection endpoint cannot be reached safely."""


class IntrospectionValidationError(ValueError):
    """Raised when an introspection response violates the issuer profile."""


@dataclass(frozen=True, slots=True)
class IntrospectionEndpoint:
    """Exact HTTPS introspection endpoint ceilings (no discovery, no redirects)."""

    url: str
    timeout_seconds: float = 3.0
    maximum_response_bytes: int = _MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        """Reject non-HTTPS or non-positive ceilings."""
        _validate_introspection_url(self.url)
        if self.timeout_seconds <= 0 or self.maximum_response_bytes < 1:
            msg = "introspection network ceilings must be positive"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class IntrospectionIssuerProfile:
    """Issuer trust and claim mapping for plain RFC 7662 responses."""

    issuer: str
    environment: str
    audiences: frozenset[str] = frozenset()
    principal_kind: str = "service"
    subject_claim: str = "sub"
    require_client_id: bool = True
    payment_authorization: PaymentAuthorizationPolicy | None = None

    def __post_init__(self) -> None:
        """Reject human principals or empty issuer labels."""
        if not self.issuer or not self.environment:
            msg = "introspection issuer and environment are required"
            raise ValueError(msg)
        if self.principal_kind == "human":
            msg = "introspection principals cannot use kind='human'"
            raise ValueError(msg)
        if self.subject_claim not in {"sub", "client_id"}:
            msg = "subject_claim must be 'sub' or 'client_id'"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class IntrospectionClaims:
    """Secret-free parsed introspection facts (never stores the access token)."""

    active: bool
    subject: str | None = None
    client_id: str | None = None
    audiences: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    expires_at: datetime | None = None
    issued_at: datetime | None = None
    not_before: datetime | None = None
    token_type: str | None = None
    confirmation_thumbprint: str | None = None
    confirmation_jkt: str | None = None
    authorization_details: tuple[Mapping[str, AuthorizationValue], ...] | None = None


@runtime_checkable
class AsyncJWTSigner(Protocol):
    """External signer seam; private key material stays outside AuthWeave."""

    async def sign(
        self,
        *,
        protected_headers: Mapping[str, object],
        claims: Mapping[str, object],
    ) -> str:
        """Return one compact signed JWT."""
        ...


@runtime_checkable
class IntrospectionClientAuth(Protocol):
    """Mutate one outbound introspection request with client credentials."""

    async def authorize(self, *, endpoint: str, form: dict[str, str], headers: dict[str, str]) -> None:
        """Authorize one call; request credentials are never logged by AuthWeave."""
        ...


@dataclass(frozen=True, slots=True)
class StaticBearerClientAuth:
    """Outbound Bearer credential for the introspection endpoint (not the merchant token)."""

    token: str

    def __post_init__(self) -> None:
        """Require a non-empty outbound credential."""
        if not self.token or len(self.token.encode()) > _MAX_TOKEN_BYTES:
            msg = "outbound introspection client token is invalid"
            raise ValueError(msg)

    async def authorize(
        self,
        *,
        endpoint: str,  # ruff: ignore[unused-method-argument] - protocol keyword name is public
        form: dict[str, str],  # ruff: ignore[unused-method-argument] - protocol keyword name is public
        headers: dict[str, str],
    ) -> None:
        """Authorize the RS as an introspection client."""
        headers["authorization"] = f"Bearer {self.token}"


@dataclass(frozen=True, slots=True)
class PrivateKeyJWTClientAuth:
    """RFC 7523 client authentication using an external asymmetric signer."""

    client_id: str
    audience: str
    key_id: str
    algorithm: str
    signer: AsyncJWTSigner
    lifetime: timedelta = timedelta(seconds=60)
    time_source: Callable[[], datetime] = lambda: datetime.now(UTC)
    jti_source: Callable[[], str] = lambda: secrets.token_urlsafe(24)

    def __post_init__(self) -> None:
        """Require exact HTTPS audience, bounded identifiers, and modern JOSE."""
        _validate_introspection_url(self.audience)
        identity_invalid = not self.client_id or len(self.client_id) > _MAX_CLIENT_ID_LENGTH
        key_invalid = not self.key_id or len(self.key_id) > _MAX_KEY_ID_LENGTH
        if identity_invalid or key_invalid or self.algorithm not in _JOSE_ALGORITHMS:
            msg = "private_key_jwt client authentication policy is invalid"
            raise ValueError(msg)
        if not timedelta(0) < self.lifetime <= timedelta(minutes=5):
            msg = "private_key_jwt client authentication policy is invalid"
            raise ValueError(msg)

    async def authorize(
        self,
        *,
        endpoint: str,  # ruff: ignore[unused-method-argument] - protocol keyword name is public
        form: dict[str, str],
        headers: dict[str, str],  # ruff: ignore[unused-method-argument] - protocol keyword name is public
    ) -> None:
        """Add a fresh, replay-resistant client assertion to the form body."""
        now = self.time_source()
        if now.tzinfo is None:
            msg = "private_key_jwt time_source must return an aware datetime"
            raise ValueError(msg)
        issued_at = int(now.timestamp())
        assertion = await self.signer.sign(
            protected_headers={"alg": self.algorithm, "kid": self.key_id, "typ": "JWT"},
            claims={
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": self.audience,
                "iat": issued_at,
                "exp": issued_at + int(self.lifetime.total_seconds()),
                "jti": self.jti_source(),
            },
        )
        if not assertion or len(assertion.encode("ascii", errors="ignore")) > _MAX_TOKEN_BYTES:
            msg = "private_key_jwt signer returned an invalid assertion"
            raise IntrospectionValidationError(msg)
        form["client_assertion_type"] = _CLIENT_ASSERTION_TYPE
        form["client_assertion"] = assertion


@dataclass(frozen=True, slots=True)
class SignedIntrospectionResponsePolicy:
    """RFC 9701 signed introspection response trust policy."""

    issuer: str
    audience: str
    jwks: BoundedJWKSClient
    algorithms: frozenset[str] = _JOSE_ALGORITHMS
    maximum_age: timedelta = timedelta(minutes=5)
    clock_skew: timedelta = timedelta(seconds=30)
    time_source: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        """Reject open-ended or legacy signature policy."""
        identity_invalid = not self.issuer or not self.audience
        algorithms_invalid = not self.algorithms or not self.algorithms <= _JOSE_ALGORITHMS
        time_invalid = self.maximum_age <= timedelta(0) or self.clock_skew < timedelta(0)
        if identity_invalid or algorithms_invalid or time_invalid:
            msg = "signed introspection response policy is invalid"
            raise ValueError(msg)


@runtime_checkable
class IntrospectionCache(Protocol):
    """Minimal async cache storing only bounded, secret-free claim snapshots."""

    async def get(self, key: str) -> bytes | None:
        """Return a cached snapshot or ``None``."""
        ...

    async def set(self, key: str, value: bytes, *, ttl_seconds: int) -> None:
        """Store one snapshot for a positive number of seconds."""
        ...


@dataclass(frozen=True, slots=True)
class IntrospectionCachePolicy:
    """Short, issuer-scoped cache ceilings; active caching is opt-in."""

    issuer: str
    active_ttl_seconds: int = 0
    inactive_ttl_seconds: int = 5
    revocation_risk_ceiling_seconds: int = 30
    time_source: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        """Reject negative or unscoped cache ceilings."""
        if (
            not self.issuer
            or self.active_ttl_seconds < 0
            or self.inactive_ttl_seconds < 0
            or self.revocation_risk_ceiling_seconds < 1
        ):
            msg = "introspection cache policy is invalid"
            raise ValueError(msg)


class BoundedIntrospectionClient:
    """POST ``application/x-www-form-urlencoded`` introspection with hard response bounds."""

    def __init__(  # ruff: ignore[too-many-arguments]
        self,
        *,
        endpoint: IntrospectionEndpoint,
        client_auth: IntrospectionClientAuth | None = None,
        signed_response: SignedIntrospectionResponsePolicy | None = None,
        cache: IntrospectionCache | None = None,
        cache_policy: IntrospectionCachePolicy | None = None,
        poster: IntrospectionPoster | None = None,
    ) -> None:
        """Bind endpoint policy and optional outbound client authentication."""
        self.endpoint = endpoint
        self.client_auth = client_auth
        self.signed_response = signed_response
        if (cache is None) != (cache_policy is None):
            msg = "introspection cache and cache_policy must be configured together"
            raise ValueError(msg)
        self.cache = cache
        self.cache_policy = cache_policy
        self.poster = _post_introspection if poster is None else poster

    async def introspect(self, token: str) -> IntrospectionClaims:
        """Call the introspection endpoint and parse a plain JSON response.

        Returns:
            Parsed claims. The access token is never retained on the result.

        Raises:
            IntrospectionUnavailableError: On network/timeout/non-success transport failure.
            IntrospectionValidationError: On profile/schema violations.
            ValueError: If ``token`` is empty or oversized.
        """
        if not token or len(token.encode("utf-8")) > _MAX_TOKEN_BYTES:
            msg = "introspection token is empty or oversized"
            raise ValueError(msg)
        cached = await self._cached(token)
        if cached is not None:
            return cached
        form = {"token": token}
        headers = {
            "accept": _SIGNED_MEDIA_TYPE if self.signed_response is not None else "application/json",
            "content-type": "application/x-www-form-urlencoded",
        }
        if self.client_auth is not None:
            await self.client_auth.authorize(endpoint=self.endpoint.url, form=form, headers=headers)
        body = urlencode(form).encode("ascii")
        try:
            status, content, content_type = await self.poster(
                self.endpoint.url,
                headers,
                body,
                self.endpoint.timeout_seconds,
                self.endpoint.maximum_response_bytes,
            )
        except IntrospectionUnavailableError:
            raise
        except IntrospectionValidationError:
            raise
        except Exception as exc:
            raise IntrospectionUnavailableError("introspection request failed") from exc
        if len(content) > self.endpoint.maximum_response_bytes:
            raise IntrospectionValidationError("introspection response exceeds the configured size limit")
        if status != _HTTP_OK:
            raise IntrospectionUnavailableError("introspection endpoint returned a non-success status")
        media = content_type.split(";", 1)[0].strip().lower()
        if self.signed_response is None:
            if media != "application/json":
                raise IntrospectionValidationError("introspection Content-Type must be application/json")
            claims = parse_plain_introspection(content)
            await self._cache(token, claims)
            return claims
        if media != _SIGNED_MEDIA_TYPE:
            msg = f"introspection Content-Type must be {_SIGNED_MEDIA_TYPE}"
            raise IntrospectionValidationError(msg)
        claims = await parse_signed_introspection(content, self.signed_response)
        await self._cache(token, claims)
        return claims

    async def _cached(self, token: str) -> IntrospectionClaims | None:
        if self.cache is None or self.cache_policy is None:
            return None
        try:
            content = await self.cache.get(self._cache_key(token))
            return None if content is None else _parse_cached_claims(content)
        except Exception:  # ruff: ignore[blind-except] - cache is an optional optimization
            return None

    async def _cache(self, token: str, claims: IntrospectionClaims) -> None:
        if self.cache is None or self.cache_policy is None:
            return
        ttl = _cache_ttl(claims, self.cache_policy)
        if ttl < 1:
            return
        try:
            await self.cache.set(self._cache_key(token), _encode_cached_claims(claims), ttl_seconds=ttl)
        except Exception:  # ruff: ignore[blind-except] - cache is an optional optimization
            return

    def _cache_key(self, token: str) -> str:
        policy = cast("IntrospectionCachePolicy", self.cache_policy)
        return f"authweave:introspection:{token_digest(token, issuer=policy.issuer)}"


def parse_plain_introspection(content: bytes) -> IntrospectionClaims:
    """Parse a plain RFC 7662 JSON introspection body.

    Returns:
        Validated claims.

    Raises:
        IntrospectionValidationError: If the body is malformed or inactive metadata leaks.
    """
    try:
        decoded = json.loads(content)
    except (TypeError, ValueError) as exc:
        raise IntrospectionValidationError("introspection response is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise IntrospectionValidationError("introspection response must be an object")
    active = decoded.get("active")
    if not isinstance(active, bool):
        raise IntrospectionValidationError("introspection active claim must be boolean")
    if not active:
        if set(decoded) - _INACTIVE_ONLY_KEYS:
            raise IntrospectionValidationError("inactive introspection must not include token metadata")
        return IntrospectionClaims(active=False)
    subject = _optional_string(decoded.get("sub"), maximum=_MAX_SUBJECT_LENGTH)
    client_id = _optional_string(decoded.get("client_id"), maximum=_MAX_CLIENT_ID_LENGTH)
    audiences = _optional_string_list(decoded.get("aud"), maximum_items=_MAX_AUDIENCES)
    scopes = _parse_scopes(decoded.get("scope"))
    token_type = _optional_string(decoded.get("token_type"), maximum=_MAX_VALUE_LENGTH)
    try:
        expires_at = _optional_numeric_date(decoded.get("exp"))
        issued_at = _optional_numeric_date(decoded.get("iat"))
        not_before = _optional_numeric_date(decoded.get("nbf"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise IntrospectionValidationError("introspection time claims are invalid") from exc
    confirmation_thumbprint, confirmation_jkt = _parse_confirmation(decoded.get("cnf"))
    raw_authorization_details = decoded.get("authorization_details")
    if raw_authorization_details is None:
        authorization_details = None
    else:
        try:
            authorization_details = freeze_authorization_details(raw_authorization_details)
        except (TypeError, ValueError) as exc:
            msg = "introspection authorization_details transport is invalid"
            raise IntrospectionValidationError(msg) from exc
    return IntrospectionClaims(
        active=True,
        subject=subject,
        client_id=client_id,
        audiences=audiences,
        scopes=scopes,
        expires_at=expires_at,
        issued_at=issued_at,
        not_before=not_before,
        token_type=token_type,
        confirmation_thumbprint=confirmation_thumbprint,
        confirmation_jkt=confirmation_jkt,
        authorization_details=authorization_details,
    )


async def parse_signed_introspection(
    content: bytes,
    policy: SignedIntrospectionResponsePolicy,
    *,
    now: datetime | None = None,
) -> IntrospectionClaims:
    """Verify and parse an RFC 9701 signed introspection response."""
    jwt = _load_jwt()
    try:
        compact = content.decode("ascii")
        header = jwt.get_unverified_header(compact)
    except (UnicodeDecodeError, jwt.PyJWTError) as exc:
        raise IntrospectionValidationError("signed introspection response is not a compact JWT") from exc
    if header.get("typ") != "token-introspection+jwt":
        raise IntrospectionValidationError("signed introspection JWT typ is invalid")
    algorithm = header.get("alg")
    kid = header.get("kid")
    if algorithm not in policy.algorithms:
        raise IntrospectionValidationError("signed introspection JWT algorithm is invalid")
    if not isinstance(kid, str):
        raise IntrospectionValidationError("signed introspection JWT kid is missing")
    try:
        key = await policy.jwks.get_key(kid, algorithm)
    except JWKSUnavailableError as exc:
        raise IntrospectionUnavailableError("signed introspection keys are unavailable") from exc
    except JWKSValidationError as exc:
        raise IntrospectionValidationError("signed introspection key is invalid") from exc
    try:
        claims = jwt.decode(
            compact,
            key,
            algorithms=[algorithm],
            audience=policy.audience,
            issuer=policy.issuer,
            options={
                "require": ["iss", "aud", "iat", "token_introspection"],
                "verify_iat": False,
                "strict_aud": False,
            },
        )
    except jwt.InvalidIssuerError as exc:
        raise IntrospectionValidationError("signed introspection issuer is invalid") from exc
    except jwt.InvalidAudienceError as exc:
        raise IntrospectionValidationError("signed introspection audience is invalid") from exc
    except jwt.PyJWTError as exc:
        raise IntrospectionValidationError("signed introspection signature or claims are invalid") from exc
    audience = claims.get("aud")
    if audience not in (policy.audience, [policy.audience]):
        raise IntrospectionValidationError("signed introspection audience is invalid")
    checked_at = policy.time_source() if now is None else now
    if checked_at.tzinfo is None:
        raise ValueError("signed introspection now must be timezone-aware")
    try:
        issued_at = _optional_numeric_date(claims["iat"])
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise IntrospectionValidationError("signed introspection iat is invalid") from exc
    if issued_at is None or issued_at > checked_at + policy.clock_skew:
        raise IntrospectionValidationError("signed introspection response is not yet valid")
    if issued_at < checked_at - policy.maximum_age - policy.clock_skew:
        raise IntrospectionValidationError("signed introspection response is stale")
    encoded = json.dumps(claims.get("token_introspection"), separators=(",", ":")).encode()
    return parse_plain_introspection(encoded)


def token_digest(token: str, *, issuer: str) -> str:
    """Return an issuer-namespaced SHA-256 digest suitable as a cache key.

    Returns:
        Unpadded base64url digest (never the raw token).
    """
    material = f"{issuer}\0{token}".encode()
    digest = hashlib.sha256(material).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _encode_cached_claims(claims: IntrospectionClaims) -> bytes:
    if not claims.active:
        return b'{"active":false}'
    payload: dict[str, object] = {"active": True}
    optional: tuple[tuple[str, object | None], ...] = (
        ("sub", claims.subject),
        ("client_id", claims.client_id),
        ("aud", list(claims.audiences) if claims.audiences else None),
        ("scope", " ".join(claims.scopes) if claims.scopes else None),
        ("exp", claims.expires_at.timestamp() if claims.expires_at else None),
        ("iat", claims.issued_at.timestamp() if claims.issued_at else None),
        ("nbf", claims.not_before.timestamp() if claims.not_before else None),
        ("token_type", claims.token_type),
    )
    payload.update((name, value) for name, value in optional if value is not None)
    if claims.confirmation_thumbprint is not None:
        payload["cnf"] = {"x5t#S256": claims.confirmation_thumbprint}
    elif claims.confirmation_jkt is not None:
        payload["cnf"] = {"jkt": claims.confirmation_jkt}
    if claims.authorization_details is not None:
        payload["authorization_details"] = _json_authorization_value(claims.authorization_details)
    return json.dumps(payload, separators=(",", ":")).encode()


def _json_authorization_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {name: _json_authorization_value(member) for name, member in value.items()}
    if isinstance(value, tuple):
        return [_json_authorization_value(member) for member in value]
    return value


def _parse_cached_claims(content: bytes) -> IntrospectionClaims:
    if len(content) > _MAX_RESPONSE_BYTES:
        raise IntrospectionValidationError("cached introspection response is oversized")
    return parse_plain_introspection(content)


def _cache_ttl(claims: IntrospectionClaims, policy: IntrospectionCachePolicy) -> int:
    if not claims.active:
        return policy.inactive_ttl_seconds
    ttl = min(policy.active_ttl_seconds, policy.revocation_risk_ceiling_seconds)
    if claims.expires_at is not None:
        now = policy.time_source()
        if now.tzinfo is None:
            return 0
        ttl = min(ttl, int((claims.expires_at - now).total_seconds()))
    return max(0, ttl)


class DPoPBoundIntrospectionProvider:
    """Authenticate an opaque access token bound to a locally verified DPoP proof."""

    profile = "dpop_bound_introspection"

    def __init__(  # ruff: ignore[too-many-arguments]
        self,
        *,
        name: str,
        client: BoundedIntrospectionClient,
        profile: IntrospectionIssuerProfile,
        dpop: DPoPPolicy,
        replay_store: ReplayStore,
        event_callback: Callable[[SecurityEvent], object] | None = None,
    ) -> None:
        """Bind introspection, DPoP, replay, and event policies."""
        self.name = name
        self.client = client
        self.issuer_profile = profile
        self.dpop = dpop
        self.replay_store = replay_store
        self.event_callback = event_callback

    def match(self, request: RequestView) -> CredentialMatch:
        """Own exactly one DPoP authorization plus proof header."""
        authorization = request.header_values(b"authorization")
        proofs = request.header_values(b"dpop")
        if not authorization and not proofs:
            return CredentialMatch.NOT_APPLICABLE
        if (
            len(authorization) > 1
            or len(proofs) > 1
            or request.header_values(b"cookie")
            or request.tls_peer is not None
        ):
            return CredentialMatch.AMBIGUOUS
        if authorization:
            scheme = authorization[0].partition(b" ")[0].lower()
            if scheme == b"bearer":
                return CredentialMatch.AMBIGUOUS if proofs else CredentialMatch.NOT_APPLICABLE
            if scheme != b"dpop":
                return CredentialMatch.NOT_APPLICABLE
        return CredentialMatch.OWNED

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Verify proof, introspection binding, replay, and mapped identity fail-closed."""
        try:
            return await self._authenticate(request, runtime)
        except EventDeliveryError:
            return Unavailable()

    async def _authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        presentation = _extract_presentation(request)
        if presentation is None:
            return await self._failure(request, FailureCode.MALFORMED)
        access_token, proof_jwt = presentation
        proof = await verify_dpop_proof(
            request,
            runtime,
            access_token=access_token,
            proof_jwt=proof_jwt,
            policy=self.dpop,
        )
        if isinstance(proof, FailureCode):
            return await self._failure(request, proof)
        jkt, proof_jti = proof
        with observe_security(
            runtime.observer, SecurityOperation.OAUTH_INTROSPECT, profile=self.profile
        ) as observation:
            try:
                claims = await self.client.introspect(access_token)
            except IntrospectionUnavailableError:
                observation.set_outcome(SecurityOutcome.UNAVAILABLE)
                return await self._failure(request, FailureCode.PROVIDER_UNAVAILABLE)
            except (IntrospectionValidationError, ValueError):
                observation.set_outcome(SecurityOutcome.ERROR)
                return await self._failure(request, FailureCode.MALFORMED)
            observation.set_outcome(SecurityOutcome.SUCCESS)
        if not claims.active:
            return await self._failure(request, FailureCode.INVALID)
        if (
            claims.token_type != _DPOP_TOKEN_TYPE
            or claims.confirmation_jkt is None
            or not hmac.compare_digest(claims.confirmation_jkt.encode(), jkt.encode())
        ):
            return await self._failure(request, FailureCode.SENDER_CONSTRAINT_MISMATCH)
        mapped = _map_active_claims(claims, self.issuer_profile, timestamp=request.timestamp)
        if isinstance(mapped, FailureCode):
            return await self._failure(request, mapped)
        subject, client_id, audiences, scopes, issued_at, not_before, expires_at = mapped
        try:
            authorization_details = payment_authorization_evidence(
                claims.authorization_details,
                policy=self.issuer_profile.payment_authorization,
                scopes=scopes,
            )
        except PaymentAuthorizationError:
            return await self._failure(request, FailureCode.INVALID)
        replay_key = f"dpop-introspection:{self.dpop.resource_server_id}:{jkt}:{proof_jti}"
        replay_ttl = (self.dpop.iat_window + self.dpop.clock_skew).total_seconds()
        outcome = await self.replay_store.check_and_store(replay_key, ttl_seconds=replay_ttl)
        if outcome is ReplayOutcome.REPLAY:
            return await self._failure(request, FailureCode.INVALID)
        if outcome is not ReplayOutcome.STORED:
            return await self._failure(request, FailureCode.PROVIDER_UNAVAILABLE)
        try:
            principal = PrincipalRef(self.issuer_profile.issuer, subject, self.issuer_profile.principal_kind)
            evidence = AuthenticationEvidence(
                provider=self.name,
                profile=self.profile,
                method="dpop",
                issuer=self.issuer_profile.issuer,
                audiences=audiences,
                scopes=scopes,
                issued_at=issued_at,
                not_before=not_before,
                expires_at=expires_at,
                confirmation_thumbprint=jkt,
                environment=self.issuer_profile.environment,
                authorization_details=authorization_details,
                extensions={
                    "authweave-workload:application_id": client_id,
                    "authweave-workload:client_id": client_id,
                },
            )
        except (TypeError, ValueError):
            return await self._failure(request, FailureCode.INVALID)
        context = AuthenticationContext(subject=principal, actor=principal, evidence=evidence)
        await deliver_security_event(
            self.event_callback,
            SecurityEvent(
                SecurityEventType.AUTHENTICATION_SUCCEEDED,
                target_principal=principal,
                actor=principal,
                provider=self.name,
                profile=self.profile,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )
        return Authenticated(context)

    async def _failure(self, request: RequestView, code: FailureCode) -> AuthenticationDecision:
        event_type = (
            SecurityEventType.SENDER_CONSTRAINT_REJECTED
            if code is FailureCode.SENDER_CONSTRAINT_MISMATCH
            else SecurityEventType.AUTHENTICATION_FAILED
        )
        await deliver_security_event(
            self.event_callback,
            SecurityEvent(
                event_type,
                provider=self.name,
                profile=self.profile,
                reason=code,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )
        return Unavailable() if code is FailureCode.PROVIDER_UNAVAILABLE else Invalid(code)


class MTLSBoundIntrospectionProvider:
    """Authenticate an opaque Bearer token via introspection bound to trusted mTLS evidence."""

    profile = "mtls_bound_introspection"

    def __init__(
        self,
        *,
        name: str,
        client: BoundedIntrospectionClient,
        profile: IntrospectionIssuerProfile,
        tls_policy: DirectMTLSPolicy,
        event_callback: Callable[[SecurityEvent], object] | None = None,
    ) -> None:
        """Bind introspection client, issuer mapping, and TLS evidence policy."""
        self.name = name
        self.client = client
        self.issuer_profile = profile
        self.tls_policy = tls_policy
        self.event_callback = event_callback

    def match(self, request: RequestView) -> CredentialMatch:
        """Own exactly one Bearer presentation without cookies or DPoP proofs."""
        authorization = request.header_values(b"authorization")
        if not authorization:
            return CredentialMatch.NOT_APPLICABLE
        if len(authorization) != 1 or request.header_values(b"cookie") or request.header_values(b"dpop"):
            return CredentialMatch.AMBIGUOUS
        scheme, separator, token = authorization[0].partition(b" ")
        if scheme.lower() != b"bearer":
            return CredentialMatch.NOT_APPLICABLE
        if separator != b" " or not token.strip() or len(token) > _MAX_TOKEN_BYTES:
            return CredentialMatch.OWNED
        return CredentialMatch.OWNED

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Introspect the opaque token and enforce ``cnf.x5t#S256`` against TLS peer evidence.

        Fails closed to :class:`~authweave_core.Unavailable` if mandatory event
        delivery fails (ADR 0001).

        Returns:
            Authenticated context, Invalid, or Unavailable.
        """
        try:
            return await self._authenticate(request, runtime)
        except EventDeliveryError:
            return Unavailable()

    async def _authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        token = _extract_bearer_token(request)
        if token is None:
            await self._emit_failure(request, FailureCode.MALFORMED)
            return Invalid(FailureCode.MALFORMED)
        peer_failure = _validate_tls_peer(request, self.tls_policy)
        if peer_failure is not None:
            await self._emit_failure(request, peer_failure)
            if peer_failure is FailureCode.PROVIDER_UNAVAILABLE:
                return Unavailable()
            return Invalid(peer_failure)
        peer = cast("TlsPeerEvidence", request.tls_peer)
        with observe_security(
            runtime.observer,
            SecurityOperation.OAUTH_INTROSPECT,
            profile=self.profile,
        ) as observation:
            try:
                claims = await self.client.introspect(token)
            except IntrospectionUnavailableError:
                observation.set_outcome(SecurityOutcome.UNAVAILABLE)
                await self._emit_failure(request, FailureCode.PROVIDER_UNAVAILABLE)
                return Unavailable()
            except (IntrospectionValidationError, ValueError):
                observation.set_outcome(SecurityOutcome.ERROR)
                await self._emit_failure(request, FailureCode.MALFORMED)
                return Invalid(FailureCode.MALFORMED)
            observation.set_outcome(SecurityOutcome.SUCCESS)
        if not claims.active:
            await self._emit_failure(request, FailureCode.INVALID)
            return Invalid(FailureCode.INVALID)
        if claims.confirmation_thumbprint is None or not hmac.compare_digest(
            claims.confirmation_thumbprint.encode(),
            peer.certificate_thumbprint.encode(),
        ):
            await self._emit_failure(request, FailureCode.SENDER_CONSTRAINT_MISMATCH)
            return Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)
        mapped = _map_active_claims(claims, self.issuer_profile, timestamp=request.timestamp)
        if isinstance(mapped, FailureCode):
            await self._emit_failure(request, mapped)
            return Invalid(mapped)
        subject, client_id, audiences, scopes, issued_at, not_before, expires_at = mapped
        try:
            authorization_details = payment_authorization_evidence(
                claims.authorization_details,
                policy=self.issuer_profile.payment_authorization,
                scopes=scopes,
            )
        except PaymentAuthorizationError:
            await self._emit_failure(request, FailureCode.INVALID)
            return Invalid(FailureCode.INVALID)
        try:
            principal = PrincipalRef(self.issuer_profile.issuer, subject, self.issuer_profile.principal_kind)
            evidence = AuthenticationEvidence(
                provider=self.name,
                profile=self.profile,
                method="introspection",
                issuer=self.issuer_profile.issuer,
                audiences=audiences,
                scopes=scopes,
                issued_at=issued_at,
                not_before=not_before,
                expires_at=expires_at,
                confirmation_thumbprint=claims.confirmation_thumbprint,
                environment=self.issuer_profile.environment,
                authorization_details=authorization_details,
                extensions={
                    "authweave-workload:application_id": client_id,
                    "authweave-workload:client_id": client_id,
                },
            )
        except (TypeError, ValueError):
            await self._emit_failure(request, FailureCode.INVALID)
            return Invalid(FailureCode.INVALID)
        context = AuthenticationContext(subject=principal, actor=principal, evidence=evidence)
        await self._emit(
            SecurityEvent(
                SecurityEventType.AUTHENTICATION_SUCCEEDED,
                target_principal=principal,
                actor=principal,
                provider=self.name,
                profile=self.profile,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )
        return Authenticated(context)

    async def _emit_failure(self, request: RequestView, code: FailureCode) -> None:
        event_type = (
            SecurityEventType.SENDER_CONSTRAINT_REJECTED
            if code is FailureCode.SENDER_CONSTRAINT_MISMATCH
            else SecurityEventType.AUTHENTICATION_FAILED
        )
        await self._emit(
            SecurityEvent(
                event_type,
                provider=self.name,
                profile=self.profile,
                reason=code,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )

    async def _emit(self, event: SecurityEvent) -> None:
        await deliver_security_event(self.event_callback, event)


def _validate_introspection_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc or parts.fragment or parts.username or parts.password:
        msg = "introspection URL must be an absolute https URL without userinfo or fragment"
        raise ValueError(msg)


async def _post_introspection(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> tuple[int, bytes, str]:
    try:
        import httpx
    except ImportError as exc:
        msg = "introspection requires the 'authweave-workload[introspection]' extra."
        raise ImportError(msg) from exc
    content = bytearray()
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout_seconds) as client:
            async with client.stream("POST", url, headers=dict(headers), content=body) as response:
                content_type = response.headers.get("content-type", "")
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > maximum_response_bytes:
                        raise IntrospectionValidationError(
                            "introspection response exceeds the configured size limit",
                        )
                return response.status_code, bytes(content), content_type
    except IntrospectionValidationError:
        raise
    except (httpx.HTTPError, TimeoutError) as exc:
        raise IntrospectionUnavailableError("introspection request failed") from exc


def _extract_bearer_token(request: RequestView) -> str | None:
    authorization = request.header_values(b"authorization")
    if len(authorization) != 1:
        return None
    scheme, separator, token = authorization[0].partition(b" ")
    if scheme.lower() != b"bearer" or separator != b" " or not token.strip():
        return None
    if len(token) > _MAX_TOKEN_BYTES:
        return None
    try:
        return token.decode("ascii")
    except UnicodeDecodeError:
        return None


def _validate_tls_peer(request: RequestView, policy: DirectMTLSPolicy) -> FailureCode | None:
    peer = request.tls_peer
    if peer is None or peer.tls_version != "TLSv1.3":
        return FailureCode.SENDER_CONSTRAINT_MISMATCH
    if peer.trust_anchor not in policy.trust_anchors or peer.termination_boundary not in policy.termination_boundaries:
        return FailureCode.SENDER_CONSTRAINT_MISMATCH
    if not (peer.certificate_not_before <= request.timestamp < peer.certificate_not_after):
        return FailureCode.SENDER_CONSTRAINT_MISMATCH
    if request.timestamp - peer.revocation_checked_at > policy.maximum_revocation_age:
        return FailureCode.PROVIDER_UNAVAILABLE
    if peer.revocation_checked_at > request.timestamp:
        return FailureCode.INTERNAL_INVARIANT
    return None


def _map_active_claims(
    claims: IntrospectionClaims,
    profile: IntrospectionIssuerProfile,
    *,
    timestamp: datetime,
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], datetime | None, datetime | None, datetime | None] | FailureCode:
    if profile.require_client_id and not claims.client_id:
        return FailureCode.MALFORMED
    subject_source = claims.subject if profile.subject_claim == "sub" else claims.client_id
    if not subject_source:
        return FailureCode.MALFORMED
    client_id = claims.client_id or subject_source
    if profile.audiences:
        if not claims.audiences or not set(claims.audiences) <= profile.audiences:
            return FailureCode.AUDIENCE_MISMATCH
        audiences = tuple(sorted(set(claims.audiences) & profile.audiences))
    else:
        audiences = claims.audiences
    if claims.not_before is not None and timestamp < claims.not_before:
        return FailureCode.NOT_YET_VALID
    if claims.expires_at is not None and timestamp >= claims.expires_at:
        return FailureCode.EXPIRED
    return subject_source, client_id, audiences, claims.scopes, claims.issued_at, claims.not_before, claims.expires_at


def _parse_confirmation(value: object) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, dict) or len(value) != 1 or not set(value) <= {"x5t#S256", "jkt"}:
        raise IntrospectionValidationError("introspection cnf must contain exactly one supported confirmation")
    name, confirmation = next(iter(value.items()))
    if not isinstance(confirmation, str) or _THUMBPRINT_PATTERN.fullmatch(confirmation) is None:
        raise IntrospectionValidationError("introspection confirmation thumbprint is invalid")
    return (confirmation, None) if name == "x5t#S256" else (None, confirmation)


def _parse_scopes(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, str):
        raise IntrospectionValidationError("introspection scope must be a space-delimited string")
    if not value:
        return ()
    scopes = tuple(value.split(" "))
    if (
        len(scopes) > _MAX_SCOPES
        or len(scopes) != len(set(scopes))
        or any(_optional_string(scope, maximum=_MAX_VALUE_LENGTH) is None for scope in scopes)
    ):
        raise IntrospectionValidationError("introspection scope list is invalid")
    return scopes


def _optional_string_list(value: object, *, maximum_items: int) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        values = tuple(value)
    else:
        raise IntrospectionValidationError("introspection aud claim is invalid")
    if (
        len(values) > maximum_items
        or len(values) != len(set(values))
        or any(_optional_string(item, maximum=_MAX_VALUE_LENGTH) is None for item in values)
    ):
        raise IntrospectionValidationError("introspection aud claim is invalid")
    return cast("tuple[str, ...]", values)


def _optional_string(value: object, *, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > maximum:
        raise IntrospectionValidationError("introspection string claim is invalid")
    return value


def _optional_numeric_date(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise TypeError
    return datetime.fromtimestamp(value, tz=UTC)


__all__ = (
    "AsyncJWTSigner",
    "BoundedIntrospectionClient",
    "DPoPBoundIntrospectionProvider",
    "IntrospectionCache",
    "IntrospectionCachePolicy",
    "IntrospectionClaims",
    "IntrospectionClientAuth",
    "IntrospectionEndpoint",
    "IntrospectionIssuerProfile",
    "IntrospectionUnavailableError",
    "IntrospectionValidationError",
    "MTLSBoundIntrospectionProvider",
    "PrivateKeyJWTClientAuth",
    "SignedIntrospectionResponsePolicy",
    "StaticBearerClientAuth",
    "parse_plain_introspection",
    "parse_signed_introspection",
    "token_digest",
)
