"""DPoP-bound external OAuth access-token resource-server profile (RFC 9449)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

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
    observe_security,
)

from authweave_workload.authorization_details import PaymentAuthorizationError, payment_authorization_evidence
from authweave_workload.events import (
    EventDeliveryError,
    SecurityEvent,
    SecurityEventType,
    deliver_security_event,
)
from authweave_workload.jwks import JWKSUnavailableError, JWKSValidationError
from authweave_workload.jwt import TrustedIssuer, _load_jwt

if TYPE_CHECKING:
    from authweave_core import AuthenticationDecision, AuthenticationRuntime, RequestView

_ALLOWED_PROOF_ALGORITHMS = frozenset({"ES256", "EdDSA"})
_ALLOWED_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
_MAX_TOKEN_BYTES = 16_384
_MAX_PROOF_BYTES = 16_384
_MAX_SUBJECT_LENGTH = 512
_MAX_CLIENT_ID_LENGTH = 256
_MAX_VALUE_LENGTH = 512
_MAX_AUDIENCES = 64
_MAX_SCOPES = 64
_THUMBPRINT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_PUBLIC_JWK_METADATA = frozenset({"alg", "use", "kid", "key_ops"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
type _ValidatedDPoPToken = tuple[
    str,
    str,
    tuple[str, ...],
    tuple[str, ...],
    datetime,
    datetime | None,
    datetime,
    str,
    tuple[Mapping[str, AuthorizationValue], ...],
]


@dataclass(frozen=True, slots=True)
class DPoPPolicy:
    """Exact DPoP proof policy for one resource-server profile."""

    resource_server_id: str
    algorithms: frozenset[str] = _ALLOWED_PROOF_ALGORITHMS
    iat_window: timedelta = timedelta(seconds=60)
    clock_skew: timedelta = timedelta(seconds=30)
    require_nonce: bool = False
    nonce_store: DPoPNonceStore | None = None

    def __post_init__(self) -> None:
        """Reject empty identity or legacy algorithms."""
        if not self.resource_server_id:
            msg = "resource_server_id must be non-empty"
            raise ValueError(msg)
        if not self.algorithms or not self.algorithms <= _ALLOWED_PROOF_ALGORITHMS:
            msg = "DPoP algorithms must use the modern allowlist"
            raise ValueError(msg)
        if self.iat_window <= timedelta(0) or self.clock_skew < timedelta(0):
            msg = "DPoP time policy is invalid"
            raise ValueError(msg)
        if self.require_nonce and self.nonce_store is None:
            msg = "require_nonce requires a nonce_store"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class DPoPNonceChallenge:
    """Opaque RS nonce challenge returned to the client."""

    nonce: str = field(repr=False)

    def www_authenticate(self) -> str:
        """Return the RFC 9449 ``WWW-Authenticate`` challenge value.

        Returns:
            A secret-free challenge header value.
        """
        return 'DPoP error="use_dpop_nonce"'

    def response_headers(self) -> dict[str, str]:
        """Return headers for a nonce challenge response.

        Returns:
            ``DPoP-Nonce`` and ``Cache-Control: no-store``.
        """
        return {"DPoP-Nonce": self.nonce, "Cache-Control": "no-store"}


@runtime_checkable
class DPoPNonceStore(Protocol):
    """Issue and single-consume opaque DPoP nonces for high-risk mutations."""

    async def issue(self, *, origin: str, jkt: str) -> str:
        """Issue one opaque nonce scoped to an origin and proof key."""
        ...

    async def consume(self, *, origin: str, jkt: str, nonce: str) -> ReplayOutcome:
        """Consume one previously issued nonce exactly once."""
        ...


type DPoPReplayStore = ReplayStore


class InMemoryDPoPNonceStore:
    """Single-process nonce issuer/consumer for tests and single-worker demos."""

    __slots__ = ("_capacity", "_entries", "_time_source")

    def __init__(self, *, capacity: int, time_source: Callable[[], float]) -> None:
        """Bound capacity and inject a monotonic clock."""
        if capacity <= 0:
            msg = "capacity must be positive"
            raise ValueError(msg)
        self._capacity = capacity
        self._entries: dict[str, float] = {}
        self._time_source = time_source

    async def issue(self, *, origin: str, jkt: str) -> str:
        """Issue one opaque nonce scoped to an origin and proof key.

        Returns:
            The opaque nonce string.
        """
        now = self._time_source()
        if len(self._entries) >= self._capacity:
            self._purge(now)
            if len(self._entries) >= self._capacity:
                msg = "nonce store capacity exceeded"
                raise RuntimeError(msg)
        nonce = secrets.token_urlsafe(32)
        key = _nonce_key(origin, jkt, nonce)
        if key in self._entries:
            msg = "nonce collision"
            raise RuntimeError(msg)
        self._entries[key] = now + 120.0
        return nonce

    async def consume(self, *, origin: str, jkt: str, nonce: str) -> ReplayOutcome:
        """Consume one previously issued nonce exactly once.

        Returns:
            A typed put-if-absent-style outcome for the nonce claim.
        """
        key = _nonce_key(origin, jkt, nonce)
        now = self._time_source()
        expiry = self._entries.pop(key, None)
        if expiry is None or expiry <= now:
            return ReplayOutcome.REPLAY
        return ReplayOutcome.STORED

    def _purge(self, now: float) -> None:
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]


class DPoPBoundJWTProvider:
    """Authenticate an external access token only when bound to a valid DPoP proof."""

    profile = "dpop_bound_access_token"

    def __init__(
        self,
        *,
        name: str,
        issuer: TrustedIssuer,
        dpop: DPoPPolicy,
        replay_store: ReplayStore,
        event_callback: Callable[[SecurityEvent], object] | None = None,
    ) -> None:
        """Bind issuer policy, DPoP policy, and the proof replay store."""
        self.name = name
        self.issuer = issuer
        self.dpop = dpop
        self.replay_store = replay_store
        self.event_callback = event_callback

    def match(self, request: RequestView) -> CredentialMatch:
        """Own the DPoP composite presentation and reject mixed credentials."""
        authorization = request.header_values(b"authorization")
        proof_headers = request.header_values(b"dpop")
        if not authorization and not proof_headers:
            return CredentialMatch.NOT_APPLICABLE
        if (
            len(authorization) > 1
            or len(proof_headers) > 1
            or request.header_values(b"cookie")
            or request.tls_peer is not None
        ):
            return CredentialMatch.AMBIGUOUS
        if authorization:
            scheme = authorization[0].partition(b" ")[0].lower()
            if scheme == b"bearer":
                return CredentialMatch.AMBIGUOUS if proof_headers else CredentialMatch.NOT_APPLICABLE
            if scheme != b"dpop":
                return CredentialMatch.NOT_APPLICABLE
        return CredentialMatch.OWNED

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Authenticate and fail closed if mandatory event delivery fails (ADR 0001).

        Returns:
            A terminal typed authentication decision.
        """
        with observe_security(
            runtime.observer,
            SecurityOperation.VERIFY_DPOP,
            profile=self.profile,
            credential_kind="dpop",
        ) as observation:
            try:
                decision = await self._authenticate(request, runtime)
            except EventDeliveryError:
                decision = Unavailable()
            observation.set_outcome(_authentication_outcome(decision), reason_code=_decision_reason(decision))
            return decision

    async def _authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        """Validate DPoP proof and access-token binding fail-closed."""
        presentation = _extract_presentation(request)
        if presentation is None:
            await self._emit_failure(request, FailureCode.MALFORMED)
            return Invalid(FailureCode.MALFORMED)
        access_token, proof_jwt = presentation
        proof = await verify_dpop_proof(
            request,
            runtime,
            access_token=access_token,
            proof_jwt=proof_jwt,
            policy=self.dpop,
        )
        if isinstance(proof, FailureCode):
            await self._emit_failure(request, proof)
            if proof is FailureCode.PROVIDER_UNAVAILABLE:
                return Unavailable()
            return Invalid(proof)
        jkt, proof_jti = proof
        token_result = await self._verify_access_token(
            request,
            runtime,
            access_token=access_token,
            expected_jkt=jkt,
        )
        if isinstance(token_result, FailureCode):
            await self._emit_failure(request, token_result)
            if token_result is FailureCode.PROVIDER_UNAVAILABLE:
                return Unavailable()
            return Invalid(token_result)
        subject, client_id, audiences, scopes, issued_at, not_before, expires_at, token_id, authorization_details = (
            token_result
        )
        replay_ttl = _proof_replay_ttl_seconds(self.dpop)
        replay_key = f"dpop:{self.dpop.resource_server_id}:{jkt}:{proof_jti}"
        with observe_security(runtime.observer, SecurityOperation.REPLAY_CHECK, profile=self.profile) as observation:
            outcome = await self.replay_store.check_and_store(replay_key, ttl_seconds=replay_ttl)
            observation.set_outcome(_replay_outcome(outcome))
        if outcome is ReplayOutcome.REPLAY:
            await self._emit_failure(request, FailureCode.INVALID)
            return Invalid(FailureCode.INVALID)
        if outcome is not ReplayOutcome.STORED:
            await self._emit_failure(request, FailureCode.PROVIDER_UNAVAILABLE)
            return Unavailable()
        try:
            principal = PrincipalRef(self.issuer.issuer, subject, self.issuer.principal_kind)
            evidence = AuthenticationEvidence(
                provider=self.name,
                profile=self.profile,
                method="dpop",
                issuer=self.issuer.issuer,
                audiences=audiences,
                scopes=scopes,
                issued_at=issued_at,
                not_before=not_before,
                expires_at=expires_at,
                token_id=token_id,
                confirmation_thumbprint=jkt,
                environment=self.issuer.environment,
                authorization_details=authorization_details,
                extensions={
                    "authweave-workload:application_id": client_id,
                    "authweave-workload:client_id": client_id,
                },
            )
        except (TypeError, ValueError):
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

    async def _verify_access_token(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
        *,
        access_token: str,
        expected_jkt: str,
    ) -> _ValidatedDPoPToken | FailureCode:
        jwt = _load_jwt()
        try:
            header = jwt.get_unverified_header(access_token)
        except jwt.PyJWTError:
            return FailureCode.MALFORMED
        algorithm = header.get("alg")
        kid = header.get("kid")
        token_type = header.get("typ")
        if token_type not in _ALLOWED_TOKEN_TYPES:
            return FailureCode.TOKEN_TYPE_MISMATCH
        if algorithm not in self.issuer.algorithms:
            return FailureCode.ALGORITHM_MISMATCH
        if not isinstance(kid, str):
            return FailureCode.MALFORMED
        with observe_security(runtime.observer, SecurityOperation.KEY_REFRESH, profile=self.profile) as observation:
            try:
                key = await self.issuer.jwks.get_key(kid, algorithm)
            except JWKSUnavailableError:
                observation.set_outcome(SecurityOutcome.UNAVAILABLE)
                return FailureCode.PROVIDER_UNAVAILABLE
            except JWKSValidationError:
                observation.set_outcome(SecurityOutcome.ERROR)
                return FailureCode.INVALID
            observation.set_outcome(SecurityOutcome.SUCCESS)
        try:
            claims = jwt.decode(
                access_token,
                key,
                algorithms=[algorithm],
                audience=tuple(self.issuer.audiences),
                issuer=self.issuer.issuer,
                options={
                    "require": ["iss", "sub", "aud", "exp", "iat", "jti", "client_id", "cnf"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "strict_aud": False,
                },
            )
        except jwt.InvalidIssuerError:
            return FailureCode.ISSUER_MISMATCH
        except jwt.InvalidAudienceError:
            return FailureCode.AUDIENCE_MISMATCH
        except jwt.PyJWTError:
            return FailureCode.INVALID
        return _validate_dpop_token_claims(claims, request=request, issuer=self.issuer, expected_jkt=expected_jkt)

    async def _emit_failure(self, request: RequestView, reason: FailureCode) -> None:
        event_type = (
            SecurityEventType.SENDER_CONSTRAINT_REJECTED
            if reason is FailureCode.SENDER_CONSTRAINT_MISMATCH
            else SecurityEventType.AUTHENTICATION_FAILED
        )
        await self._emit(
            SecurityEvent(
                event_type,
                provider=self.name,
                profile=self.profile,
                reason=reason,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )

    async def _emit(self, event: SecurityEvent) -> None:
        await deliver_security_event(self.event_callback, event)


async def verify_dpop_proof(
    request: RequestView,
    runtime: AuthenticationRuntime,
    *,
    access_token: str,
    proof_jwt: str,
    policy: DPoPPolicy,
) -> tuple[str, str] | FailureCode:
    """Verify one DPoP proof independently of access-token representation."""
    jwt = _load_jwt()
    try:
        header = jwt.get_unverified_header(proof_jwt)
    except jwt.PyJWTError:
        return FailureCode.MALFORMED
    if header.get("typ") != "dpop+jwt":
        return FailureCode.TOKEN_TYPE_MISMATCH
    algorithm = header.get("alg")
    if algorithm not in policy.algorithms or algorithm == "none":
        return FailureCode.ALGORITHM_MISMATCH
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or _PRIVATE_JWK_MEMBERS.intersection(jwk):
        return FailureCode.MALFORMED
    try:
        _assert_jwk_algorithm(jwk, algorithm)
        jkt = _jwk_thumbprint(jwk)
        key = jwt.algorithms.get_default_algorithms()[algorithm].from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            proof_jwt,
            key=key,
            algorithms=[algorithm],
            options={
                "require": ["jti", "htm", "htu", "iat", "ath"],
                "verify_aud": False,
                "verify_iss": False,
                "verify_iat": False,
            },
        )
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        return FailureCode.INVALID
    jti = _bounded_string(claims.get("jti"), maximum=_MAX_VALUE_LENGTH)
    htm = _bounded_string(claims.get("htm"), maximum=16)
    htu = _bounded_string(claims.get("htu"), maximum=2048)
    ath = _bounded_string(claims.get("ath"), maximum=128)
    if jti is None or htm is None or htu is None or ath is None:
        return FailureCode.MALFORMED
    if htm.upper() != request.method.upper():
        return FailureCode.SENDER_CONSTRAINT_MISMATCH
    expected_htu = _normalize_htu(request.target_uri)
    if expected_htu is None or not hmac.compare_digest(htu.encode(), expected_htu.encode()):
        return FailureCode.SENDER_CONSTRAINT_MISMATCH
    try:
        issued_at = _numeric_date(claims["iat"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return FailureCode.MALFORMED
    skew = policy.clock_skew
    if issued_at > request.timestamp + skew:
        return FailureCode.NOT_YET_VALID
    if issued_at < request.timestamp - policy.iat_window - skew:
        return FailureCode.EXPIRED
    expected_ath = _access_token_hash(access_token)
    if not hmac.compare_digest(ath.encode(), expected_ath.encode()):
        return FailureCode.SENDER_CONSTRAINT_MISMATCH
    if policy.require_nonce:
        nonce_store = cast("DPoPNonceStore", policy.nonce_store)
        nonce = _bounded_string(claims.get("nonce"), maximum=_MAX_VALUE_LENGTH)
        if nonce is None:
            return FailureCode.MALFORMED
        with observe_security(runtime.observer, SecurityOperation.REPLAY_CHECK, profile="dpop_proof") as observation:
            outcome = await nonce_store.consume(origin=expected_htu, jkt=jkt, nonce=nonce)
            observation.set_outcome(_replay_outcome(outcome))
        if outcome is ReplayOutcome.REPLAY:
            return FailureCode.INVALID
        if outcome is not ReplayOutcome.STORED:
            return FailureCode.PROVIDER_UNAVAILABLE
    return jkt, jti


def _extract_presentation(request: RequestView) -> tuple[str, str] | None:
    authorization = request.header_values(b"authorization")
    proof_headers = request.header_values(b"dpop")
    if len(authorization) != 1 or len(proof_headers) != 1:
        return None
    scheme, separator, raw_token = authorization[0].partition(b" ")
    token = raw_token.strip()
    proof = proof_headers[0].strip()
    if scheme.lower() != b"dpop" or separator != b" " or not token or not proof:
        return None
    if len(token) > _MAX_TOKEN_BYTES or len(proof) > _MAX_PROOF_BYTES:
        return None
    try:
        return token.decode("ascii"), proof.decode("ascii")
    except UnicodeDecodeError:
        return None


def _authentication_outcome(decision: AuthenticationDecision) -> SecurityOutcome:
    if isinstance(decision, Authenticated):
        return SecurityOutcome.AUTHENTICATED
    if isinstance(decision, Invalid):
        return SecurityOutcome.INVALID
    return SecurityOutcome.UNAVAILABLE


def _decision_reason(decision: AuthenticationDecision) -> str | None:
    return decision.code.value if isinstance(decision, (Invalid, Unavailable)) else None


def _replay_outcome(outcome: ReplayOutcome) -> SecurityOutcome:
    if outcome is ReplayOutcome.STORED:
        return SecurityOutcome.STORED
    if outcome is ReplayOutcome.REPLAY:
        return SecurityOutcome.REPLAY
    if outcome is ReplayOutcome.CAPACITY_EXCEEDED:
        return SecurityOutcome.CAPACITY_EXCEEDED
    return SecurityOutcome.UNAVAILABLE


def _proof_replay_ttl_seconds(policy: DPoPPolicy) -> float:
    """Cover the full acceptance window for a proof at the future-skew boundary."""
    return (policy.iat_window + 2 * policy.clock_skew).total_seconds() + 1


def _normalize_htu(target_uri: str | None) -> str | None:
    if target_uri is None:
        return None
    parts = urlsplit(target_uri)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return None
    host = parts.hostname.lower()
    port = parts.port
    netloc = host if port in {None, 443} else f"{host}:{port}"
    path = parts.path or "/"
    return f"https://{netloc}{path}"


def _access_token_hash(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _assert_jwk_algorithm(jwk: dict[str, Any], algorithm: str) -> None:
    declared = jwk.get("alg")
    if declared is not None and declared != algorithm:
        msg = "JWK alg does not match proof alg"
        raise ValueError(msg)
    if algorithm == "ES256":
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            msg = "ES256 requires EC P-256"
            raise ValueError(msg)
        required = frozenset({"kty", "crv", "x", "y"})
    elif algorithm == "EdDSA":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            msg = "EdDSA requires OKP Ed25519"
            raise ValueError(msg)
        required = frozenset({"kty", "crv", "x"})
    else:
        msg = "unsupported algorithm"
        raise ValueError(msg)
    if not required <= set(jwk) or set(jwk) - required - _PUBLIC_JWK_METADATA:
        msg = "unexpected JWK members"
        raise ValueError(msg)


def _jwk_thumbprint(jwk: dict[str, Any]) -> str:
    kty = jwk["kty"]
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        msg = "unsupported JWK kty"
        raise ValueError(msg)
    payload = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    digest = hashlib.sha256(payload).digest()
    thumbprint = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    if _THUMBPRINT_PATTERN.fullmatch(thumbprint) is None:
        msg = "invalid thumbprint"
        raise ValueError(msg)
    return thumbprint


def _validate_dpop_token_claims(
    claims: dict[str, Any],
    *,
    request: RequestView,
    issuer: TrustedIssuer,
    expected_jkt: str,
) -> _ValidatedDPoPToken | FailureCode:
    subject = _bounded_string(claims.get("sub"), maximum=_MAX_SUBJECT_LENGTH)
    client_id = _bounded_string(claims.get("client_id"), maximum=_MAX_CLIENT_ID_LENGTH)
    token_id = _bounded_string(claims.get("jti"), maximum=_MAX_VALUE_LENGTH)
    if subject is None or client_id is None or token_id is None:
        return FailureCode.INVALID
    audiences = _validated_audiences(claims.get("aud"), issuer.audiences)
    if audiences is None:
        return FailureCode.AUDIENCE_MISMATCH
    try:
        issued_at = _numeric_date(claims["iat"])
        expires_at = _numeric_date(claims["exp"])
        not_before = None if "nbf" not in claims else _numeric_date(claims["nbf"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return FailureCode.INVALID
    skew = issuer.clock_skew
    if expires_at <= request.timestamp - skew:
        return FailureCode.EXPIRED
    if issued_at > request.timestamp + skew or (not_before is not None and not_before > request.timestamp + skew):
        return FailureCode.NOT_YET_VALID
    if expires_at <= issued_at or expires_at - issued_at > issuer.maximum_token_lifetime:
        return FailureCode.INVALID
    cnf = claims.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) and set(cnf) == {"jkt"} else None
    if not isinstance(jkt, str) or not hmac.compare_digest(jkt.encode(), expected_jkt.encode()):
        return FailureCode.SENDER_CONSTRAINT_MISMATCH
    scope = claims.get("scope", "")
    if not isinstance(scope, str):
        return FailureCode.INVALID
    scopes = tuple(scope.split())
    if (
        len(scopes) > _MAX_SCOPES
        or len(scopes) != len(set(scopes))
        or any(_bounded_string(item, maximum=_MAX_VALUE_LENGTH) is None or "*" in item for item in scopes)
    ):
        return FailureCode.INVALID
    try:
        authorization_details = payment_authorization_evidence(
            claims.get("authorization_details"),
            policy=issuer.payment_authorization,
            scopes=scopes,
        )
    except PaymentAuthorizationError:
        return FailureCode.INVALID
    return subject, client_id, audiences, scopes, issued_at, not_before, expires_at, token_id, authorization_details


def _validated_audiences(value: object, trusted: frozenset[str]) -> tuple[str, ...] | None:
    if isinstance(value, str):
        audiences = (value,)
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        audiences = tuple(item for item in value)
    else:
        return None
    if (
        not audiences
        or len(audiences) > _MAX_AUDIENCES
        or len(audiences) != len(set(audiences))
        or any(_bounded_string(audience, maximum=_MAX_VALUE_LENGTH) is None for audience in audiences)
        or not set(audiences) <= trusted
    ):
        return None
    return tuple(sorted(cast("tuple[str, ...]", audiences)))


def _numeric_date(value: object) -> datetime:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise TypeError
    return datetime.fromtimestamp(value, tz=UTC)


def _bounded_string(value: object, *, maximum: int) -> str | None:
    return value if isinstance(value, str) and value == value.strip() and value and len(value) <= maximum else None


def _nonce_key(origin: str, jkt: str, nonce: str) -> str:
    return f"dpop-nonce:{origin}:{jkt}:{nonce}"


__all__ = (
    "DPoPBoundJWTProvider",
    "DPoPNonceChallenge",
    "DPoPNonceStore",
    "DPoPPolicy",
    "DPoPReplayStore",
    "InMemoryDPoPNonceStore",
    "verify_dpop_proof",
)
