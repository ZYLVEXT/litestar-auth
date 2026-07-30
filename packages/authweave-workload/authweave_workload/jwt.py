"""Modern-only external mTLS-bound OAuth access-token provider."""

from __future__ import annotations

import hmac
import inspect
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationEvidence,
    CredentialMatch,
    FailureCode,
    Invalid,
    InvariantFailure,
    PrincipalRef,
    Unavailable,
)

from authweave_workload.events import SecurityEvent, SecurityEventType
from authweave_workload.jwks import BoundedJWKSClient, JWKSUnavailableError, JWKSValidationError

if TYPE_CHECKING:
    from authweave_core import AuthenticationDecision, AuthenticationRuntime, RequestView

    from authweave_workload.provider import DirectMTLSPolicy

_ALLOWED_ALGORITHMS = frozenset({"PS256", "ES256", "EdDSA"})
_ALLOWED_TYPES = frozenset({"at+jwt", "application/at+jwt"})
_MAX_TOKEN_BYTES = 16_384
_MAX_SUBJECT_LENGTH = 512
_MAX_CLIENT_ID_LENGTH = 256
_MAX_VALUE_LENGTH = 512
_MAX_AUDIENCES = 64
_MAX_SCOPES = 64
_THUMBPRINT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
type DelegationPolicy = Callable[[PrincipalRef, PrincipalRef, tuple[PrincipalRef, ...]], bool]


@dataclass(frozen=True, slots=True)
class TrustedIssuer:
    """Exact external Authorization Server resource-server policy."""

    issuer: str
    audiences: frozenset[str]
    environment: str
    jwks: BoundedJWKSClient
    algorithms: frozenset[str] = _ALLOWED_ALGORITHMS
    principal_kind: str = "service"
    clock_skew: timedelta = timedelta(seconds=30)
    maximum_token_lifetime: timedelta = timedelta(minutes=10)
    allow_rfc8693_actor: bool = False
    maximum_delegation_depth: int = 4

    def __post_init__(self) -> None:
        """Reject broad or legacy issuer policy."""
        if not self.issuer or not self.audiences:
            raise ValueError("trusted issuer and audiences must be explicit")
        if not self.algorithms or not self.algorithms <= _ALLOWED_ALGORITHMS:
            raise ValueError("trusted issuer algorithms must use the modern allowlist")
        if self.clock_skew < timedelta(0) or self.maximum_token_lifetime <= timedelta(0):
            raise ValueError("JWT time policy is invalid")
        if self.principal_kind == "human":
            raise ValueError("workload JWT principals cannot use kind='human'")
        if self.maximum_delegation_depth < 1:
            raise ValueError("maximum_delegation_depth must be positive")


class MTLSBoundJWTProvider:
    """Authenticate an external access token only when bound to trusted TLS evidence."""

    profile = "mtls_bound_access_token"

    def __init__(
        self,
        *,
        name: str,
        issuer: TrustedIssuer,
        tls_policy: DirectMTLSPolicy,
        delegation_policy: DelegationPolicy | None = None,
        event_callback: Callable[[SecurityEvent], object] | None = None,
    ) -> None:
        """Bind exact issuer, signing-key, and TLS policies."""
        self.name = name
        self.issuer = issuer
        self.tls_policy = tls_policy
        self.delegation_policy = delegation_policy
        self.event_callback = event_callback

    def match(self, request: RequestView) -> CredentialMatch:
        """Own exactly one Bearer presentation and reject collisions."""
        authorization = request.header_values(b"authorization")
        if not authorization:
            return CredentialMatch.NOT_APPLICABLE
        if len(authorization) != 1 or request.header_values(b"cookie"):
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
        """Validate access-token semantics, signature, and certificate binding."""
        _ = runtime
        token = _extract_token(request)
        if token is None:
            return Invalid(FailureCode.MALFORMED)
        peer_failure = _validate_tls_peer(request, self.tls_policy)
        if peer_failure is not None:
            await self._emit_failure(request, peer_failure)
            if peer_failure is FailureCode.PROVIDER_UNAVAILABLE:
                return Unavailable()
            if peer_failure is FailureCode.INTERNAL_INVARIANT:
                return InvariantFailure()
            return Invalid(peer_failure)
        jwt = _load_jwt()
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return Invalid(FailureCode.MALFORMED)
        algorithm = header.get("alg")
        kid = header.get("kid")
        token_type = header.get("typ")
        if token_type not in _ALLOWED_TYPES:
            return Invalid(FailureCode.TOKEN_TYPE_MISMATCH)
        if algorithm not in self.issuer.algorithms:
            return Invalid(FailureCode.ALGORITHM_MISMATCH)
        if not isinstance(kid, str):
            return Invalid(FailureCode.MALFORMED)
        try:
            key = await self.issuer.jwks.get_key(kid, algorithm)
        except JWKSUnavailableError:
            await self._emit_failure(request, FailureCode.PROVIDER_UNAVAILABLE)
            return Unavailable()
        except JWKSValidationError:
            return Invalid(FailureCode.INVALID)
        try:
            claims = jwt.decode(
                token,
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
            return Invalid(FailureCode.ISSUER_MISMATCH)
        except jwt.InvalidAudienceError:
            return Invalid(FailureCode.AUDIENCE_MISMATCH)
        except jwt.PyJWTError:
            return Invalid(FailureCode.INVALID)
        validation = _validate_claims(claims, request=request, issuer=self.issuer)
        if isinstance(validation, FailureCode):
            await self._emit_failure(request, validation)
            return Invalid(validation)
        subject, client_id, audiences, scopes, issued_at, not_before, expires_at, token_id, thumbprint = validation
        peer = request.tls_peer
        if peer is None or not hmac.compare_digest(thumbprint.encode(), peer.certificate_thumbprint.encode()):
            await self._emit_failure(request, FailureCode.SENDER_CONSTRAINT_MISMATCH)
            return Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)
        try:
            principal = PrincipalRef(self.issuer.issuer, subject, self.issuer.principal_kind)
        except (TypeError, ValueError):
            return Invalid(FailureCode.INVALID)
        actor = principal
        delegation_chain: tuple[PrincipalRef, ...] = ()
        actor_claim = claims.get("act")
        if actor_claim is not None:
            if not self.issuer.allow_rfc8693_actor or self.delegation_policy is None:
                return Invalid(FailureCode.INVALID)
            from authweave_workload.delegation import map_rfc8693_actor

            delegation = map_rfc8693_actor(
                actor_claim,
                issuer=self.issuer.issuer,
                subject=principal,
                actor_kind=self.issuer.principal_kind,
                credential_scopes=scopes,
                maximum_depth=self.issuer.maximum_delegation_depth,
            )
            if isinstance(delegation, FailureCode):
                return Invalid(delegation)
            actor = delegation.actor
            delegation_chain = delegation.chain
            scopes = delegation.effective_scopes
            if not self.delegation_policy(principal, actor, delegation_chain):
                return Invalid(FailureCode.INVALID)
        try:
            evidence = AuthenticationEvidence(
                provider=self.name,
                profile=self.profile,
                method="mtls",
                issuer=self.issuer.issuer,
                audiences=audiences,
                scopes=scopes,
                issued_at=issued_at,
                not_before=not_before,
                expires_at=expires_at,
                token_id=token_id,
                confirmation_thumbprint=thumbprint,
                environment=self.issuer.environment,
                extensions={
                    "authweave-workload:application_id": client_id,
                    "authweave-workload:client_id": client_id,
                },
            )
        except (TypeError, ValueError):
            return Invalid(FailureCode.INVALID)
        context = AuthenticationContext(
            subject=principal,
            actor=actor,
            evidence=evidence,
            delegation_chain=delegation_chain,
        )
        await self._emit(
            SecurityEvent(
                SecurityEventType.AUTHENTICATION_SUCCEEDED,
                target_principal=principal,
                actor=actor,
                provider=self.name,
                profile=self.profile,
                correlation_id=request.correlation_id,
                timestamp=request.timestamp,
            ),
        )
        return Authenticated(context)

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
        if self.event_callback is not None:
            result = self.event_callback(event)
            if inspect.isawaitable(result):
                await result


def _extract_token(request: RequestView) -> str | None:
    authorization = request.header_values(b"authorization")
    if len(authorization) != 1:
        return None
    scheme, separator, raw_token = authorization[0].partition(b" ")
    token = raw_token.strip()
    if scheme.lower() != b"bearer" or separator != b" " or not token or len(token) > _MAX_TOKEN_BYTES:
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


def _validate_claims(
    claims: dict[str, Any],
    *,
    request: RequestView,
    issuer: TrustedIssuer,
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], datetime, datetime | None, datetime, str, str] | FailureCode:
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
    thumbprint = cnf.get("x5t#S256") if isinstance(cnf, dict) and set(cnf) == {"x5t#S256"} else None
    if not isinstance(thumbprint, str) or _THUMBPRINT_PATTERN.fullmatch(thumbprint) is None:
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
    return subject, client_id, audiences, scopes, issued_at, not_before, expires_at, token_id, thumbprint


def _validated_audiences(value: object, trusted: frozenset[str]) -> tuple[str, ...] | None:
    if isinstance(value, str):
        audiences = (value,)
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        audiences = tuple(cast("str", item) for item in value)
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
    return tuple(sorted(audiences))


def _numeric_date(value: object) -> datetime:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise TypeError
    return datetime.fromtimestamp(value, tz=UTC)


def _bounded_string(value: object, *, maximum: int) -> str | None:
    return value if isinstance(value, str) and value == value.strip() and value and len(value) <= maximum else None


def _load_jwt() -> Any:
    try:
        import jwt
    except ImportError as exc:
        msg = "JWT verification requires the 'authweave-workload[jwt]' extra."
        raise ImportError(msg) from exc
    return jwt


__all__ = ("DelegationPolicy", "MTLSBoundJWTProvider", "TrustedIssuer")
