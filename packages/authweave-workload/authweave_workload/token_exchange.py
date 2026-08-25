"""Strict outbound RFC 8693 token exchange with verified narrowing."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from urllib.parse import urlencode, urlsplit

import anyio

from authweave_workload.authorization_details import (
    PaymentAuthorizationDetail,
    PaymentAuthorizationError,
    PaymentAuthorizationPolicy,
    validate_payment_authorization_narrowing,
)

if TYPE_CHECKING:
    from authweave_core import AuthenticationContext
from authweave_workload.dpop import _assert_jwk_algorithm, _jwk_thumbprint
from authweave_workload.introspection import (
    AsyncJWTSigner,
    IntrospectionValidationError,
    PrivateKeyJWTClientAuth,
)

TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"  # ruff: ignore[hardcoded-password-string] - Public RFC 8693 URN.
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # ruff: ignore[hardcoded-password-string] - Public RFC 8693 URN.
_ALGORITHMS = frozenset({"ES256", "EdDSA"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_SCOPE_PATTERN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]{1,512}$")
_MAX_TOKEN_BYTES = 16_384
_MAX_RESPONSE_BYTES = 65_536
_MAX_VALUE_LENGTH = 512
_MAX_SCOPES = 64
_MAX_URI_LENGTH = 2048
_JWT_SEPARATOR_COUNT = 2
_HTTP_OK = 200
_HTTP_CLIENT_ERROR = 400
_HTTP_SERVER_ERROR = 500
_USE_DPOP_NONCE = "use_dpop_nonce"

type TokenExchangePoster = Callable[
    [str, Mapping[str, str], bytes, float, int],
    Awaitable[tuple[int, bytes, Mapping[str, str]]],
]


class TokenExchangeUnavailableError(Exception):
    """Raised when the configured STS, signer, or verifier is unavailable."""


class TokenExchangeValidationError(ValueError):
    """Raised when an exchange request or response violates its exact profile."""


class TokenExchangeRejectedError(TokenExchangeValidationError):
    """Raised for a bounded OAuth error response from the STS."""

    def __init__(self, error: str) -> None:
        """Store only the stable OAuth error code, never server prose."""
        self.error = error
        super().__init__(f"token exchange was rejected: {error}")


@runtime_checkable
class IssuedTokenVerifier(Protocol):
    """Verify one issued token without returning raw claims or key material."""

    async def verify(
        self,
        access_token: str,
        *,
        token_type: str,
        confirmation_thumbprint: str,
    ) -> AuthenticationContext:
        """Return a fully verified context or raise a typed exchange error."""
        ...


@dataclass(frozen=True, slots=True)
class DPoPTokenEndpointBinding:
    """External DPoP signer and public key for one token endpoint."""

    signer: AsyncJWTSigner = field(repr=False)
    public_jwk: Mapping[str, object]
    algorithm: str
    jti_source: Callable[[], str] = lambda: secrets.token_urlsafe(24)
    confirmation_thumbprint: str = field(init=False)

    def __post_init__(self) -> None:
        """Freeze one public modern JWK and derive its RFC 7638 thumbprint.

        Raises:
            TypeError: If the signer does not implement the external seam.
            ValueError: If the key or algorithm is invalid.
        """
        try:
            jwk = dict(self.public_jwk)
        except (TypeError, ValueError) as exc:
            msg = "DPoP token-endpoint binding is invalid"
            raise ValueError(msg) from exc
        if self.algorithm not in _ALGORITHMS or _PRIVATE_JWK_MEMBERS.intersection(jwk):
            msg = "DPoP token-endpoint binding is invalid"
            raise ValueError(msg)
        try:
            _assert_jwk_algorithm(jwk, self.algorithm)
            thumbprint = _jwk_thumbprint(jwk)
        except (KeyError, TypeError, ValueError) as exc:
            msg = "DPoP token-endpoint binding is invalid"
            raise ValueError(msg) from exc
        if not isinstance(self.signer, AsyncJWTSigner):
            msg = "DPoP token-endpoint signer is invalid"
            raise TypeError(msg)
        object.__setattr__(self, "public_jwk", MappingProxyType(jwk))
        object.__setattr__(self, "confirmation_thumbprint", thumbprint)


@dataclass(frozen=True, slots=True)
class MTLSTokenEndpointBinding:
    """Expected certificate binding for an injected mTLS HTTP transport."""

    certificate_thumbprint: str

    def __post_init__(self) -> None:
        """Require one canonical SHA-256 certificate thumbprint.

        Raises:
            ValueError: If the thumbprint is not canonical base64url.
        """
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", self.certificate_thumbprint) is None:
            msg = "mTLS token-endpoint binding is invalid"
            raise ValueError(msg)

    @property
    def confirmation_thumbprint(self) -> str:
        """Expected issued-token confirmation thumbprint."""
        return self.certificate_thumbprint


type TokenEndpointBinding = DPoPTokenEndpointBinding | MTLSTokenEndpointBinding


@dataclass(frozen=True, slots=True)
class TokenExchangeCredential:
    """One raw input token paired with the context produced by its verifier."""

    token: str = field(repr=False)
    context: AuthenticationContext
    token_type: str = ACCESS_TOKEN_TYPE

    def __post_init__(self) -> None:
        """Accept only a bounded OAuth access token input.

        Raises:
            ValueError: If the credential is malformed or unsupported.
        """
        if self.token_type != ACCESS_TOKEN_TYPE or not _valid_token(self.token):
            msg = "token exchange input credential is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class TokenExchangeProfile:
    """Exact external STS, target, narrowing, and verification policy."""

    endpoint: str
    issuer: str
    source_issuer: str
    source_audience: str
    resource: str
    audience: str
    client_auth: PrivateKeyJWTClientAuth = field(repr=False)
    sender_binding: TokenEndpointBinding = field(repr=False)
    verifier: IssuedTokenVerifier = field(repr=False)
    allowed_scopes: frozenset[str]
    payment_authorization: PaymentAuthorizationPolicy | None = None
    maximum_delegation_depth: int = 4
    maximum_token_lifetime: timedelta = timedelta(minutes=10)
    clock_skew: timedelta = timedelta(seconds=30)
    timeout_seconds: float = 3.0
    maximum_response_bytes: int = _MAX_RESPONSE_BYTES
    time_source: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        """Reject discovery, caller-selected targets, and open-ended authority.

        Raises:
            TypeError: If the verifier or sender constraint is invalid.
            ValueError: If an exact profile bound is invalid.
        """
        _validate_https_uri(self.endpoint, clean=True)
        _validate_https_uri(self.resource, clean=False)
        identity_values = (self.issuer, self.source_issuer, self.source_audience, self.audience)
        identity_invalid = any(not _valid_value(value) or "*" in value for value in identity_values)
        scope_invalid = (
            not self.allowed_scopes
            or len(self.allowed_scopes) > _MAX_SCOPES
            or any(_SCOPE_PATTERN.fullmatch(scope) is None or "*" in scope for scope in self.allowed_scopes)
        )
        bounds_invalid = (
            self.maximum_delegation_depth < 1
            or not timedelta(0) < self.maximum_token_lifetime <= timedelta(hours=1)
            or self.clock_skew < timedelta(0)
            or self.timeout_seconds <= 0
            or not 1 <= self.maximum_response_bytes <= _MAX_RESPONSE_BYTES
        )
        if identity_invalid or scope_invalid or bounds_invalid or self.client_auth.audience != self.endpoint:
            msg = "token exchange profile is invalid"
            raise ValueError(msg)
        if not isinstance(self.sender_binding, DPoPTokenEndpointBinding | MTLSTokenEndpointBinding):
            msg = "token exchange requires exactly one sender constraint"
            raise TypeError(msg)
        if not isinstance(self.verifier, IssuedTokenVerifier):
            msg = "token exchange issued-token verifier is invalid"
            raise TypeError(msg)
        if self.payment_authorization is not None and self.resource not in self.payment_authorization.allowed_locations:
            msg = "payment policy must allow the token exchange resource"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class TokenExchangeResult:
    """Verified sender-constrained access token and its context."""

    access_token: str = field(repr=False)
    token_type: str
    issued_token_type: str
    expires_at: datetime
    context: AuthenticationContext


@dataclass(frozen=True, slots=True)
class _Transition:
    subject: str
    actor: str
    chain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ParsedTokenResponse:
    access_token: str = field(repr=False)
    token_type: str
    scopes: tuple[str, ...]
    authorization_details: tuple[PaymentAuthorizationDetail, ...]
    expires_at: datetime


class TokenExchangeClient:
    """Exchange a verified credential only for narrower configured authority."""

    __slots__ = ("_dpop_nonce", "_nonce_lock", "poster", "profile")

    def __init__(self, profile: TokenExchangeProfile, *, poster: TokenExchangePoster | None = None) -> None:
        """Bind a profile and one bounded transport.

        Raises:
            ValueError: If an mTLS profile has no certificate-owning transport.
        """
        if isinstance(profile.sender_binding, MTLSTokenEndpointBinding) and poster is None:
            msg = "mTLS token exchange requires an injected certificate-owning transport"
            raise ValueError(msg)
        self.profile = profile
        self.poster = _post_token_exchange if poster is None else poster
        self._dpop_nonce: str | None = None
        self._nonce_lock = anyio.Lock()

    async def exchange(
        self,
        subject: TokenExchangeCredential,
        *,
        scopes: tuple[str, ...],
        authorization_details: tuple[PaymentAuthorizationDetail, ...] = (),
        actor: TokenExchangeCredential | None = None,
    ) -> TokenExchangeResult:
        """Perform one exchange and return only a locally verified result.

        Returns:
            Sender-constrained token and verified identity/authority context.

        Raises:
            TokenExchangeValidationError: If authority or a response is invalid.
            TokenExchangeRejectedError: If the STS returns a bounded OAuth error.
            TokenExchangeUnavailableError: If a required dependency is unavailable.
        """
        now = _aware_now(self.profile.time_source)
        requested_scopes = _validate_request_authority(self.profile, subject, scopes, now=now)
        requested_details = _validate_requested_details(
            self.profile,
            subject.context,
            authorization_details,
            scopes=requested_scopes,
        )
        transition = _expected_transition(
            self.profile,
            subject,
            actor,
            scopes=requested_scopes,
            now=now,
        )
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "resource": self.profile.resource,
            "audience": self.profile.audience,
            "scope": " ".join(requested_scopes),
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "subject_token": subject.token,
            "subject_token_type": subject.token_type,
        }
        if requested_details:
            form["authorization_details"] = _json_details(requested_details)
        if actor is not None:
            form["actor_token"] = actor.token
            form["actor_token_type"] = actor.token_type
        status, content, response_headers = await self._post_with_nonce_handling(form, now=now)
        if status != _HTTP_OK:
            if _HTTP_CLIENT_ERROR <= status < _HTTP_SERVER_ERROR:
                raise TokenExchangeRejectedError(_parse_error(content))
            msg = "token exchange endpoint returned a non-success status"
            raise TokenExchangeUnavailableError(msg)
        cache_control = {item.strip().lower() for item in response_headers.get("cache-control", "").split(",")}
        if "no-store" not in cache_control:
            msg = "token exchange response must be non-cacheable"
            raise TokenExchangeValidationError(msg)
        parsed = _parse_success(
            content,
            profile=self.profile,
            requested_scopes=requested_scopes,
            requested_details=requested_details,
            now=now,
        )
        try:
            context = await self.profile.verifier.verify(
                parsed.access_token,
                token_type=parsed.token_type,
                confirmation_thumbprint=self.profile.sender_binding.confirmation_thumbprint,
            )
        except (TokenExchangeValidationError, TokenExchangeUnavailableError):
            raise
        except Exception as exc:
            msg = "issued-token verifier failed"
            raise TokenExchangeValidationError(msg) from exc
        _validate_issued_context(
            self.profile,
            context,
            response=parsed,
            transition=transition,
            now=now,
        )
        return TokenExchangeResult(
            access_token=parsed.access_token,
            token_type=parsed.token_type,
            issued_token_type=ACCESS_TOKEN_TYPE,
            expires_at=parsed.expires_at,
            context=context,
        )

    async def _post_with_nonce_handling(
        self,
        form: dict[str, str],
        *,
        now: datetime,
    ) -> tuple[int, bytes, Mapping[str, str]]:
        """Send the exchange request, handling the DPoP ``use_dpop_nonce`` retry.

        The cached server nonce is shared mutable state read before the request
        and written after the response, so DPoP sends are serialized under a
        lock: concurrent exchanges on one client can no longer clobber a fresh
        nonce with a stale one or burn retries on outdated nonces.

        Returns:
            Status, body, and headers of the last transport response.
        """
        if not isinstance(self.profile.sender_binding, DPoPTokenEndpointBinding):
            status, content, response_headers = await _send_exchange(
                self.profile,
                self.poster,
                form,
                now=now,
                nonce=None,
            )
            _validate_response_envelope(self.profile, content, response_headers)
            return status, content, response_headers
        async with self._nonce_lock:
            status, content, response_headers = await _send_exchange(
                self.profile,
                self.poster,
                form,
                now=now,
                nonce=self._dpop_nonce,
            )
            _validate_response_envelope(self.profile, content, response_headers)
            if status == _HTTP_CLIENT_ERROR and _parse_error(content) == _USE_DPOP_NONCE:
                nonce = _parse_dpop_nonce(response_headers)
                self._dpop_nonce = nonce
                status, content, response_headers = await _send_exchange(
                    self.profile,
                    self.poster,
                    form,
                    now=now,
                    nonce=nonce,
                )
                _validate_response_envelope(self.profile, content, response_headers)
            if status == _HTTP_OK and "dpop-nonce" in response_headers:
                self._dpop_nonce = _parse_dpop_nonce(response_headers)
            return status, content, response_headers


async def _apply_sender_binding(
    profile: TokenExchangeProfile,
    headers: dict[str, str],
    *,
    now: datetime,
    nonce: str | None = None,
) -> None:
    binding = profile.sender_binding
    if isinstance(binding, MTLSTokenEndpointBinding):
        return
    jti = binding.jti_source()
    if not _valid_value(jti):
        msg = "DPoP jti source returned an invalid value"
        raise TokenExchangeValidationError(msg)
    signer = binding.signer
    claims: dict[str, object] = {
        "jti": jti,
        "htm": "POST",
        "htu": profile.endpoint,
        "iat": int(now.timestamp()),
    }
    if nonce is not None:
        claims["nonce"] = nonce
    proof = await signer.sign(
        protected_headers={
            "alg": binding.algorithm,
            "typ": "dpop+jwt",
            "jwk": dict(binding.public_jwk),
        },
        claims=claims,
    )
    if not _valid_compact_jwt(proof):
        msg = "DPoP signer returned an invalid proof"
        raise TokenExchangeValidationError(msg)
    headers["dpop"] = proof


async def _send_exchange(
    profile: TokenExchangeProfile,
    poster: TokenExchangePoster,
    form: dict[str, str],
    *,
    now: datetime,
    nonce: str | None = None,
) -> tuple[int, bytes, Mapping[str, str]]:
    request_form = dict(form)
    headers = {"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
    try:
        await profile.client_auth.authorize(endpoint=profile.endpoint, form=request_form, headers=headers)
        await _apply_sender_binding(profile, headers, now=now, nonce=nonce)
    except (TokenExchangeValidationError, TokenExchangeUnavailableError):
        raise
    except IntrospectionValidationError as exc:
        msg = "token exchange client assertion is invalid"
        raise TokenExchangeValidationError(msg) from exc
    except Exception as exc:
        msg = "token exchange signer is unavailable"
        raise TokenExchangeUnavailableError(msg) from exc
    try:
        return await poster(
            profile.endpoint,
            headers,
            urlencode(request_form).encode("utf-8"),
            profile.timeout_seconds,
            profile.maximum_response_bytes,
        )
    except (TokenExchangeValidationError, TokenExchangeUnavailableError):
        raise
    except Exception as exc:
        msg = "token exchange request failed"
        raise TokenExchangeUnavailableError(msg) from exc


def _validate_response_envelope(
    profile: TokenExchangeProfile,
    content: bytes,
    headers: Mapping[str, str],
) -> None:
    if len(content) > profile.maximum_response_bytes:
        msg = "token exchange response exceeds the configured size limit"
        raise TokenExchangeValidationError(msg)
    media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        msg = "token exchange Content-Type must be application/json"
        raise TokenExchangeValidationError(msg)


def _parse_dpop_nonce(headers: Mapping[str, str]) -> str:
    nonce = headers.get("dpop-nonce")
    if not isinstance(nonce, str) or _SCOPE_PATTERN.fullmatch(nonce) is None:
        msg = "token exchange DPoP nonce is invalid"
        raise TokenExchangeValidationError(msg)
    return nonce


def _validate_request_authority(
    profile: TokenExchangeProfile,
    credential: TokenExchangeCredential,
    scopes: tuple[str, ...],
    *,
    now: datetime,
) -> tuple[str, ...]:
    _validate_source_context(profile, credential.context, now=now)
    shape_invalid = (
        not scopes
        or len(scopes) > _MAX_SCOPES
        or len(scopes) != len(set(scopes))
        or any(_SCOPE_PATTERN.fullmatch(scope) is None or "*" in scope for scope in scopes)
    )
    authority_invalid = not set(scopes) <= profile.allowed_scopes or not set(scopes) <= set(
        credential.context.evidence.scopes
    )
    if shape_invalid or authority_invalid:
        msg = "token exchange scopes widen verified authority"
        raise TokenExchangeValidationError(msg)
    return scopes


def _validate_source_context(
    profile: TokenExchangeProfile,
    context: AuthenticationContext,
    *,
    now: datetime,
) -> None:
    evidence = context.evidence
    invalid = (
        evidence.issuer != profile.source_issuer
        or profile.source_audience not in evidence.audiences
        or evidence.expires_at is None
        or evidence.expires_at <= now - profile.clock_skew
        or (evidence.not_before is not None and evidence.not_before > now + profile.clock_skew)
    )
    if invalid:
        msg = "token exchange source context is invalid or expired"
        raise TokenExchangeValidationError(msg)
    chain = tuple(principal.subject for principal in context.delegation_chain)
    identities = (context.subject.subject, *chain)
    expected_actor = chain[0] if chain else context.subject.subject
    if (
        context.actor.subject != expected_actor
        or len(chain) > profile.maximum_delegation_depth
        or len(identities) != len(set(identities))
    ):
        msg = "token exchange source delegation is invalid"
        raise TokenExchangeValidationError(msg)


def _validate_requested_details(
    profile: TokenExchangeProfile,
    context: AuthenticationContext,
    requested: tuple[PaymentAuthorizationDetail, ...],
    *,
    scopes: tuple[str, ...],
) -> tuple[PaymentAuthorizationDetail, ...]:
    policy = profile.payment_authorization
    if policy is None:
        if requested or context.evidence.authorization_details:
            msg = "payment authorization is not enabled for token exchange"
            raise TokenExchangeValidationError(msg)
        return ()
    try:
        granted = policy.from_evidence(context.evidence)
    except PaymentAuthorizationError as exc:
        msg = "token exchange subject payment authority is invalid"
        raise TokenExchangeValidationError(msg) from exc
    if not requested:
        if policy.required:
            msg = "token exchange requires narrower payment authority"
            raise TokenExchangeValidationError(msg)
        return ()
    try:
        parsed = policy.parse(tuple(detail.as_evidence() for detail in requested), scopes=scopes)
        validate_payment_authorization_narrowing(granted, parsed)
    except PaymentAuthorizationError as exc:
        msg = "token exchange payment authority widens the subject grant"
        raise TokenExchangeValidationError(msg) from exc
    if any(set(detail.locations) != {profile.resource} for detail in parsed):
        msg = "token exchange payment authority must target the configured resource"
        raise TokenExchangeValidationError(msg)
    return parsed


def _expected_transition(
    profile: TokenExchangeProfile,
    subject: TokenExchangeCredential,
    actor: TokenExchangeCredential | None,
    *,
    scopes: tuple[str, ...],
    now: datetime,
) -> _Transition:
    source = subject.context
    source_chain = tuple(principal.subject for principal in source.delegation_chain)
    if actor is None:
        return _Transition(source.subject.subject, source.actor.subject, source_chain)
    _validate_source_context(profile, actor.context, now=now)
    actor_context = actor.context
    if (
        actor_context.delegation_chain
        or actor_context.actor.subject != actor_context.subject.subject
        or not set(scopes) <= set(actor_context.evidence.scopes)
    ):
        msg = "token exchange actor credential must be direct and cover requested scopes"
        raise TokenExchangeValidationError(msg)
    actor_subject = actor_context.subject.subject
    chain = (actor_subject, *source_chain)
    identities = (source.subject.subject, *chain)
    if len(chain) > profile.maximum_delegation_depth or len(identities) != len(set(identities)):
        msg = "token exchange delegation depth or cycle is invalid"
        raise TokenExchangeValidationError(msg)
    return _Transition(source.subject.subject, actor_subject, chain)


def _parse_success(
    content: bytes,
    *,
    profile: TokenExchangeProfile,
    requested_scopes: tuple[str, ...],
    requested_details: tuple[PaymentAuthorizationDetail, ...],
    now: datetime,
) -> _ParsedTokenResponse:
    value = _decode_object(content)
    allowed = {"access_token", "issued_token_type", "token_type", "expires_in", "scope"}
    if requested_details:
        allowed.add("authorization_details")
    if set(value) - allowed or not {"access_token", "issued_token_type", "token_type", "expires_in"} <= set(value):
        msg = "token exchange response schema is invalid"
        raise TokenExchangeValidationError(msg)
    access_token = value.get("access_token")
    issued_token_type = value.get("issued_token_type")
    token_type = value.get("token_type")
    expires_in = value.get("expires_in")
    if not isinstance(access_token, str) or not _valid_token(access_token):
        msg = "token exchange access token is invalid"
        raise TokenExchangeValidationError(msg)
    if issued_token_type != ACCESS_TOKEN_TYPE:
        msg = "token exchange issued token type is invalid"
        raise TokenExchangeValidationError(msg)
    expected_token_type = "DPoP" if isinstance(profile.sender_binding, DPoPTokenEndpointBinding) else "Bearer"
    if not isinstance(token_type, str) or token_type.casefold() != expected_token_type.casefold():
        msg = "token exchange sender constraint was downgraded"
        raise TokenExchangeValidationError(msg)
    if (
        not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or expires_in < 1
        or expires_in > int(profile.maximum_token_lifetime.total_seconds())
    ):
        msg = "token exchange expires_in is invalid"
        raise TokenExchangeValidationError(msg)
    response_scopes = _parse_response_scopes(value.get("scope"), requested_scopes)
    raw_details = value.get("authorization_details")
    if requested_details:
        policy = profile.payment_authorization
        if policy is None or raw_details is None:
            msg = "token exchange response omitted payment authority"
            raise TokenExchangeValidationError(msg)
        try:
            issued_details = policy.parse(raw_details, scopes=response_scopes)
            validate_payment_authorization_narrowing(requested_details, issued_details)
        except PaymentAuthorizationError as exc:
            msg = "token exchange response widens payment authority"
            raise TokenExchangeValidationError(msg) from exc
    else:
        issued_details = ()
    return _ParsedTokenResponse(
        access_token=access_token,
        token_type=expected_token_type,
        scopes=response_scopes,
        authorization_details=issued_details,
        expires_at=now + timedelta(seconds=expires_in),
    )


def _parse_response_scopes(value: object, requested: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return requested
    if not isinstance(value, str):
        msg = "token exchange response scope is invalid"
        raise TokenExchangeValidationError(msg)
    scopes = tuple(value.split())
    if (
        not scopes
        or len(scopes) > _MAX_SCOPES
        or len(scopes) != len(set(scopes))
        or any(_SCOPE_PATTERN.fullmatch(scope) is None or "*" in scope for scope in scopes)
        or not set(scopes) <= set(requested)
    ):
        msg = "token exchange response scope widens requested authority"
        raise TokenExchangeValidationError(msg)
    return scopes


def _validate_issued_context(
    profile: TokenExchangeProfile,
    context: AuthenticationContext,
    *,
    response: _ParsedTokenResponse,
    transition: _Transition,
    now: datetime,
) -> None:
    evidence = context.evidence
    actual_chain = tuple(principal.subject for principal in context.delegation_chain)
    common_invalid = (
        evidence.issuer != profile.issuer
        or len(evidence.audiences) != 1
        or evidence.audiences[0] != profile.audience
        or set(evidence.scopes) != set(response.scopes)
        or len(evidence.scopes) != len(response.scopes)
        or evidence.confirmation_thumbprint != profile.sender_binding.confirmation_thumbprint
        or evidence.expires_at is None
        or evidence.expires_at <= now - profile.clock_skew
        or evidence.expires_at > response.expires_at + profile.clock_skew
        or (evidence.issued_at is not None and evidence.issued_at > now + profile.clock_skew)
    )
    transition_invalid = (
        context.subject.subject != transition.subject
        or context.actor.subject != transition.actor
        or actual_chain != transition.chain
    )
    if common_invalid or transition_invalid:
        msg = "issued token violates exchange identity or authority expectations"
        raise TokenExchangeValidationError(msg)
    policy = profile.payment_authorization
    try:
        verified_details = () if policy is None else policy.from_evidence(evidence)
    except PaymentAuthorizationError as exc:
        msg = "issued token payment authority is invalid"
        raise TokenExchangeValidationError(msg) from exc
    if set(verified_details) != set(response.authorization_details) or len(verified_details) != len(
        response.authorization_details
    ):
        msg = "issued token payment authority differs from the token response"
        raise TokenExchangeValidationError(msg)


def _parse_error(content: bytes) -> str:
    value = _decode_object(content)
    if not {"error"} <= set(value) or set(value) - {"error", "error_description", "error_uri"}:
        msg = "token exchange error response schema is invalid"
        raise TokenExchangeValidationError(msg)
    error = value.get("error")
    if not isinstance(error, str) or not _valid_value(error):
        msg = "token exchange error code is invalid"
        raise TokenExchangeValidationError(msg)
    for name in ("error_description", "error_uri"):
        member = value.get(name)
        if member is not None and (not isinstance(member, str) or len(member) > _MAX_VALUE_LENGTH):
            msg = "token exchange error response is invalid"
            raise TokenExchangeValidationError(msg)
    return error


def _decode_object(content: bytes) -> dict[str, object]:
    try:
        value = json.loads(content)
    except (TypeError, ValueError) as exc:
        msg = "token exchange response is not valid JSON"
        raise TokenExchangeValidationError(msg) from exc
    if not isinstance(value, dict):
        msg = "token exchange response must be an object"
        raise TokenExchangeValidationError(msg)
    return value


def _json_details(details: tuple[PaymentAuthorizationDetail, ...]) -> str:
    return json.dumps(
        [_json_value(detail.as_evidence()) for detail in details],
        separators=(",", ":"),
        sort_keys=True,
    )


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {name: _json_value(member) for name, member in value.items()}
    if isinstance(value, tuple):
        return [_json_value(member) for member in value]
    return value


def _validate_https_uri(value: str, *, clean: bool) -> None:
    if not isinstance(value, str):
        msg = "token exchange URLs must be exact HTTPS URIs"
        raise TypeError(msg)
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except (TypeError, ValueError) as exc:
        msg = "token exchange URLs must be exact HTTPS URIs"
        raise ValueError(msg) from exc
    invalid = (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "#" in value
        or not value.isascii()
        or any(character.isspace() for character in value)
        or len(value) > _MAX_URI_LENGTH
        or (clean and bool(parsed.query))
    )
    if invalid:
        msg = "token exchange URLs must be exact HTTPS URIs"
        raise ValueError(msg)


def _aware_now(source: Callable[[], datetime]) -> datetime:
    value = source()
    if value.tzinfo is None:
        msg = "token exchange time source must return an aware datetime"
        raise TokenExchangeValidationError(msg)
    return value


def _valid_value(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.isascii()
        and value.isprintable()
        and value == value.strip()
        and len(value) <= _MAX_VALUE_LENGTH
    )


def _valid_token(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.isascii()
        and len(value.encode()) <= _MAX_TOKEN_BYTES
        and value.isprintable()
        and not any(character.isspace() for character in value)
    )


def _valid_compact_jwt(value: object) -> bool:
    return isinstance(value, str) and _valid_token(value) and value.count(".") == _JWT_SEPARATOR_COUNT


async def _post_token_exchange(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> tuple[int, bytes, Mapping[str, str]]:
    try:
        import httpx
    except ImportError as exc:
        msg = "token exchange requires the 'authweave-workload[token-exchange]' extra"
        raise ImportError(msg) from exc
    content = bytearray()
    try:
        async with (
            httpx.AsyncClient(follow_redirects=False, timeout=timeout_seconds) as client,
            client.stream("POST", url, headers=dict(headers), content=body) as response,
        ):
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > maximum_response_bytes:
                    msg = "token exchange response exceeds the configured size limit"
                    raise TokenExchangeValidationError(msg)
            status = response.status_code
            response_headers = {
                "cache-control": response.headers.get("cache-control", ""),
                "content-type": response.headers.get("content-type", ""),
            }
            nonce_values = response.headers.get_list("dpop-nonce")
            if len(nonce_values) > 1:
                msg = "token exchange response contains duplicate DPoP nonce headers"
                raise TokenExchangeValidationError(msg)
            if nonce_values:
                response_headers["dpop-nonce"] = nonce_values[0]
    except TokenExchangeValidationError:
        raise
    except (httpx.HTTPError, TimeoutError) as exc:
        msg = "token exchange request failed"
        raise TokenExchangeUnavailableError(msg) from exc
    return status, bytes(content), response_headers


__all__ = (
    "ACCESS_TOKEN_TYPE",
    "TOKEN_EXCHANGE_GRANT_TYPE",
    "AsyncJWTSigner",
    "DPoPTokenEndpointBinding",
    "IssuedTokenVerifier",
    "MTLSTokenEndpointBinding",
    "PrivateKeyJWTClientAuth",
    "TokenEndpointBinding",
    "TokenExchangeClient",
    "TokenExchangeCredential",
    "TokenExchangePoster",
    "TokenExchangeProfile",
    "TokenExchangeRejectedError",
    "TokenExchangeResult",
    "TokenExchangeUnavailableError",
    "TokenExchangeValidationError",
)
