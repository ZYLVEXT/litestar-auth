"""SPIFFE X.509-SVID validation and resource-server provider (library-ready)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationEvidence,
    CredentialMatch,
    FailureCode,
    Invalid,
    PrincipalRef,
    SecurityOperation,
    SecurityOutcome,
    SpiffePeerEvidence,
    Unavailable,
    observe_security,
)

from authweave_workload.events import (
    EventDeliveryError,
    SecurityEvent,
    SecurityEventType,
    deliver_security_event,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from authweave_core import AuthenticationRuntime, RequestView

_TRUST_DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$")
_PATH_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9._~-]+$")
_MAX_SPIFFE_ID_LENGTH = 2048
_MAX_BUNDLE_CERTS = 64
_MAX_INTERMEDIATES = 8


class SpiffeValidationError(ValueError):
    """Raised when SPIFFE ID or X.509-SVID validation fails."""


@dataclass(frozen=True, slots=True)
class SpiffeID:
    """Parsed SPIFFE ID (trust domain + non-root workload path)."""

    trust_domain: str
    path: str

    def __str__(self) -> str:
        """Return the canonical ``spiffe://`` URI."""
        return f"spiffe://{self.trust_domain}/{self.path}"


def parse_spiffe_id(value: str) -> SpiffeID:
    """Parse and validate a SPIFFE ID.

    Returns:
        The trust domain and workload path.

    Raises:
        SpiffeValidationError: If the URI violates SPIFFE ID syntax.
    """
    if not value or len(value) > _MAX_SPIFFE_ID_LENGTH or not value.isascii():
        msg = "SPIFFE ID length or charset is invalid"
        raise SpiffeValidationError(msg)
    parts = urlsplit(value)
    if parts.scheme != "spiffe" or not parts.netloc or parts.fragment or parts.query:
        msg = "SPIFFE ID must be spiffe://trust-domain/path"
        raise SpiffeValidationError(msg)
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        msg = "SPIFFE ID must not contain userinfo"
        raise SpiffeValidationError(msg)
    trust_domain = parts.netloc.lower()
    if trust_domain != parts.netloc:
        msg = "SPIFFE trust domain must be lowercase"
        raise SpiffeValidationError(msg)
    if _TRUST_DOMAIN_PATTERN.fullmatch(trust_domain) is None:
        msg = "SPIFFE trust domain is invalid"
        raise SpiffeValidationError(msg)
    path = parts.path
    if not path.startswith("/") or path == "/" or path.endswith("/") or "//" in path:
        msg = "SPIFFE path must be a non-root workload path"
        raise SpiffeValidationError(msg)
    segments = path[1:].split("/")
    if any(segment in {".", ".."} or _PATH_SEGMENT_PATTERN.fullmatch(segment) is None for segment in segments):
        msg = "SPIFFE path segments are invalid"
        raise SpiffeValidationError(msg)
    return SpiffeID(trust_domain=trust_domain, path="/".join(segments))


@dataclass(frozen=True, slots=True)
class SpiffeBundleSnapshot:
    """Immutable trust-bundle authorities for one trust domain."""

    trust_domain: str
    version: str
    authorities: tuple[bytes, ...]
    fetched_at: datetime
    maximum_staleness: timedelta = timedelta(hours=1)
    maximum_future_skew: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        """Reject empty bundles or unsafe metadata.

        Raises:
            ValueError: If bundle metadata or bounds are invalid.
        """
        if not self.trust_domain or not self.version:
            msg = "bundle trust_domain and version are required"
            raise ValueError(msg)
        if not self.authorities or len(self.authorities) > _MAX_BUNDLE_CERTS:
            msg = "bundle authorities are required and bounded"
            raise ValueError(msg)
        if self.fetched_at.utcoffset() is None:
            msg = "fetched_at must be timezone-aware"
            raise ValueError(msg)
        if self.maximum_staleness <= timedelta(0) or self.maximum_future_skew < timedelta(0):
            msg = "bundle freshness bounds are invalid"
            raise ValueError(msg)

    def assert_fresh(self, *, now: datetime) -> None:
        """Fail closed when the snapshot is too old.

        Raises:
            SpiffeValidationError: If the snapshot exceeds maximum staleness.
        """
        if now.utcoffset() is None:
            msg = "now must be timezone-aware"
            raise SpiffeValidationError(msg)
        if self.fetched_at > now + self.maximum_future_skew:
            msg = "SPIFFE bundle snapshot is from the future"
            raise SpiffeValidationError(msg)
        if now - self.fetched_at > self.maximum_staleness:
            msg = "SPIFFE bundle snapshot is stale"
            raise SpiffeValidationError(msg)


@runtime_checkable
class SpiffeBundleSource(Protocol):
    """Provide versioned SPIFFE trust-bundle snapshots."""

    async def snapshot(self, trust_domain: str) -> SpiffeBundleSnapshot | None:
        """Return the current snapshot for ``trust_domain``, or ``None`` if unknown."""
        ...


class StaticSpiffeBundleSource:
    """In-memory bundle map for tests and bounded reference deployments."""

    __slots__ = ("_bundles",)

    def __init__(self, bundles: Mapping[str, SpiffeBundleSnapshot]) -> None:
        """Bind one snapshot per trust domain.

        Raises:
            ValueError: If no bundles are supplied.
        """
        if not bundles:
            msg = "at least one SPIFFE bundle is required"
            raise ValueError(msg)
        self._bundles = dict(bundles)

    async def snapshot(self, trust_domain: str) -> SpiffeBundleSnapshot | None:
        """Return a configured snapshot."""
        return self._bundles.get(trust_domain)


@dataclass(frozen=True, slots=True)
class SpiffeResolvedPrincipal:
    """Application mapping for one SPIFFE ID (no path-based authority)."""

    principal: PrincipalRef
    application_id: str
    environment: str
    audiences: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require explicit application and environment labels.

        Raises:
            ValueError: If either label is empty.
        """
        if not self.application_id or not self.environment:
            msg = "application_id and environment are required"
            raise ValueError(msg)


class SpiffeResolverUnavailableError(Exception):
    """Raised when the SPIFFE principal resolver cannot reach its store."""


@runtime_checkable
class SpiffePrincipalResolver(Protocol):
    """Map a verified SPIFFE ID to an application principal."""

    async def resolve(self, spiffe_id: SpiffeID) -> SpiffeResolvedPrincipal | None:
        """Return the mapping, ``None`` when unmapped, or raise on store outage."""
        ...


@dataclass(frozen=True, slots=True)
class SpiffePolicy:
    """Exact SPIFFE RS policy for one deployment boundary mode."""

    allowed_trust_domains: frozenset[str]
    termination_boundaries: frozenset[str]
    maximum_svid_lifetime: timedelta = timedelta(hours=24)
    require_empty_authorization: bool = True

    def __post_init__(self) -> None:
        """Reject empty allowlists or non-positive lifetime.

        Raises:
            ValueError: If policy bounds are invalid.
        """
        if not self.allowed_trust_domains or not self.termination_boundaries:
            msg = "SPIFFE policy requires trust domains and termination boundaries"
            raise ValueError(msg)
        if self.maximum_svid_lifetime <= timedelta(0):
            msg = "maximum_svid_lifetime must be positive"
            raise ValueError(msg)
        for domain in self.allowed_trust_domains:
            parse_spiffe_id(f"spiffe://{domain}/placeholder")


@dataclass(frozen=True, slots=True)
class ValidatedSpiffeSvid:
    """Secret-free result of headless X.509-SVID validation."""

    spiffe_id: SpiffeID
    not_before: datetime
    not_after: datetime


class SpiffeX509SvidValidator:
    """Validate a leaf+intermediates chain against a SPIFFE trust bundle."""

    __slots__ = ("_bundle_source", "_maximum_svid_lifetime")

    def __init__(
        self,
        *,
        bundle_source: SpiffeBundleSource,
        maximum_svid_lifetime: timedelta = timedelta(hours=24),
    ) -> None:
        """Bind bundle lookups and lifetime ceiling.

        Raises:
            ValueError: If the lifetime ceiling is not positive.
        """
        if maximum_svid_lifetime <= timedelta(0):
            msg = "maximum_svid_lifetime must be positive"
            raise ValueError(msg)
        self._bundle_source = bundle_source
        self._maximum_svid_lifetime = maximum_svid_lifetime

    async def validate(
        self,
        *,
        leaf: bytes,
        intermediates: Iterable[bytes] = (),
        now: datetime | None = None,
    ) -> ValidatedSpiffeSvid:
        """Validate path + SPIFFE leaf profile and return the SPIFFE ID.

        Returns:
            Validated SPIFFE identity and certificate validity window.

        Raises:
            SpiffeValidationError: On any validation failure.
        """
        instant = datetime.now(UTC) if now is None else now
        if instant.utcoffset() is None:
            msg = "now must be timezone-aware"
            raise SpiffeValidationError(msg)
        crypto = _load_cryptography()
        x509 = crypto["x509"]
        leaf_cert = _load_certificate(x509, leaf)
        intermediate_certs = [_load_certificate(x509, value) for value in intermediates]
        if len(intermediate_certs) > _MAX_INTERMEDIATES:
            msg = "too many intermediate certificates"
            raise SpiffeValidationError(msg)
        spiffe_id = _spiffe_id_from_leaf(leaf_cert, x509)
        _validate_spiffe_leaf_profile(leaf_cert, crypto)
        not_before = leaf_cert.not_valid_before_utc
        not_after = leaf_cert.not_valid_after_utc
        if not_after - not_before > self._maximum_svid_lifetime:
            msg = "SVID lifetime exceeds policy"
            raise SpiffeValidationError(msg)
        if instant < not_before or instant >= not_after:
            msg = "SVID is not currently valid"
            raise SpiffeValidationError(msg)
        bundle = await self._bundle_source.snapshot(spiffe_id.trust_domain)
        if bundle is None:
            msg = "SPIFFE bundle is unavailable for trust domain"
            raise SpiffeValidationError(msg)
        bundle.assert_fresh(now=instant)
        anchors = [_load_certificate(x509, value) for value in bundle.authorities]
        try:
            verifier = crypto["PolicyBuilder"]().store(crypto["Store"](anchors)).time(instant).build_client_verifier()
            verifier.verify(leaf_cert, intermediate_certs)
        except crypto["VerificationError"] as exc:
            msg = "SPIFFE certificate path validation failed"
            raise SpiffeValidationError(msg) from exc
        return ValidatedSpiffeSvid(spiffe_id=spiffe_id, not_before=not_before, not_after=not_after)


class SPIFFEProvider:
    """Authenticate a projected SPIFFE peer (mesh or headless adapter output)."""

    profile = "spiffe_x509_svid"

    def __init__(
        self,
        *,
        name: str,
        policy: SpiffePolicy,
        resolver: SpiffePrincipalResolver,
        event_callback: Callable[[SecurityEvent], object] | None = None,
    ) -> None:
        """Bind policy and principal mapping (never a thumbprint registry)."""
        self.name = name
        self.policy = policy
        self.resolver = resolver
        self.event_callback = event_callback

    def match(self, request: RequestView) -> CredentialMatch:
        """Own projected SPIFFE evidence; reject mixed human credential headers.

        Returns:
            Whether this provider owns the request credentials.
        """
        if request.spiffe_peer is None:
            return CredentialMatch.NOT_APPLICABLE
        if self.policy.require_empty_authorization and (
            request.header_values(b"authorization") or request.header_values(b"cookie")
        ):
            return CredentialMatch.AMBIGUOUS
        return CredentialMatch.OWNED

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> Authenticated | Invalid | Unavailable:
        """Verify boundary facts and resolve the SPIFFE ID to a principal.

        Fails closed to :class:`~authweave_core.Unavailable` if mandatory event
        delivery fails (ADR 0001).

        Returns:
            Authenticated context, Invalid, or Unavailable.
        """
        with observe_security(
            runtime.observer,
            SecurityOperation.VALIDATE_SPIFFE_SVID,
            profile=self.profile,
            credential_kind="x509_svid",
        ) as observation:
            try:
                decision = await self._authenticate(request, runtime)
            except EventDeliveryError:
                decision = Unavailable()
            if isinstance(decision, Authenticated):
                observation.set_outcome(SecurityOutcome.VERIFIED)
            elif isinstance(decision, Invalid):
                observation.set_outcome(SecurityOutcome.INVALID, reason_code=decision.code.value)
            else:
                observation.set_outcome(SecurityOutcome.UNAVAILABLE, reason_code=decision.code.value)
            return decision

    async def _authenticate(  # ruff: ignore[complex-structure, too-many-return-statements] - fail-closed profile matrix
        self,
        request: RequestView,
        _runtime: AuthenticationRuntime,
    ) -> Authenticated | Invalid | Unavailable:
        peer = request.spiffe_peer
        if peer is None:
            return Invalid(FailureCode.MISSING)
        if peer.termination_boundary not in self.policy.termination_boundaries:
            await self._emit_failure(request, FailureCode.SENDER_CONSTRAINT_MISMATCH)
            return Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)
        try:
            spiffe_id = parse_spiffe_id(peer.spiffe_id)
        except SpiffeValidationError:
            await self._emit_failure(request, FailureCode.MALFORMED)
            return Invalid(FailureCode.MALFORMED)
        if spiffe_id.trust_domain != peer.trust_domain:
            await self._emit_failure(request, FailureCode.MALFORMED)
            return Invalid(FailureCode.MALFORMED)
        if spiffe_id.trust_domain not in self.policy.allowed_trust_domains:
            await self._emit_failure(request, FailureCode.ISSUER_MISMATCH)
            return Invalid(FailureCode.ISSUER_MISMATCH)
        if request.timestamp < peer.not_before:
            await self._emit_failure(request, FailureCode.NOT_YET_VALID)
            return Invalid(FailureCode.NOT_YET_VALID)
        if request.timestamp >= peer.not_after:
            await self._emit_failure(request, FailureCode.EXPIRED)
            return Invalid(FailureCode.EXPIRED)
        if peer.not_after - peer.not_before > self.policy.maximum_svid_lifetime:
            await self._emit_failure(request, FailureCode.MALFORMED)
            return Invalid(FailureCode.MALFORMED)
        try:
            resolved = await self.resolver.resolve(spiffe_id)
        except SpiffeResolverUnavailableError:
            await self._emit_failure(request, FailureCode.PROVIDER_UNAVAILABLE)
            return Unavailable()
        if resolved is None:
            await self._emit_failure(request, FailureCode.INVALID)
            return Invalid(FailureCode.INVALID)
        evidence = AuthenticationEvidence(
            provider=self.name,
            profile=self.profile,
            method="spiffe",
            issuer=f"spiffe://{spiffe_id.trust_domain}",
            audiences=resolved.audiences,
            scopes=resolved.scopes,
            not_before=peer.not_before,
            expires_at=peer.not_after,
            environment=resolved.environment,
            extensions={
                "authweave-workload:application_id": resolved.application_id,
                "authweave-workload:spiffe_id": str(spiffe_id),
            },
        )
        context = AuthenticationContext(
            subject=resolved.principal,
            actor=resolved.principal,
            evidence=evidence,
        )
        await self._emit(
            SecurityEvent(
                SecurityEventType.AUTHENTICATION_SUCCEEDED,
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


def project_spiffe_peer(
    *,
    validated: ValidatedSpiffeSvid,
    termination_boundary: str,
) -> SpiffePeerEvidence:
    """Build RequestView evidence after mesh or headless validation.

    Returns:
        Secret-free SPIFFE peer projection (no certificate bytes).
    """
    return SpiffePeerEvidence(
        spiffe_id=str(validated.spiffe_id),
        trust_domain=validated.spiffe_id.trust_domain,
        not_before=validated.not_before,
        not_after=validated.not_after,
        termination_boundary=termination_boundary,
    )


def _load_cryptography() -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
    except ImportError as exc:
        msg = "SPIFFE X.509 validation requires the 'authweave-workload[spiffe]' extra."
        raise ImportError(msg) from exc
    return {
        "PolicyBuilder": PolicyBuilder,
        "Store": Store,
        "VerificationError": VerificationError,
        "ec": ec,
        "ed25519": ed25519,
        "rsa": rsa,
        "x509": x509,
    }


def _load_certificate(x509: Any, value: bytes) -> Any:
    try:
        if b"-----BEGIN CERTIFICATE-----" in value:
            return x509.load_pem_x509_certificate(value)
        return x509.load_der_x509_certificate(value)
    except ValueError as exc:
        msg = "certificate encoding is invalid"
        raise SpiffeValidationError(msg) from exc


def _spiffe_id_from_leaf(certificate: Any, x509: Any) -> SpiffeID:
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        msg = "SVID requires a Subject Alternative Name"
        raise SpiffeValidationError(msg) from exc
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        msg = "SVID must contain exactly one URI SAN"
        raise SpiffeValidationError(msg)
    return parse_spiffe_id(uris[0])


def _validate_spiffe_leaf_profile(certificate: Any, crypto: dict[str, Any]) -> None:
    x509 = crypto["x509"]
    try:
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        msg = "SVID BasicConstraints are required"
        raise SpiffeValidationError(msg) from exc
    if basic.ca:
        msg = "SVID leaf must not be a CA"
        raise SpiffeValidationError(msg)
    try:
        key_usage_extension = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound as exc:
        msg = "SVID KeyUsage is required"
        raise SpiffeValidationError(msg) from exc
    if not key_usage_extension.critical:
        msg = "SVID KeyUsage must be critical"
        raise SpiffeValidationError(msg)
    key_usage = key_usage_extension.value
    if not key_usage.digital_signature:
        msg = "SVID must permit digital signatures"
        raise SpiffeValidationError(msg)
    if key_usage.key_cert_sign or key_usage.crl_sign:
        msg = "SVID must not permit certificate or CRL signing"
        raise SpiffeValidationError(msg)
    _validate_spiffe_public_key(certificate.public_key(), crypto)


def _validate_spiffe_public_key(public_key: Any, crypto: dict[str, Any]) -> None:
    if isinstance(public_key, crypto["rsa"].RSAPublicKey):
        minimum_rsa_bits = 2048
        if public_key.key_size < minimum_rsa_bits:
            msg = "RSA SVID keys must be at least 2048 bits"
            raise SpiffeValidationError(msg)
    elif isinstance(public_key, crypto["ec"].EllipticCurvePublicKey):
        if public_key.curve.name not in {"secp256r1", "secp384r1"}:
            msg = "ECDSA SVID keys must use P-256 or P-384"
            raise SpiffeValidationError(msg)
    elif not isinstance(public_key, crypto["ed25519"].Ed25519PublicKey):
        msg = "SVID public key type is not supported"
        raise SpiffeValidationError(msg)
