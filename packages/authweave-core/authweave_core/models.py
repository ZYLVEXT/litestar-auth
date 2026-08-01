"""Immutable contracts shared by authentication providers and adapters."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from authweave_core.observability import SecurityObserver

_LABEL_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_EXTENSION_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,62}:[a-z][a-z0-9_.-]{0,62}$")
_HTTP_TOKEN_PATTERN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_THUMBPRINT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_ISSUER_LENGTH = 2048
_MAX_SUBJECT_LENGTH = 512
_MAX_VALUE_LENGTH = 512
_MAX_TARGET_URI_LENGTH = 2048
_MAX_EXTENSIONS = 16
_MAX_EVIDENCE_VALUES = 64
_MAX_HEADERS = 128
_MAX_HEADER_BYTES = 65_536
_MAX_AUTHORIZATION_DETAILS = 16
_MAX_AUTHORIZATION_FIELDS = 32
_MAX_AUTHORIZATION_ARRAY = 64
_MAX_AUTHORIZATION_DEPTH = 8
_MAX_AUTHORIZATION_STRING = 512
_MAX_AUTHORIZATION_BYTES = 8192

type EvidenceValue = str | int | bool
type AuthorizationValue = str | int | bool | tuple[AuthorizationValue, ...] | Mapping[str, AuthorizationValue] | None


def _validate_text(value: str, *, name: str, max_length: int = _MAX_VALUE_LENGTH) -> None:
    if not value or value != value.strip() or len(value) > max_length:
        msg = f"{name} must be non-empty, trimmed, and at most {max_length} characters"
        raise ValueError(msg)


def _validate_label(value: str, *, name: str) -> None:
    if _LABEL_PATTERN.fullmatch(value) is None:
        msg = f"{name} must match {_LABEL_PATTERN.pattern!r}"
        raise ValueError(msg)


def _validate_aware(value: datetime | None, *, name: str) -> None:
    if value is not None and value.utcoffset() is None:
        msg = f"{name} must be timezone-aware"
        raise ValueError(msg)


def _validate_target_uri(value: str | None, *, name: str = "target_uri") -> None:
    """Validate a bounded, absolute HTTPS request-target URI.

    The URI is validated structurally without normalization so that the raw
    percent-encoding of the path and query is preserved for signature and
    proof-of-possession comparisons. Adapters must build it from a trusted
    external request target, never from unverified ``Forwarded`` headers.

    Raises:
        ValueError: If the URI is not a bounded, absolute, fragment-free HTTPS
            URI with an authority and no userinfo.
    """
    if value is None:
        return
    if not value or len(value) > _MAX_TARGET_URI_LENGTH:
        msg = f"{name} must be non-empty and at most {_MAX_TARGET_URI_LENGTH} characters"
        raise ValueError(msg)
    if not value.isascii() or not value.isprintable() or any(char.isspace() for char in value):
        msg = f"{name} must be printable ASCII without whitespace or control characters"
        raise ValueError(msg)
    parts = urlsplit(value)
    if parts.scheme != "https":
        msg = f"{name} must use the https scheme"
        raise ValueError(msg)
    if not parts.hostname:
        msg = f"{name} must include an authority host"
        raise ValueError(msg)
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        msg = f"{name} must not contain userinfo"
        raise ValueError(msg)
    if parts.fragment or "#" in value:
        msg = f"{name} must not contain a fragment"
        raise ValueError(msg)


@dataclass(frozen=True, slots=True, eq=False)
class PrincipalRef:
    """Stable principal identity with a verified classification."""

    issuer: str
    subject: str
    kind: str

    def __post_init__(self) -> None:
        """Validate bounded identity components."""
        _validate_text(self.issuer, name="issuer", max_length=_MAX_ISSUER_LENGTH)
        _validate_text(self.subject, name="subject", max_length=_MAX_SUBJECT_LENGTH)
        _validate_label(self.kind, name="kind")

    def __eq__(self, other: object) -> bool:
        """Compare stable identity independently from classification.

        Returns:
            Whether issuer and subject match.
        """
        if not isinstance(other, PrincipalRef):
            return NotImplemented
        return (self.issuer, self.subject) == (other.issuer, other.subject)

    def __hash__(self) -> int:
        """Hash the stable identity independently from classification.

        Returns:
            Hash of issuer and subject.
        """
        return hash((self.issuer, self.subject))


@dataclass(frozen=True, slots=True)
class TlsPeerEvidence:
    """Verified TLS peer facts produced by a trusted termination boundary."""

    tls_version: str
    certificate_thumbprint: str
    certificate_not_before: datetime
    certificate_not_after: datetime
    revocation_checked_at: datetime
    trust_anchor: str
    termination_boundary: str

    def __post_init__(self) -> None:
        """Reject malformed or internally inconsistent TLS evidence.

        Raises:
            ValueError: If a field is malformed or the validity interval is empty.
        """
        _validate_text(self.tls_version, name="tls_version", max_length=32)
        if _THUMBPRINT_PATTERN.fullmatch(self.certificate_thumbprint) is None:
            msg = "certificate_thumbprint must be an unpadded base64url SHA-256 digest"
            raise ValueError(msg)
        _validate_aware(self.certificate_not_before, name="certificate_not_before")
        _validate_aware(self.certificate_not_after, name="certificate_not_after")
        _validate_aware(self.revocation_checked_at, name="revocation_checked_at")
        if self.certificate_not_before >= self.certificate_not_after:
            msg = "certificate_not_before must be earlier than certificate_not_after"
            raise ValueError(msg)
        _validate_text(self.trust_anchor, name="trust_anchor")
        _validate_text(self.termination_boundary, name="termination_boundary")


@dataclass(frozen=True, slots=True)
class SpiffePeerEvidence:
    """Verified SPIFFE peer identity projected by a trusted validation boundary.

    Identity is the SPIFFE ID alone. Short-lived SVIDs are never registered by
    certificate thumbprint.
    """

    spiffe_id: str
    trust_domain: str
    not_before: datetime
    not_after: datetime
    termination_boundary: str

    def __post_init__(self) -> None:
        """Reject malformed SPIFFE peer projections.

        Raises:
            ValueError: If the SPIFFE ID, trust domain, or validity window is invalid.
        """
        _validate_text(self.spiffe_id, name="spiffe_id", max_length=2048)
        _validate_text(self.trust_domain, name="trust_domain", max_length=255)
        _validate_aware(self.not_before, name="not_before")
        _validate_aware(self.not_after, name="not_after")
        _validate_text(self.termination_boundary, name="termination_boundary")
        if self.not_before >= self.not_after:
            msg = "not_before must be earlier than not_after"
            raise ValueError(msg)
        if not self.spiffe_id.startswith("spiffe://"):
            msg = "spiffe_id must use the spiffe scheme"
            raise ValueError(msg)
        remainder = self.spiffe_id.removeprefix("spiffe://")
        if "/" not in remainder:
            msg = "spiffe_id must include a trust domain and path"
            raise ValueError(msg)
        domain, path = remainder.split("/", 1)
        if domain != self.trust_domain:
            msg = "trust_domain must match the SPIFFE ID trust domain"
            raise ValueError(msg)
        if not path or path.startswith("/") or "//" in path or path.endswith("/"):
            msg = "spiffe_id path must be a non-root workload path"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RequestView:
    """Immutable, framework-neutral projection of authentication inputs."""

    method: str
    headers: tuple[tuple[bytes, bytes], ...] = field(default=(), repr=False)
    scheme: str | None = None
    authority: str | None = None
    target_uri: str | None = None
    tls_peer: TlsPeerEvidence | None = None
    spiffe_peer: SpiffePeerEvidence | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        """Validate request metadata without collapsing duplicate headers.

        Raises:
            ValueError: If request metadata is malformed.
        """
        try:
            method = self.method.encode("ascii")
        except UnicodeEncodeError as exc:
            msg = "method must be an ASCII HTTP token"
            raise ValueError(msg) from exc
        if _HTTP_TOKEN_PATTERN.fullmatch(method) is None:
            msg = "method must be an ASCII HTTP token"
            raise ValueError(msg)
        object.__setattr__(self, "headers", tuple(self.headers))
        if (
            len(self.headers) > _MAX_HEADERS
            or sum(len(name) + len(value) for name, value in self.headers) > _MAX_HEADER_BYTES
        ):
            msg = "headers exceed the authentication projection limits"
            raise ValueError(msg)
        for name, value in self.headers:
            if _HTTP_TOKEN_PATTERN.fullmatch(name) is None:
                msg = "header names must be non-empty ASCII HTTP tokens"
                raise ValueError(msg)
            if b"\x00" in value or b"\r" in value or b"\n" in value:
                msg = "header values must not contain NUL, CR, or LF"
                raise ValueError(msg)
        if self.scheme is not None:
            _validate_text(self.scheme, name="scheme", max_length=32)
        if self.authority is not None:
            _validate_text(self.authority, name="authority", max_length=512)
        _validate_target_uri(self.target_uri)
        _validate_aware(self.timestamp, name="timestamp")
        if self.correlation_id is not None:
            _validate_text(self.correlation_id, name="correlation_id")

    def header_values(self, name: bytes) -> tuple[bytes, ...]:
        """Return every value for a case-insensitive header name."""
        normalized = name.lower()
        return tuple(value for header_name, value in self.headers if header_name.lower() == normalized)


@dataclass(frozen=True, slots=True)
class AuthenticationEvidence:
    """Verified, secret-free facts produced by an authentication provider."""

    provider: str
    profile: str
    method: str
    issuer: str
    audiences: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    issued_at: datetime | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    credential_id: str | None = None
    token_id: str | None = None
    confirmation_thumbprint: str | None = None
    environment: str | None = None
    extensions: Mapping[str, EvidenceValue] = field(default_factory=dict)
    authorization_details: tuple[Mapping[str, AuthorizationValue], ...] = ()

    def __post_init__(self) -> None:
        """Validate bounded evidence and freeze extension and authorization data."""
        _validate_label(self.provider, name="provider")
        _validate_label(self.profile, name="profile")
        _validate_label(self.method, name="method")
        _validate_text(self.issuer, name="issuer", max_length=_MAX_ISSUER_LENGTH)
        object.__setattr__(self, "audiences", _freeze_evidence_values(self.audiences, name="audiences"))
        object.__setattr__(self, "scopes", _freeze_evidence_values(self.scopes, name="scopes"))
        _validate_evidence_times(self)
        _validate_evidence_identifiers(self)
        object.__setattr__(self, "extensions", _freeze_extensions(self.extensions))
        object.__setattr__(
            self,
            "authorization_details",
            freeze_authorization_details(self.authorization_details),
        )


@dataclass(frozen=True, slots=True)
class AuthenticationContext:
    """Authenticated subject, actor, delegation chain, and verified evidence."""

    subject: PrincipalRef
    actor: PrincipalRef
    evidence: AuthenticationEvidence
    delegation_chain: tuple[PrincipalRef, ...] = ()

    def __post_init__(self) -> None:
        """Freeze the delegation chain."""
        object.__setattr__(self, "delegation_chain", tuple(self.delegation_chain))


class FailureCode(StrEnum):
    """Stable neutral authentication failure codes."""

    MISSING = "missing"
    MALFORMED = "malformed"
    INVALID = "invalid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REVOKED = "revoked"
    PRINCIPAL_DISABLED = "principal_disabled"
    ISSUER_MISMATCH = "issuer_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    TOKEN_TYPE_MISMATCH = "token_type_mismatch"
    ALGORITHM_MISMATCH = "algorithm_mismatch"
    SENDER_CONSTRAINT_MISMATCH = "sender_constraint_mismatch"
    AMBIGUOUS_CREDENTIALS = "ambiguous_credentials"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INTERNAL_INVARIANT = "internal_invariant"


class CredentialMatch(StrEnum):
    """Credential ownership result returned by a provider matcher."""

    NOT_APPLICABLE = "not_applicable"
    OWNED = "owned"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class NotApplicable:
    """No allowed provider owns a credential presentation."""


@dataclass(frozen=True, slots=True)
class Authenticated:
    """Credential was fully verified."""

    context: AuthenticationContext


@dataclass(frozen=True, slots=True)
class Invalid:
    """Credential was owned but failed verification."""

    code: FailureCode


@dataclass(frozen=True, slots=True)
class Unavailable:
    """Credential verification could not complete safely."""

    code: FailureCode = FailureCode.PROVIDER_UNAVAILABLE


@dataclass(frozen=True, slots=True)
class InvariantFailure:
    """Provider or coordinator contract was violated."""

    code: FailureCode = field(default=FailureCode.INTERNAL_INVARIANT, init=False)


type AuthenticationDecision = NotApplicable | Authenticated | Invalid | Unavailable | InvariantFailure


@dataclass(frozen=True, slots=True)
class AuthenticationRuntime:
    """Request-scoped execution limits and optional operational telemetry."""

    deadline: float | None = None
    observer: SecurityObserver | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class RouteProviderPolicy:
    """Ordered-free set of provider names permitted for a route."""

    providers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate and deduplicate provider names.

        Raises:
            ValueError: If a provider name is invalid or duplicated.
        """
        providers = tuple(self.providers)
        for provider in providers:
            _validate_label(provider, name="provider")
        if len(providers) > 1:
            msg = "route provider policy permits at most one authentication profile"
            raise ValueError(msg)
        object.__setattr__(self, "providers", providers)


def _freeze_evidence_values(values: tuple[str, ...], *, name: str) -> tuple[str, ...]:
    frozen = tuple(values)
    if len(frozen) > _MAX_EVIDENCE_VALUES:
        msg = f"{name} must contain at most {_MAX_EVIDENCE_VALUES} values"
        raise ValueError(msg)
    for value in frozen:
        _validate_text(value, name=name)
    return frozen


def _validate_evidence_times(evidence: AuthenticationEvidence) -> None:
    for name in ("issued_at", "not_before", "expires_at"):
        _validate_aware(getattr(evidence, name), name=name)
    if (
        evidence.not_before is not None
        and evidence.expires_at is not None
        and evidence.not_before >= evidence.expires_at
    ):
        msg = "not_before must be earlier than expires_at"
        raise ValueError(msg)


def _validate_evidence_identifiers(evidence: AuthenticationEvidence) -> None:
    for name in ("credential_id", "token_id", "environment"):
        value = getattr(evidence, name)
        if value is not None:
            _validate_text(value, name=name)
    if (
        evidence.confirmation_thumbprint is not None
        and _THUMBPRINT_PATTERN.fullmatch(
            evidence.confirmation_thumbprint,
        )
        is None
    ):
        msg = "confirmation_thumbprint must be an unpadded base64url SHA-256 digest"
        raise ValueError(msg)


def _freeze_extensions(extensions: Mapping[str, EvidenceValue]) -> Mapping[str, EvidenceValue]:
    frozen = dict(extensions)
    if len(frozen) > _MAX_EXTENSIONS:
        msg = f"extensions must contain at most {_MAX_EXTENSIONS} entries"
        raise ValueError(msg)
    for key, value in frozen.items():
        if _EXTENSION_KEY_PATTERN.fullmatch(key) is None:
            msg = f"extension key {key!r} must be namespaced"
            raise ValueError(msg)
        if isinstance(value, str):
            _validate_text(value, name=f"extension {key}", max_length=256)
        elif not isinstance(value, (bool, int)):
            msg = f"extension {key!r} must contain a string, integer, or boolean"
            raise TypeError(msg)
    return MappingProxyType(frozen)


def freeze_authorization_details(
    details: object,
) -> tuple[Mapping[str, AuthorizationValue], ...]:
    """Freeze validated RFC 9396 authorization details into a bounded immutable form.

    This helper enforces only neutral structural bounds and immutability. A
    provider may use it to bound untrusted JSON, but must apply its type-specific
    schema before constructing authentication evidence.

    Returns:
        The frozen, immutable authorization-details tuple.

    Raises:
        TypeError: If details are not an array or contain unsupported values.
        ValueError: If the details exceed structural bounds.
    """
    if not isinstance(details, (list, tuple)):
        msg = "authorization_details must be an array"
        raise TypeError(msg)
    entries = tuple(details)
    if len(entries) > _MAX_AUTHORIZATION_DETAILS:
        msg = f"authorization_details must contain at most {_MAX_AUTHORIZATION_DETAILS} objects"
        raise ValueError(msg)
    budget = [_MAX_AUTHORIZATION_BYTES]
    frozen: list[Mapping[str, AuthorizationValue]] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or not entry:
            msg = "each authorization_details entry must be a non-empty object"
            raise ValueError(msg)
        frozen.append(
            cast("Mapping[str, AuthorizationValue]", _freeze_authorization_value(entry, depth=1, budget=budget))
        )
    return tuple(frozen)


def _freeze_authorization_value(value: object, *, depth: int, budget: list[int]) -> AuthorizationValue:
    if depth > _MAX_AUTHORIZATION_DEPTH:
        msg = f"authorization_details must not nest deeper than {_MAX_AUTHORIZATION_DEPTH} levels"
        raise ValueError(msg)
    if value is None or isinstance(value, bool):
        budget[0] -= 1
    elif isinstance(value, int):
        budget[0] -= 8
    elif isinstance(value, str):
        _validate_authorization_string(value)
        budget[0] -= len(value)
    elif isinstance(value, Mapping):
        return _freeze_authorization_object(cast("Mapping[str, object]", value), depth=depth, budget=budget)
    elif isinstance(value, (list, tuple)):
        return _freeze_authorization_array(cast("list[object] | tuple[object, ...]", value), depth=depth, budget=budget)
    else:
        msg = "authorization_details values must be JSON scalars, arrays, or objects"
        raise TypeError(msg)
    if budget[0] < 0:
        _raise_authorization_budget()
    return value


def _freeze_authorization_object(
    value: Mapping[str, object],
    *,
    depth: int,
    budget: list[int],
) -> Mapping[str, AuthorizationValue]:
    if len(value) > _MAX_AUTHORIZATION_FIELDS:
        msg = f"authorization_details objects must have at most {_MAX_AUTHORIZATION_FIELDS} fields"
        raise ValueError(msg)
    frozen: dict[str, AuthorizationValue] = {}
    for key, member in value.items():
        if not isinstance(key, str):
            msg = "authorization_details object keys must be strings"
            raise TypeError(msg)
        _validate_authorization_string(key, name="authorization_details key")
        budget[0] -= len(key)
        if budget[0] < 0:
            _raise_authorization_budget()
        frozen[key] = _freeze_authorization_value(member, depth=depth + 1, budget=budget)
    return MappingProxyType(frozen)


def _freeze_authorization_array(
    value: list[object] | tuple[object, ...],
    *,
    depth: int,
    budget: list[int],
) -> tuple[AuthorizationValue, ...]:
    if len(value) > _MAX_AUTHORIZATION_ARRAY:
        msg = f"authorization_details arrays must have at most {_MAX_AUTHORIZATION_ARRAY} items"
        raise ValueError(msg)
    return tuple(_freeze_authorization_value(item, depth=depth + 1, budget=budget) for item in value)


def _validate_authorization_string(value: str, *, name: str = "authorization_details string") -> None:
    if len(value) > _MAX_AUTHORIZATION_STRING:
        msg = f"{name} must be at most {_MAX_AUTHORIZATION_STRING} characters"
        raise ValueError(msg)


def _raise_authorization_budget() -> None:
    msg = f"authorization_details must decode to at most {_MAX_AUTHORIZATION_BYTES} bytes"
    raise ValueError(msg)
