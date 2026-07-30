"""Immutable contracts shared by authentication providers and adapters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

_LABEL_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_EXTENSION_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,62}:[a-z][a-z0-9_.-]{0,62}$")
_HTTP_TOKEN_PATTERN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_THUMBPRINT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_ISSUER_LENGTH = 2048
_MAX_SUBJECT_LENGTH = 512
_MAX_VALUE_LENGTH = 512
_MAX_EXTENSIONS = 16
_MAX_EVIDENCE_VALUES = 64
_MAX_HEADERS = 128
_MAX_HEADER_BYTES = 65_536

type EvidenceValue = str | int | bool


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
class RequestView:
    """Immutable, framework-neutral projection of authentication inputs."""

    method: str
    headers: tuple[tuple[bytes, bytes], ...] = field(default=(), repr=False)
    scheme: str | None = None
    authority: str | None = None
    tls_peer: TlsPeerEvidence | None = None
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

    def __post_init__(self) -> None:
        """Validate bounded evidence and freeze extension data."""
        _validate_label(self.provider, name="provider")
        _validate_label(self.profile, name="profile")
        _validate_label(self.method, name="method")
        _validate_text(self.issuer, name="issuer", max_length=_MAX_ISSUER_LENGTH)
        object.__setattr__(self, "audiences", _freeze_evidence_values(self.audiences, name="audiences"))
        object.__setattr__(self, "scopes", _freeze_evidence_values(self.scopes, name="scopes"))
        _validate_evidence_times(self)
        _validate_evidence_identifiers(self)
        object.__setattr__(self, "extensions", _freeze_extensions(self.extensions))


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
    """Request-scoped execution limits for providers."""

    deadline: float | None = None


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
