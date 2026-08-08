"""Framework-neutral workload registration and credential models."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from authweave_core import PrincipalRef

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ENVIRONMENT_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_METADATA_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MAX_METADATA_ITEMS = 32
_MAX_METADATA_VALUE_LENGTH = 512
_MAX_CONSTRAINT_VALUES = 64
_MAX_CERTIFICATE_TEXT_LENGTH = 2048
_THUMBPRINT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class EntityStatus(StrEnum):
    """Lifecycle status shared by applications and principals."""

    ACTIVE = "active"
    DISABLED = "disabled"


class CredentialStatus(StrEnum):
    """Lifecycle status for registered public credentials."""

    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


def _validate_id(value: str, *, name: str) -> None:
    if _ID_PATTERN.fullmatch(value) is None:
        msg = f"{name} must match {_ID_PATTERN.pattern!r}"
        raise ValueError(msg)


def _validate_time(value: datetime, *, name: str) -> None:
    if value.utcoffset() is None:
        msg = f"{name} must be timezone-aware"
        raise ValueError(msg)


def freeze_metadata(metadata: Mapping[str, str]) -> Mapping[str, str]:
    """Validate and freeze bounded, secret-free metadata."""
    frozen = dict(metadata)
    if len(frozen) > _MAX_METADATA_ITEMS:
        msg = f"metadata must contain at most {_MAX_METADATA_ITEMS} items"
        raise ValueError(msg)
    for key, value in frozen.items():
        if _METADATA_KEY_PATTERN.fullmatch(key) is None:
            msg = f"metadata key must match {_METADATA_KEY_PATTERN.pattern!r}"
            raise ValueError(msg)
        if not value or value != value.strip() or len(value) > _MAX_METADATA_VALUE_LENGTH:
            msg = f"metadata values must be trimmed and at most {_MAX_METADATA_VALUE_LENGTH} characters"
            raise ValueError(msg)
    return MappingProxyType(frozen)


@dataclass(frozen=True, slots=True)
class ServiceApplication:
    """Registered integration and ownership aggregate."""

    id: str
    status: EntityStatus
    environment: str
    owner_ref: str
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate stable public fields."""
        _validate_id(self.id, name="application id")
        _validate_id(self.owner_ref, name="owner_ref")
        if _ENVIRONMENT_PATTERN.fullmatch(self.environment) is None:
            msg = f"environment must match {_ENVIRONMENT_PATTERN.pattern!r}"
            raise ValueError(msg)
        object.__setattr__(self, "metadata", freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class MachinePrincipal:
    """Registered non-human security identity."""

    id: str
    application_id: str
    ref: PrincipalRef
    status: EntityStatus
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate public IDs and supported principal classification."""
        _validate_id(self.id, name="principal id")
        _validate_id(self.application_id, name="application_id")
        if self.ref.kind == "human":
            msg = "authweave-workload principals cannot use kind='human'"
            raise ValueError(msg)
        object.__setattr__(self, "metadata", freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class MachineCredential:
    """Registered public X.509 credential identity and constraints."""

    id: str
    principal_id: str
    status: CredentialStatus
    certificate_thumbprint: str
    trust_anchor: str
    scopes: tuple[str, ...]
    audiences: tuple[str, ...]
    environment: str
    not_before: datetime
    expires_at: datetime
    subject_dn: str
    issuer_dn: str
    serial_number: str
    rotation_of: str | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    last_used_at: datetime | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate bounded credential identity and temporal constraints."""
        _validate_id(self.id, name="credential id")
        _validate_id(self.principal_id, name="principal_id")
        _validate_id(self.trust_anchor, name="trust_anchor")
        if self.rotation_of is not None:
            _validate_id(self.rotation_of, name="rotation_of")
        if _THUMBPRINT_PATTERN.fullmatch(self.certificate_thumbprint) is None:
            msg = "certificate_thumbprint must be an unpadded base64url SHA-256 digest"
            raise ValueError(msg)
        if _ENVIRONMENT_PATTERN.fullmatch(self.environment) is None:
            msg = f"environment must match {_ENVIRONMENT_PATTERN.pattern!r}"
            raise ValueError(msg)
        for name in ("not_before", "expires_at", "revoked_at", "last_used_at"):
            value = getattr(self, name)
            if value is not None:
                _validate_time(value, name=name)
        if self.not_before >= self.expires_at:
            msg = "credential not_before must be earlier than expires_at"
            raise ValueError(msg)
        if self.status is CredentialStatus.REVOKED:
            if self.revoked_at is None or not self.revocation_reason:
                msg = "revoked credentials require revoked_at and revocation_reason"
                raise ValueError(msg)
        elif self.revoked_at is not None or self.revocation_reason is not None:
            msg = "non-revoked credentials cannot carry revocation metadata"
            raise ValueError(msg)
        object.__setattr__(self, "scopes", _freeze_values(self.scopes, name="scopes"))
        object.__setattr__(self, "audiences", _freeze_values(self.audiences, name="audiences"))
        object.__setattr__(self, "metadata", freeze_metadata(self.metadata))


def _freeze_values(values: tuple[str, ...], *, name: str) -> tuple[str, ...]:
    frozen = tuple(values)
    if len(frozen) > _MAX_CONSTRAINT_VALUES or len(frozen) != len(set(frozen)):
        msg = f"{name} must contain at most {_MAX_CONSTRAINT_VALUES} unique values"
        raise ValueError(msg)
    for value in frozen:
        _validate_id(value, name=name)
    return frozen


@dataclass(frozen=True, slots=True)
class ResolvedMachineIdentity:
    """Atomic application, principal, and credential lookup result."""

    application: ServiceApplication
    principal: MachinePrincipal
    credential: MachineCredential


@dataclass(frozen=True, slots=True)
class WorkloadPage[PAGE_ITEM]:
    """One deterministic bounded page of workload inventory results."""

    items: tuple[PAGE_ITEM, ...]
    total: int
    limit: int
    offset: int

    def __post_init__(self) -> None:
        """Reject internally inconsistent page metadata."""
        if self.total < 0 or self.limit < 1 or self.offset < 0 or len(self.items) > self.limit:
            msg = "workload page metadata is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True, init=False)
class CertificateMetadata:
    """Opaque public-certificate facts produced by an AuthWeave validator."""

    thumbprint: str
    trust_anchor: str
    not_before: datetime
    not_after: datetime
    subject_dn: str
    issuer_dn: str
    serial_number: str

    def __new__(cls) -> Self:
        """Prevent construction outside the certificate validator."""
        msg = "CertificateMetadata is created by AuthWeave certificate validators"
        raise TypeError(msg)

    def __post_init__(self) -> None:
        """Reuse credential validation through bounded primitive checks."""
        if _THUMBPRINT_PATTERN.fullmatch(self.thumbprint) is None:
            msg = "thumbprint must be an unpadded base64url SHA-256 digest"
            raise ValueError(msg)
        _validate_id(self.trust_anchor, name="trust_anchor")
        _validate_time(self.not_before, name="not_before")
        _validate_time(self.not_after, name="not_after")
        if self.not_before >= self.not_after:
            msg = "not_before must be earlier than not_after"
            raise ValueError(msg)
        for name in ("subject_dn", "issuer_dn", "serial_number"):
            value = getattr(self, name)
            if not value or len(value) > _MAX_CERTIFICATE_TEXT_LENGTH:
                msg = f"{name} must be non-empty and at most {_MAX_CERTIFICATE_TEXT_LENGTH} characters"
                raise ValueError(msg)


def _certificate_metadata(  # ruff: ignore[too-many-arguments]
    *,
    thumbprint: str,
    trust_anchor: str,
    not_before: datetime,
    not_after: datetime,
    subject_dn: str,
    issuer_dn: str,
    serial_number: str,
) -> CertificateMetadata:
    certificate = object.__new__(CertificateMetadata)
    for name, value in locals().items():
        if name != "certificate":
            object.__setattr__(certificate, name, value)  # ruff: ignore[unnecessary-dunder-call]
    certificate.__post_init__()
    return certificate


__all__ = (
    "CertificateMetadata",
    "CredentialStatus",
    "EntityStatus",
    "MachineCredential",
    "MachinePrincipal",
    "ResolvedMachineIdentity",
    "ServiceApplication",
    "WorkloadPage",
    "freeze_metadata",
)
