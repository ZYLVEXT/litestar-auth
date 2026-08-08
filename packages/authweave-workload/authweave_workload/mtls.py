"""X.509 public-certificate validation for workload registration."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from authweave_workload.models import CertificateMetadata, _certificate_metadata

if TYPE_CHECKING:
    from collections.abc import Iterable


class CertificateValidationError(ValueError):
    """Raised when public certificate material fails the release security profile."""


_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_THUMBPRINT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


@dataclass(frozen=True, slots=True)
class CertificateValidationPolicy:
    """Configured trust material for one registration environment."""

    trust_anchor: str
    trust_anchor_certificates: tuple[bytes, ...]
    revocation_checked_at: datetime
    revoked_serial_numbers: frozenset[int] = frozenset()
    maximum_revocation_age: timedelta = timedelta(minutes=15)
    maximum_certificate_lifetime: timedelta = timedelta(days=90)

    def __post_init__(self) -> None:
        """Require explicit trust material.

        Raises:
            ValueError: If no trust anchor certificate is configured.
        """
        if not self.trust_anchor_certificates:
            msg = "at least one trust anchor certificate is required"
            raise ValueError(msg)
        if self.revocation_checked_at.utcoffset() is None:
            msg = "revocation_checked_at must be timezone-aware"
            raise ValueError(msg)
        if self.maximum_revocation_age <= timedelta(0):
            msg = "maximum_revocation_age must be positive"
            raise ValueError(msg)
        if self.maximum_certificate_lifetime <= timedelta(0):
            msg = "maximum_certificate_lifetime must be positive"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ProviderCertificateAttestation:
    """Fresh public-certificate facts from an authenticated provider control plane.

    Applications must construct this object only from a successful, authenticated response from
    the pinned certificate provider. It is evidence of provider issuance, not a PKIX path.
    """

    provider: str
    trust_anchor: str
    certificate_thumbprint: str
    not_before: datetime
    not_after: datetime
    attested_at: datetime
    status: str

    def __post_init__(self) -> None:
        """Reject invalid provider evidence.

        Raises:
            ValueError: If evidence is unbounded, inactive, or temporally invalid.
        """
        _validate_identifier(self.provider, name="provider")
        _validate_identifier(self.trust_anchor, name="trust_anchor")
        if _THUMBPRINT_PATTERN.fullmatch(self.certificate_thumbprint) is None:
            msg = "certificate_thumbprint must be an unpadded base64url SHA-256 digest"
            raise ValueError(msg)
        for name in ("not_before", "not_after", "attested_at"):
            if getattr(self, name).utcoffset() is None:
                msg = f"{name} must be timezone-aware"
                raise ValueError(msg)
        if self.not_before >= self.not_after:
            msg = "not_before must be earlier than not_after"
            raise ValueError(msg)
        if self.status != "active":
            msg = "provider certificate status must be active"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class AttestedCertificateValidationPolicy:
    """Local policy for one authenticated external certificate provider."""

    provider: str
    trust_anchor: str
    maximum_attestation_age: timedelta = timedelta(minutes=5)
    maximum_certificate_lifetime: timedelta = timedelta(days=90)
    maximum_clock_skew: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        """Require a pinned provider boundary.

        Raises:
            ValueError: If an identifier or bounded policy interval is invalid.
        """
        _validate_identifier(self.provider, name="provider")
        _validate_identifier(self.trust_anchor, name="trust_anchor")
        if self.maximum_attestation_age <= timedelta(0):
            msg = "maximum_attestation_age must be positive"
            raise ValueError(msg)
        if self.maximum_certificate_lifetime <= timedelta(0):
            msg = "maximum_certificate_lifetime must be positive"
            raise ValueError(msg)
        if self.maximum_clock_skew < timedelta(0):
            msg = "maximum_clock_skew cannot be negative"
            raise ValueError(msg)


def validate_public_certificate(
    certificate: bytes,
    *,
    policy: CertificateValidationPolicy,
    intermediates: Iterable[bytes] = (),
    verification_time: datetime | None = None,
) -> CertificateMetadata:
    """Validate a CA-issued client certificate and return only safe public facts.

    Returns:
        Canonical certificate metadata. Certificate bytes are not retained.

    Raises:
        CertificateValidationError: If parsing, path validation, key policy, usage,
            validity, or revocation checks fail.
        ImportError: If the ``mtls`` extra is not installed.
    """
    if b"PRIVATE KEY" in certificate:
        raise CertificateValidationError("private key material is not accepted")
    crypto = _load_cryptography()
    x509 = crypto["x509"]
    try:
        leaf = _load_certificate(x509, certificate)
        anchors = [_load_certificate(x509, value) for value in policy.trust_anchor_certificates]
        untrusted = [_load_certificate(x509, value) for value in intermediates]
        now = datetime.now(UTC) if verification_time is None else verification_time
        if now.utcoffset() is None:
            raise CertificateValidationError("verification_time must be timezone-aware")
        if policy.revocation_checked_at > now or now - policy.revocation_checked_at > policy.maximum_revocation_age:
            raise CertificateValidationError("certificate revocation information is stale")
        verifier = crypto["PolicyBuilder"]().store(crypto["Store"](anchors)).time(now).build_client_verifier()
        verifier.verify(leaf, untrusted)
        _validate_leaf_profile(leaf, crypto)
        if leaf.not_valid_after_utc - leaf.not_valid_before_utc > policy.maximum_certificate_lifetime:
            raise CertificateValidationError("certificate lifetime exceeds policy")
    except CertificateValidationError:
        raise
    except (TypeError, ValueError, crypto["VerificationError"]) as exc:
        raise CertificateValidationError("certificate validation failed") from exc
    if leaf.serial_number in policy.revoked_serial_numbers:
        raise CertificateValidationError("certificate is revoked")
    return _metadata_from_leaf(leaf, trust_anchor=policy.trust_anchor, encoding=crypto["Encoding"])


def validate_attested_certificate(
    certificate: bytes,
    *,
    attestation: ProviderCertificateAttestation,
    policy: AttestedCertificateValidationPolicy,
    verification_time: datetime | None = None,
) -> CertificateMetadata:
    """Validate a leaf against fresh evidence from a pinned external provider.

    This path is for managed certificate authorities whose authenticated control plane returns the
    issued leaf and its digest but intentionally does not export the CA certificate. It validates
    the leaf profile and reconciles it with that provider evidence; it does not perform or claim
    local PKIX path validation.

    Returns:
        Canonical certificate metadata. Certificate and attestation bytes are not retained.

    Raises:
        CertificateValidationError: If parsing, provider binding, freshness, profile, validity,
            fingerprint, or attested dates fail.
        ImportError: If the ``mtls`` extra is not installed.
    """
    if b"PRIVATE KEY" in certificate:
        raise CertificateValidationError("private key material is not accepted")
    crypto = _load_cryptography()
    x509 = crypto["x509"]
    try:
        leaf = _load_single_certificate(x509, certificate)
        now = datetime.now(UTC) if verification_time is None else verification_time
        if now.utcoffset() is None:
            raise CertificateValidationError("verification_time must be timezone-aware")
        _validate_provider_attestation(attestation, policy=policy, verification_time=now)
        _validate_attested_leaf(
            leaf,
            attestation=attestation,
            policy=policy,
            verification_time=now,
            crypto=crypto,
        )
    except CertificateValidationError:
        raise
    except (TypeError, ValueError) as exc:
        raise CertificateValidationError("certificate validation failed") from exc
    return _metadata_from_leaf(leaf, trust_anchor=policy.trust_anchor, encoding=crypto["Encoding"])


def _load_cryptography() -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509 import ExtendedKeyUsageOID
        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
    except ImportError as exc:
        msg = "X.509 validation requires the 'authweave-workload[mtls]' extra."
        raise ImportError(msg) from exc
    return {
        "Encoding": Encoding,
        "ExtendedKeyUsageOID": ExtendedKeyUsageOID,
        "PolicyBuilder": PolicyBuilder,
        "Store": Store,
        "VerificationError": VerificationError,
        "ec": ec,
        "rsa": rsa,
        "x509": x509,
    }


def _load_certificate(x509: Any, value: bytes) -> Any:
    try:
        if b"-----BEGIN CERTIFICATE-----" in value:
            return x509.load_pem_x509_certificate(value)
        return x509.load_der_x509_certificate(value)
    except ValueError as exc:
        raise CertificateValidationError("certificate encoding is invalid") from exc


def _load_single_certificate(x509: Any, value: bytes) -> Any:
    if b"-----BEGIN CERTIFICATE-----" not in value:
        return _load_certificate(x509, value)
    try:
        certificates = x509.load_pem_x509_certificates(value)
    except ValueError as exc:
        raise CertificateValidationError("certificate encoding is invalid") from exc
    if len(certificates) != 1:
        raise CertificateValidationError("exactly one public certificate is required")
    return certificates[0]


def _validate_leaf_profile(certificate: Any, crypto: dict[str, Any]) -> None:
    x509 = crypto["x509"]
    public_key = certificate.public_key()
    if isinstance(public_key, crypto["rsa"].RSAPublicKey):
        if public_key.key_size < 3072:
            raise CertificateValidationError("RSA certificate keys must be at least 3072 bits")
    elif isinstance(public_key, crypto["ec"].EllipticCurvePublicKey):
        if public_key.curve.name not in {"secp256r1", "secp384r1"}:
            raise CertificateValidationError("ECDSA certificate keys must use P-256 or P-384")
    else:
        raise CertificateValidationError("certificate public key type is not supported")

    signature_hash = certificate.signature_hash_algorithm
    if signature_hash is None or signature_hash.name.lower() in {"md5", "sha1"}:
        raise CertificateValidationError("certificate signature hash is not supported")
    try:
        extended_key_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("client certificate must include clientAuth EKU") from exc
    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.digital_signature:
        raise CertificateValidationError("client certificate must permit digital signatures")
    if crypto["ExtendedKeyUsageOID"].CLIENT_AUTH not in extended_key_usage:
        raise CertificateValidationError("client certificate must include clientAuth EKU")


def _validate_attested_leaf_profile(certificate: Any, crypto: dict[str, Any]) -> None:
    _validate_leaf_profile(certificate, crypto)
    x509 = crypto["x509"]
    try:
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("client certificate must include BasicConstraints") from exc
    if not basic_constraints.critical or basic_constraints.value.ca:
        raise CertificateValidationError("client certificate must be a critical CA=false end entity")


def _validate_provider_attestation(
    attestation: ProviderCertificateAttestation,
    *,
    policy: AttestedCertificateValidationPolicy,
    verification_time: datetime,
) -> None:
    if attestation.provider != policy.provider or attestation.trust_anchor != policy.trust_anchor:
        raise CertificateValidationError("certificate provider attestation is not trusted")
    if attestation.attested_at > verification_time + policy.maximum_clock_skew:
        raise CertificateValidationError("certificate provider attestation is from the future")
    if verification_time - attestation.attested_at > policy.maximum_attestation_age:
        raise CertificateValidationError("certificate provider attestation is stale")


def _validate_attested_leaf(
    certificate: Any,
    *,
    attestation: ProviderCertificateAttestation,
    policy: AttestedCertificateValidationPolicy,
    verification_time: datetime,
    crypto: dict[str, Any],
) -> None:
    _validate_attested_leaf_profile(certificate, crypto)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if not_before > verification_time + policy.maximum_clock_skew or not_after <= verification_time:
        raise CertificateValidationError("certificate validity window is not currently usable")
    if not_after - not_before > policy.maximum_certificate_lifetime + policy.maximum_clock_skew:
        raise CertificateValidationError("certificate lifetime exceeds policy")
    if (
        abs(attestation.not_before - not_before) > policy.maximum_clock_skew
        or abs(attestation.not_after - not_after) > policy.maximum_clock_skew
    ):
        raise CertificateValidationError("certificate dates disagree with provider attestation")
    thumbprint = _certificate_thumbprint(certificate, encoding=crypto["Encoding"])
    if not hmac.compare_digest(thumbprint, attestation.certificate_thumbprint):
        raise CertificateValidationError("certificate fingerprint disagrees with provider attestation")


def _certificate_thumbprint(certificate: Any, *, encoding: Any) -> str:
    der = certificate.public_bytes(encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("ascii")


def _metadata_from_leaf(certificate: Any, *, trust_anchor: str, encoding: Any) -> CertificateMetadata:
    return _certificate_metadata(
        thumbprint=_certificate_thumbprint(certificate, encoding=encoding),
        trust_anchor=trust_anchor,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        subject_dn=certificate.subject.rfc4514_string(),
        issuer_dn=certificate.issuer.rfc4514_string(),
        serial_number=format(certificate.serial_number, "x"),
    )


def _validate_identifier(value: str, *, name: str) -> None:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        msg = f"{name} must match {_IDENTIFIER_PATTERN.pattern!r}"
        raise ValueError(msg)


__all__ = (
    "AttestedCertificateValidationPolicy",
    "CertificateValidationError",
    "CertificateValidationPolicy",
    "ProviderCertificateAttestation",
    "validate_attested_certificate",
    "validate_public_certificate",
)
