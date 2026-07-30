"""X.509 public-certificate validation for workload registration."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from authweave_workload.models import CertificateMetadata, _certificate_metadata

if TYPE_CHECKING:
    from collections.abc import Iterable


class CertificateValidationError(ValueError):
    """Raised when public certificate material fails the release security profile."""


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
    der = leaf.public_bytes(crypto["Encoding"].DER)
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("ascii")
    return _certificate_metadata(
        thumbprint=thumbprint,
        trust_anchor=policy.trust_anchor,
        not_before=leaf.not_valid_before_utc,
        not_after=leaf.not_valid_after_utc,
        subject_dn=leaf.subject.rfc4514_string(),
        issuer_dn=leaf.issuer.rfc4514_string(),
        serial_number=format(leaf.serial_number, "x"),
    )


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
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended_key_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("client certificate key usage extensions are required") from exc
    if not key_usage.digital_signature:
        raise CertificateValidationError("client certificate must permit digital signatures")
    if crypto["ExtendedKeyUsageOID"].CLIENT_AUTH not in extended_key_usage:
        raise CertificateValidationError("client certificate must include clientAuth EKU")


__all__ = (
    "CertificateValidationError",
    "CertificateValidationPolicy",
    "validate_public_certificate",
)
