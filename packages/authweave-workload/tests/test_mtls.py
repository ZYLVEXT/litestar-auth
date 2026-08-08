"""X.509 registration validation tests."""

from __future__ import annotations

import base64
import builtins
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast

import pytest
from authweave_workload import mtls as mtls_module
from authweave_workload.mtls import (
    AttestedCertificateValidationPolicy,
    CertificateValidationError,
    CertificateValidationPolicy,
    ProviderCertificateAttestation,
    validate_attested_certificate,
    validate_public_certificate,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_THUMBPRINT_LENGTH = 43


pytestmark = pytest.mark.unit


def test_valid_client_certificate_is_canonicalized_without_private_material() -> None:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    ca = (
        x509
        .CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "workload")])
    leaf = (
        x509
        .CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("workload.test")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)
    policy = CertificateValidationPolicy(
        trust_anchor="test-root",
        trust_anchor_certificates=(ca.public_bytes(serialization.Encoding.PEM),),
        revocation_checked_at=now,
    )

    metadata = validate_public_certificate(leaf_pem, policy=policy, verification_time=now)

    assert metadata.trust_anchor == "test-root"
    assert metadata.subject_dn == "CN=workload"
    assert len(metadata.thumbprint) == _THUMBPRINT_LENGTH
    assert not hasattr(metadata, "certificate")
    with pytest.raises(TypeError):
        type(metadata)()

    short_lifetime_policy = CertificateValidationPolicy(
        trust_anchor="test-root",
        trust_anchor_certificates=policy.trust_anchor_certificates,
        revocation_checked_at=now,
        maximum_certificate_lifetime=timedelta(minutes=30),
    )
    with pytest.raises(CertificateValidationError, match="lifetime"):
        validate_public_certificate(leaf_pem, policy=short_lifetime_policy, verification_time=now)

    private_blob = leaf_pem + leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(CertificateValidationError, match="private key"):
        validate_public_certificate(private_blob, policy=policy, verification_time=now)

    revoked = CertificateValidationPolicy(
        trust_anchor="test-root",
        trust_anchor_certificates=policy.trust_anchor_certificates,
        revocation_checked_at=now,
        revoked_serial_numbers=frozenset({leaf.serial_number}),
    )
    with pytest.raises(CertificateValidationError, match="revoked"):
        validate_public_certificate(leaf_pem, policy=revoked, verification_time=now)
    other_key = ec.generate_private_key(ec.SECP256R1())
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other Root")])
    other_ca = (
        x509
        .CertificateBuilder()
        .subject_name(other_name)
        .issuer_name(other_name)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(other_key, hashes.SHA256())
    )
    invalid_chain = CertificateValidationPolicy(
        trust_anchor="other-ca",
        trust_anchor_certificates=(other_ca.public_bytes(serialization.Encoding.PEM),),
        revocation_checked_at=now,
    )
    with pytest.raises(CertificateValidationError, match="validation failed"):
        validate_public_certificate(leaf_pem, policy=invalid_chain, verification_time=now)


def test_provider_attested_certificate_is_reconciled_without_exported_ca() -> None:
    now, leaf, leaf_pem = _attested_leaf()
    attestation = _provider_attestation(leaf, now=now)
    policy = _attested_policy()

    metadata = validate_attested_certificate(
        leaf_pem,
        attestation=attestation,
        policy=policy,
        verification_time=now,
    )
    der_metadata = validate_attested_certificate(
        leaf.public_bytes(serialization.Encoding.DER),
        attestation=attestation,
        policy=policy,
        verification_time=now,
    )

    assert metadata == der_metadata
    assert metadata.thumbprint == attestation.certificate_thumbprint
    assert metadata.trust_anchor == "managed-ca-1"
    assert metadata.subject_dn == "CN=managed-workload"


def test_provider_attested_certificate_rejects_untrusted_or_stale_evidence() -> None:
    now, leaf, leaf_pem = _attested_leaf()
    attestation = _provider_attestation(leaf, now=now)
    policy = _attested_policy()

    cases = (
        (replace(attestation, provider="other-provider"), policy, now, "not trusted"),
        (replace(attestation, trust_anchor="other-ca"), policy, now, "not trusted"),
        (replace(attestation, attested_at=now + timedelta(minutes=6)), policy, now, "future"),
        (replace(attestation, attested_at=now - timedelta(minutes=6)), policy, now, "stale"),
        (
            replace(attestation, certificate_thumbprint="A" * _THUMBPRINT_LENGTH),
            policy,
            now,
            "fingerprint",
        ),
        (replace(attestation, not_before=attestation.not_before - timedelta(minutes=6)), policy, now, "dates"),
        (attestation, policy, datetime(2026, 1, 1), "timezone"),
    )
    for evidence, validation_policy, verification_time, message in cases:
        with pytest.raises(CertificateValidationError, match=message):
            validate_attested_certificate(
                leaf_pem,
                attestation=evidence,
                policy=validation_policy,
                verification_time=verification_time,
            )


def test_provider_attested_certificate_enforces_leaf_and_encoding_profile() -> None:
    now, leaf, leaf_pem = _attested_leaf()
    attestation = _provider_attestation(leaf, now=now)

    with pytest.raises(CertificateValidationError, match="exactly one"):
        validate_attested_certificate(
            leaf_pem + leaf_pem,
            attestation=attestation,
            policy=_attested_policy(),
            verification_time=now,
        )
    with pytest.raises(CertificateValidationError, match="private key"):
        validate_attested_certificate(
            leaf_pem + b"PRIVATE KEY",
            attestation=attestation,
            policy=_attested_policy(),
            verification_time=now,
        )
    with pytest.raises(CertificateValidationError, match="encoding"):
        validate_attested_certificate(
            b"not-a-certificate",
            attestation=attestation,
            policy=_attested_policy(),
            verification_time=now,
        )
    with pytest.raises(CertificateValidationError, match="encoding"):
        validate_attested_certificate(
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
            attestation=attestation,
            policy=_attested_policy(),
            verification_time=now,
        )
    with pytest.raises(CertificateValidationError, match="lifetime"):
        validate_attested_certificate(
            leaf_pem,
            attestation=attestation,
            policy=replace(_attested_policy(), maximum_certificate_lifetime=timedelta(minutes=30)),
            verification_time=now,
        )
    with pytest.raises(CertificateValidationError, match="currently usable"):
        validate_attested_certificate(
            leaf_pem,
            attestation=replace(attestation, attested_at=leaf.not_valid_after_utc),
            policy=_attested_policy(),
            verification_time=leaf.not_valid_after_utc,
        )

    for include_basic_constraints, is_ca, critical, message in (
        (False, False, True, "BasicConstraints"),
        (True, False, False, "CA=false"),
        (True, True, True, "CA=false"),
    ):
        profile_now, profile_leaf, profile_pem = _attested_leaf(
            include_basic_constraints=include_basic_constraints,
            basic_constraints_ca=is_ca,
            basic_constraints_critical=critical,
        )
        with pytest.raises(CertificateValidationError, match=message):
            validate_attested_certificate(
                profile_pem,
                attestation=_provider_attestation(profile_leaf, now=profile_now),
                policy=_attested_policy(),
                verification_time=profile_now,
            )


def test_provider_attested_certificate_normalizes_unexpected_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now, leaf, leaf_pem = _attested_leaf()

    def fail_validation(*_: object, **__: object) -> None:
        msg = "unexpected certificate API value"
        raise TypeError(msg)

    monkeypatch.setattr(mtls_module, "_validate_attested_leaf", fail_validation)

    with pytest.raises(CertificateValidationError, match="certificate validation failed"):
        validate_attested_certificate(
            leaf_pem,
            attestation=_provider_attestation(leaf, now=now),
            policy=_attested_policy(),
            verification_time=now,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"provider": "bad provider"},
        {"trust_anchor": "bad anchor"},
        {"certificate_thumbprint": "invalid"},
        {"not_before": datetime(2026, 1, 1)},
        {"not_after": datetime(2026, 1, 1)},
        {"attested_at": datetime(2026, 1, 1)},
        {"not_after": datetime(2026, 1, 1, tzinfo=UTC)},
        {"status": "revoked"},
    ],
)
def test_provider_attestation_rejects_invalid_evidence(changes: dict[str, object]) -> None:
    now, leaf, _ = _attested_leaf()
    values: dict[str, object] = {
        "provider": "cloudflare",
        "trust_anchor": "managed-ca-1",
        "certificate_thumbprint": _thumbprint(leaf),
        "not_before": leaf.not_valid_before_utc,
        "not_after": leaf.not_valid_after_utc,
        "attested_at": now,
        "status": "active",
    }
    values.update(changes)
    with pytest.raises(ValueError, match=r".+"):
        ProviderCertificateAttestation(**values)


@pytest.mark.parametrize(
    "changes",
    [
        {"provider": "bad provider"},
        {"trust_anchor": "bad anchor"},
        {"maximum_attestation_age": timedelta(0)},
        {"maximum_certificate_lifetime": timedelta(0)},
        {"maximum_clock_skew": timedelta(microseconds=-1)},
    ],
)
def test_attested_certificate_policy_rejects_invalid_values(changes: dict[str, object]) -> None:
    values: dict[str, object] = {"provider": "cloudflare", "trust_anchor": "managed-ca-1"}
    values.update(changes)
    with pytest.raises(ValueError, match=r".+"):
        AttestedCertificateValidationPolicy(**values)  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize(
    "options",
    [
        {"trust_anchor_certificates": ()},
        {"revocation_checked_at": datetime(2026, 1, 1)},
        {"maximum_revocation_age": timedelta(0)},
        {"maximum_certificate_lifetime": timedelta(0)},
    ],
)
def test_certificate_policy_requires_fresh_explicit_trust(options: dict[str, object]) -> None:
    values: dict[str, object] = {
        "revocation_checked_at": datetime.now(UTC),
        "trust_anchor": "ca",
        "trust_anchor_certificates": (b"certificate",),
    }
    values.update(options)
    with pytest.raises(ValueError, match=r".+"):
        CertificateValidationPolicy(**values)  # ty: ignore[invalid-argument-type]


def test_certificate_validation_rejects_encoding_time_and_stale_revocation() -> None:
    now = datetime.now(UTC)
    policy = CertificateValidationPolicy(
        trust_anchor="ca",
        trust_anchor_certificates=(b"not-a-certificate",),
        revocation_checked_at=now,
    )
    with pytest.raises(CertificateValidationError, match="encoding"):
        validate_public_certificate(b"not-a-certificate", policy=policy, verification_time=now)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
    ca = (
        x509
        .CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    for checked_at, verification_time, message in (
        (now, datetime(2026, 1, 1), "timezone"),
        (now - timedelta(hours=1), now, "stale"),
        (now + timedelta(seconds=1), now, "stale"),
    ):
        checked_policy = CertificateValidationPolicy(
            trust_anchor="ca",
            trust_anchor_certificates=(ca_pem,),
            revocation_checked_at=checked_at,
        )
        with pytest.raises(CertificateValidationError, match=message):
            validate_public_certificate(ca_pem, policy=checked_policy, verification_time=verification_time)


class _Extensions:
    def __init__(
        self,
        *,
        digital_signature: bool = True,
        client_auth: bool = True,
        missing_key_usage: bool = False,
        missing_extended_key_usage: bool = False,
    ) -> None:
        self.digital_signature = digital_signature
        self.client_auth = client_auth
        self.missing_key_usage = missing_key_usage
        self.missing_extended_key_usage = missing_extended_key_usage

    def get_extension_for_class(self, extension_type: type[object]) -> object:
        if (extension_type is x509.KeyUsage and self.missing_key_usage) or (
            extension_type is x509.ExtendedKeyUsage and self.missing_extended_key_usage
        ):
            message = "missing"
            raise x509.ExtensionNotFound(message, x509.ObjectIdentifier("1.2.3"))
        if extension_type is x509.KeyUsage:
            return SimpleNamespace(value=SimpleNamespace(digital_signature=self.digital_signature))
        values = [ExtendedKeyUsageOID.CLIENT_AUTH] if self.client_auth else []
        return SimpleNamespace(value=values)


class _Certificate:
    def __init__(
        self,
        key: object,
        *,
        signature_hash: object = hashes.SHA256(),
        extensions: _Extensions | None = None,
    ) -> None:
        self.key = key
        self.signature_hash_algorithm = signature_hash
        self.extensions = _Extensions() if extensions is None else extensions

    def public_key(self) -> object:
        return self.key


@pytest.mark.parametrize(
    ("certificate", "message"),
    [
        (_Certificate(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()), "3072"),
        (_Certificate(ec.generate_private_key(ec.SECP521R1()).public_key()), "P-256"),
        (_Certificate(ed25519.Ed25519PrivateKey.generate().public_key(), signature_hash=None), "not supported"),
        (_Certificate(ec.generate_private_key(ec.SECP256R1()).public_key(), signature_hash=hashes.SHA1()), "hash"),
        (
            _Certificate(
                ec.generate_private_key(ec.SECP256R1()).public_key(),
                extensions=_Extensions(missing_extended_key_usage=True),
            ),
            "clientAuth",
        ),
        (
            _Certificate(
                ec.generate_private_key(ec.SECP256R1()).public_key(),
                extensions=_Extensions(digital_signature=False),
            ),
            "digital",
        ),
        (
            _Certificate(
                ec.generate_private_key(ec.SECP256R1()).public_key(),
                extensions=_Extensions(client_auth=False),
            ),
            "clientAuth",
        ),
    ],
)
def test_leaf_certificate_profile_negative_matrix(certificate: _Certificate, message: str) -> None:
    with pytest.raises(CertificateValidationError, match=message):
        mtls_module._validate_leaf_profile(
            cast("object", certificate),
            mtls_module._load_cryptography(),
        )


def test_leaf_certificate_profile_accepts_strong_rsa() -> None:
    certificate = _Certificate(rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key())
    mtls_module._validate_leaf_profile(cast("object", certificate), mtls_module._load_cryptography())


def test_leaf_certificate_profile_accepts_omitted_key_usage() -> None:
    certificate = _Certificate(
        ec.generate_private_key(ec.SECP256R1()).public_key(),
        extensions=_Extensions(missing_key_usage=True),
    )
    mtls_module._validate_leaf_profile(cast("object", certificate), mtls_module._load_cryptography())


def _attested_leaf(
    *,
    include_basic_constraints: bool = True,
    basic_constraints_ca: bool = False,
    basic_constraints_critical: bool = True,
) -> tuple[datetime, x509.Certificate, bytes]:
    now = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Opaque Managed CA")])
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "managed-workload")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    )
    if include_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=basic_constraints_ca, path_length=None),
            critical=basic_constraints_critical,
        )
    leaf = builder.sign(ca_key, hashes.SHA256())
    return now, leaf, leaf.public_bytes(serialization.Encoding.PEM)


def _thumbprint(certificate: x509.Certificate) -> str:
    return base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256())).rstrip(b"=").decode("ascii")


def _provider_attestation(certificate: x509.Certificate, *, now: datetime) -> ProviderCertificateAttestation:
    return ProviderCertificateAttestation(
        provider="cloudflare",
        trust_anchor="managed-ca-1",
        certificate_thumbprint=_thumbprint(certificate),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        attested_at=now,
        status="active",
    )


def _attested_policy() -> AttestedCertificateValidationPolicy:
    return AttestedCertificateValidationPolicy(
        provider="cloudflare",
        trust_anchor="managed-ca-1",
    )


def test_mtls_optional_dependency_error_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def reject(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("cryptography"):
            raise ImportError
        return original_import(name, *args, **kwargs)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(builtins, "__import__", reject)
    with pytest.raises(ImportError, match=r"\[mtls\]"):
        mtls_module._load_cryptography()
