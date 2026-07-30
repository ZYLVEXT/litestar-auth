"""X.509 registration validation tests."""

from __future__ import annotations

import builtins
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast

import pytest
from authweave_workload import mtls as mtls_module
from authweave_workload.mtls import (
    CertificateValidationError,
    CertificateValidationPolicy,
    validate_public_certificate,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_THUMBPRINT_LENGTH = 43


def test_valid_client_certificate_is_canonicalized_without_private_material() -> None:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    ca = (
        x509.CertificateBuilder()
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
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
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
        x509.CertificateBuilder()
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
        x509.CertificateBuilder()
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
    def __init__(self, *, digital_signature: bool = True, client_auth: bool = True, missing: bool = False) -> None:
        self.digital_signature = digital_signature
        self.client_auth = client_auth
        self.missing = missing

    def get_extension_for_class(self, extension_type: type[object]) -> object:
        if self.missing:
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
            _Certificate(ec.generate_private_key(ec.SECP256R1()).public_key(), extensions=_Extensions(missing=True)),
            "required",
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


def test_mtls_optional_dependency_error_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def reject(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("cryptography"):
            raise ImportError
        return original_import(name, *args, **kwargs)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(builtins, "__import__", reject)
    with pytest.raises(ImportError, match=r"\[mtls\]"):
        mtls_module._load_cryptography()
