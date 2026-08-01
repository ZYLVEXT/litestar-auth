"""SPIFFE ID, X.509-SVID validator, and provider behavior tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

import pytest
from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    PrincipalRef,
    RequestView,
    SpiffePeerEvidence,
    Unavailable,
)
from authweave_workload.spiffe import (
    SpiffeBundleSnapshot,
    SpiffeID,
    SpiffePolicy,
    SPIFFEProvider,
    SpiffeResolvedPrincipal,
    SpiffeResolverUnavailableError,
    SpiffeValidationError,
    SpiffeX509SvidValidator,
    StaticSpiffeBundleSource,
    parse_spiffe_id,
    project_spiffe_peer,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

if TYPE_CHECKING:
    from authweave_workload.events import SecurityEvent

_NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
_DOMAIN = "example.org"
_SPIFFE = f"spiffe://{_DOMAIN}/payments/worker"
_BOUNDARY = "mesh-local"


def _ca_and_leaf(
    *,
    spiffe_id: str = _SPIFFE,
    ca: bool = False,
    key_cert_sign: bool = False,
    digital_signature: bool = True,
    key_usage_critical: bool = True,
    extra_uris: tuple[str, ...] = (),
    lifetime: timedelta = timedelta(hours=1),
) -> tuple[bytes, bytes]:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca_cert = (
        x509
        .CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
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
    uris = (spiffe_id, *extra_uris)
    ski = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    builder = (
        x509
        .CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + lifetime)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=key_usage_critical,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri) for uri in uris]),
            critical=False,
        )
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
    )
    leaf = builder.sign(ca_key, hashes.SHA256())
    return (
        ca_cert.public_bytes(Encoding.PEM),
        leaf.public_bytes(Encoding.PEM),
    )


class _MapResolver:
    def __init__(self, mapping: dict[str, SpiffeResolvedPrincipal] | None = None, *, fail: bool = False) -> None:
        self._mapping = (
            {
                _SPIFFE: SpiffeResolvedPrincipal(
                    principal=PrincipalRef(f"spiffe://{_DOMAIN}", "payments-worker", "service"),
                    application_id="payments",
                    environment="sandbox",
                    audiences=("payments-api",),
                    scopes=("payments:write",),
                )
            }
            if mapping is None
            else mapping
        )
        self._fail = fail

    async def resolve(self, spiffe_id: SpiffeID) -> SpiffeResolvedPrincipal | None:
        if self._fail:
            raise SpiffeResolverUnavailableError
        return self._mapping.get(str(spiffe_id))


def _peer(**changes: object) -> SpiffePeerEvidence:
    values: dict[str, Any] = {
        "spiffe_id": _SPIFFE,
        "trust_domain": _DOMAIN,
        "not_before": _NOW - timedelta(minutes=1),
        "not_after": _NOW + timedelta(hours=1),
        "termination_boundary": _BOUNDARY,
    }
    values.update(changes)
    return SpiffePeerEvidence(**values)


def _provider(**kwargs: object) -> SPIFFEProvider:
    return SPIFFEProvider(
        name="spiffe_rs",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
        ),
        resolver=_MapResolver(),
        **cast("Any", kwargs),
    )


pytestmark = pytest.mark.unit


def test_parse_spiffe_id_accepts_workload_path() -> None:
    parsed = parse_spiffe_id(_SPIFFE)
    assert str(parsed) == _SPIFFE
    assert parsed.trust_domain == _DOMAIN


@pytest.mark.parametrize(
    "value",
    [
        "https://example.org/payments",
        "spiffe://Example.org/payments/worker",
        "spiffe://example.org/",
        "spiffe://example.org",
        "spiffe://example.org/payments/../x",
        "spiffe://example.org//payments",
    ],
)
def test_parse_spiffe_id_rejects_invalid(value: str) -> None:
    with pytest.raises(SpiffeValidationError):
        parse_spiffe_id(value)


async def test_validator_accepts_valid_svid_and_rejects_matrix() -> None:
    ca_pem, leaf_pem = _ca_and_leaf()
    source = StaticSpiffeBundleSource({
        _DOMAIN: SpiffeBundleSnapshot(
            trust_domain=_DOMAIN,
            version="1",
            authorities=(ca_pem,),
            fetched_at=_NOW,
        )
    })
    validator = SpiffeX509SvidValidator(bundle_source=source)
    validated = await validator.validate(leaf=leaf_pem, now=_NOW)
    assert str(validated.spiffe_id) == _SPIFFE
    peer = project_spiffe_peer(validated=validated, termination_boundary=_BOUNDARY)
    assert peer.spiffe_id == _SPIFFE

    _, ca_leaf = _ca_and_leaf(ca=True)
    with pytest.raises(SpiffeValidationError, match="must not be a CA"):
        await validator.validate(leaf=ca_leaf, now=_NOW)

    _, multi = _ca_and_leaf(extra_uris=("spiffe://example.org/other",))
    with pytest.raises(SpiffeValidationError, match="exactly one URI SAN"):
        await validator.validate(leaf=multi, now=_NOW)

    _, bad_ku = _ca_and_leaf(key_cert_sign=True)
    with pytest.raises(SpiffeValidationError, match="certificate or CRL"):
        await validator.validate(leaf=bad_ku, now=_NOW)

    _, noncritical_ku = _ca_and_leaf(key_usage_critical=False)
    with pytest.raises(SpiffeValidationError, match="must be critical"):
        await validator.validate(leaf=noncritical_ku, now=_NOW)

    stale = StaticSpiffeBundleSource({
        _DOMAIN: SpiffeBundleSnapshot(
            trust_domain=_DOMAIN,
            version="1",
            authorities=(ca_pem,),
            fetched_at=_NOW - timedelta(hours=2),
            maximum_staleness=timedelta(hours=1),
        )
    })
    with pytest.raises(SpiffeValidationError, match="stale"):
        await SpiffeX509SvidValidator(bundle_source=stale).validate(leaf=leaf_pem, now=_NOW)


async def test_provider_happy_path_and_negatives() -> None:
    provider = _provider()
    request = RequestView(method="POST", timestamp=_NOW, spiffe_peer=_peer())
    assert provider.match(request) is CredentialMatch.OWNED
    decision = await provider.authenticate(request, AuthenticationRuntime())
    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.extensions["authweave-workload:spiffe_id"] == _SPIFFE

    assert provider.match(RequestView(method="GET", timestamp=_NOW)) is CredentialMatch.NOT_APPLICABLE
    assert (
        provider.match(
            RequestView(
                method="GET",
                timestamp=_NOW,
                spiffe_peer=_peer(),
                headers=((b"authorization", b"Bearer x"),),
            )
        )
        is CredentialMatch.AMBIGUOUS
    )

    spoofed = RequestView(method="POST", timestamp=_NOW, spiffe_peer=_peer(termination_boundary="evil"))
    spoofed_decision = await provider.authenticate(spoofed, AuthenticationRuntime())
    assert isinstance(spoofed_decision, Invalid)
    assert spoofed_decision.code is FailureCode.SENDER_CONSTRAINT_MISMATCH

    wrong_domain = RequestView(
        method="POST",
        timestamp=_NOW,
        spiffe_peer=_peer(spiffe_id="spiffe://other.org/payments/worker", trust_domain="other.org"),
    )
    other = SPIFFEProvider(
        name="spiffe_rs",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
        ),
        resolver=_MapResolver(),
    )
    decision = await other.authenticate(wrong_domain, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.ISSUER_MISMATCH

    expired = RequestView(method="POST", timestamp=_NOW + timedelta(hours=2), spiffe_peer=_peer())
    decision = await provider.authenticate(expired, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.EXPIRED

    unmapped = SPIFFEProvider(
        name="spiffe_rs",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
        ),
        resolver=_MapResolver({}),
    )
    decision = await unmapped.authenticate(request, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.INVALID

    unavailable = SPIFFEProvider(
        name="spiffe_rs",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
        ),
        resolver=_MapResolver(fail=True),
    )
    decision = await unavailable.authenticate(request, AuthenticationRuntime())
    assert isinstance(decision, Unavailable)


async def test_spiffe_callback_failure_fails_closed() -> None:
    """ADR 0001: a raised event callback maps the outcome to Unavailable."""

    def _raise(_event: object) -> None:
        raise RuntimeError

    provider = _provider(event_callback=_raise)
    spoofed = RequestView(method="POST", timestamp=_NOW, spiffe_peer=_peer(termination_boundary="evil"))
    decision = await provider.authenticate(spoofed, AuthenticationRuntime())
    assert isinstance(decision, Unavailable)


async def test_spiffe_validation_failure_matrix() -> None:
    from types import SimpleNamespace
    from unittest.mock import patch

    from authweave_workload.spiffe import _MAX_SPIFFE_ID_LENGTH, _load_cryptography

    with pytest.raises(SpiffeValidationError):
        parse_spiffe_id("spiffe://example.org/payments worker")
    with pytest.raises(SpiffeValidationError):
        parse_spiffe_id("spiffe://user:pass@example.org/payments/worker")
    with pytest.raises(SpiffeValidationError):
        parse_spiffe_id("spiffe://example.org/payments/worker#frag")
    with pytest.raises(SpiffeValidationError):
        parse_spiffe_id("spiffe://-bad.org/payments/worker")
    with pytest.raises(SpiffeValidationError):
        parse_spiffe_id("spiffe://example.org/payments/worker?x=1")
    with pytest.raises(SpiffeValidationError):
        parse_spiffe_id("a" * (_MAX_SPIFFE_ID_LENGTH + 1))

    with pytest.raises(ValueError):
        SpiffeBundleSnapshot(trust_domain="", version="1", authorities=(b"x",), fetched_at=_NOW)
    with pytest.raises(ValueError):
        SpiffeBundleSnapshot(trust_domain=_DOMAIN, version="1", authorities=(), fetched_at=_NOW)
    with pytest.raises(ValueError):
        SpiffeBundleSnapshot(
            trust_domain=_DOMAIN,
            version="1",
            authorities=(b"x",),
            fetched_at=datetime(2026, 7, 31, 12, 0),
        )
    with pytest.raises(ValueError):
        SpiffeBundleSnapshot(
            trust_domain=_DOMAIN,
            version="1",
            authorities=(b"x",),
            fetched_at=_NOW,
            maximum_staleness=timedelta(0),
        )
    with pytest.raises(ValueError):
        SpiffeBundleSnapshot(
            trust_domain=_DOMAIN,
            version="1",
            authorities=(b"x",),
            fetched_at=_NOW,
            maximum_future_skew=timedelta(seconds=-1),
        )
    snap = SpiffeBundleSnapshot(trust_domain=_DOMAIN, version="1", authorities=(b"x",), fetched_at=_NOW)
    with pytest.raises(SpiffeValidationError):
        snap.assert_fresh(now=datetime(2026, 7, 31, 12, 0))
    with pytest.raises(SpiffeValidationError, match="future"):
        snap.assert_fresh(now=_NOW - timedelta(minutes=1))

    with pytest.raises(ValueError):
        StaticSpiffeBundleSource({})
    with pytest.raises(ValueError):
        SpiffeResolvedPrincipal(
            principal=PrincipalRef(f"spiffe://{_DOMAIN}", "x", "service"),
            application_id="",
            environment="sandbox",
        )
    with pytest.raises(ValueError):
        SpiffePolicy(allowed_trust_domains=frozenset(), termination_boundaries=frozenset({_BOUNDARY}))
    with pytest.raises(ValueError):
        SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
            maximum_svid_lifetime=timedelta(0),
        )
    with pytest.raises(ValueError):
        SpiffeX509SvidValidator(
            bundle_source=StaticSpiffeBundleSource({
                _DOMAIN: SpiffeBundleSnapshot(trust_domain=_DOMAIN, version="1", authorities=(b"x",), fetched_at=_NOW)
            }),
            maximum_svid_lifetime=timedelta(0),
        )

    ca_pem, leaf_pem = _ca_and_leaf()
    source = StaticSpiffeBundleSource({
        _DOMAIN: SpiffeBundleSnapshot(trust_domain=_DOMAIN, version="1", authorities=(ca_pem,), fetched_at=_NOW)
    })
    validator = SpiffeX509SvidValidator(bundle_source=source)
    with pytest.raises(SpiffeValidationError):
        await validator.validate(leaf=leaf_pem, now=datetime(2026, 7, 31, 12, 0))
    with pytest.raises(SpiffeValidationError):
        await validator.validate(leaf=b"not-a-cert", now=_NOW)
    with pytest.raises(SpiffeValidationError):
        await validator.validate(leaf=leaf_pem, intermediates=(b"not-pem",), now=_NOW)
    with pytest.raises(SpiffeValidationError, match="too many intermediate"):
        await validator.validate(leaf=leaf_pem, intermediates=(ca_pem,) * 20, now=_NOW)

    _, long_life = _ca_and_leaf(lifetime=timedelta(days=40))
    with pytest.raises(SpiffeValidationError, match="lifetime"):
        await validator.validate(leaf=long_life, now=_NOW)

    _, short = _ca_and_leaf(lifetime=timedelta(minutes=5))
    with pytest.raises(SpiffeValidationError, match="not currently valid"):
        await validator.validate(leaf=short, now=_NOW + timedelta(hours=1))

    # path validation failure: leaf signed by other CA
    other_ca, _ = _ca_and_leaf()
    wrong_bundle = StaticSpiffeBundleSource({
        _DOMAIN: SpiffeBundleSnapshot(trust_domain=_DOMAIN, version="1", authorities=(other_ca,), fetched_at=_NOW)
    })
    with pytest.raises(SpiffeValidationError, match="path validation"):
        await SpiffeX509SvidValidator(bundle_source=wrong_bundle).validate(leaf=leaf_pem, now=_NOW)

    empty_domain = StaticSpiffeBundleSource({
        "other.org": SpiffeBundleSnapshot(trust_domain="other.org", version="1", authorities=(ca_pem,), fetched_at=_NOW)
    })
    with pytest.raises(SpiffeValidationError, match="unavailable"):
        await SpiffeX509SvidValidator(bundle_source=empty_domain).validate(leaf=leaf_pem, now=_NOW)

    _, no_sig = _ca_and_leaf(digital_signature=False)
    with pytest.raises(SpiffeValidationError, match="digital signatures"):
        await validator.validate(leaf=no_sig, now=_NOW)

    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca2")])
    ca2 = (
        x509
        .CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bare = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bare")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    source2 = StaticSpiffeBundleSource({
        _DOMAIN: SpiffeBundleSnapshot(
            trust_domain=_DOMAIN,
            version="1",
            authorities=(ca2.public_bytes(Encoding.PEM),),
            fetched_at=_NOW,
        )
    })
    with pytest.raises(SpiffeValidationError, match="Subject Alternative Name"):
        await SpiffeX509SvidValidator(bundle_source=source2).validate(leaf=bare.public_bytes(Encoding.PEM), now=_NOW)

    # RSA-1024 SVID rejected by key-size policy
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")]))
        .issuer_name(ca_name)
        .public_key(weak_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SPIFFE)]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(weak_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    with pytest.raises(SpiffeValidationError, match="2048"):
        await SpiffeX509SvidValidator(bundle_source=source2).validate(leaf=weak.public_bytes(Encoding.PEM), now=_NOW)

    # missing BasicConstraints
    no_bc = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nobc")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SPIFFE)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    with pytest.raises(SpiffeValidationError, match="BasicConstraints"):
        await SpiffeX509SvidValidator(bundle_source=source2).validate(leaf=no_bc.public_bytes(Encoding.PEM), now=_NOW)

    no_ku = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "noku")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SPIFFE)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    with pytest.raises(SpiffeValidationError, match="KeyUsage"):
        await SpiffeX509SvidValidator(bundle_source=source2).validate(leaf=no_ku.public_bytes(Encoding.PEM), now=_NOW)

    from cryptography.hazmat.primitives.asymmetric import dsa

    dsa_key = dsa.generate_private_key(key_size=2048)
    dsa_leaf = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dsa")]))
        .issuer_name(ca_name)
        .public_key(dsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SPIFFE)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    with pytest.raises(SpiffeValidationError, match="public key type"):
        await SpiffeX509SvidValidator(bundle_source=source2).validate(
            leaf=dsa_leaf.public_bytes(Encoding.PEM), now=_NOW
        )

    from authweave_workload.spiffe import _validate_spiffe_leaf_profile
    from cryptography.hazmat.primitives.asymmetric import ed25519

    crypto = _load_cryptography()
    bad_ec_key = ec.generate_private_key(ec.SECP224R1())
    bad_ec = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "badec")]))
        .issuer_name(ca_name)
        .public_key(bad_ec_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SPIFFE)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    with pytest.raises(SpiffeValidationError, match="P-256"):
        _validate_spiffe_leaf_profile(bad_ec, crypto)

    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_leaf = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed")]))
        .issuer_name(ca_name)
        .public_key(ed_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SPIFFE)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _validate_spiffe_leaf_profile(ed_leaf, crypto)

    rsa_ok = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsaok")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(minutes=1))
        .not_valid_after(_NOW + timedelta(hours=1))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(_SPIFFE)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _validate_spiffe_leaf_profile(rsa_ok, crypto)

    provider = SPIFFEProvider(
        name="spiffe_rs",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
            require_empty_authorization=False,
        ),
        resolver=_MapResolver(),
    )
    mixed = RequestView(
        method="GET",
        timestamp=_NOW,
        spiffe_peer=_peer(),
        headers=((b"authorization", b"Bearer x"),),
    )
    assert provider.match(mixed) is CredentialMatch.OWNED

    missing = await provider.authenticate(RequestView(method="GET", timestamp=_NOW), AuthenticationRuntime())
    assert isinstance(missing, Invalid)
    assert missing.code is FailureCode.MISSING

    malformed_peer = RequestView(
        method="POST",
        timestamp=_NOW,
        spiffe_peer=cast(
            "Any",
            SimpleNamespace(
                spiffe_id="not-a-spiffe-id",
                trust_domain=_DOMAIN,
                not_before=_NOW - timedelta(minutes=1),
                not_after=_NOW + timedelta(hours=1),
                termination_boundary=_BOUNDARY,
            ),
        ),
    )
    decision = await provider.authenticate(malformed_peer, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.MALFORMED

    mismatched = RequestView(
        method="POST",
        timestamp=_NOW,
        spiffe_peer=cast(
            "Any",
            SimpleNamespace(
                spiffe_id=_SPIFFE,
                trust_domain="other.org",
                not_before=_NOW - timedelta(minutes=1),
                not_after=_NOW + timedelta(hours=1),
                termination_boundary=_BOUNDARY,
            ),
        ),
    )
    decision = await provider.authenticate(mismatched, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.MALFORMED

    early = RequestView(
        method="POST",
        timestamp=_NOW - timedelta(hours=1),
        spiffe_peer=_peer(),
    )
    decision = await provider.authenticate(early, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.NOT_YET_VALID

    long_lived = RequestView(
        method="POST",
        timestamp=_NOW,
        spiffe_peer=_peer(not_after=_NOW + timedelta(days=40)),
    )
    decision = await provider.authenticate(long_lived, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.MALFORMED

    events: list[SecurityEvent] = []

    async def _cb(event: SecurityEvent) -> None:
        events.append(event)

    with_cb = SPIFFEProvider(
        name="spiffe_rs",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
        ),
        resolver=_MapResolver(),
        event_callback=_cb,
    )
    ok = await with_cb.authenticate(
        RequestView(method="POST", timestamp=_NOW, spiffe_peer=_peer()), AuthenticationRuntime()
    )
    assert isinstance(ok, Authenticated)
    assert events[-1].target_principal == ok.context.subject
    assert events[-1].actor == ok.context.actor

    sync_events: list[object] = []

    def _sync_cb(event: object) -> None:
        sync_events.append(event)

    sync_provider = SPIFFEProvider(
        name="spiffe_rs",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({_DOMAIN}),
            termination_boundaries=frozenset({_BOUNDARY}),
        ),
        resolver=_MapResolver(),
        event_callback=_sync_cb,
    )
    assert isinstance(
        await sync_provider.authenticate(
            RequestView(method="POST", timestamp=_NOW, spiffe_peer=_peer()), AuthenticationRuntime()
        ),
        Authenticated,
    )
    assert sync_events

    def _boom(name: str, *args: object, **kwargs: object) -> object:
        if name == "cryptography" or name.startswith("cryptography."):
            msg = "missing cryptography"
            raise ImportError(msg)
        return cast("Any", __import__)(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_boom), pytest.raises(ImportError, match="spiffe"):
        _load_cryptography()
