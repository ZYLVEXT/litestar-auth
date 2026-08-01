"""Atomic SPIFFE Workload API snapshot lifecycle tests."""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import anyio.lowlevel
import pytest
from authweave_workload.spiffe import SpiffeBundleSnapshot
from authweave_workload.spiffe_snapshot import (
    PySpiffeWorkloadSnapshotSource,
    SpiffeSnapshotPolicy,
    SpiffeSnapshotSourceUnavailableError,
    SpiffeSnapshotUnavailableError,
    SpiffeSnapshotValidationError,
    SpiffeWorkloadSnapshot,
    SpiffeWorkloadSnapshotManager,
    _open_x509_source,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
_DOMAIN = "example.org"


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _Source:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls = 0

    async def fetch_snapshot(self) -> SpiffeWorkloadSnapshot:
        self.calls += 1
        await anyio.lowlevel.checkpoint()
        value = self.values.pop(0)
        if isinstance(value, SpiffeSnapshotSourceUnavailableError):
            raise value
        return cast("SpiffeWorkloadSnapshot", value)


def _issued(domain: str = _DOMAIN) -> tuple[bytes, bytes]:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{domain} CA")])
    ca = (
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
    leaf = (
        x509
        .CertificateBuilder()
        .subject_name(x509.Name([]))
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
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"spiffe://{domain}/payments/worker")]),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return ca.public_bytes(Encoding.PEM), leaf.public_bytes(Encoding.PEM)


def _bundle(domain: str, authority: bytes, *, fetched_at: datetime = _NOW, version: str = "1") -> SpiffeBundleSnapshot:
    return SpiffeBundleSnapshot(
        trust_domain=domain,
        version=version,
        authorities=(authority,),
        fetched_at=fetched_at,
    )


def _snapshot(
    generation: int = 1,
    *,
    domain: str = _DOMAIN,
    fetched_at: datetime = _NOW,
    bundles: tuple[SpiffeBundleSnapshot, ...] | None = None,
) -> SpiffeWorkloadSnapshot:
    authority, leaf = _issued(domain)
    return SpiffeWorkloadSnapshot(
        generation=generation,
        svid_chain=(leaf,),
        bundles=(_bundle(domain, authority, fetched_at=fetched_at),) if bundles is None else bundles,
        fetched_at=fetched_at,
    )


def _policy(  # ruff: ignore[too-many-arguments] - each lifecycle bound is independently exercised
    *,
    federated_trust_domains: frozenset[str] = frozenset(),
    refresh_interval: timedelta = timedelta(minutes=1),
    maximum_staleness: timedelta = timedelta(minutes=5),
    maximum_future_skew: timedelta = timedelta(seconds=30),
    maximum_svid_lifetime: timedelta = timedelta(hours=24),
    maximum_chain_certificates: int = 9,
    maximum_bundles: int = 16,
    maximum_total_bytes: int = 2_097_152,
) -> SpiffeSnapshotPolicy:
    return SpiffeSnapshotPolicy(
        local_trust_domain=_DOMAIN,
        federated_trust_domains=federated_trust_domains,
        refresh_interval=refresh_interval,
        maximum_staleness=maximum_staleness,
        maximum_future_skew=maximum_future_skew,
        maximum_svid_lifetime=maximum_svid_lifetime,
        maximum_chain_certificates=maximum_chain_certificates,
        maximum_bundles=maximum_bundles,
        maximum_total_bytes=maximum_total_bytes,
    )


pytestmark = pytest.mark.unit


def test_snapshot_and_policy_reject_invalid_configuration() -> None:
    authority, leaf = _issued()
    bundle = _bundle(_DOMAIN, authority)
    with pytest.raises(SpiffeSnapshotValidationError, match="generation"):
        SpiffeWorkloadSnapshot(0, (leaf,), (bundle,), _NOW)
    for chain in ((), (b"",), (cast("bytes", "not-bytes"),)):
        with pytest.raises(SpiffeSnapshotValidationError, match="SVID chain"):
            SpiffeWorkloadSnapshot(1, chain, (bundle,), _NOW)
    with pytest.raises(SpiffeSnapshotValidationError, match="bundles"):
        SpiffeWorkloadSnapshot(1, (leaf,), (), _NOW)
    with pytest.raises(SpiffeSnapshotValidationError, match="timezone-aware"):
        SpiffeWorkloadSnapshot(1, (leaf,), (bundle,), _NOW.replace(tzinfo=None))

    assert _policy(federated_trust_domains=frozenset({"partner.example"})).allowed_trust_domains == {
        _DOMAIN,
        "partner.example",
    }
    with pytest.raises(ValueError, match="excluded"):
        _policy(federated_trust_domains=frozenset({_DOMAIN}))
    with pytest.raises(ValueError, match="lowercase"):
        _policy(federated_trust_domains=frozenset({"Partner.example"}))
    with pytest.raises(ValueError, match="timeout"):
        PySpiffeWorkloadSnapshotSource(timeout_seconds=0)
    invalid_bounds = (
        {"refresh_interval": timedelta(0)},
        {"refresh_interval": timedelta(minutes=2), "maximum_staleness": timedelta(minutes=1)},
        {"maximum_future_skew": timedelta(seconds=-1)},
        {"maximum_svid_lifetime": timedelta(0)},
        {"maximum_chain_certificates": 0},
        {"maximum_bundles": 0},
        {"maximum_total_bytes": 0},
    )
    for values in invalid_bounds:
        with pytest.raises(ValueError, match="bounds"):
            _policy(**cast("Any", values))


async def test_snapshot_refresh_is_single_flight_and_cacheable() -> None:
    source = _Source(_snapshot())
    manager = SpiffeWorkloadSnapshotManager(source=source, policy=_policy(), time_source=_Clock())
    results = await asyncio.gather(*(manager.snapshot() for _ in range(32)))
    assert source.calls == 1
    assert len({id(result) for result in results}) == 1
    assert str(results[0].svid.spiffe_id) == f"spiffe://{_DOMAIN}/payments/worker"
    assert await manager.snapshot() is results[0]
    assert source.calls == 1


async def test_refresh_failure_uses_bounded_lkg_then_fails_closed() -> None:
    clock = _Clock()
    source = _Source(
        _snapshot(),
        SpiffeSnapshotSourceUnavailableError("offline"),
        SpiffeSnapshotSourceUnavailableError("offline"),
    )
    manager = SpiffeWorkloadSnapshotManager(source=source, policy=_policy(), time_source=clock)
    first = await manager.snapshot()
    clock.value += timedelta(minutes=2)
    assert await manager.snapshot() is first
    clock.value += timedelta(minutes=4)
    with pytest.raises(SpiffeSnapshotUnavailableError, match="unavailable"):
        await manager.snapshot()


async def test_refresh_rejects_rollback_and_invalid_atomic_updates() -> None:
    clock = _Clock()
    authority, _ = _issued()
    valid = _snapshot()
    valid_size = sum(len(value) for value in valid.svid_chain) + sum(
        len(value) for bundle in valid.bundles for value in bundle.authorities
    )
    cases: tuple[object, ...] = (
        _snapshot(),
        _snapshot(2, fetched_at=_NOW - timedelta(seconds=1)),
        _snapshot(2, fetched_at=_NOW + timedelta(minutes=10)),
        SpiffeWorkloadSnapshot(
            2,
            valid.svid_chain * 2,
            valid.bundles,
            _NOW,
        ),
        SpiffeWorkloadSnapshot(
            2,
            valid.svid_chain,
            (valid.bundles[0], _bundle("partner.example", authority)),
            _NOW,
        ),
        SpiffeWorkloadSnapshot(
            2,
            valid.svid_chain,
            (valid.bundles[0], valid.bundles[0]),
            _NOW,
        ),
        SpiffeWorkloadSnapshot(
            2,
            valid.svid_chain,
            (_bundle("other.example", authority),),
            _NOW,
        ),
        SpiffeWorkloadSnapshot(
            2,
            valid.svid_chain,
            (_bundle(_DOMAIN, authority, fetched_at=_NOW + timedelta(seconds=1)),),
            _NOW,
        ),
        SpiffeWorkloadSnapshot(2, (*valid.svid_chain, b"x"), valid.bundles, _NOW),
        cast("SpiffeWorkloadSnapshot", object()),
    )
    policies = (
        _policy(),
        _policy(),
        _policy(),
        _policy(maximum_chain_certificates=1),
        _policy(maximum_bundles=1, federated_trust_domains=frozenset({"partner.example"})),
        _policy(),
        _policy(),
        _policy(),
        _policy(maximum_total_bytes=valid_size),
        _policy(),
    )
    for candidate, policy in zip(cases, policies, strict=True):
        source = _Source(valid, candidate, candidate)
        manager = SpiffeWorkloadSnapshotManager(source=source, policy=policy, time_source=clock)
        first = await manager.snapshot()
        assert await manager.snapshot(force_refresh=True) is first
        clock.value = _NOW + timedelta(minutes=6)
        with pytest.raises(SpiffeSnapshotUnavailableError):
            await manager.snapshot(force_refresh=True)
        clock.value = _NOW


async def test_snapshot_rejects_malformed_and_nonlocal_svid_without_lkg() -> None:
    malformed = _snapshot()
    malformed = SpiffeWorkloadSnapshot(1, (b"not-a-certificate",), malformed.bundles, _NOW)
    manager = SpiffeWorkloadSnapshotManager(source=_Source(malformed), policy=_policy(), time_source=_Clock())
    with pytest.raises(SpiffeSnapshotUnavailableError):
        await manager.snapshot()

    local_authority, _ = _issued()
    foreign = _snapshot(domain="partner.example")
    mixed = SpiffeWorkloadSnapshot(
        generation=1,
        svid_chain=foreign.svid_chain,
        bundles=(
            _bundle(_DOMAIN, local_authority),
            foreign.bundles[0],
        ),
        fetched_at=_NOW,
    )
    manager = SpiffeWorkloadSnapshotManager(
        source=_Source(mixed),
        policy=_policy(federated_trust_domains=frozenset({"partner.example"})),
        time_source=_Clock(),
    )
    with pytest.raises(SpiffeSnapshotUnavailableError):
        await manager.snapshot()

    federated_only = SpiffeWorkloadSnapshot(
        generation=1,
        svid_chain=foreign.svid_chain,
        bundles=(foreign.bundles[0],),
        fetched_at=_NOW,
    )
    manager = SpiffeWorkloadSnapshotManager(
        source=_Source(federated_only),
        policy=_policy(federated_trust_domains=frozenset({"partner.example"})),
        time_source=_Clock(),
    )
    with pytest.raises(SpiffeSnapshotUnavailableError):
        await manager.snapshot()


async def test_snapshot_clock_must_be_timezone_aware() -> None:
    clock = _Clock(_NOW.replace(tzinfo=None))
    manager = SpiffeWorkloadSnapshotManager(source=_Source(_snapshot()), policy=_policy(), time_source=clock)
    with pytest.raises(SpiffeSnapshotValidationError, match="time source"):
        await manager.snapshot()


async def test_py_spiffe_source_maps_atomic_context_and_closes() -> None:
    authority, leaf = _issued()
    context = SimpleNamespace(
        default_svid=SimpleNamespace(cert_chain=[x509.load_pem_x509_certificate(leaf)]),
        x509_bundle_set=SimpleNamespace(
            bundles=(
                SimpleNamespace(
                    trust_domain=_DOMAIN,
                    x509_authorities={x509.load_pem_x509_certificate(authority)},
                ),
            ),
        ),
    )

    class _SdkSource:
        closed = False

        def get_x509_context(self) -> object:
            return context

        def close(self) -> None:
            self.closed = True

    sdk_source = _SdkSource()
    with patch("authweave_workload.spiffe_snapshot._open_x509_source", return_value=sdk_source):
        source = PySpiffeWorkloadSnapshotSource(socket_path="unix:///run/spire/agent.sock", time_source=_Clock())
        first = await source.fetch_snapshot()
        second = await source.fetch_snapshot()
        await source.aclose()

    assert first.generation == 1
    assert second.generation == first.generation + 1
    assert first.svid_chain == (leaf,)
    assert first.bundles[0].trust_domain == _DOMAIN
    assert sdk_source.closed


async def test_py_spiffe_source_lifecycle_is_idempotent() -> None:
    class _SdkSource:
        closed = False

        def close(self) -> None:
            self.closed = True

    sdk_source = _SdkSource()
    with patch("authweave_workload.spiffe_snapshot._open_x509_source", return_value=sdk_source):
        source = PySpiffeWorkloadSnapshotSource()
        await source.aclose()
        async with source as opened:
            assert opened is source
            await source.start()
    assert sdk_source.closed


def test_open_x509_source_forwards_configuration() -> None:
    expected_timeout = 3

    def _sdk_source(*, socket_path: str | None, timeout_in_seconds: float) -> SimpleNamespace:
        return SimpleNamespace(socket_path=socket_path, timeout=timeout_in_seconds)

    with patch.dict(sys.modules, {"spiffe": SimpleNamespace(X509Source=_sdk_source)}):
        source = cast(
            "SimpleNamespace",
            _open_x509_source(socket_path="unix:///run/spire.sock", timeout_seconds=expected_timeout),
        )
    assert source.socket_path == "unix:///run/spire.sock"
    assert source.timeout == expected_timeout


async def test_py_spiffe_source_maps_sdk_failure() -> None:
    class _BrokenSource:
        def get_x509_context(self) -> object:
            raise RuntimeError

        def close(self) -> None:
            pass

    with patch("authweave_workload.spiffe_snapshot._open_x509_source", return_value=_BrokenSource()):
        source = PySpiffeWorkloadSnapshotSource()
        with pytest.raises(SpiffeSnapshotSourceUnavailableError):
            await source.fetch_snapshot()
