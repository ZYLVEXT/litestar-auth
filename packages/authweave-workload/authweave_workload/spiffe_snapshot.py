"""Atomic, bounded lifecycle for SPIFFE Workload API X.509 snapshots."""

from __future__ import annotations

import asyncio
import hashlib
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

import anyio
from authweave_core import SecurityOperation, SecurityOutcome, observe_security
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.utils import CryptographyDeprecationWarning

from authweave_workload.spiffe import (
    SpiffeBundleSnapshot,
    SpiffeValidationError,
    SpiffeX509SvidValidator,
    StaticSpiffeBundleSource,
    ValidatedSpiffeSvid,
    parse_spiffe_id,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from authweave_core import SecurityObserver
    from spiffe import X509Source
    from spiffe.workloadapi.x509_context import X509Context


class SpiffeSnapshotSourceUnavailableError(Exception):
    """Raised by a Workload API adapter when its trusted local source is unavailable."""


class SpiffeSnapshotUnavailableError(Exception):
    """Raised when neither a valid refresh nor a usable last-known-good snapshot exists."""


class SpiffeSnapshotValidationError(ValueError):
    """Raised when an atomic Workload API snapshot violates lifecycle policy."""


@dataclass(frozen=True, slots=True)
class SpiffeWorkloadSnapshot:
    """One atomic leaf+chain+bundle update produced by a maintained SDK adapter."""

    generation: int
    svid_chain: tuple[bytes, ...]
    bundles: tuple[SpiffeBundleSnapshot, ...]
    fetched_at: datetime

    def __post_init__(self) -> None:
        """Reject structurally empty or ambiguous snapshots.

        Raises:
            SpiffeSnapshotValidationError: If required atomic material is invalid.
        """
        if self.generation < 1:
            msg = "snapshot generation must be positive"
            raise SpiffeSnapshotValidationError(msg)
        if not self.svid_chain or any(
            not isinstance(certificate, bytes) or not certificate for certificate in self.svid_chain
        ):
            msg = "snapshot SVID chain must contain non-empty bytes"
            raise SpiffeSnapshotValidationError(msg)
        if not self.bundles:
            msg = "snapshot bundles must not be empty"
            raise SpiffeSnapshotValidationError(msg)
        if self.fetched_at.utcoffset() is None:
            msg = "snapshot fetched_at must be timezone-aware"
            raise SpiffeSnapshotValidationError(msg)


@dataclass(frozen=True, slots=True)
class ValidatedSpiffeWorkloadSnapshot:
    """Validated atomic snapshot retained as last-known-good state."""

    source: SpiffeWorkloadSnapshot
    svid: ValidatedSpiffeSvid


@runtime_checkable
class SpiffeWorkloadSnapshotSource(Protocol):
    """Load atomic X.509 material from a maintained SPIFFE SDK adapter."""

    async def fetch_snapshot(self) -> SpiffeWorkloadSnapshot:
        """Return one update or raise :class:`SpiffeSnapshotSourceUnavailableError`."""
        ...


class PySpiffeWorkloadSnapshotSource:
    """Read coherent X.509 contexts from the community py-spiffe SDK."""

    __slots__ = ("_generation", "_lock", "_socket_path", "_source", "_time_source", "_timeout_seconds")

    def __init__(
        self,
        *,
        socket_path: str | None = None,
        timeout_seconds: float = 5.0,
        time_source: Callable[[], datetime] | None = None,
    ) -> None:
        """Configure the SDK endpoint without opening it.

        Raises:
            ValueError: If ``timeout_seconds`` is not positive.
        """
        if timeout_seconds <= 0:
            msg = "SPIFFE Workload API timeout must be positive"
            raise ValueError(msg)
        self._socket_path = socket_path
        self._timeout_seconds = timeout_seconds
        self._time_source = time_source or (lambda: datetime.now(UTC))
        self._source: X509Source | None = None
        self._generation = 0
        self._lock = anyio.Lock()

    async def start(self) -> None:
        """Connect and wait for the SDK's first coherent Workload API update."""
        async with self._lock:
            if self._source is not None:
                return
            opener = partial(
                _open_x509_source,
                socket_path=self._socket_path,
                timeout_seconds=self._timeout_seconds,
            )
            self._source = await asyncio.to_thread(opener)

    async def fetch_snapshot(self) -> SpiffeWorkloadSnapshot:
        """Return the SDK's current leaf, chain, and bundle set atomically.

        Raises:
            SpiffeSnapshotSourceUnavailableError: If the SDK cannot provide a context.
        """
        await self.start()
        async with self._lock:
            source = self._source
            if source is None:  # pragma: no cover - guarded by start()
                raise SpiffeSnapshotSourceUnavailableError
            try:
                context = await asyncio.to_thread(source.get_x509_context)
                fetched_at = self._time_source()
                self._generation += 1
                return _snapshot_from_context(context, generation=self._generation, fetched_at=fetched_at)
            except Exception as exc:
                msg = "SPIFFE Workload API context is unavailable"
                raise SpiffeSnapshotSourceUnavailableError(msg) from exc

    async def aclose(self) -> None:
        """Stop the SDK watcher and release its Workload API connection."""
        async with self._lock:
            source, self._source = self._source, None
            if source is not None:
                await asyncio.to_thread(source.close)

    async def __aenter__(self) -> Self:
        """Open and return the Workload API source.

        Returns:
            This source.
        """
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the Workload API source."""
        await self.aclose()


@dataclass(frozen=True, slots=True)
class SpiffeSnapshotPolicy:
    """Bounds and trust-domain policy for one Workload API lifecycle."""

    local_trust_domain: str
    federated_trust_domains: frozenset[str] = frozenset()
    refresh_interval: timedelta = timedelta(minutes=1)
    maximum_staleness: timedelta = timedelta(minutes=5)
    maximum_future_skew: timedelta = timedelta(seconds=30)
    maximum_svid_lifetime: timedelta = timedelta(hours=24)
    maximum_chain_certificates: int = 9
    maximum_bundles: int = 16
    maximum_total_bytes: int = 2_097_152

    def __post_init__(self) -> None:
        """Reject invalid domains and non-positive lifecycle bounds.

        Raises:
            ValueError: If any trust-domain or lifecycle constraint is unsafe.
        """
        local = parse_spiffe_id(f"spiffe://{self.local_trust_domain}/placeholder").trust_domain
        if local != self.local_trust_domain or self.local_trust_domain in self.federated_trust_domains:
            msg = "local trust domain must be canonical and excluded from federation"
            raise ValueError(msg)
        for domain in self.federated_trust_domains:
            parse_spiffe_id(f"spiffe://{domain}/placeholder")
        duration_bounds = (
            self.refresh_interval > timedelta(0),
            self.maximum_staleness >= self.refresh_interval,
            self.maximum_future_skew >= timedelta(0),
            self.maximum_svid_lifetime > timedelta(0),
        )
        count_bounds = (self.maximum_chain_certificates, self.maximum_bundles, self.maximum_total_bytes)
        if not all(duration_bounds) or any(value < 1 for value in count_bounds):
            msg = "SPIFFE snapshot lifecycle bounds are invalid"
            raise ValueError(msg)

    @property
    def allowed_trust_domains(self) -> frozenset[str]:
        """The exact local plus explicitly federated trust domains."""
        return self.federated_trust_domains | {self.local_trust_domain}


class SpiffeWorkloadSnapshotManager:
    """Single-flight refresh with atomic replacement and bounded LKG fallback."""

    __slots__ = ("_current", "_lock", "_observer", "_policy", "_source", "_time_source")

    def __init__(
        self,
        *,
        source: SpiffeWorkloadSnapshotSource,
        policy: SpiffeSnapshotPolicy,
        time_source: Callable[[], datetime] | None = None,
        observer: SecurityObserver | None = None,
    ) -> None:
        """Bind an SDK adapter and deterministic lifecycle policy."""
        self._source = source
        self._policy = policy
        self._time_source = time_source or (lambda: datetime.now(UTC))
        self._observer = observer
        self._current: ValidatedSpiffeWorkloadSnapshot | None = None
        self._lock = anyio.Lock()

    async def snapshot(self, *, force_refresh: bool = False) -> ValidatedSpiffeWorkloadSnapshot:
        """Return a fresh snapshot or a bounded last-known-good snapshot.

        Raises:
            SpiffeSnapshotUnavailableError: If refresh fails and LKG is unusable.
        """
        with observe_security(
            self._observer,
            SecurityOperation.KEY_REFRESH,
            profile="spiffe_workload_snapshot",
            credential_kind="x509_svid",
        ) as observation:
            now = self._now()
            baseline = self._current
            if baseline is not None and not force_refresh and self._is_cache_fresh(baseline, now=now):
                observation.set_outcome(SecurityOutcome.HIT)
                return baseline
            async with self._lock:
                now = self._now()
                current = self._current
                refreshed_by_peer = current is not baseline
                cache_is_fresh = current is not None and not force_refresh and self._is_cache_fresh(current, now=now)
                if current is not None and (refreshed_by_peer or cache_is_fresh) and self._is_usable(current, now=now):
                    observation.set_outcome(SecurityOutcome.HIT)
                    return current
                try:
                    candidate = await self._source.fetch_snapshot()
                    validated = await self._validate(candidate, current=current, now=now)
                except (
                    SpiffeSnapshotSourceUnavailableError,
                    SpiffeSnapshotValidationError,
                    SpiffeValidationError,
                ) as exc:
                    if current is not None and self._is_usable(current, now=now):
                        observation.set_outcome(SecurityOutcome.STALE, reason_code="refresh_failed_lkg")
                        return current
                    observation.set_outcome(SecurityOutcome.UNAVAILABLE, reason_code="snapshot_unavailable")
                    msg = "SPIFFE Workload API snapshot is unavailable"
                    raise SpiffeSnapshotUnavailableError(msg) from exc
                self._current = validated
                observation.set_outcome(SecurityOutcome.VERIFIED)
                return validated

    def _now(self) -> datetime:
        now = self._time_source()
        if now.utcoffset() is None:
            msg = "SPIFFE snapshot time source must return a timezone-aware datetime"
            raise SpiffeSnapshotValidationError(msg)
        return now

    def _is_cache_fresh(self, snapshot: ValidatedSpiffeWorkloadSnapshot, *, now: datetime) -> bool:
        return self._is_usable(snapshot, now=now) and now - snapshot.source.fetched_at < self._policy.refresh_interval

    def _is_usable(self, snapshot: ValidatedSpiffeWorkloadSnapshot | None, *, now: datetime) -> bool:
        return bool(
            snapshot is not None
            and now < snapshot.svid.not_after
            and now - snapshot.source.fetched_at <= self._policy.maximum_staleness
        )

    async def _validate(
        self,
        candidate: SpiffeWorkloadSnapshot,
        *,
        current: ValidatedSpiffeWorkloadSnapshot | None,
        now: datetime,
    ) -> ValidatedSpiffeWorkloadSnapshot:
        if not isinstance(candidate, SpiffeWorkloadSnapshot):
            msg = "snapshot source returned an unsupported value"
            raise SpiffeSnapshotValidationError(msg)
        self._validate_progress(candidate, current=current, now=now)
        bundle_map = self._validated_bundle_map(candidate)
        validator = SpiffeX509SvidValidator(
            bundle_source=StaticSpiffeBundleSource(bundle_map),
            maximum_svid_lifetime=self._policy.maximum_svid_lifetime,
        )
        svid = await validator.validate(
            leaf=candidate.svid_chain[0],
            intermediates=candidate.svid_chain[1:],
            now=now,
        )
        if svid.spiffe_id.trust_domain != self._policy.local_trust_domain:
            msg = "workload SVID is outside the local trust domain"
            raise SpiffeSnapshotValidationError(msg)
        return ValidatedSpiffeWorkloadSnapshot(source=candidate, svid=svid)

    def _validate_progress(
        self,
        candidate: SpiffeWorkloadSnapshot,
        *,
        current: ValidatedSpiffeWorkloadSnapshot | None,
        now: datetime,
    ) -> None:
        if candidate.fetched_at > now + self._policy.maximum_future_skew:
            msg = "snapshot fetched_at is in the future"
            raise SpiffeSnapshotValidationError(msg)
        if current is not None:
            if candidate.generation <= current.source.generation:
                msg = "snapshot generation rollback or replay detected"
                raise SpiffeSnapshotValidationError(msg)
            if candidate.fetched_at < current.source.fetched_at:
                msg = "snapshot timestamp rollback detected"
                raise SpiffeSnapshotValidationError(msg)
        if len(candidate.svid_chain) > self._policy.maximum_chain_certificates:
            msg = "snapshot SVID chain exceeds its certificate bound"
            raise SpiffeSnapshotValidationError(msg)
        if len(candidate.bundles) > self._policy.maximum_bundles:
            msg = "snapshot bundle count exceeds its bound"
            raise SpiffeSnapshotValidationError(msg)

    def _validated_bundle_map(self, candidate: SpiffeWorkloadSnapshot) -> dict[str, SpiffeBundleSnapshot]:
        bundle_map: dict[str, SpiffeBundleSnapshot] = {}
        total_bytes = sum(len(certificate) for certificate in candidate.svid_chain)
        for bundle in candidate.bundles:
            if bundle.trust_domain in bundle_map or bundle.trust_domain not in self._policy.allowed_trust_domains:
                msg = "snapshot contains duplicate or untrusted bundle domains"
                raise SpiffeSnapshotValidationError(msg)
            if bundle.fetched_at != candidate.fetched_at:
                msg = "snapshot leaf and bundles were not fetched atomically"
                raise SpiffeSnapshotValidationError(msg)
            bundle_map[bundle.trust_domain] = bundle
            total_bytes += sum(len(authority) for authority in bundle.authorities)
        if self._policy.local_trust_domain not in bundle_map:
            msg = "snapshot omits the local trust-domain bundle"
            raise SpiffeSnapshotValidationError(msg)
        if total_bytes > self._policy.maximum_total_bytes:
            msg = "snapshot exceeds its total byte bound"
            raise SpiffeSnapshotValidationError(msg)
        return bundle_map


def _open_x509_source(*, socket_path: str | None, timeout_seconds: float) -> X509Source:
    try:
        with warnings.catch_warnings():
            # py-spiffe 0.3.0 evaluates this deprecated FFDH type alias while importing.
            warnings.filterwarnings(
                "ignore",
                message=r"Diffie-Hellman over finite fields .*",
                category=CryptographyDeprecationWarning,
                module=r"spiffe\.utils\.certificate_utils",
            )
            from spiffe import (
                X509Source,
            )
    except ImportError as exc:  # pragma: no cover - exercised by import-isolation tests
        msg = "Install authweave-workload[spiffe] to use the Workload API adapter"
        raise ImportError(msg) from exc
    return X509Source(socket_path=socket_path, timeout_in_seconds=timeout_seconds)


def _snapshot_from_context(
    context: X509Context,
    *,
    generation: int,
    fetched_at: datetime,
) -> SpiffeWorkloadSnapshot:
    svid_chain = tuple(certificate.public_bytes(Encoding.PEM) for certificate in context.default_svid.cert_chain)
    bundles = tuple(
        SpiffeBundleSnapshot(
            trust_domain=str(bundle.trust_domain),
            version=hashlib.sha256(b"".join(authorities)).hexdigest(),
            authorities=authorities,
            fetched_at=fetched_at,
        )
        for bundle in sorted(context.x509_bundle_set.bundles, key=lambda item: str(item.trust_domain))
        if (
            authorities := tuple(
                sorted(certificate.public_bytes(Encoding.PEM) for certificate in bundle.x509_authorities)
            )
        )
    )
    return SpiffeWorkloadSnapshot(
        generation=generation,
        svid_chain=svid_chain,
        bundles=bundles,
        fetched_at=fetched_at,
    )


__all__ = (
    "PySpiffeWorkloadSnapshotSource",
    "SpiffeSnapshotPolicy",
    "SpiffeSnapshotSourceUnavailableError",
    "SpiffeSnapshotUnavailableError",
    "SpiffeSnapshotValidationError",
    "SpiffeWorkloadSnapshot",
    "SpiffeWorkloadSnapshotManager",
    "SpiffeWorkloadSnapshotSource",
    "ValidatedSpiffeWorkloadSnapshot",
)
