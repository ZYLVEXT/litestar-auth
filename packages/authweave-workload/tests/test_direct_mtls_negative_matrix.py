"""Direct mTLS provider status, trust, and availability matrix."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    NotApplicable,
    PrincipalRef,
    RequestView,
    TlsPeerEvidence,
    Unavailable,
)
from authweave_workload.models import (
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ResolvedMachineIdentity,
    ServiceApplication,
)
from authweave_workload.provider import DirectMTLSPolicy, DirectMTLSProvider
from authweave_workload.stores import MachineCredentialStore, StoreUnavailableError

_THUMBPRINT = "A" * 43


def _resolved(now: datetime) -> ResolvedMachineIdentity:
    application = ServiceApplication("application", EntityStatus.ACTIVE, "sandbox", "team")
    principal = MachinePrincipal(
        "principal",
        application.id,
        PrincipalRef("urn:test", "worker", "workload"),
        EntityStatus.ACTIVE,
    )
    credential = MachineCredential(
        "credential",
        principal.id,
        CredentialStatus.ACTIVE,
        _THUMBPRINT,
        "ca",
        ("write",),
        ("api",),
        "sandbox",
        now - timedelta(minutes=1),
        now + timedelta(minutes=10),
        "CN=worker",
        "CN=ca",
        "01",
    )
    return ResolvedMachineIdentity(application, principal, credential)


def _peer(now: datetime, **changes: object) -> TlsPeerEvidence:
    values: dict[str, object] = {
        "certificate_not_after": now + timedelta(minutes=10),
        "certificate_not_before": now - timedelta(minutes=1),
        "certificate_thumbprint": _THUMBPRINT,
        "revocation_checked_at": now,
        "termination_boundary": "envoy",
        "tls_version": "TLSv1.3",
        "trust_anchor": "ca",
    }
    values.update(changes)
    return TlsPeerEvidence(**values)


class MatrixStore:
    """Controllable atomic resolver."""

    def __init__(
        self,
        resolved: ResolvedMachineIdentity | None,
        *,
        fail_resolve: bool = False,
        fail_last_used: bool = False,
    ) -> None:
        self.resolved = resolved
        self.fail_resolve = fail_resolve
        self.fail_last_used = fail_last_used

    async def resolve_by_thumbprint(self, thumbprint: str) -> ResolvedMachineIdentity | None:
        if self.fail_resolve:
            raise StoreUnavailableError
        return self.resolved

    async def record_last_used(self, credential_id: str, *, used_at_epoch: int, minimum_interval: int) -> None:
        if self.fail_last_used:
            raise StoreUnavailableError


def _provider(store: MatrixStore, *, event_callback: object = None) -> DirectMTLSProvider:
    return DirectMTLSProvider(
        name="direct",
        store=cast("MachineCredentialStore", store),
        policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
        event_callback=event_callback,  # ty: ignore[invalid-argument-type]
    )


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "options",
    [
        {"trust_anchors": frozenset()},
        {"termination_boundaries": frozenset()},
        {"maximum_revocation_age": timedelta(0)},
        {"last_used_minimum_interval_seconds": -1},
    ],
)
def test_direct_mtls_policy_rejects_unsafe_configuration(options: dict[str, object]) -> None:
    values: dict[str, object] = {
        "termination_boundaries": frozenset({"envoy"}),
        "trust_anchors": frozenset({"ca"}),
    }
    values.update(options)
    with pytest.raises(ValueError, match=r".+"):
        DirectMTLSPolicy(**values)  # ty: ignore[invalid-argument-type]


def test_direct_mtls_match_classifies_presentations() -> None:
    now = datetime.now(UTC)
    provider = _provider(MatrixStore(None))
    assert provider.match(RequestView("GET")) is CredentialMatch.NOT_APPLICABLE
    assert provider.match(RequestView("GET", tls_peer=_peer(now))) is CredentialMatch.OWNED
    assert (
        provider.match(
            RequestView(
                "GET",
                headers=((b"cookie", b"session=x"),),
                tls_peer=_peer(now),
            ),
        )
        is CredentialMatch.AMBIGUOUS
    )
    assert provider._validate_peer(RequestView("GET")) is FailureCode.MISSING


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"trust_anchor": "other"}, FailureCode.SENDER_CONSTRAINT_MISMATCH),
        ({"certificate_not_before": datetime(2030, 1, 1, tzinfo=UTC)}, FailureCode.NOT_YET_VALID),
        ({"certificate_not_after": datetime(2020, 1, 1, tzinfo=UTC)}, FailureCode.EXPIRED),
    ],
)
def test_direct_mtls_peer_trust_and_time_matrix(changes: dict[str, object], expected: FailureCode) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    if "certificate_not_before" in changes:
        changes["certificate_not_after"] = datetime(2031, 1, 1, tzinfo=UTC)
    if "certificate_not_after" in changes:
        changes.setdefault("certificate_not_before", datetime(2019, 1, 1, tzinfo=UTC))
    request = RequestView("GET", timestamp=now, tls_peer=_peer(now, **changes))
    assert _provider(MatrixStore(None))._validate_peer(request) is expected


async def test_direct_mtls_absence_unknown_and_store_outage_are_terminal() -> None:
    now = datetime.now(UTC)
    assert isinstance(
        await _provider(MatrixStore(None)).authenticate(RequestView("GET"), AuthenticationRuntime()),
        NotApplicable,
    )
    request = RequestView("GET", timestamp=now, tls_peer=_peer(now))
    assert await _provider(MatrixStore(None)).authenticate(request, AuthenticationRuntime()) == Invalid(
        FailureCode.INVALID,
    )
    assert isinstance(
        await _provider(MatrixStore(None, fail_resolve=True)).authenticate(request, AuthenticationRuntime()),
        Unavailable,
    )
    assert isinstance(
        await _provider(MatrixStore(_resolved(now), fail_last_used=True)).authenticate(
            request,
            AuthenticationRuntime(),
        ),
        Unavailable,
    )


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"application": {"status": EntityStatus.DISABLED}}, FailureCode.PRINCIPAL_DISABLED),
        ({"principal": {"status": EntityStatus.DISABLED}}, FailureCode.PRINCIPAL_DISABLED),
        ({"credential": {"status": CredentialStatus.PENDING}}, FailureCode.NOT_YET_VALID),
        (
            {
                "credential": {
                    "status": CredentialStatus.REVOKED,
                    "revoked_at": datetime(2026, 1, 1, tzinfo=UTC),
                    "revocation_reason": "operator",
                },
            },
            FailureCode.REVOKED,
        ),
        ({"credential": {"not_before": datetime(2030, 1, 1, tzinfo=UTC)}}, FailureCode.NOT_YET_VALID),
        ({"credential": {"expires_at": datetime(2020, 1, 1, tzinfo=UTC)}}, FailureCode.EXPIRED),
        ({"credential": {"environment": "live"}}, FailureCode.SENDER_CONSTRAINT_MISMATCH),
        ({"credential": {"trust_anchor": "other"}}, FailureCode.SENDER_CONSTRAINT_MISMATCH),
    ],
)
async def test_direct_mtls_entity_and_credential_status_matrix(
    change: dict[str, dict[str, object]],
    expected: FailureCode,
) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    resolved = _resolved(now)
    if "application" in change:
        resolved = replace(resolved, application=replace(resolved.application, **change["application"]))
    if "principal" in change:
        resolved = replace(resolved, principal=replace(resolved.principal, **change["principal"]))
    if "credential" in change:
        credential_changes = change["credential"]
        if "not_before" in credential_changes and "expires_at" not in credential_changes:
            credential_changes = {**credential_changes, "expires_at": datetime(2031, 1, 1, tzinfo=UTC)}
        if "expires_at" in credential_changes and "not_before" not in credential_changes:
            credential_changes = {**credential_changes, "not_before": datetime(2019, 1, 1, tzinfo=UTC)}
        resolved = replace(resolved, credential=replace(resolved.credential, **credential_changes))
    decision = await _provider(MatrixStore(resolved)).authenticate(
        RequestView("GET", timestamp=now, tls_peer=_peer(now)),
        AuthenticationRuntime(),
    )
    assert decision == Invalid(expected)


async def test_direct_mtls_success_supports_sync_event_callback() -> None:
    now = datetime.now(UTC)
    events: list[object] = []
    provider = _provider(MatrixStore(_resolved(now)), event_callback=events.append)
    decision = await provider.authenticate(
        RequestView("GET", timestamp=now, tls_peer=_peer(now)),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Authenticated)
    assert events


async def test_direct_mtls_success_supports_async_event_callback() -> None:
    now = datetime.now(UTC)
    events: list[object] = []

    async def _record(event: object) -> None:
        await asyncio.to_thread(events.append, event)

    provider = _provider(MatrixStore(_resolved(now)), event_callback=_record)
    decision = await provider.authenticate(
        RequestView("GET", timestamp=now, tls_peer=_peer(now)),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Authenticated)
    assert events


async def test_direct_mtls_callback_exception_fails_closed() -> None:
    """ADR 0001: a raised callback maps the terminal outcome to Unavailable."""
    now = datetime.now(UTC)

    def _raise(_event: object) -> None:
        raise RuntimeError

    provider = _provider(MatrixStore(_resolved(now)), event_callback=_raise)
    decision = await provider.authenticate(
        RequestView("GET", timestamp=now, tls_peer=_peer(now)),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Unavailable)


async def test_direct_mtls_callback_returning_unavailable_fails_closed() -> None:
    """ADR 0001: a returned Unavailable is a delivery failure, not a decision."""
    now = datetime.now(UTC)

    def _decline(_event: object) -> Unavailable:
        return Unavailable()

    provider = _provider(MatrixStore(_resolved(now)), event_callback=_decline)
    decision = await provider.authenticate(
        RequestView("GET", timestamp=now, tls_peer=_peer(now)),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Unavailable)


async def test_direct_mtls_failure_callback_exception_fails_closed() -> None:
    """A callback fault on a rejection path still fails closed to Unavailable."""
    now = datetime.now(UTC)

    def _raise(_event: object) -> None:
        raise RuntimeError

    provider = _provider(MatrixStore(None), event_callback=_raise)
    decision = await provider.authenticate(
        RequestView("GET", timestamp=now, tls_peer=_peer(now)),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Unavailable)
