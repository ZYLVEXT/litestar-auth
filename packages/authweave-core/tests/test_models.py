"""Behavior tests for public authweave-core contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from authweave_core import (
    AuthenticationContext,
    AuthenticationEvidence,
    FailureCode,
    InvariantFailure,
    PrincipalRef,
    RequestView,
    RouteProviderPolicy,
    TlsPeerEvidence,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 7, 30, tzinfo=UTC)
_THUMBPRINT = "A" * 43


def test_principal_identity_is_issuer_and_subject() -> None:
    human = PrincipalRef("https://issuer.example", "subject-1", "human")
    service = PrincipalRef("https://issuer.example", "subject-1", "service")

    assert human == service
    assert len({human, service}) == 1
    assert human != object()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", ""),
        ("subject", " subject"),
        ("kind", "Not Valid"),
    ],
)
def test_principal_rejects_invalid_identity_components(field: str, value: str) -> None:
    values = {"issuer": "issuer", "subject": "subject", "kind": "service", field: value}

    with pytest.raises(ValueError, match="must"):
        PrincipalRef(**cast("dict[str, Any]", values))


def test_request_preserves_duplicate_headers_case_insensitively() -> None:
    request = RequestView(
        method="GET",
        headers=((b"Authorization", b"one"), (b"authorization", b"two")),
        timestamp=_NOW,
    )

    assert request.header_values(b"AUTHORIZATION") == (b"one", b"two")
    assert request.header_values(b"missing") == ()


def test_request_hides_credentials_and_bounds_headers() -> None:
    token = b"secret-session-token"
    request = RequestView(method="GET", headers=((b"cookie", token),), timestamp=_NOW)

    assert token.decode() not in repr(request)
    with pytest.raises(ValueError, match="projection limits"):
        RequestView(method="GET", headers=tuple((b"x", b"1") for _ in range(129)), timestamp=_NOW)


@pytest.mark.parametrize(
    ("method", "headers"),
    [
        ("G ET", ()),
        ("GÉT", ()),
        ("GET", ((b"", b"value"),)),
        ("GET", ((b"x-test", b"bad\rvalue"),)),
        ("GET", ((b"x-test", b"bad\nvalue"),)),
        ("GET", ((b"x-test", b"bad\x00value"),)),
    ],
)
def test_request_rejects_malformed_http_metadata(
    method: str,
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    with pytest.raises(ValueError, match="must"):
        RequestView(method=method, headers=headers, timestamp=_NOW)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scheme", ""),
        ("authority", " host"),
        ("correlation_id", ""),
    ],
)
def test_request_rejects_invalid_optional_text(field: str, value: str) -> None:
    values = {"method": "GET", "timestamp": _NOW, field: value}

    with pytest.raises(ValueError, match="must"):
        RequestView(**cast("dict[str, Any]", values))


def test_request_requires_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        RequestView(method="GET", timestamp=datetime(2026, 7, 30))


def test_tls_peer_evidence_validates_thumbprint_and_times() -> None:
    evidence = TlsPeerEvidence(
        tls_version="TLSv1.3",
        certificate_thumbprint=_THUMBPRINT,
        certificate_not_before=_NOW,
        certificate_not_after=_NOW + timedelta(hours=1),
        revocation_checked_at=_NOW,
        trust_anchor="ca:payments",
        termination_boundary="envoy:ingress",
    )

    assert evidence.certificate_thumbprint == _THUMBPRINT


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tls_version", ""),
        ("certificate_thumbprint", "not-a-thumbprint"),
        ("trust_anchor", ""),
        ("termination_boundary", ""),
        ("certificate_not_before", datetime(2026, 7, 30)),
        ("certificate_not_after", datetime(2026, 7, 30)),
        ("revocation_checked_at", datetime(2026, 7, 30)),
    ],
)
def test_tls_peer_evidence_rejects_invalid_fields(field: str, value: object) -> None:
    values = {
        "tls_version": "TLSv1.3",
        "certificate_thumbprint": _THUMBPRINT,
        "certificate_not_before": _NOW,
        "certificate_not_after": _NOW + timedelta(hours=1),
        "revocation_checked_at": _NOW,
        "trust_anchor": "ca:payments",
        "termination_boundary": "envoy:ingress",
        field: value,
    }

    with pytest.raises(ValueError, match="must"):
        TlsPeerEvidence(**values)


def test_tls_peer_evidence_rejects_reversed_validity() -> None:
    with pytest.raises(ValueError, match="earlier"):
        TlsPeerEvidence(
            tls_version="TLSv1.3",
            certificate_thumbprint=_THUMBPRINT,
            certificate_not_before=_NOW,
            certificate_not_after=_NOW,
            revocation_checked_at=_NOW,
            trust_anchor="ca:payments",
            termination_boundary="envoy:ingress",
        )


def test_authentication_evidence_is_bounded_and_immutable() -> None:
    extensions: dict[str, str | int | bool] = {
        "example:risk": "low",
        "example:score": 7,
        "example:reviewed": True,
    }
    evidence = AuthenticationEvidence(
        provider="service_mtls",
        profile="direct_mtls",
        method="mtls",
        issuer="urn:example:payments",
        audiences=("payments",),
        scopes=("payments.read",),
        issued_at=_NOW,
        not_before=_NOW,
        expires_at=_NOW + timedelta(hours=1),
        credential_id="credential-1",
        token_id="token-1",
        confirmation_thumbprint=_THUMBPRINT,
        environment="sandbox",
        extensions=extensions,
    )
    extensions["example:risk"] = "high"

    assert evidence.extensions == {
        "example:risk": "low",
        "example:score": 7,
        "example:reviewed": True,
    }
    with pytest.raises(TypeError):
        cast("dict[str, str | int | bool]", evidence.extensions)["example:risk"] = "high"


@pytest.mark.parametrize(
    ("field", "value", "exception"),
    [
        ("provider", "Not Valid", ValueError),
        ("audiences", ("",), ValueError),
        ("scopes", tuple(str(index) for index in range(65)), ValueError),
        ("issued_at", datetime(2026, 7, 30), ValueError),
        ("confirmation_thumbprint", "bad", ValueError),
        ("extensions", {"not-namespaced": "value"}, ValueError),
        ("extensions", {"example:value": object()}, TypeError),
        ("extensions", {f"example:{index}": index for index in range(17)}, ValueError),
    ],
)
def test_authentication_evidence_rejects_invalid_data(
    field: str,
    value: object,
    exception: type[Exception],
) -> None:
    values = {
        "provider": "service_mtls",
        "profile": "direct_mtls",
        "method": "mtls",
        "issuer": "urn:example:payments",
        field: value,
    }

    with pytest.raises(exception):
        AuthenticationEvidence(**cast("dict[str, Any]", values))


def test_authentication_evidence_rejects_reversed_time_window() -> None:
    with pytest.raises(ValueError, match="earlier"):
        AuthenticationEvidence(
            provider="service_mtls",
            profile="direct_mtls",
            method="mtls",
            issuer="urn:example:payments",
            not_before=_NOW,
            expires_at=_NOW,
        )


def test_context_and_route_policy_freeze_inputs() -> None:
    principal = PrincipalRef("issuer", "subject", "service")
    evidence = AuthenticationEvidence("provider", "profile", "mtls", "issuer")
    chain = [PrincipalRef("issuer", "actor", "agent")]
    context = AuthenticationContext(principal, chain[0], evidence, cast("tuple[PrincipalRef, ...]", chain))
    providers = ["provider"]
    policy = RouteProviderPolicy(cast("tuple[str, ...]", providers))
    chain.clear()
    providers.clear()

    assert len(context.delegation_chain) == 1
    assert policy.providers == ("provider",)
    assert InvariantFailure().code is FailureCode.INTERNAL_INVARIANT


def test_route_policy_rejects_invalid_or_duplicate_names() -> None:
    with pytest.raises(ValueError, match="must match"):
        RouteProviderPolicy(("Not Valid",))
    with pytest.raises(ValueError, match="at most one"):
        RouteProviderPolicy(("provider", "provider"))

    with pytest.raises(ValueError, match="at most one"):
        RouteProviderPolicy(("provider", "other"))
