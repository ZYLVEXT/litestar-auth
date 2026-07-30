"""Negative matrix for the external certificate-bound access-token profile."""

from __future__ import annotations

import asyncio
import builtins
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import jwt
import jwt.algorithms
import pytest
from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    InvariantFailure,
    RequestView,
    TlsPeerEvidence,
    Unavailable,
)
from authweave_workload import jwt as jwt_module
from authweave_workload.jwks import BoundedJWKSClient, JWKSUnavailableError, JWKSValidationError
from authweave_workload.jwt import MTLSBoundJWTProvider, TrustedIssuer
from authweave_workload.provider import DirectMTLSPolicy
from cryptography.hazmat.primitives.asymmetric import ec

_ISSUER = "https://issuer.test"
_AUDIENCE = "payments-api"
_KID = "key-1"
_THUMBPRINT = "A" * 43


def _key_and_jwks() -> tuple[ec.EllipticCurvePrivateKey, dict[str, object]]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"alg": "ES256", "kid": _KID, "use": "sig"})
    return key, {"keys": [jwk]}


def _claims(now: datetime) -> dict[str, object]:
    return {
        "aud": _AUDIENCE,
        "client_id": "client-1",
        "cnf": {"x5t#S256": _THUMBPRINT},
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "iss": _ISSUER,
        "jti": "token-1",
        "scope": "payments:read payments:write",
        "sub": "service-1",
    }


def _token(
    key: ec.EllipticCurvePrivateKey,
    now: datetime,
    *,
    claims: dict[str, object] | None = None,
    token_type: str = "at+jwt",
) -> str:
    return jwt.encode(
        _claims(now) if claims is None else claims,
        key,
        algorithm="ES256",
        headers={"kid": _KID, "typ": token_type},
    )


def _peer(now: datetime) -> TlsPeerEvidence:
    return TlsPeerEvidence(
        tls_version="TLSv1.3",
        certificate_thumbprint=_THUMBPRINT,
        certificate_not_before=now - timedelta(minutes=1),
        certificate_not_after=now + timedelta(minutes=10),
        revocation_checked_at=now,
        trust_anchor="ca",
        termination_boundary="envoy",
    )


def _request(token: str, now: datetime, *, peer: TlsPeerEvidence | None = None) -> RequestView:
    return RequestView(
        "POST",
        headers=((b"authorization", f"Bearer {token}".encode()),),
        timestamp=now,
        tls_peer=_peer(now) if peer is None else peer,
    )


def _provider(
    jwks: object,
    *,
    allow_actor: bool = False,
    delegation_policy: object = None,
    event_callback: object = None,
) -> MTLSBoundJWTProvider:
    return MTLSBoundJWTProvider(
        name="external",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=jwks,  # ty: ignore[invalid-argument-type]
            allow_rfc8693_actor=allow_actor,
        ),
        tls_policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
        delegation_policy=delegation_policy,  # ty: ignore[invalid-argument-type]
        event_callback=event_callback,  # ty: ignore[invalid-argument-type]
    )


@pytest.mark.parametrize(
    ("issuer_options", "message"),
    [
        ({"issuer": ""}, "explicit"),
        ({"audiences": frozenset()}, "explicit"),
        ({"algorithms": frozenset({"HS256"})}, "allowlist"),
        ({"clock_skew": timedelta(seconds=-1)}, "time policy"),
        ({"maximum_token_lifetime": timedelta(0)}, "time policy"),
        ({"principal_kind": "human"}, "kind"),
        ({"maximum_delegation_depth": 0}, "positive"),
    ],
)
def test_trusted_issuer_rejects_unsafe_policy(issuer_options: dict[str, object], message: str) -> None:
    """Issuer configuration cannot widen the modern resource-server profile."""
    _, jwks = _key_and_jwks()
    options: dict[str, object] = {
        "audiences": frozenset({_AUDIENCE}),
        "environment": "sandbox",
        "issuer": _ISSUER,
        "jwks": BoundedJWKSClient(static_jwks=jwks),
    }
    options.update(issuer_options)
    with pytest.raises(ValueError, match=message):
        TrustedIssuer(**options)  # ty: ignore[invalid-argument-type]


def test_jwt_audience_normalization_rejects_non_json_audience_shapes() -> None:
    """Only a JSON string or string array can become verified audience evidence."""
    assert jwt_module._validated_audiences(1, frozenset({_AUDIENCE})) is None


def test_jwt_provider_match_rejects_ambiguous_presentations() -> None:
    """Ownership routing distinguishes absence, wrong scheme, and collisions."""
    _, jwks = _key_and_jwks()
    provider = _provider(BoundedJWKSClient(static_jwks=jwks))
    assert provider.match(RequestView("GET", headers=((b"authorization", b"Bearer token"),))) is CredentialMatch.OWNED

    assert provider.match(RequestView("GET")) is CredentialMatch.NOT_APPLICABLE
    assert (
        provider.match(RequestView("GET", headers=((b"authorization", b"Basic value"),)))
        is CredentialMatch.NOT_APPLICABLE
    )
    assert (
        provider.match(
            RequestView(
                "GET",
                headers=((b"authorization", b"Bearer one"), (b"authorization", b"Bearer two")),
            ),
        )
        is CredentialMatch.AMBIGUOUS
    )
    assert (
        provider.match(
            RequestView("GET", headers=((b"authorization", b"Bearer one"), (b"cookie", b"session=x"))),
        )
        is CredentialMatch.AMBIGUOUS
    )
    assert provider.match(RequestView("GET", headers=((b"authorization", b"Bearer "),))) is CredentialMatch.OWNED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("peer_change", "expected"),
    [
        ({"tls_version": "TLSv1.2"}, Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)),
        ({"trust_anchor": "other"}, Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)),
        ({"termination_boundary": "other"}, Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)),
        (
            {
                "certificate_not_before": datetime(2019, 1, 1, tzinfo=UTC),
                "certificate_not_after": datetime(2020, 1, 1, tzinfo=UTC),
            },
            Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH),
        ),
        ({"revocation_checked_at": datetime(2020, 1, 1, tzinfo=UTC)}, Unavailable()),
        ({"revocation_checked_at": datetime(2100, 1, 1, tzinfo=UTC)}, InvariantFailure()),
    ],
)
async def test_jwt_provider_tls_negative_matrix(
    peer_change: dict[str, object],
    expected: Invalid | Unavailable | InvariantFailure,
) -> None:
    """JWT verification never bypasses trusted fresh TLS evidence."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    key, jwks = _key_and_jwks()
    peer = replace(_peer(now), **peer_change)

    decision = await _provider(BoundedJWKSClient(static_jwks=jwks)).authenticate(
        _request(_token(key, now), now, peer=peer),
        AuthenticationRuntime(),
    )

    assert decision == expected


@pytest.mark.asyncio
async def test_jwt_provider_rejects_missing_and_malformed_presentations() -> None:
    """Owned malformed credentials terminate as malformed."""
    now = datetime.now(UTC)
    _, jwks = _key_and_jwks()
    provider = _provider(BoundedJWKSClient(static_jwks=jwks))
    requests = (
        RequestView("GET"),
        RequestView("GET", headers=((b"authorization", b"Bearer not-a-jwt"),), timestamp=now, tls_peer=_peer(now)),
        RequestView("GET", headers=((b"authorization", b"Bearer \xff"),), timestamp=now, tls_peer=_peer(now)),
        RequestView(
            "GET",
            headers=((b"authorization", b"Bearer " + b"x" * 16_385),),
            timestamp=now,
            tls_peer=_peer(now),
        ),
    )
    for request in requests:
        assert await provider.authenticate(request, AuthenticationRuntime()) == Invalid(FailureCode.MALFORMED)


@pytest.mark.asyncio
async def test_jwt_provider_maps_jwks_outage_to_unavailable() -> None:
    """Trust-service outage is terminal and never anonymous."""

    class UnavailableKeys:
        async def get_key(self, kid: str, algorithm: str) -> object:
            raise JWKSUnavailableError

    now = datetime.now(UTC)
    key, _ = _key_and_jwks()
    decision = await _provider(UnavailableKeys()).authenticate(_request(_token(key, now), now), AuthenticationRuntime())
    assert isinstance(decision, Unavailable)


@pytest.mark.asyncio
async def test_jwt_header_key_and_signature_negative_matrix() -> None:
    class InvalidKeys:
        async def get_key(self, kid: str, algorithm: str) -> object:
            raise JWKSValidationError

    now = datetime.now(UTC)
    key, jwks = _key_and_jwks()
    algorithm_mismatch = _provider(BoundedJWKSClient(static_jwks=jwks))
    algorithm_mismatch.issuer = replace(algorithm_mismatch.issuer, algorithms=frozenset({"PS256"}))
    assert await algorithm_mismatch.authenticate(
        _request(_token(key, now), now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.ALGORITHM_MISMATCH)
    missing_kid = jwt.encode(_claims(now), key, algorithm="ES256", headers={"typ": "at+jwt"})
    assert await _provider(BoundedJWKSClient(static_jwks=jwks)).authenticate(
        _request(missing_kid, now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.MALFORMED)
    assert await _provider(InvalidKeys()).authenticate(
        _request(_token(key, now), now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.INVALID)
    header, payload, signature = _token(key, now).split(".")
    replacement = "A" if signature[0] != "A" else "B"
    corrupt = f"{header}.{payload}.{replacement}{signature[1:]}"
    assert await _provider(BoundedJWKSClient(static_jwks=jwks)).authenticate(
        _request(corrupt, now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.INVALID)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        ({"iss": "https://other.test"}, FailureCode.ISSUER_MISMATCH),
        ({"aud": "other"}, FailureCode.AUDIENCE_MISMATCH),
        ({"sub": ""}, FailureCode.INVALID),
        ({"client_id": ""}, FailureCode.INVALID),
        ({"jti": ""}, FailureCode.INVALID),
        ({"iat": "bad"}, FailureCode.INVALID),
        ({"iat": True}, FailureCode.INVALID),
        ({"iat": 10**30}, FailureCode.INVALID),
        ({"exp": 0}, FailureCode.EXPIRED),
        ({"scope": 1}, FailureCode.INVALID),
        ({"scope": "a a"}, FailureCode.INVALID),
        ({"scope": "payments:*"}, FailureCode.INVALID),
        ({"cnf": {}}, FailureCode.SENDER_CONSTRAINT_MISMATCH),
        ({"cnf": {"x5t#S256": _THUMBPRINT, "extra": "x"}}, FailureCode.SENDER_CONSTRAINT_MISMATCH),
        ({"cnf": {"x5t#S256": "short"}}, FailureCode.SENDER_CONSTRAINT_MISMATCH),
    ],
)
async def test_jwt_claim_negative_matrix(mutate: dict[str, object], expected: FailureCode) -> None:
    """Invalid signed claims fail with stable typed reasons."""
    now = datetime.now(UTC)
    key, jwks = _key_and_jwks()
    claims = _claims(now)
    claims.update(mutate)
    decision = await _provider(BoundedJWKSClient(static_jwks=jwks)).authenticate(
        _request(_token(key, now, claims=claims), now),
        AuthenticationRuntime(),
    )
    assert decision == Invalid(expected)


@pytest.mark.asyncio
async def test_jwt_time_and_scope_ceilings() -> None:
    """Future, excessive-lifetime, duplicate, and oversized claims fail closed."""
    now = datetime.now(UTC)
    key, jwks = _key_and_jwks()
    provider = _provider(BoundedJWKSClient(static_jwks=jwks))
    variants = (
        ({"iat": int((now + timedelta(minutes=2)).timestamp())}, FailureCode.NOT_YET_VALID),
        ({"nbf": int((now + timedelta(minutes=2)).timestamp())}, FailureCode.NOT_YET_VALID),
        ({"exp": int((now + timedelta(hours=1)).timestamp())}, FailureCode.INVALID),
        (
            {
                "iat": int(now.timestamp()),
                "exp": int(now.timestamp()),
            },
            FailureCode.INVALID,
        ),
        ({"scope": " ".join(f"s{index}" for index in range(65))}, FailureCode.INVALID),
        ({"sub": "x" * 513}, FailureCode.INVALID),
        ({"client_id": "x" * 257}, FailureCode.INVALID),
        ({"jti": "x" * 513}, FailureCode.INVALID),
        ({"aud": "x" * 513}, FailureCode.AUDIENCE_MISMATCH),
        ({"scope": "x" * 513}, FailureCode.INVALID),
        ({"cnf": {"x5t#S256": "!" * 43}}, FailureCode.SENDER_CONSTRAINT_MISMATCH),
    )
    for updates, expected in variants:
        claims = _claims(now)
        claims.update(updates)
        decision = await provider.authenticate(
            _request(_token(key, now, claims=claims), now),
            AuthenticationRuntime(),
        )
        assert decision == Invalid(expected)


@pytest.mark.asyncio
async def test_jwt_provider_maps_invalid_runtime_configuration_to_typed_failure() -> None:
    """Invalid provider projection never escapes as a model-construction exception."""
    now = datetime.now(UTC)
    key, jwks = _key_and_jwks()
    provider = _provider(BoundedJWKSClient(static_jwks=jwks))
    provider.issuer = replace(provider.issuer, principal_kind="Bad Kind")
    assert await provider.authenticate(
        _request(_token(key, now), now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.INVALID)

    provider = _provider(BoundedJWKSClient(static_jwks=jwks))
    provider.name = "Bad Name"
    assert await provider.authenticate(
        _request(_token(key, now), now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.INVALID)


@pytest.mark.asyncio
async def test_jwt_delegation_requires_trust_and_application_policy() -> None:
    """Signed actor data grants no authority without both explicit controls."""
    now = datetime.now(UTC)
    key, jwks = _key_and_jwks()
    claims = _claims(now)
    claims["act"] = {"sub": "agent-1", "scope": "payments:read"}
    token = _token(key, now, claims=claims)

    assert await _provider(BoundedJWKSClient(static_jwks=jwks)).authenticate(
        _request(token, now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.INVALID)
    assert await _provider(
        BoundedJWKSClient(static_jwks=jwks),
        allow_actor=True,
        delegation_policy=lambda _subject, _actor, _chain: False,
    ).authenticate(_request(token, now), AuthenticationRuntime()) == Invalid(FailureCode.INVALID)
    accepted = await _provider(
        BoundedJWKSClient(static_jwks=jwks),
        allow_actor=True,
        delegation_policy=lambda _subject, _actor, _chain: True,
    ).authenticate(_request(token, now), AuthenticationRuntime())
    assert isinstance(accepted, Authenticated)
    assert accepted.context.subject.subject == "service-1"
    assert accepted.context.actor.subject == "agent-1"
    assert accepted.context.evidence.scopes == ("payments:read",)
    claims["act"] = {"sub": ""}
    assert await _provider(
        BoundedJWKSClient(static_jwks=jwks),
        allow_actor=True,
        delegation_policy=lambda _subject, _actor, _chain: True,
    ).authenticate(
        _request(_token(key, now, claims=claims), now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.INVALID)


@pytest.mark.asyncio
async def test_jwt_async_event_and_optional_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(UTC)
    key, jwks = _key_and_jwks()
    events: list[object] = []

    async def record(event: object) -> None:
        await asyncio.sleep(0)
        events.append(event)

    claims = _claims(now)
    claims["exp"] = 0
    await _provider(BoundedJWKSClient(static_jwks=jwks), event_callback=record).authenticate(
        _request(_token(key, now, claims=claims), now),
        AuthenticationRuntime(),
    )
    assert events
    await _provider(BoundedJWKSClient(static_jwks=jwks), event_callback=events.append).authenticate(
        _request(_token(key, now, claims=claims), now),
        AuthenticationRuntime(),
    )

    original_import = builtins.__import__

    def reject(name: str, *args: object, **kwargs: object) -> object:
        if name == "jwt":
            raise ImportError
        return original_import(name, *args, **kwargs)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(builtins, "__import__", reject)
    with pytest.raises(ImportError, match=r"\[jwt\]"):
        jwt_module._load_jwt()
