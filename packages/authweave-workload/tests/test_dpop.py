"""RFC 9449 DPoP-bound access-token resource-server tests."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import jwt
import jwt.algorithms
import pytest
from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    InMemoryReplayStore,
    Invalid,
    ReplayOutcome,
    RequestView,
    SecurityOutcome,
    TlsPeerEvidence,
    Unavailable,
)
from authweave_workload.authorization_details import PAYMENT_AUTHORIZATION_TYPE, PaymentAuthorizationPolicy
from authweave_workload.dpop import (
    DPoPBoundJWTProvider,
    DPoPNonceChallenge,
    DPoPPolicy,
    InMemoryDPoPNonceStore,
    _access_token_hash,
    _jwk_thumbprint,
    _normalize_htu,
    _replay_outcome,
)
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.jwt import TrustedIssuer
from authweave_workload.redis_store import RedisDPoPNonceStore, RedisDPoPReplayStore
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

_ISSUER = "https://issuer.test"
_AUDIENCE = "payments-api"
_KID = "signing-1"


pytestmark = pytest.mark.unit


def test_capacity_replay_outcome_is_bounded_for_telemetry() -> None:
    assert _replay_outcome(ReplayOutcome.CAPACITY_EXCEEDED) is SecurityOutcome.CAPACITY_EXCEEDED


_TARGET = "https://api.test/payments"
_RS = "payments-rs"
_CONCURRENT_WORKERS = 32


class _Clock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


class _Redis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail = False

    async def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
        _ = ex
        if self.fail:
            msg = "down"
            raise ConnectionError(msg)
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def delete(self, key: str) -> int:
        if self.fail:
            msg = "down"
            raise ConnectionError(msg)
        return 1 if self.values.pop(key, None) is not None else 0


def _issuer_keys() -> tuple[ec.EllipticCurvePrivateKey, dict[str, object]]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": _KID, "alg": "ES256", "use": "sig"})
    return key, {"keys": [jwk]}


def _proof_key() -> tuple[ec.EllipticCurvePrivateKey, dict[str, str], str]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jkt = _jwk_thumbprint(jwk)
    return key, jwk, jkt


def _access_token(
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    jkt: str,
    now: datetime,
    token_type: str = "at+jwt",
    audience: str | list[str] = _AUDIENCE,
    claims: dict[str, object] | None = None,
    headers: dict[str, object] | None = None,
) -> str:
    payload: dict[str, object] = {
        "iss": _ISSUER,
        "sub": "service-1",
        "aud": audience,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": "token-1",
        "client_id": "client-1",
        "scope": "payments:read",
        "cnf": {"jkt": jkt},
    }
    if claims:
        payload.update(claims)
    return jwt.encode(
        payload,
        issuer_key,
        algorithm="ES256",
        headers={"kid": _KID, "typ": token_type, **(headers or {})},
    )


def _proof(
    proof_key: ec.EllipticCurvePrivateKey,
    proof_jwk: dict[str, str],
    *,
    access_token: str,
    now: datetime,
    method: str = "POST",
    htu: str = _TARGET,
    jti: str = "proof-1",
    extra_claims: dict[str, object] | None = None,
    header_overrides: dict[str, object] | None = None,
) -> str:
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": proof_jwk, **(header_overrides or {})}
    claims: dict[str, object] = {
        "jti": jti,
        "htm": method,
        "htu": htu,
        "iat": int(now.timestamp()),
        "ath": _access_token_hash(access_token),
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, proof_key, algorithm="ES256", headers=header)


def _request(
    *,
    access_token: str | None = None,
    proof: str | None = None,
    now: datetime | None = None,
    method: str = "POST",
    target_uri: str = _TARGET,
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
    tls_peer: TlsPeerEvidence | None = None,
) -> RequestView:
    headers: list[tuple[bytes, bytes]] = list(extra_headers)
    if access_token is not None:
        headers.append((b"authorization", f"DPoP {access_token}".encode()))
    if proof is not None:
        headers.append((b"dpop", proof.encode()))
    return RequestView(
        method=method,
        headers=tuple(headers),
        timestamp=now or datetime.now(UTC),
        target_uri=target_uri,
        tls_peer=tls_peer,
        correlation_id="corr-1",
    )


def _provider(
    jwks: dict[str, object],
    *,
    require_nonce: bool = False,
    nonce_store: InMemoryDPoPNonceStore | None = None,
    replay: InMemoryReplayStore | None = None,
    events: list[object] | None = None,
    payment_authorization: PaymentAuthorizationPolicy | None = None,
) -> DPoPBoundJWTProvider:
    return DPoPBoundJWTProvider(
        name="dpop_rs",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE, "reports-api"}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
            payment_authorization=payment_authorization,
        ),
        dpop=DPoPPolicy(
            resource_server_id=_RS,
            require_nonce=require_nonce,
            nonce_store=nonce_store,
        ),
        replay_store=replay or InMemoryReplayStore(capacity=32, time_source=_Clock()),
        event_callback=None if events is None else events.append,
    )


async def test_dpop_happy_path_and_replay() -> None:
    issuer_key, jwks = _issuer_keys()
    proof_key, proof_jwk, jkt = _proof_key()
    now = datetime.now(UTC).replace(microsecond=0)
    token = _access_token(issuer_key, jkt=jkt, now=now)
    policy = DPoPPolicy(resource_server_id=_RS)
    proof = _proof(
        proof_key,
        proof_jwk,
        access_token=token,
        now=now,
        extra_claims={"iat": int((now + policy.clock_skew).timestamp())},
    )
    clock = _Clock()
    provider = _provider(jwks, replay=InMemoryReplayStore(capacity=8, time_source=clock))

    decision = await provider.authenticate(_request(access_token=token, proof=proof, now=now), AuthenticationRuntime())
    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.confirmation_thumbprint == jkt
    assert decision.context.evidence.method == "dpop"
    assert decision.context.evidence.extensions["authweave-workload:client_id"] == "client-1"

    elapsed = policy.iat_window + 2 * policy.clock_skew
    clock.now = elapsed.total_seconds()
    replayed = await provider.authenticate(
        _request(access_token=token, proof=proof, now=now + elapsed),
        AuthenticationRuntime(),
    )
    assert replayed == Invalid(FailureCode.INVALID)


async def test_dpop_jwt_maps_typed_payment_authority_and_rejects_widening() -> None:
    """DPoP JWT evidence carries only payment authority consistent with verified scopes."""
    issuer_key, jwks = _issuer_keys()
    proof_key, proof_jwk, jkt = _proof_key()
    now = datetime.now(UTC)
    policy = PaymentAuthorizationPolicy(
        scope_actions={"payments:write": frozenset({"initiate"})},
        allowed_locations=frozenset({_TARGET}),
        currency_limits={"EUR": "500.00"},
    )

    def token(action: str) -> str:
        return _access_token(
            issuer_key,
            jkt=jkt,
            now=now,
            claims={
                "scope": "payments:write",
                "authorization_details": [
                    {
                        "type": PAYMENT_AUTHORIZATION_TYPE,
                        "actions": [action],
                        "locations": [_TARGET],
                        "instructedAmount": {"currency": "EUR", "amount": "125.50"},
                    }
                ],
            },
        )

    provider = _provider(jwks, payment_authorization=policy)
    valid = token("initiate")
    decision = await provider.authenticate(
        _request(access_token=valid, proof=_proof(proof_key, proof_jwk, access_token=valid, now=now), now=now),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.authorization_details[0]["type"] == PAYMENT_AUTHORIZATION_TYPE

    widened = token("refund")
    assert await provider.authenticate(
        _request(
            access_token=widened,
            proof=_proof(proof_key, proof_jwk, access_token=widened, now=now, jti="proof-widened"),
            now=now,
        ),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.INVALID)


async def test_dpop_match_ownership_matrix() -> None:
    _, jwks = _issuer_keys()
    provider = _provider(jwks)
    assert provider.match(RequestView("GET")) is CredentialMatch.NOT_APPLICABLE
    assert provider.match(_request(access_token="t", proof="p")) is CredentialMatch.OWNED
    assert provider.match(_request(access_token="t")) is CredentialMatch.OWNED
    assert provider.match(_request(proof="p")) is CredentialMatch.OWNED
    assert (
        provider.match(RequestView("GET", headers=((b"authorization", b"Bearer t"),))) is CredentialMatch.NOT_APPLICABLE
    )
    assert (
        provider.match(RequestView("GET", headers=((b"authorization", b"Bearer t"), (b"dpop", b"p"))))
        is CredentialMatch.AMBIGUOUS
    )
    assert (
        provider.match(RequestView("GET", headers=((b"authorization", b"Basic x"), (b"dpop", b"p"))))
        is CredentialMatch.NOT_APPLICABLE
    )
    assert (
        provider.match(
            RequestView(
                "GET",
                headers=((b"authorization", b"DPoP t"), (b"authorization", b"DPoP u"), (b"dpop", b"p")),
            )
        )
        is CredentialMatch.AMBIGUOUS
    )
    assert (
        provider.match(
            RequestView("GET", headers=((b"authorization", b"DPoP t"), (b"cookie", b"a=b"), (b"dpop", b"p")))
        )
        is CredentialMatch.AMBIGUOUS
    )
    peer = TlsPeerEvidence(
        tls_version="TLSv1.3",
        certificate_thumbprint="A" * 43,
        certificate_not_before=datetime.now(UTC) - timedelta(minutes=1),
        certificate_not_after=datetime.now(UTC) + timedelta(minutes=10),
        revocation_checked_at=datetime.now(UTC),
        trust_anchor="ca",
        termination_boundary="envoy",
    )
    assert provider.match(_request(access_token="t", proof="p", tls_peer=peer)) is CredentialMatch.AMBIGUOUS


async def test_dpop_negative_matrix() -> None:
    issuer_key, jwks = _issuer_keys()
    proof_key, proof_jwk, jkt = _proof_key()
    now = datetime.now(UTC)
    provider = _provider(jwks)
    runtime = AuthenticationRuntime()

    assert await provider.authenticate(_request(access_token="t"), runtime) == Invalid(FailureCode.MALFORMED)

    token = _access_token(issuer_key, jkt=jkt, now=now)
    bad_typ = _proof(proof_key, proof_jwk, access_token=token, now=now, header_overrides={"typ": "JWT"})
    assert await provider.authenticate(_request(access_token=token, proof=bad_typ, now=now), runtime) == Invalid(
        FailureCode.TOKEN_TYPE_MISMATCH
    )

    none_proof = ".".join([
        base64
        .urlsafe_b64encode(json.dumps({"typ": "dpop+jwt", "alg": "none", "jwk": proof_jwk}).encode())
        .rstrip(b"=")
        .decode(),
        base64
        .urlsafe_b64encode(
            json.dumps({
                "jti": "x",
                "htm": "POST",
                "htu": _TARGET,
                "iat": int(now.timestamp()),
                "ath": _access_token_hash(token),
            }).encode()
        )
        .rstrip(b"=")
        .decode(),
        "",
    ])
    assert await provider.authenticate(_request(access_token=token, proof=none_proof, now=now), runtime) == Invalid(
        FailureCode.ALGORITHM_MISMATCH
    )

    crit = _proof(proof_key, proof_jwk, access_token=token, now=now, header_overrides={"crit": ["b64"]})
    assert await provider.authenticate(_request(access_token=token, proof=crit, now=now), runtime) == Invalid(
        FailureCode.MALFORMED
    )

    private = dict(proof_jwk)
    private["d"] = "secret"
    with_private = _proof(proof_key, private, access_token=token, now=now)
    assert await provider.authenticate(_request(access_token=token, proof=with_private, now=now), runtime) == Invalid(
        FailureCode.MALFORMED
    )

    wrong_method = _proof(proof_key, proof_jwk, access_token=token, now=now, method="GET")
    assert await provider.authenticate(_request(access_token=token, proof=wrong_method, now=now), runtime) == Invalid(
        FailureCode.SENDER_CONSTRAINT_MISMATCH
    )

    wrong_htu = _proof(proof_key, proof_jwk, access_token=token, now=now, htu="https://evil.test/payments")
    assert await provider.authenticate(_request(access_token=token, proof=wrong_htu, now=now), runtime) == Invalid(
        FailureCode.SENDER_CONSTRAINT_MISMATCH
    )

    wrong_ath = _proof(proof_key, proof_jwk, access_token=token, now=now, extra_claims={"ath": "A" * 43})
    assert await provider.authenticate(_request(access_token=token, proof=wrong_ath, now=now), runtime) == Invalid(
        FailureCode.SENDER_CONSTRAINT_MISMATCH
    )

    future = _proof(
        proof_key,
        proof_jwk,
        access_token=token,
        now=now,
        extra_claims={"iat": int((now + timedelta(minutes=5)).timestamp())},
    )
    assert await provider.authenticate(_request(access_token=token, proof=future, now=now), runtime) == Invalid(
        FailureCode.NOT_YET_VALID
    )

    stale = _proof(
        proof_key,
        proof_jwk,
        access_token=token,
        now=now,
        extra_claims={"iat": int((now - timedelta(minutes=10)).timestamp())},
    )
    assert await provider.authenticate(_request(access_token=token, proof=stale, now=now), runtime) == Invalid(
        FailureCode.EXPIRED
    )

    wrong_jkt_token = _access_token(issuer_key, jkt="B" * 43, now=now)
    proof = _proof(proof_key, proof_jwk, access_token=wrong_jkt_token, now=now)
    assert await provider.authenticate(
        _request(access_token=wrong_jkt_token, proof=proof, now=now),
        runtime,
    ) == Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)

    wrong_type = _access_token(issuer_key, jkt=jkt, now=now, token_type="JWT")
    proof = _proof(proof_key, proof_jwk, access_token=wrong_type, now=now)
    assert await provider.authenticate(_request(access_token=wrong_type, proof=proof, now=now), runtime) == Invalid(
        FailureCode.TOKEN_TYPE_MISMATCH
    )

    wrong_aud = _access_token(issuer_key, jkt=jkt, now=now, audience="other-api")
    proof = _proof(proof_key, proof_jwk, access_token=wrong_aud, now=now)
    assert await provider.authenticate(_request(access_token=wrong_aud, proof=proof, now=now), runtime) == Invalid(
        FailureCode.AUDIENCE_MISMATCH
    )

    wildcard = _access_token(issuer_key, jkt=jkt, now=now, claims={"scope": "payments:*"})
    proof = _proof(proof_key, proof_jwk, access_token=wildcard, now=now)
    assert await provider.authenticate(_request(access_token=wildcard, proof=proof, now=now), runtime) == Invalid(
        FailureCode.INVALID
    )


async def test_dpop_nonce_required_and_challenge_headers() -> None:
    issuer_key, jwks = _issuer_keys()
    proof_key, proof_jwk, jkt = _proof_key()
    now = datetime.now(UTC)
    clock = _Clock()
    nonce_store = InMemoryDPoPNonceStore(capacity=8, time_source=clock)
    provider = _provider(jwks, require_nonce=True, nonce_store=nonce_store)
    token = _access_token(issuer_key, jkt=jkt, now=now)
    missing = _proof(proof_key, proof_jwk, access_token=token, now=now)
    assert await provider.authenticate(
        _request(access_token=token, proof=missing, now=now), AuthenticationRuntime()
    ) == Invalid(FailureCode.MALFORMED)

    nonce = await nonce_store.issue(origin=_TARGET, jkt=jkt)
    ok = _proof(proof_key, proof_jwk, access_token=token, now=now, jti="proof-nonce", extra_claims={"nonce": nonce})
    decision = await provider.authenticate(_request(access_token=token, proof=ok, now=now), AuthenticationRuntime())
    assert isinstance(decision, Authenticated)

    reused = _proof(
        proof_key, proof_jwk, access_token=token, now=now, jti="proof-nonce-2", extra_claims={"nonce": nonce}
    )
    assert await provider.authenticate(
        _request(access_token=token, proof=reused, now=now), AuthenticationRuntime()
    ) == Invalid(FailureCode.INVALID)

    challenge = DPoPNonceChallenge("abc")
    assert challenge.www_authenticate() == 'DPoP error="use_dpop_nonce"'
    assert challenge.response_headers() == {"DPoP-Nonce": "abc", "Cache-Control": "no-store"}


async def test_dpop_htu_strips_query_and_default_port() -> None:
    assert _normalize_htu("https://API.TEST:443/payments?x=1") == "https://api.test/payments"
    assert _normalize_htu("https://api.test:8443/payments") == "https://api.test:8443/payments"
    assert _normalize_htu(None) is None
    assert _normalize_htu("http://api.test/payments") is None

    issuer_key, jwks = _issuer_keys()
    proof_key, proof_jwk, jkt = _proof_key()
    now = datetime.now(UTC)
    provider = _provider(jwks)
    token = _access_token(issuer_key, jkt=jkt, now=now)
    proof = _proof(proof_key, proof_jwk, access_token=token, now=now, htu="https://api.test/payments")
    decision = await provider.authenticate(
        _request(access_token=token, proof=proof, now=now, target_uri="https://api.test/payments?trace=1"),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Authenticated)


async def test_dpop_policy_and_nonce_store_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="resource_server_id"):
        DPoPPolicy(resource_server_id="")
    with pytest.raises(ValueError, match="algorithms"):
        DPoPPolicy(resource_server_id=_RS, algorithms=frozenset({"HS256"}))
    with pytest.raises(ValueError, match="time policy"):
        DPoPPolicy(resource_server_id=_RS, iat_window=timedelta(0))
    with pytest.raises(ValueError, match="nonce_store"):
        DPoPPolicy(resource_server_id=_RS, require_nonce=True)
    with pytest.raises(ValueError, match="capacity"):
        InMemoryDPoPNonceStore(capacity=0, time_source=_Clock())

    from authweave_workload import dpop as dpop_mod

    clock = _Clock()
    generated = iter(("nonce-1", "nonce-2"))
    monkeypatch.setattr(dpop_mod.secrets, "token_urlsafe", lambda _size: next(generated))
    store = InMemoryDPoPNonceStore(capacity=2, time_source=clock)
    first = await store.issue(origin=_TARGET, jkt="A" * 43)
    second = await store.issue(origin=_TARGET, jkt="A" * 43)
    assert first != second

    monkeypatch.setattr(dpop_mod.secrets, "token_urlsafe", lambda _size: "collision")
    collision_store = InMemoryDPoPNonceStore(capacity=2, time_source=clock)
    await collision_store.issue(origin=_TARGET, jkt="A" * 43)
    with pytest.raises(RuntimeError, match="collision"):
        await collision_store.issue(origin=_TARGET, jkt="A" * 43)

    with pytest.raises(TypeError):
        await cast("Any", store).issue(origin=_TARGET)

    store = InMemoryDPoPNonceStore(capacity=1, time_source=clock)
    await store.issue(origin=_TARGET, jkt="A" * 43)
    clock.now = 200.0
    await store.issue(origin=_TARGET, jkt="A" * 43)
    clock.now = 0.0
    store2 = InMemoryDPoPNonceStore(capacity=1, time_source=clock)
    await store2.issue(origin=_TARGET, jkt="A" * 43)
    with pytest.raises(RuntimeError, match="capacity"):
        await store2.issue(origin=_TARGET, jkt="A" * 43)


async def test_dpop_replay_store_unavailable() -> None:
    issuer_key, jwks = _issuer_keys()
    proof_key, proof_jwk, jkt = _proof_key()
    now = datetime.now(UTC)

    class _Broken:
        async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
            _ = key, ttl_seconds
            return ReplayOutcome.UNAVAILABLE

    provider = DPoPBoundJWTProvider(
        name="dpop_rs",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
        ),
        dpop=DPoPPolicy(resource_server_id=_RS),
        replay_store=cast("Any", _Broken()),
    )
    token = _access_token(issuer_key, jkt=jkt, now=now)
    proof = _proof(proof_key, proof_jwk, access_token=token, now=now)
    assert (
        await provider.authenticate(_request(access_token=token, proof=proof, now=now), AuthenticationRuntime())
        == Unavailable()
    )


async def test_redis_dpop_stores() -> None:
    redis = _Redis()
    replay = RedisDPoPReplayStore(redis)
    assert await replay.check_and_store("dpop:a", ttl_seconds=30) is ReplayOutcome.STORED
    assert await replay.check_and_store("dpop:a", ttl_seconds=30) is ReplayOutcome.REPLAY
    with pytest.raises(ValueError):
        await replay.check_and_store("dpop:b", ttl_seconds=0)
    redis.fail = True
    assert await replay.check_and_store("dpop:c", ttl_seconds=30) is ReplayOutcome.UNAVAILABLE

    redis.fail = False
    nonce_store = RedisDPoPNonceStore(redis, ttl_seconds=60)
    with pytest.raises(ValueError):
        RedisDPoPNonceStore(redis, ttl_seconds=0)
    nonce = await nonce_store.issue(origin=_TARGET, jkt="A" * 43)
    assert await nonce_store.consume(origin=_TARGET, jkt="A" * 43, nonce=nonce) is ReplayOutcome.STORED
    assert await nonce_store.consume(origin=_TARGET, jkt="A" * 43, nonce=nonce) is ReplayOutcome.REPLAY
    redis.fail = True
    with pytest.raises(RuntimeError, match="unavailable"):
        await nonce_store.issue(origin=_TARGET, jkt="A" * 43)
    assert await nonce_store.consume(origin=_TARGET, jkt="A" * 43, nonce="x") is ReplayOutcome.UNAVAILABLE


async def test_redis_dpop_stores_are_atomic_across_concurrent_workers() -> None:
    redis = _Redis()
    replay_outcomes = await asyncio.gather(
        *(
            RedisDPoPReplayStore(redis).check_and_store("dpop:workers:one", ttl_seconds=90)
            for _ in range(_CONCURRENT_WORKERS)
        )
    )
    assert replay_outcomes.count(ReplayOutcome.STORED) == 1
    assert replay_outcomes.count(ReplayOutcome.REPLAY) == _CONCURRENT_WORKERS - 1

    nonce_store = RedisDPoPNonceStore(redis)
    nonce = await nonce_store.issue(origin=_TARGET, jkt="A" * 43)
    nonce_outcomes = await asyncio.gather(
        *(nonce_store.consume(origin=_TARGET, jkt="A" * 43, nonce=nonce) for _ in range(_CONCURRENT_WORKERS))
    )
    assert nonce_outcomes.count(ReplayOutcome.STORED) == 1
    assert nonce_outcomes.count(ReplayOutcome.REPLAY) == _CONCURRENT_WORKERS - 1


async def test_dpop_eddsa_proof_and_async_event_callback() -> None:
    issuer_key, jwks = _issuer_keys()
    proof_key = ed25519.Ed25519PrivateKey.generate()
    proof_jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(proof_key.public_key()))
    jkt = _jwk_thumbprint(proof_jwk)
    now = datetime.now(UTC)
    events: list[object] = []

    async def _cb(event: object) -> None:
        events.append(event)

    provider = DPoPBoundJWTProvider(
        name="dpop_rs",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
        ),
        dpop=DPoPPolicy(resource_server_id=_RS, algorithms=frozenset({"EdDSA", "ES256"})),
        replay_store=InMemoryReplayStore(capacity=8, time_source=_Clock()),
        event_callback=_cb,
    )
    token = _access_token(issuer_key, jkt=jkt, now=now)
    proof = jwt.encode(
        {
            "jti": "ed-proof",
            "htm": "POST",
            "htu": _TARGET,
            "iat": int(now.timestamp()),
            "ath": _access_token_hash(token),
        },
        proof_key,
        algorithm="EdDSA",
        headers={"typ": "dpop+jwt", "alg": "EdDSA", "jwk": proof_jwk},
    )
    decision = await provider.authenticate(_request(access_token=token, proof=proof, now=now), AuthenticationRuntime())
    assert isinstance(decision, Authenticated)
    assert events


async def test_dpop_callback_failure_fails_closed() -> None:
    """ADR 0001: a raised event callback maps the outcome to Unavailable."""
    _issuer_key, jwks = _issuer_keys()

    def _raise(_event: object) -> None:
        raise RuntimeError

    provider = DPoPBoundJWTProvider(
        name="dpop_rs",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
        ),
        dpop=DPoPPolicy(resource_server_id=_RS),
        replay_store=InMemoryReplayStore(capacity=4, time_source=_Clock()),
        event_callback=_raise,
    )
    decision = await provider.authenticate(_request(access_token="t"), AuthenticationRuntime())
    assert isinstance(decision, Unavailable)


async def test_litestar_dpop_extension_wiring() -> None:
    from authweave_workload.integrations.litestar import (
        DPoPBoundJWTProviderConfig,
        WorkloadAuthExtension,
        raise_dpop_nonce_challenge,
    )
    from litestar.exceptions import NotAuthorizedException

    _, jwks = _issuer_keys()
    settings = DPoPBoundJWTProviderConfig(
        name="dpop",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
        ),
        dpop=DPoPPolicy(resource_server_id=_RS),
        replay_store=InMemoryReplayStore(capacity=4, time_source=_Clock()),
    )
    extension = WorkloadAuthExtension(
        tls_peer_evidence_factory=lambda _scope: None,
        dpop_bound_jwt=(settings,),
        allow_unaudited=True,
    )
    registered: dict[str, object] = {}

    class _Ctx:
        backend_names: frozenset[str] = frozenset()

        def add_tls_peer_evidence_factory(self, *_args: object, **_kwargs: object) -> None:
            return None

        def add_authentication_provider(self, *_args: object, **kwargs: object) -> None:
            registered["provider"] = kwargs

        def add_openapi_security_scheme(self, *_args: object, **kwargs: object) -> None:
            registered["scheme"] = kwargs

    extension.validate(cast("Any", _Ctx()))
    extension.register(cast("Any", _Ctx()))
    factory = cast("Any", registered["provider"])["factory"]
    binding = factory(SimpleNamespace())
    assert binding.provider.profile == "dpop_bound_access_token"

    with pytest.raises(NotAuthorizedException) as exc:
        raise_dpop_nonce_challenge("nonce-1")
    assert exc.value.headers is not None
    assert exc.value.headers["DPoP-Nonce"] == "nonce-1"
    assert "use_dpop_nonce" in exc.value.headers["WWW-Authenticate"]

    with pytest.raises(ValueError, match="at most one"):
        WorkloadAuthExtension(
            tls_peer_evidence_factory=lambda _scope: None,
            dpop_bound_jwt=(settings, settings),
        ).validate(cast("Any", _Ctx()))


async def test_dpop_validation_edge_cases() -> None:
    from authweave_workload import dpop as dpop_mod
    from authweave_workload.jwks import JWKSUnavailableError, JWKSValidationError

    issuer_key, jwks = _issuer_keys()
    proof_key, proof_jwk, jkt = _proof_key()
    now = datetime.now(UTC)
    runtime = AuthenticationRuntime()

    class _NonceUnavailable:
        async def issue(self, *, origin: str, jkt: str) -> str:
            _ = origin, jkt
            return "n"

        async def consume(self, *, origin: str, jkt: str, nonce: str) -> ReplayOutcome:
            _ = origin, jkt, nonce
            return ReplayOutcome.UNAVAILABLE

    provider = DPoPBoundJWTProvider(
        name="dpop_rs",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
        ),
        dpop=DPoPPolicy(resource_server_id=_RS, require_nonce=True, nonce_store=cast("Any", _NonceUnavailable())),
        replay_store=InMemoryReplayStore(capacity=8, time_source=_Clock()),
    )
    token = _access_token(issuer_key, jkt=jkt, now=now)
    proof = _proof(proof_key, proof_jwk, access_token=token, now=now, extra_claims={"nonce": "n"})
    assert await provider.authenticate(_request(access_token=token, proof=proof, now=now), runtime) == Unavailable()

    provider2 = _provider(jwks)
    proof2 = _proof(proof_key, proof_jwk, access_token=token, now=now)
    bare = RequestView(
        method="POST",
        headers=((b"authorization", f"DPoP {token}".encode()), (b"dpop", proof2.encode())),
        timestamp=now,
    )
    assert await provider2.authenticate(bare, runtime) == Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)

    assert await provider2.authenticate(
        _request(access_token=token, proof="not-a-jwt", now=now),
        runtime,
    ) == Invalid(FailureCode.MALFORMED)
    no_jwk = jwt.encode(
        {"jti": "x", "htm": "POST", "htu": _TARGET, "iat": int(now.timestamp()), "ath": _access_token_hash(token)},
        proof_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "alg": "ES256"},
    )
    assert await provider2.authenticate(_request(access_token=token, proof=no_jwk, now=now), runtime) == Invalid(
        FailureCode.MALFORMED
    )
    huge = "a" * 20_000
    assert await provider2.authenticate(_request(access_token=huge, proof=huge, now=now), runtime) == Invalid(
        FailureCode.MALFORMED
    )
    assert (
        dpop_mod._extract_presentation(
            RequestView(
                "POST",
                headers=((b"authorization", b"DPoP \xff"), (b"dpop", b"proof")),
                timestamp=now,
                target_uri=_TARGET,
            )
        )
        is None
    )
    assert (
        dpop_mod._extract_presentation(
            RequestView(
                "POST",
                headers=((b"authorization", b"DPoPt"), (b"dpop", b"p")),
                timestamp=now,
                target_uri=_TARGET,
            )
        )
        is None
    )

    class _Jwks:
        async def get_key(self, kid: str, algorithm: str) -> object:
            _ = kid, algorithm
            raise JWKSUnavailableError

    provider3 = DPoPBoundJWTProvider(
        name="dpop_rs",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=cast("Any", _Jwks()),
        ),
        dpop=DPoPPolicy(resource_server_id=_RS),
        replay_store=InMemoryReplayStore(capacity=8, time_source=_Clock()),
    )
    assert await provider3.authenticate(_request(access_token=token, proof=proof2, now=now), runtime) == Unavailable()

    class _JwksBad:
        async def get_key(self, kid: str, algorithm: str) -> object:
            _ = kid, algorithm
            raise JWKSValidationError("bad")

    provider4 = DPoPBoundJWTProvider(
        name="dpop_rs",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=cast("Any", _JwksBad()),
        ),
        dpop=DPoPPolicy(resource_server_id=_RS),
        replay_store=InMemoryReplayStore(capacity=8, time_source=_Clock()),
    )
    assert await provider4.authenticate(_request(access_token=token, proof=proof2, now=now), runtime) == Invalid(
        FailureCode.INVALID
    )

    bad_iss = _access_token(issuer_key, jkt=jkt, now=now, claims={"iss": "https://evil.test"})
    proof_iss = _proof(proof_key, proof_jwk, access_token=bad_iss, now=now)
    assert await provider2.authenticate(_request(access_token=bad_iss, proof=proof_iss, now=now), runtime) == Invalid(
        FailureCode.ISSUER_MISMATCH
    )

    no_kid = jwt.encode(
        {
            "iss": _ISSUER,
            "sub": "s",
            "aud": _AUDIENCE,
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": "t",
            "client_id": "c",
            "cnf": {"jkt": jkt},
        },
        issuer_key,
        algorithm="ES256",
        headers={"typ": "at+jwt"},
    )
    proof_kid = _proof(proof_key, proof_jwk, access_token=no_kid, now=now)
    assert await provider2.authenticate(_request(access_token=no_kid, proof=proof_kid, now=now), runtime) == Invalid(
        FailureCode.MALFORMED
    )

    req = _request(access_token=token, proof=proof2, now=now)
    issuer = TrustedIssuer(
        issuer=_ISSUER,
        audiences=frozenset({_AUDIENCE}),
        environment="sandbox",
        jwks=BoundedJWKSClient(static_jwks=jwks),
    )
    base_claims: dict[str, object] = {
        "sub": "service-1",
        "client_id": "client-1",
        "jti": "token-1",
        "aud": _AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "cnf": {"jkt": jkt},
        "scope": "payments:read",
    }
    assert (
        dpop_mod._validate_dpop_token_claims({**base_claims, "sub": " "}, request=req, issuer=issuer, expected_jkt=jkt)
        == FailureCode.INVALID
    )
    assert (
        dpop_mod._validate_dpop_token_claims({**base_claims, "aud": 1}, request=req, issuer=issuer, expected_jkt=jkt)
        == FailureCode.AUDIENCE_MISMATCH
    )
    assert (
        dpop_mod._validate_dpop_token_claims({**base_claims, "iat": True}, request=req, issuer=issuer, expected_jkt=jkt)
        == FailureCode.INVALID
    )
    assert (
        dpop_mod._validate_dpop_token_claims(
            {**base_claims, "exp": int((now - timedelta(minutes=5)).timestamp())},
            request=req,
            issuer=issuer,
            expected_jkt=jkt,
        )
        == FailureCode.EXPIRED
    )
    assert (
        dpop_mod._validate_dpop_token_claims(
            {**base_claims, "nbf": int((now + timedelta(minutes=5)).timestamp())},
            request=req,
            issuer=issuer,
            expected_jkt=jkt,
        )
        == FailureCode.NOT_YET_VALID
    )
    assert (
        dpop_mod._validate_dpop_token_claims(
            {**base_claims, "exp": int(now.timestamp())},
            request=req,
            issuer=issuer,
            expected_jkt=jkt,
        )
        == FailureCode.INVALID
    )
    assert (
        dpop_mod._validate_dpop_token_claims(
            {**base_claims, "scope": ["x"]},
            request=req,
            issuer=issuer,
            expected_jkt=jkt,
        )
        == FailureCode.INVALID
    )
    assert dpop_mod._validated_audiences([], frozenset({_AUDIENCE})) is None
    assert dpop_mod._validated_audiences([_AUDIENCE, _AUDIENCE], frozenset({_AUDIENCE})) is None
    assert dpop_mod._validated_audiences([_AUDIENCE, "reports-api"], frozenset({_AUDIENCE})) is None

    with pytest.raises(ValueError, match="alg"):
        dpop_mod._assert_jwk_algorithm({**proof_jwk, "alg": "EdDSA"}, "ES256")
    with pytest.raises(ValueError, match="EC P-256"):
        dpop_mod._assert_jwk_algorithm({"kty": "EC", "crv": "P-384", "x": "a", "y": "b"}, "ES256")
    with pytest.raises(ValueError, match="EdDSA"):
        dpop_mod._assert_jwk_algorithm({"kty": "OKP", "crv": "Ed448", "x": "a"}, "EdDSA")
    with pytest.raises(ValueError, match="unsupported algorithm"):
        dpop_mod._assert_jwk_algorithm(proof_jwk, "PS256")
    with pytest.raises(ValueError, match="unexpected"):
        dpop_mod._assert_jwk_algorithm({**proof_jwk, "extra": "no"}, "ES256")
    with pytest.raises(ValueError, match="unsupported JWK kty"):
        dpop_mod._jwk_thumbprint({"kty": "RSA", "n": "1", "e": "AQAB"})
    assert dpop_mod._normalize_htu("https://user:pass@api.test/payments") is None
    assert dpop_mod._normalize_htu("https://api.test") == "https://api.test/"

    bad_claim_proof = _proof(proof_key, proof_jwk, access_token=token, now=now, jti="  ")
    assert await provider2.authenticate(
        _request(access_token=token, proof=bad_claim_proof, now=now),
        runtime,
    ) == Invalid(FailureCode.MALFORMED)

    real_evidence = dpop_mod.AuthenticationEvidence

    def _raise(*_a: object, **_k: object) -> None:
        raise ValueError("bad evidence")

    cast("Any", dpop_mod).AuthenticationEvidence = _raise
    try:
        provider5 = _provider(jwks, replay=InMemoryReplayStore(capacity=8, time_source=_Clock()))
        ok_token = _access_token(issuer_key, jkt=jkt, now=now, claims={"jti": "tok-ev"})
        ok_proof = _proof(proof_key, proof_jwk, access_token=ok_token, now=now, jti="proof-ev")
        assert await provider5.authenticate(
            _request(access_token=ok_token, proof=ok_proof, now=now),
            runtime,
        ) == Invalid(FailureCode.INVALID)
    finally:
        cast("Any", dpop_mod).AuthenticationEvidence = real_evidence

    class _Collide(_Redis):
        async def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
            _ = key, value, nx, ex
            return False

    with pytest.raises(RuntimeError, match="collision"):
        await RedisDPoPNonceStore(_Collide()).issue(origin=_TARGET, jkt="A" * 43)

    token_app = _access_token(
        issuer_key,
        jkt=jkt,
        now=now,
        token_type="application/at+jwt",
        claims={"nbf": int(now.timestamp())},
    )
    proof_app = _proof(proof_key, proof_jwk, access_token=token_app, now=now, jti="proof-app")
    decision = await provider2.authenticate(_request(access_token=token_app, proof=proof_app, now=now), runtime)
    assert isinstance(decision, Authenticated)

    other_key, _, _ = _proof_key()
    bad_sig = _proof(other_key, proof_jwk, access_token=token, now=now, jti="badsig")
    assert await provider2.authenticate(_request(access_token=token, proof=bad_sig, now=now), runtime) == Invalid(
        FailureCode.INVALID
    )

    # PyJWT rejects unknown critical headers before our verifier runs
    with pytest.raises(jwt.InvalidTokenError):
        jwt.get_unverified_header(
            _proof(proof_key, proof_jwk, access_token=token, now=now, jti="crit-1", header_overrides={"crit": ["b64"]})
        )
    crit_proof = _proof(
        proof_key,
        proof_jwk,
        access_token=token,
        now=now,
        jti="crit-1",
        header_overrides={"crit": ["b64"]},
    )
    assert await provider2.authenticate(_request(access_token=token, proof=crit_proof, now=now), runtime) == Invalid(
        FailureCode.MALFORMED
    )

    assert await provider2.authenticate(
        _request(
            access_token="not-a-jwt",
            proof=_proof(proof_key, proof_jwk, access_token="not-a-jwt", now=now, jti="malformed-at"),
            now=now,
        ),
        runtime,
    ) == Invalid(FailureCode.MALFORMED)

    hs_header = (
        base64
        .urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "at+jwt", "kid": _KID}).encode())
        .rstrip(b"=")
        .decode()
    )
    hs_body = base64.urlsafe_b64encode(json.dumps({"sub": "x"}).encode()).rstrip(b"=").decode()
    hs_token = f"{hs_header}.{hs_body}.sig"
    hs_proof = _proof(proof_key, proof_jwk, access_token=hs_token, now=now, jti="hs")
    assert await provider2.authenticate(_request(access_token=hs_token, proof=hs_proof, now=now), runtime) == Invalid(
        FailureCode.ALGORITHM_MISMATCH
    )

    # bad access-token signature (valid header/claims shape, wrong key)
    foreign = ec.generate_private_key(ec.SECP256R1())
    forged = _access_token(foreign, jkt=jkt, now=now, claims={"jti": "forged"})
    forged_proof = _proof(proof_key, proof_jwk, access_token=forged, now=now, jti="forged-proof")
    assert await provider2.authenticate(_request(access_token=forged, proof=forged_proof, now=now), runtime) == Invalid(
        FailureCode.INVALID
    )

    # iat type after successful decode (force via monkeypatch of decode path)
    real_numeric = dpop_mod._numeric_date
    calls = {"n": 0}

    def _bad_numeric(value: object) -> datetime:
        calls["n"] += 1
        if calls["n"] == 1:
            raise TypeError
        return real_numeric(value)

    cast("Any", dpop_mod)._numeric_date = _bad_numeric
    try:
        assert await provider2.authenticate(
            _request(access_token=token, proof=proof2, now=now),
            runtime,
        ) == Invalid(FailureCode.MALFORMED)
    finally:
        cast("Any", dpop_mod)._numeric_date = real_numeric

    # impossible thumbprint length
    real_b64 = dpop_mod.base64.urlsafe_b64encode

    def _short_b64(_data: bytes) -> bytes:
        return b"short"

    cast("Any", dpop_mod.base64).urlsafe_b64encode = _short_b64
    try:
        with pytest.raises(ValueError, match="invalid thumbprint"):
            dpop_mod._jwk_thumbprint(dict(proof_jwk))
    finally:
        cast("Any", dpop_mod.base64).urlsafe_b64encode = real_b64

    # force InvalidAudienceError from PyJWT before local audience filter
    real_load = dpop_mod._load_jwt
    jwt_mod = real_load()

    class _JwtProxy:
        PyJWTError = jwt_mod.PyJWTError
        InvalidIssuerError = jwt_mod.InvalidIssuerError
        InvalidAudienceError = jwt_mod.InvalidAudienceError
        algorithms = jwt_mod.algorithms

        @staticmethod
        def get_unverified_header(token: str) -> dict[str, object]:
            return jwt_mod.get_unverified_header(token)

        @staticmethod
        def decode(*args: object, **kwargs: object) -> dict[str, object]:
            if kwargs.get("issuer") is not None:
                raise jwt_mod.InvalidAudienceError("aud")
            return jwt_mod.decode(*args, **kwargs)

    cast("Any", dpop_mod)._load_jwt = lambda: _JwtProxy
    try:
        aud_token = _access_token(issuer_key, jkt=jkt, now=now, claims={"jti": "aud-force"})
        aud_proof = _proof(proof_key, proof_jwk, access_token=aud_token, now=now, jti="aud-force-proof")
        assert await provider2.authenticate(
            _request(access_token=aud_token, proof=aud_proof, now=now),
            runtime,
        ) == Invalid(FailureCode.AUDIENCE_MISMATCH)
    finally:
        cast("Any", dpop_mod)._load_jwt = real_load

    sync_events: list[object] = []
    provider_sync = _provider(jwks, events=sync_events, replay=InMemoryReplayStore(capacity=8, time_source=_Clock()))
    sync_token = _access_token(issuer_key, jkt=jkt, now=now, claims={"jti": "sync-tok"})
    sync_proof = _proof(proof_key, proof_jwk, access_token=sync_token, now=now, jti="sync-proof")
    assert isinstance(
        await provider_sync.authenticate(_request(access_token=sync_token, proof=sync_proof, now=now), runtime),
        Authenticated,
    )
    assert sync_events
