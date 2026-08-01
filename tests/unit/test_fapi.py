"""Tests for the strict FAPI 2.0 Message Signing profile."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from authweave_core import InMemoryReplayStore, ReplayOutcome
from cryptography.hazmat.primitives.asymmetric import ec

from litestar_auth.oauth import fapi as fapi_module
from litestar_auth.oauth.fapi import (
    FAPIIssuerProfile,
    FAPIMessageSigningClient,
    FAPIUnavailableError,
    FAPIValidationError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from authweave_core import AuthorizationValue

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 1, 12, tzinfo=UTC)
_ISSUER = "https://issuer.example"
_CLIENT_ID = "fapi-client"
_KEY_ID = "issuer-key"
_PAR_EXPIRES_IN = 90


class _Signer:
    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self.key = key
        self.messages: list[tuple[Mapping[str, object], Mapping[str, object]]] = []

    async def sign(
        self,
        *,
        protected_headers: Mapping[str, object],
        claims: Mapping[str, object],
    ) -> str:
        self.messages.append((protected_headers, claims))
        return jwt.encode(dict(claims), self.key, algorithm="ES256", headers=dict(protected_headers))


class _Resolver:
    def __init__(self, key: ec.EllipticCurvePublicKey) -> None:
        self.key = key

    async def get_key(self, kid: str, algorithm: str) -> ec.EllipticCurvePublicKey:
        if (kid, algorithm) != (_KEY_ID, "ES256"):
            msg = "unknown key"
            raise ValueError(msg)
        return self.key


class _ReplayStore:
    def __init__(self, outcome: ReplayOutcome) -> None:
        self.outcome = outcome

    async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
        del key, ttl_seconds
        return self.outcome


class _RandomSource:
    count = 0

    def __call__(self) -> str:
        self.count += 1
        return f"value-{self.count:02d}-" + "x" * 32


def _profile(
    signer: _Signer,
    resolver: _Resolver,
    *,
    replay_store: InMemoryReplayStore | _ReplayStore | None = None,
) -> FAPIIssuerProfile:
    return FAPIIssuerProfile(
        issuer=_ISSUER,
        authorization_endpoint=f"{_ISSUER}/authorize",
        par_endpoint=f"{_ISSUER}/par",
        client_id=_CLIENT_ID,
        redirect_uri="https://client.example/callback",
        key_id="client-key",
        algorithm="ES256",
        signer=signer,
        key_resolver=resolver,
        replay_store=replay_store or InMemoryReplayStore(capacity=16, time_source=lambda: 0.0),
        time_source=lambda: _NOW,
        random_source=_RandomSource(),
    )


def _signed_response(
    key: ec.EllipticCurvePrivateKey,
    claims: Mapping[str, object],
    *,
    token_type: str = "oauth-authz-resp+jwt",
    key_id: str = _KEY_ID,
    algorithm: str = "ES256",
) -> str:
    return jwt.encode(dict(claims), key, algorithm=algorithm, headers={"kid": key_id, "typ": token_type})


def _jarm_claims(**updates: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "iat": int(_NOW.timestamp()),
        "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
        "jti": "jarm-1",
        "state": "expected-state-" + "x" * 32,
        "code": "authorization-code",
    }
    claims.update(updates)
    return claims


async def test_begin_pushes_only_signed_request_and_client_assertion() -> None:
    """PAR carries signed objects while the browser receives only the request URI."""
    key = ec.generate_private_key(ec.SECP256R1())
    signer = _Signer(key)
    captured: dict[str, object] = {}

    async def poster(
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
        maximum_bytes: int,
    ) -> tuple[int, bytes, str]:
        captured.update(url=url, headers=headers, body=body, timeout=timeout_seconds, maximum_bytes=maximum_bytes)
        return 201, b'{"request_uri":"urn:example:par:1","expires_in":90}', "application/json; charset=utf-8"

    result = await FAPIMessageSigningClient(_profile(signer, _Resolver(key.public_key())), poster=poster).begin(
        scopes=("openid", "payments:write"),
        authorization_details=cast(
            "tuple[Mapping[str, AuthorizationValue], ...]",
            (
                {
                    "type": "https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1",
                    "actions": ["initiate"],
                    "locations": ["https://api.example/v1/payments"],
                    "instructedAmount": {"currency": "EUR", "amount": "100.00"},
                },
            ),
        ),
    )

    form = parse_qs(cast("bytes", captured["body"]).decode())
    request_header = jwt.get_unverified_header(form["request"][0])
    request_claims = jwt.decode(
        form["request"][0],
        key.public_key(),
        algorithms=["ES256"],
        audience=_ISSUER,
        options={"verify_exp": False, "verify_nbf": False},
    )
    assertion_claims = jwt.decode(
        form["client_assertion"][0],
        key.public_key(),
        algorithms=["ES256"],
        audience=_ISSUER,
        options={"verify_exp": False, "verify_iat": False},
    )
    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(result.code_verifier.encode()).digest()).rstrip(b"=").decode()
    )

    assert set(form) == {"request", "client_assertion_type", "client_assertion"}
    assert request_header == {"alg": "ES256", "kid": "client-key", "typ": "oauth-authz-req+jwt"}
    assert request_claims["response_type"] == "code"
    assert request_claims["response_mode"] == "jwt"
    assert request_claims["state"] == result.state
    assert request_claims["nonce"] == result.nonce
    assert request_claims["code_challenge"] == expected_challenge
    assert request_claims["code_challenge_method"] == "S256"
    assert request_claims["authorization_details"][0]["actions"] == ["initiate"]
    assert assertion_claims["iss"] == assertion_claims["sub"] == _CLIENT_ID
    assert set(parse_qs(urlsplit(result.authorization_url).query)) == {"client_id", "request_uri"}
    assert result.request_uri == "urn:example:par:1"
    assert result.expires_in == _PAR_EXPIRES_IN
    assert captured["url"] == f"{_ISSUER}/par"


async def test_jarm_and_id_token_are_verified_and_single_use() -> None:
    """Signed schemas bind state and nonce and reject their second presentation."""
    key = ec.generate_private_key(ec.SECP256R1())
    client = FAPIMessageSigningClient(_profile(_Signer(key), _Resolver(key.public_key())))
    state = "expected-state-" + "x" * 32
    jarm = _signed_response(key, _jarm_claims())

    result = await client.verify_jarm(jarm, expected_state=state)

    assert result.require_code() == "authorization-code"
    with pytest.raises(FAPIValidationError, match="replayed"):
        await client.verify_jarm(jarm, expected_state=state)

    nonce = "expected-nonce-" + "x" * 32
    id_token = _signed_response(
        key,
        {
            "iss": _ISSUER,
            "sub": "user-1",
            "aud": _CLIENT_ID,
            "iat": int(_NOW.timestamp()),
            "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
            "nonce": nonce,
            "auth_time": int((_NOW - timedelta(minutes=1)).timestamp()),
        },
        token_type="JWT",
    )
    identity = await client.verify_id_token(id_token, expected_nonce=nonce)

    assert identity.subject == "user-1"
    assert identity.auth_time == _NOW - timedelta(minutes=1)
    with pytest.raises(FAPIValidationError, match="replayed"):
        await client.verify_id_token(id_token, expected_nonce=nonce)


async def test_verified_jarm_error_does_not_expose_a_code() -> None:
    """A signed authorization error remains typed and cannot be used as a code."""
    key = ec.generate_private_key(ec.SECP256R1())
    client = FAPIMessageSigningClient(_profile(_Signer(key), _Resolver(key.public_key())))
    claims = _jarm_claims(error="access_denied", error_description="denied")
    claims.pop("code")

    result = await client.verify_jarm(_signed_response(key, claims), expected_state="expected-state-" + "x" * 32)

    assert result.error == "access_denied"
    assert result.error_description == "denied"
    with pytest.raises(FAPIValidationError, match="access_denied"):
        result.require_code()


@pytest.mark.parametrize(
    ("outcome", "error"),
    [
        (ReplayOutcome.REPLAY, FAPIValidationError),
        (ReplayOutcome.UNAVAILABLE, FAPIUnavailableError),
        (ReplayOutcome.CAPACITY_EXCEEDED, FAPIUnavailableError),
    ],
)
async def test_replay_store_failures_are_fail_closed(
    outcome: ReplayOutcome,
    error: type[Exception],
) -> None:
    """Replay, outage, and capacity exhaustion never expose a JARM code."""
    key = ec.generate_private_key(ec.SECP256R1())
    client = FAPIMessageSigningClient(
        _profile(_Signer(key), _Resolver(key.public_key()), replay_store=_ReplayStore(outcome))
    )

    with pytest.raises(error):
        await client.verify_jarm(_signed_response(key, _jarm_claims()), expected_state="expected-state-" + "x" * 32)


async def test_replay_store_exception_is_typed_as_unavailable() -> None:
    """An implementation exception cannot escape the replay-store trust boundary."""

    class BrokenReplayStore(_ReplayStore):
        async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
            del key, ttl_seconds
            msg = "offline"
            raise ConnectionError(msg)

    key = ec.generate_private_key(ec.SECP256R1())
    client = FAPIMessageSigningClient(
        _profile(_Signer(key), _Resolver(key.public_key()), replay_store=BrokenReplayStore(ReplayOutcome.STORED))
    )
    with pytest.raises(FAPIUnavailableError, match="replay store"):
        await client.verify_jarm(_signed_response(key, _jarm_claims()), expected_state="expected-state-" + "x" * 32)


def test_profile_rejects_non_https_and_weak_algorithms() -> None:
    """The profile rejects discovery-shaped URLs and symmetric JOSE."""
    key = ec.generate_private_key(ec.SECP256R1())
    signer = _Signer(key)
    values = _profile(signer, _Resolver(key.public_key()))

    with pytest.raises(ValueError, match="HTTPS"):
        FAPIIssuerProfile(
            issuer="http://issuer.example",
            authorization_endpoint=values.authorization_endpoint,
            par_endpoint=values.par_endpoint,
            client_id=values.client_id,
            redirect_uri=values.redirect_uri,
            key_id=values.key_id,
            algorithm=values.algorithm,
            signer=values.signer,
            key_resolver=values.key_resolver,
            replay_store=values.replay_store,
        )
    with pytest.raises(ValueError, match="profile"):
        FAPIIssuerProfile(
            issuer=values.issuer,
            authorization_endpoint=values.authorization_endpoint,
            par_endpoint=values.par_endpoint,
            client_id=values.client_id,
            redirect_uri=values.redirect_uri,
            key_id=values.key_id,
            algorithm="HS256",
            signer=values.signer,
            key_resolver=values.key_resolver,
            replay_store=values.replay_store,
        )


@pytest.mark.parametrize(
    ("status", "body", "content_type", "error"),
    [
        (500, b"{}", "application/json", FAPIUnavailableError),
        (201, b"{}", "text/plain", FAPIValidationError),
        (201, b"not-json", "application/json", FAPIValidationError),
        (201, b"x" * 65_537, "application/json", FAPIValidationError),
        (
            201,
            json.dumps({"request_uri": "urn:x", "expires_in": 600}).encode(),
            "application/json",
            FAPIValidationError,
        ),
    ],
    ids=("server-error", "wrong-content-type", "malformed-json", "oversized-body", "invalid-schema"),
)
async def test_par_response_is_bounded_and_exact(
    status: int,
    body: bytes,
    content_type: str,
    error: type[Exception],
) -> None:
    """PAR rejects transport failures and loose response schemas."""
    key = ec.generate_private_key(ec.SECP256R1())

    async def poster(*_args: object) -> tuple[int, bytes, str]:
        return status, body, content_type

    with pytest.raises(error):
        await FAPIMessageSigningClient(_profile(_Signer(key), _Resolver(key.public_key())), poster=poster).begin(
            scopes=("openid",)
        )


async def test_begin_rejects_scopes_signer_and_transport_failures() -> None:
    """Invalid local input and unexpected signer/transport output fail closed."""
    key = ec.generate_private_key(ec.SECP256R1())
    profile = _profile(_Signer(key), _Resolver(key.public_key()))
    client = FAPIMessageSigningClient(profile)
    for scopes in ((), ("accounts",), ("openid", "openid"), ("openid", "bad scope")):
        with pytest.raises(ValueError, match="FAPI"):
            await client.begin(scopes=scopes)
    with pytest.raises(ValueError, match="authorization_details"):
        await client.begin(
            scopes=("openid",),
            authorization_details=cast("tuple[Mapping[str, AuthorizationValue], ...]", ({},)),
        )

    class InvalidSigner(_Signer):
        async def sign(
            self,
            *,
            protected_headers: Mapping[str, object],
            claims: Mapping[str, object],
        ) -> str:
            del protected_headers, claims
            return "invalid"

    with pytest.raises(FAPIValidationError, match="FAPI"):
        await FAPIMessageSigningClient(_profile(InvalidSigner(key), _Resolver(key.public_key()))).begin(
            scopes=("openid",)
        )

    class UnavailableSigner(_Signer):
        async def sign(
            self,
            *,
            protected_headers: Mapping[str, object],
            claims: Mapping[str, object],
        ) -> str:
            del protected_headers, claims
            msg = "offline"
            raise ConnectionError(msg)

    with pytest.raises(FAPIUnavailableError, match="signer"):
        await FAPIMessageSigningClient(_profile(UnavailableSigner(key), _Resolver(key.public_key()))).begin(
            scopes=("openid",)
        )

    async def known_failure(*_args: object) -> tuple[int, bytes, str]:
        msg = "known"
        raise FAPIValidationError(msg)

    async def unknown_failure(*_args: object) -> tuple[int, bytes, str]:
        msg = "unknown"
        raise RuntimeError(msg)

    with pytest.raises(FAPIValidationError, match="known"):
        await FAPIMessageSigningClient(profile, poster=known_failure).begin(scopes=("openid",))
    with pytest.raises(FAPIUnavailableError, match="PAR request failed"):
        await FAPIMessageSigningClient(profile, poster=unknown_failure).begin(scopes=("openid",))


@pytest.mark.parametrize(
    ("claims_update", "message"),
    [
        ({"state": "other-state-" + "x" * 32}, "state mismatch"),
        ({"iat": int((_NOW + timedelta(minutes=1)).timestamp())}, "not yet valid"),
        ({"exp": int((_NOW - timedelta(minutes=1)).timestamp())}, "expired"),
        ({"exp": int((_NOW + timedelta(minutes=11)).timestamp())}, "lifetime"),
        ({"aud": [_CLIENT_ID, "untrusted-audience"]}, "audience mismatch"),
        ({"code": None}, "exactly one"),
        ({"error": "denied"}, "exactly one"),
    ],
)
async def test_jarm_negative_claim_matrix(claims_update: Mapping[str, object], message: str) -> None:
    """State, time, and result-shape failures are rejected before consumption."""
    key = ec.generate_private_key(ec.SECP256R1())
    client = FAPIMessageSigningClient(_profile(_Signer(key), _Resolver(key.public_key())))
    with pytest.raises(FAPIValidationError, match=message):
        await client.verify_jarm(
            _signed_response(key, _jarm_claims(**claims_update)),
            expected_state="expected-state-" + "x" * 32,
        )


@pytest.mark.parametrize(
    ("claims_update", "message"),
    [
        ({"code": "wrong-profile"}, "another JWT profile"),
        ({"aud": [_CLIENT_ID, "untrusted-audience"]}, "audience mismatch"),
        ({"azp": "other-client"}, "authorized party mismatch"),
        ({"nonce": "other-nonce-" + "x" * 32}, "nonce mismatch"),
        ({"auth_time": int((_NOW + timedelta(minutes=1)).timestamp())}, "auth_time"),
    ],
)
async def test_id_token_negative_claim_matrix(claims_update: Mapping[str, object], message: str) -> None:
    """ID tokens cannot cross profiles or bypass nonce/auth-time binding."""
    key = ec.generate_private_key(ec.SECP256R1())
    nonce = "expected-nonce-" + "x" * 32
    claims: dict[str, object] = {
        "iss": _ISSUER,
        "sub": "user-1",
        "aud": _CLIENT_ID,
        "iat": int(_NOW.timestamp()),
        "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
        "nonce": nonce,
    }
    claims.update(claims_update)
    with pytest.raises(FAPIValidationError, match=message):
        await FAPIMessageSigningClient(_profile(_Signer(key), _Resolver(key.public_key()))).verify_id_token(
            _signed_response(key, claims, token_type="JWT"), expected_nonce=nonce
        )


async def test_jwt_header_key_and_signature_negative_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    """JWT parsing pins type, algorithm, key id, key availability, issuer, and signature."""
    key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    client = FAPIMessageSigningClient(_profile(_Signer(key), _Resolver(key.public_key())))
    state = "expected-state-" + "x" * 32
    cases = (
        (_signed_response(key, _jarm_claims(), token_type="JWT"), "type mismatch"),
        (
            jwt.encode(
                _jarm_claims(),
                "s" * 32,
                algorithm="HS256",
                headers={"kid": _KEY_ID, "typ": "oauth-authz-resp+jwt"},
            ),
            "algorithm",
        ),
        (jwt.encode(_jarm_claims(), key, algorithm="ES256", headers={"typ": "oauth-authz-resp+jwt"}), "kid"),
        (_signed_response(key, _jarm_claims(), key_id="other"), "key is invalid"),
        (_signed_response(other_key, _jarm_claims()), "signature or claims"),
        (_signed_response(key, _jarm_claims(iss="https://other.example")), "signature or claims"),
    )
    for token, message in cases:
        with pytest.raises(FAPIValidationError, match=message):
            await client.verify_jarm(token, expected_state=state)

    def invalid_header(_token: str) -> dict[str, object]:
        msg = "bad header"
        raise jwt.DecodeError(msg)

    monkeypatch.setattr(jwt, "get_unverified_header", invalid_header)
    with pytest.raises(FAPIValidationError, match="not a compact JWT"):
        await client.verify_jarm("a.b.c", expected_state=state)

    class UnavailableResolver(_Resolver):
        async def get_key(self, kid: str, algorithm: str) -> ec.EllipticCurvePublicKey:
            del kid, algorithm
            msg = "unavailable"
            raise FAPIUnavailableError(msg)

    monkeypatch.undo()
    unavailable = FAPIMessageSigningClient(_profile(_Signer(key), UnavailableResolver(key.public_key())))
    with pytest.raises(FAPIUnavailableError, match="unavailable"):
        await unavailable.verify_jarm(_signed_response(key, _jarm_claims()), expected_state=state)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"[]", "schema"),
        (b'{"request_uri":"","expires_in":1}', "request_uri"),
        (b'{"request_uri":"urn:x","expires_in":true}', "expires_in"),
    ],
)
def test_par_schema_negative_matrix(content: bytes, message: str) -> None:
    """PAR decoding accepts neither loose containers nor malformed members."""
    with pytest.raises(FAPIValidationError, match=message):
        fapi_module._parse_par_response(content)


@pytest.mark.parametrize(
    ("claims", "message"),
    [
        ({"iat": None, "exp": 1}, "iat is missing"),
        ({"iat": True, "exp": 1}, "iat is invalid"),
        ({"iat": 1, "exp": 10**30}, "exp is invalid"),
    ],
)
def test_numeric_date_negative_matrix(claims: Mapping[str, object], message: str) -> None:
    """NumericDate values are required, finite, and platform-representable."""
    with pytest.raises(FAPIValidationError, match=message):
        fapi_module._validate_token_times(
            claims,
            now=_NOW,
            maximum_lifetime=timedelta(minutes=10),
            clock_skew=timedelta(0),
            label="token",
        )


def test_boundary_helpers_reject_ambiguous_values() -> None:
    """Boundary helpers reject malformed strings, clocks, randomness, and oversized bodies."""
    failures = (
        lambda: fapi_module._validate_compact_jwt("", label="token"),
        lambda: fapi_module._validate_compact_jwt("a.b", label="token"),
        lambda: fapi_module._required_string(None, label="value"),
        lambda: fapi_module._optional_string(" value", label="value"),
        lambda: fapi_module._bounded_random(lambda: "short"),
        lambda: fapi_module._aware_now(lambda: _NOW.replace(tzinfo=None)),
        lambda: fapi_module._extend_bounded(bytearray(), b"too large", 1),
    )
    for failure in failures:
        with pytest.raises(ValueError, match=r"FAPI|value|PAR response"):
            failure()


async def test_default_par_transport_success_size_limit_and_network_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The built-in transport does not redirect, over-buffer, or leak HTTP errors."""
    original_client = httpx.AsyncClient

    def client_with(handler: httpx.MockTransport) -> object:
        def create_client(**kwargs: object) -> httpx.AsyncClient:
            return original_client(transport=handler, timeout=cast("float", kwargs["timeout"]))

        return create_client

    success = httpx.MockTransport(lambda request: httpx.Response(201, json={"ok": True}, request=request))
    monkeypatch.setattr(httpx, "AsyncClient", client_with(success))
    assert await fapi_module._post_par("https://issuer.example/par", {}, b"x", 1.0, 100) == (
        201,
        b'{"ok":true}',
        "application/json",
    )

    oversized = httpx.MockTransport(lambda request: httpx.Response(201, content=b"large", request=request))
    monkeypatch.setattr(httpx, "AsyncClient", client_with(oversized))
    with pytest.raises(FAPIValidationError, match="size limit"):
        await fapi_module._post_par("https://issuer.example/par", {}, b"x", 1.0, 1)

    def fail(_request: httpx.Request) -> httpx.Response:
        msg = "offline"
        raise httpx.ConnectError(msg)

    monkeypatch.setattr(httpx, "AsyncClient", client_with(httpx.MockTransport(fail)))
    with pytest.raises(FAPIUnavailableError, match="PAR request failed"):
        await fapi_module._post_par("https://issuer.example/par", {}, b"x", 1.0, 100)
