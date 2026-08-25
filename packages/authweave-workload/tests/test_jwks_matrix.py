"""Bounded JWKS validation, caching, and network failure matrix."""

from __future__ import annotations

import asyncio
import builtins
import json
from typing import Self

import httpx
import jwt.algorithms
import pytest
from authweave_workload import jwks as jwks_module
from authweave_workload.jwks import BoundedJWKSClient, JWKSCachePolicy, JWKSUnavailableError, JWKSValidationError
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

_KID = "key-1"
_EXPECTED_PAIR = 2


def _ec_jwk(*, kid: str = _KID, algorithm: str = "ES256") -> dict[str, object]:
    key = ec.generate_private_key(ec.SECP256R1())
    value = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    value.update({"alg": algorithm, "kid": kid, "use": "sig"})
    return value


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "options",
    [
        {"ttl_seconds": 0},
        {"timeout_seconds": 0},
        {"maximum_response_bytes": 0},
        {"maximum_keys": 0},
    ],
)
def test_jwks_policy_requires_positive_ceilings(options: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="positive"):
        JWKSCachePolicy(**options)  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"url": "https://issuer.test/jwks", "static_jwks": {"keys": []}},
        {"url": "http://issuer.test/jwks"},
        {"url": "https://user@issuer.test/jwks"},
        {"url": "https://issuer.test/jwks#fragment"},
        {"url": "https:///jwks"},
    ],
)
def test_jwks_client_requires_one_clean_https_source(options: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r"(exactly one|HTTPS)"):
        BoundedJWKSClient(**options)  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize(
    ("kid", "algorithm", "message"),
    [
        ("", "ES256", "missing"),
        ("x" * 129, "ES256", "oversized"),
        (_KID, "HS256", "not allowed"),
    ],
)
async def test_jwks_lookup_rejects_unbounded_identity(kid: str, algorithm: str, message: str) -> None:
    client = BoundedJWKSClient(static_jwks={"keys": [_ec_jwk()]})
    with pytest.raises(JWKSValidationError, match=message):
        await client.get_key(kid, algorithm)


async def test_jwks_unknown_kids_cannot_force_unbounded_refreshes() -> None:
    calls = 0

    async def fetch(_url: str, _timeout: float, _maximum_bytes: int) -> dict[str, object]:
        nonlocal calls
        await asyncio.sleep(0)
        calls += 1
        return {"keys": [_ec_jwk()]}

    client = BoundedJWKSClient(url="https://issuer.test/jwks", fetcher=fetch)
    await client.get_key(_KID, "ES256")
    for kid in ("attacker-1", "attacker-2"):
        with pytest.raises(JWKSValidationError, match="unknown"):
            await client.get_key(kid, "ES256")

    # Unknown kids inside the refresh cooldown never reach the fetcher.
    assert calls == 1


async def test_jwks_unknown_kid_refreshes_after_cooldown_for_rotation() -> None:
    calls = 0
    rotated_kid = "rotated"

    async def fetch(_url: str, _timeout: float, _maximum_bytes: int) -> dict[str, object]:
        nonlocal calls
        await asyncio.sleep(0)
        calls += 1
        keys = [_ec_jwk()] if calls == 1 else [_ec_jwk(), _ec_jwk(kid=rotated_kid)]
        return {"keys": keys}

    client = BoundedJWKSClient(
        url="https://issuer.test/jwks",
        fetcher=fetch,
        policy=JWKSCachePolicy(refresh_cooldown_seconds=0.0),
    )
    await client.get_key(_KID, "ES256")

    # With the cooldown elapsed, a newly rotated kid triggers one refresh and resolves.
    await client.get_key(rotated_kid, "ES256")
    assert calls == _EXPECTED_PAIR


@pytest.mark.parametrize(
    "jwks",
    [
        {},
        {"keys": [], "extra": True},
        {"keys": []},
        {"keys": "bad"},
        {"keys": ["bad"]},
        {"keys": [{**_ec_jwk(), "kid": ""}]},
        {"keys": [{**_ec_jwk(), "alg": "HS256"}]},
        {"keys": [{**_ec_jwk(), "kty": "bad"}]},
        {"keys": [_ec_jwk(), _ec_jwk()]},
        {"keys": [_ec_jwk(kid=f"k{index}") for index in range(2)]},
    ],
)
async def test_jwks_rejects_malformed_sets(jwks: object) -> None:
    raw_keys = jwks.get("keys") if isinstance(jwks, dict) else None
    maximum_keys = 1 if isinstance(raw_keys, list) and len(raw_keys) == _EXPECTED_PAIR else 32
    client = BoundedJWKSClient(
        static_jwks=jwks,  # ty: ignore[invalid-argument-type]
        policy=JWKSCachePolicy(maximum_keys=maximum_keys),
    )
    with pytest.raises(JWKSValidationError):
        await client.get_key(_KID, "ES256")


async def test_jwks_enforces_algorithm_and_key_type_profiles() -> None:
    ec384 = ec.generate_private_key(ec.SECP384R1())
    bad_ec = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec384.public_key()))
    bad_ec.update({"alg": "ES256", "kid": _KID})
    with pytest.raises(JWKSValidationError, match="P-256"):
        await BoundedJWKSClient(static_jwks={"keys": [bad_ec]}).get_key(_KID, "ES256")

    weak_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad_rsa = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(weak_rsa.public_key()))
    bad_rsa.update({"alg": "PS256", "kid": _KID})
    with pytest.raises(JWKSValidationError, match="3072"):
        await BoundedJWKSClient(static_jwks={"keys": [bad_rsa]}).get_key(_KID, "PS256")

    wrong_okp = ed448.Ed448PrivateKey.generate()
    bad_okp = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(wrong_okp.public_key()))
    bad_okp.update({"alg": "EdDSA", "kid": _KID})
    with pytest.raises(JWKSValidationError, match="Ed25519"):
        await BoundedJWKSClient(static_jwks={"keys": [bad_okp]}).get_key(_KID, "EdDSA")

    client = BoundedJWKSClient(static_jwks={"keys": [_ec_jwk()]})
    await client.get_key(_KID, "ES256")
    with pytest.raises(JWKSValidationError, match="does not match"):
        await client.get_key(_KID, "PS256")

    strong_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(strong_rsa.public_key()))
    rsa_jwk.update({"alg": "PS256", "kid": "rsa"})
    await BoundedJWKSClient(static_jwks={"keys": [rsa_jwk]}).get_key("rsa", "PS256")

    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(ed_key.public_key()))
    ed_jwk.update({"alg": "EdDSA", "kid": "ed"})
    await BoundedJWKSClient(static_jwks={"keys": [ed_jwk]}).get_key("ed", "EdDSA")


class _Response:
    def __init__(
        self,
        *,
        status_code: int = 200,
        chunks: tuple[bytes, ...] = (b'{"keys":[]}',),
    ) -> None:
        self.status_code = status_code
        self.is_redirect = False
        self.chunks = chunks

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def aiter_bytes(self) -> object:
        for chunk in self.chunks:
            yield chunk


class _Client:
    response = _Response()

    def __init__(self, **options: object) -> None:
        self.options = options

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    def stream(self, method: str, url: str, *, headers: dict[str, str]) -> _Response:
        return self.response


async def test_jwks_network_response_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    _Client.response = _Response(status_code=503)
    with pytest.raises(JWKSUnavailableError, match="non-success"):
        await jwks_module._fetch_jwks("https://issuer.test/jwks", 1, 100)
    _Client.response = _Response(chunks=(b"x" * 101,))
    with pytest.raises(JWKSValidationError, match="size"):
        await jwks_module._fetch_jwks("https://issuer.test/jwks", 1, 100)
    _Client.response = _Response(chunks=(b"not-json",))
    with pytest.raises(JWKSValidationError, match="valid JSON"):
        await jwks_module._fetch_jwks("https://issuer.test/jwks", 1, 100)
    _Client.response = _Response(chunks=(b"[]",))
    with pytest.raises(JWKSValidationError, match="object"):
        await jwks_module._fetch_jwks("https://issuer.test/jwks", 1, 100)
    _Client.response = _Response(chunks=(b'{"keys":[]}',))
    assert await jwks_module._fetch_jwks("https://issuer.test/jwks", 1, 100) == {"keys": []}

    class FailingClient(_Client):
        def stream(self, method: str, url: str, *, headers: dict[str, str]) -> _Response:
            message = "offline"
            raise httpx.ConnectError(message)

    monkeypatch.setattr(httpx, "AsyncClient", FailingClient)
    with pytest.raises(JWKSUnavailableError, match="request failed"):
        await jwks_module._fetch_jwks("https://issuer.test/jwks", 1, 100)


async def test_jwks_optional_dependency_errors_are_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def reject(name: str, *args: object, **kwargs: object) -> object:
        if name in {"jwt", "httpx"}:
            raise ImportError
        return original_import(name, *args, **kwargs)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(builtins, "__import__", reject)
    with pytest.raises(ImportError, match=r"\[jwt\]"):
        jwks_module._load_jwt()
    with pytest.raises(ImportError, match=r"\[jwt\]"):
        await jwks_module._fetch_jwks("https://issuer.test/jwks", 1, 100)
