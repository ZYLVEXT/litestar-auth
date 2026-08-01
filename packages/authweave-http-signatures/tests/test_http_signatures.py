"""Payment HTTP Message Signature profile tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING

import http_message_signatures.signatures as upstream_signatures
import pytest
from authweave_core import (
    AuthenticationContext,
    AuthenticationEvidence,
    InMemoryReplayStore,
    PrincipalRef,
    ReplayOutcome,
)
from authweave_http_signatures import (
    PROFILE_TAG,
    SIGNATURE_LABEL,
    HttpMessageView,
    HttpSignatureFailureCode,
    HttpSignatureVerificationError,
    PaymentHttpSignatureVerifier,
    PaymentSignaturePolicy,
    SignatureKeyBinding,
    SignatureNonceGuard,
    content_digest_sha256,
    sign_payment_message,
    verify_content_digest,
)
from authweave_http_signatures.litestar_adapter import read_bounded_raw_body
from authweave_http_signatures.redis_store import RedisHttpSignatureReplayStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

_SF_MEMBER_COUNT = 2


class _Clock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


class _StreamingRequest:
    def __init__(self, stream: Callable[[], AsyncIterator[bytes]]) -> None:
        self._stream = stream

    def stream(self) -> AsyncIterator[bytes]:
        return self._stream()


def _context() -> AuthenticationContext:
    principal = PrincipalRef("https://issuer.test", "payments-worker", "service")
    evidence = AuthenticationEvidence(
        provider="dpop_rs",
        profile="dpop_bound_access_token",
        method="dpop",
        issuer="https://issuer.test",
        audiences=("payments-api",),
        scopes=("payments:write",),
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        token_id="t1",
        confirmation_thumbprint="A" * 43,
        environment="sandbox",
        extensions={"authweave-workload:application_id": "payments"},
    )
    return AuthenticationContext(subject=principal, actor=principal, evidence=evidence)


def _binding() -> SignatureKeyBinding:
    return SignatureKeyBinding(
        key_id="merchant-key-1",
        application_id="payments",
        principal_subject="payments-worker",
        environment="sandbox",
    )


def _signed(
    *,
    private_key: Ed25519PrivateKey,
    body: bytes = b'{"amount":"10.00"}',
    require_authorization: bool = False,
    target_uri: str = "https://api.example/v1/payments",
    nonce: str = "nonce-1",
) -> tuple[HttpMessageView, PaymentSignaturePolicy]:
    policy = PaymentSignaturePolicy(require_authorization_component=require_authorization)
    headers = [
        ("content-type", "application/json"),
        ("idempotency-key", "idem-1"),
    ]
    if require_authorization:
        headers.append(("authorization", "DPoP access-token"))
    view = HttpMessageView(method="POST", target_uri=target_uri, headers=tuple(headers), body=body)
    signed = sign_payment_message(
        view=view,
        policy=policy,
        key_id="merchant-key-1",
        private_key=private_key,
        nonce=nonce,
        now=datetime.now(UTC),
    )
    return signed, policy


pytestmark = pytest.mark.unit


async def test_sign_and_verify_happy_path_and_replay() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed, policy = _signed(private_key=private_key)
    store = InMemoryReplayStore(capacity=8, time_source=_Clock())
    verifier = PaymentHttpSignatureVerifier(
        policy=policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(store, profile_tag=PROFILE_TAG, ttl_seconds=60),
    )
    verified = await verifier.verify(signed, context=_context())
    assert verified.key_id == "merchant-key-1"
    assert verified.body == b'{"amount":"10.00"}'
    assert PROFILE_TAG in repr(verified)

    with pytest.raises(HttpSignatureVerificationError) as exc:
        await verifier.verify(signed, context=_context())
    assert exc.value.code is HttpSignatureFailureCode.NONCE_REPLAY


async def test_concurrent_verifiers_keep_time_policy_request_local() -> None:
    private_key = Ed25519PrivateKey.generate()
    instants = (
        datetime(2026, 7, 31, 12, 0, tzinfo=UTC),
        datetime(2030, 1, 1, 8, 30, tzinfo=UTC),
    )

    async def verify_at(instant: datetime, nonce: str) -> str:
        policy = PaymentSignaturePolicy()
        unsigned = HttpMessageView(
            method="POST",
            target_uri="https://api.example/v1/payments",
            headers=(("content-type", "application/json"), ("idempotency-key", nonce)),
            body=b"{}",
        )
        signed = sign_payment_message(
            view=unsigned,
            policy=policy,
            key_id="merchant-key-1",
            private_key=private_key,
            nonce=nonce,
            now=instant,
        )
        verifier = PaymentHttpSignatureVerifier(
            policy=policy,
            public_keys={"merchant-key-1": private_key.public_key()},
            bindings={"merchant-key-1": _binding()},
            nonce_guard=SignatureNonceGuard(
                InMemoryReplayStore(capacity=4, time_source=_Clock()),
                profile_tag=PROFILE_TAG,
                ttl_seconds=60,
            ),
            time_source=lambda: instant,
        )
        return (await verifier.verify(signed, context=_context())).nonce

    assert await asyncio.gather(
        verify_at(instants[0], "clock-a"),
        verify_at(instants[1], "clock-b"),
    ) == ["clock-a", "clock-b"]

    assert upstream_signatures.datetime.datetime is datetime


async def test_digest_and_query_and_binding_failures() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed, policy = _signed(private_key=private_key)
    digest = content_digest_sha256(b"x")
    verify_content_digest(header_value=digest, body=b"x")
    with pytest.raises(HttpSignatureVerificationError) as digest_exc:
        verify_content_digest(header_value=digest, body=b"y")
    assert digest_exc.value.code is HttpSignatureFailureCode.DIGEST_MISMATCH

    store = InMemoryReplayStore(capacity=8, time_source=_Clock())
    verifier = PaymentHttpSignatureVerifier(
        policy=policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(store, profile_tag=PROFILE_TAG, ttl_seconds=60),
    )
    mutated = HttpMessageView(
        method=signed.method,
        target_uri=signed.target_uri,
        headers=signed.headers,
        body=b'{"amount":"999.00"}',
    )
    with pytest.raises(HttpSignatureVerificationError) as exc:
        await verifier.verify(mutated, context=_context())
    assert exc.value.code is HttpSignatureFailureCode.DIGEST_MISMATCH

    with_query, _ = _signed(private_key=private_key, target_uri="https://api.example/v1/payments?x=1", nonce="n2")
    with pytest.raises(HttpSignatureVerificationError) as qexc:
        await verifier.verify(with_query, context=_context())
    assert qexc.value.code is HttpSignatureFailureCode.QUERY_REJECTED

    wrong_evidence = AuthenticationEvidence(
        provider="dpop_rs",
        profile="dpop_bound_access_token",
        method="dpop",
        issuer="https://issuer.test",
        audiences=("payments-api",),
        scopes=("payments:write",),
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        token_id="t2",
        confirmation_thumbprint="A" * 43,
        environment="sandbox",
        extensions={"authweave-workload:application_id": "other"},
    )
    wrong_principal = PrincipalRef("https://issuer.test", "payments-worker", "service")
    wrong_ctx = AuthenticationContext(subject=wrong_principal, actor=wrong_principal, evidence=wrong_evidence)
    fresh, _ = _signed(private_key=private_key, nonce="n3")
    with pytest.raises(HttpSignatureVerificationError) as bexc:
        await verifier.verify(fresh, context=wrong_ctx)
    assert bexc.value.code is HttpSignatureFailureCode.KEY_BINDING_MISMATCH


async def test_dpop_variant_and_redis() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed, policy = _signed(private_key=private_key, require_authorization=True, nonce="dpop-n1")
    assert "authorization" in policy.covered_components
    store = InMemoryReplayStore(capacity=8, time_source=_Clock())
    verifier = PaymentHttpSignatureVerifier(
        policy=policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(store, profile_tag=PROFILE_TAG, ttl_seconds=60),
    )
    verified = await verifier.verify(signed, context=_context())
    assert verified.idempotency_key == "idem-1"

    class _Redis:
        def __init__(self) -> None:
            self.values: dict[str, str] = {}
            self.fail = False

        async def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
            _ = value, ex
            if self.fail:
                msg = "down"
                raise ConnectionError(msg)
            if nx and key in self.values:
                return False
            self.values[key] = "1"
            return True

    redis = _Redis()
    replay = RedisHttpSignatureReplayStore(redis)
    assert await replay.check_and_store("http-sig:a", ttl_seconds=30) is ReplayOutcome.STORED
    assert await replay.check_and_store("http-sig:a", ttl_seconds=30) is ReplayOutcome.REPLAY
    with pytest.raises(ValueError):
        await replay.check_and_store("http-sig:b", ttl_seconds=0)
    redis.fail = True
    assert await replay.check_and_store("http-sig:c", ttl_seconds=30) is ReplayOutcome.UNAVAILABLE


async def test_litestar_raw_body_reader_and_policy_guards() -> None:
    async def _stream() -> AsyncIterator[bytes]:
        yield b'{"a":1}'

    connection = _StreamingRequest(_stream)
    body = await read_bounded_raw_body(connection, maximum_bytes=100)
    assert body == b'{"a":1}'

    async def _huge() -> AsyncIterator[bytes]:
        yield b"x" * 10

    with pytest.raises(HttpSignatureVerificationError) as exc:
        await read_bounded_raw_body(_StreamingRequest(_huge), maximum_bytes=4)
    assert exc.value.code is HttpSignatureFailureCode.BODY_TOO_LARGE
    with pytest.raises(ValueError):
        await read_bounded_raw_body(connection, maximum_bytes=0)

    with pytest.raises(ValueError):
        PaymentSignaturePolicy(max_body_bytes=0)
    with pytest.raises(ValueError):
        HttpMessageView(method="POST", target_uri="http://insecure.example/")
    with pytest.raises(ValueError):
        SignatureKeyBinding(key_id="", application_id="a", principal_subject="s", environment="e")
    with pytest.raises(ValueError):
        SignatureNonceGuard(InMemoryReplayStore(capacity=1, time_source=_Clock()), profile_tag="", ttl_seconds=1)

    err = HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED)
    assert "malformed" in repr(err).lower()


def test_http_message_view_repr_redacts_headers_and_body() -> None:
    secret_canary = "SECRET_CANARY_http_message"
    view = HttpMessageView(
        method="POST",
        target_uri=f"https://api.example/v1/payments?access_token={secret_canary}",
        headers=(("authorization", f"Bearer {secret_canary}"),),
        body=secret_canary.encode(),
    )

    assert secret_canary not in repr(view)
    assert secret_canary not in str(view)


async def test_http_signature_failure_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    from authweave_http_signatures import digest as digest_mod

    with pytest.raises(HttpSignatureVerificationError):
        verify_content_digest(header_value="sha-256=:!!!notb64!:", body=b"x")
    with pytest.raises(HttpSignatureVerificationError):
        verify_content_digest(header_value="md5=:aa:", body=b"x")

    private_key = Ed25519PrivateKey.generate()
    store = InMemoryReplayStore(capacity=8, time_source=_Clock())
    policy = PaymentSignaturePolicy()
    verifier = PaymentHttpSignatureVerifier(
        policy=policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(store, profile_tag=PROFILE_TAG, ttl_seconds=60),
    )
    with pytest.raises(ValueError):
        PaymentHttpSignatureVerifier(
            policy=policy,
            public_keys={},
            bindings={},
            nonce_guard=SignatureNonceGuard(store, profile_tag=PROFILE_TAG, ttl_seconds=60),
        )

    # content-type reject / encoding / body too large / missing components
    small_policy = PaymentSignaturePolicy(max_body_bytes=4)
    huge = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(("content-type", "application/json"), ("idempotency-key", "i")),
        body=b"12345",
    )
    verifier_small = PaymentHttpSignatureVerifier(
        policy=small_policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(
            InMemoryReplayStore(capacity=8, time_source=_Clock()),
            profile_tag=PROFILE_TAG,
            ttl_seconds=60,
        ),
    )
    with pytest.raises(HttpSignatureVerificationError) as bexc:
        await verifier_small.verify(huge, context=_context())
    assert bexc.value.code is HttpSignatureFailureCode.BODY_TOO_LARGE

    encoded = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(
            ("content-type", "application/json"),
            ("idempotency-key", "i"),
            ("content-encoding", "gzip"),
            ("content-digest", content_digest_sha256(b"{}")),
        ),
        body=b"{}",
    )
    with pytest.raises(HttpSignatureVerificationError) as eexc:
        await verifier.verify(encoded, context=_context())
    assert eexc.value.code is HttpSignatureFailureCode.CONTENT_ENCODING_REJECTED

    wrong_type = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(
            ("content-type", "text/plain"),
            ("idempotency-key", "i"),
            ("content-digest", content_digest_sha256(b"x")),
        ),
        body=b"x",
    )
    with pytest.raises(HttpSignatureVerificationError) as texc:
        await verifier.verify(wrong_type, context=_context())
    assert texc.value.code is HttpSignatureFailureCode.CONTENT_TYPE_REJECTED

    missing = HttpMessageView(method="POST", target_uri="https://api.example/v1/payments", headers=(), body=b"{}")
    with pytest.raises(HttpSignatureVerificationError) as mexc:
        await verifier.verify(missing, context=_context())
    assert mexc.value.code is HttpSignatureFailureCode.MISSING_COMPONENT

    # signer validation paths
    bare = HttpMessageView(method="POST", target_uri="https://api.example/v1/payments", headers=(), body=b"{}")
    with pytest.raises(ValueError, match="content-type"):
        sign_payment_message(view=bare, policy=policy, key_id="k", private_key=private_key, nonce="n")
    typed = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(("content-type", "application/json"),),
        body=b"{}",
    )
    with pytest.raises(ValueError, match="idempotency-key"):
        sign_payment_message(view=typed, policy=policy, key_id="k", private_key=private_key, nonce="n")
    with pytest.raises(ValueError, match="authorization"):
        sign_payment_message(
            view=HttpMessageView(
                method="POST",
                target_uri="https://api.example/v1/payments",
                headers=(("content-type", "application/json"), ("idempotency-key", "i")),
                body=b"{}",
            ),
            policy=PaymentSignaturePolicy(require_authorization_component=True),
            key_id="k",
            private_key=private_key,
            nonce="n",
        )
    signable = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(("content-type", "application/json"), ("idempotency-key", "i")),
        body=b"{}",
    )
    for invalid_lifetime in (timedelta(0), timedelta(seconds=-1), timedelta(seconds=301)):
        with pytest.raises(ValueError, match="lifetime"):
            sign_payment_message(
                view=signable,
                policy=policy,
                key_id="k",
                private_key=private_key,
                nonce="n",
                lifetime=invalid_lifetime,
            )

    # model guards
    with pytest.raises(ValueError):
        HttpMessageView(method="", target_uri="https://api.example/")
    with pytest.raises(ValueError):
        HttpMessageView(method="POST", target_uri="https://api.example/", body=b"x" * (262_144 * 2 + 1))
    view = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(("X", "1"), ("x", "2")),
        body=b"",
    )
    with pytest.raises(ValueError, match="duplicate"):
        view.header("x")
    with pytest.raises(ValueError, match="duplicate"):
        view.headers_dict()
    with pytest.raises(ValueError):
        PaymentSignaturePolicy(profile_tag="")
    with pytest.raises(ValueError):
        PaymentSignaturePolicy(max_signature_lifetime_seconds=0)

    # nonce guard malformed / unavailable
    guard = SignatureNonceGuard(store, profile_tag=PROFILE_TAG, ttl_seconds=60)
    with pytest.raises(HttpSignatureVerificationError):
        await guard.consume(key_id="", nonce="n")

    class _Broken:
        async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
            _ = key, ttl_seconds
            return ReplayOutcome.UNAVAILABLE

    broken_guard = SignatureNonceGuard(_Broken(), profile_tag=PROFILE_TAG, ttl_seconds=60)  # type: ignore[arg-type]
    with pytest.raises(HttpSignatureVerificationError) as uexc:
        await broken_guard.consume(key_id="k", nonce="n")
    assert uexc.value.code is HttpSignatureFailureCode.STORE_UNAVAILABLE

    class _Full:
        async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
            _ = key, ttl_seconds
            return ReplayOutcome.CAPACITY_EXCEEDED

    full_guard = SignatureNonceGuard(_Full(), profile_tag=PROFILE_TAG, ttl_seconds=60)  # type: ignore[arg-type]
    with pytest.raises(HttpSignatureVerificationError) as full_exc:
        await full_guard.consume(key_id="k", nonce="n")
    assert full_exc.value.code is HttpSignatureFailureCode.STORE_UNAVAILABLE

    # key resolver / unknown key / public resolver private path
    from authweave_http_signatures.verify import _PublicKeyResolver

    resolver = _PublicKeyResolver({"k": private_key.public_key()})
    with pytest.raises(KeyError):
        resolver.resolve_public_key("missing")
    with pytest.raises(KeyError):
        resolver.resolve_private_key("k")

    # litestar disconnect
    async def _boom() -> AsyncIterator[bytes]:
        msg = "disconnect"
        raise RuntimeError(msg)
        yield b""  # pragma: no cover

    with pytest.raises(HttpSignatureVerificationError) as lexc:
        await read_bounded_raw_body(_StreamingRequest(_boom), maximum_bytes=10)
    assert lexc.value.code is HttpSignatureFailureCode.MALFORMED

    # allow_query path
    q_policy = PaymentSignaturePolicy(allow_query=True)
    signed_q, _ = _signed(
        private_key=private_key,
        target_uri="https://api.example/v1/payments?ok=1",
        nonce="q-n1",
    )
    q_verifier = PaymentHttpSignatureVerifier(
        policy=q_policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(
            InMemoryReplayStore(capacity=8, time_source=_Clock()),
            profile_tag=PROFILE_TAG,
            ttl_seconds=60,
        ),
    )
    # signature was created for URI with query; covered @target-uri includes query
    verified_q = await q_verifier.verify(signed_q, context=_context())
    assert verified_q.key_id == "merchant-key-1"

    # invalid signature header
    bad = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(
            ("content-type", "application/json"),
            ("idempotency-key", "i"),
            ("content-digest", content_digest_sha256(b"{}")),
            ("Signature-Input", "bad"),
            ("Signature", "bad"),
        ),
        body=b"{}",
    )
    with pytest.raises(HttpSignatureVerificationError):
        await verifier.verify(bad, context=_context())

    def _bad_b64decode(*_args: object, **_kwargs: object) -> bytes:
        msg = "bad"
        raise ValueError(msg)

    with monkeypatch.context() as patch:
        patch.setattr(digest_mod.base64, "b64decode", _bad_b64decode)
        with pytest.raises(HttpSignatureVerificationError) as dexc:
            verify_content_digest(header_value="sha-256=:YWJjZGVmZ2hpams=:", body=b"x")
        assert dexc.value.code is HttpSignatureFailureCode.MALFORMED

    from authweave_http_signatures.signer import _KeyResolver

    assert _KeyResolver({"merchant-key-1": private_key}).resolve_public_key("merchant-key-1") is not None

    # unknown verify key id → malformed wrapper
    signed_ok, _ = _signed(private_key=private_key, nonce="cov-n1")
    other = Ed25519PrivateKey.generate()
    bad_key_verifier = PaymentHttpSignatureVerifier(
        policy=policy,
        public_keys={"other": other.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(
            InMemoryReplayStore(capacity=8, time_source=_Clock()),
            profile_tag=PROFILE_TAG,
            ttl_seconds=60,
        ),
    )
    with pytest.raises(HttpSignatureVerificationError):
        await bad_key_verifier.verify(signed_ok, context=_context())

    # lifetime too long for policy
    long_signed = sign_payment_message(
        view=HttpMessageView(
            method="POST",
            target_uri="https://api.example/v1/payments",
            headers=(("content-type", "application/json"), ("idempotency-key", "i")),
            body=b"{}",
        ),
        policy=PaymentSignaturePolicy(),
        key_id="merchant-key-1",
        private_key=private_key,
        nonce="life-n1",
        now=datetime.now(UTC),
        lifetime=timedelta(seconds=300),
    )
    short_policy = PaymentSignaturePolicy(max_signature_lifetime_seconds=60)
    short_verifier = PaymentHttpSignatureVerifier(
        policy=short_policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(
            InMemoryReplayStore(capacity=8, time_source=_Clock()),
            profile_tag=PROFILE_TAG,
            ttl_seconds=60,
        ),
    )
    with pytest.raises(HttpSignatureVerificationError) as lexc2:
        await short_verifier.verify(long_signed, context=_context())
    assert lexc2.value.code is HttpSignatureFailureCode.MALFORMED

    # binding missing for keyid
    only_pub = PaymentHttpSignatureVerifier(
        policy=policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"different": _binding()},
        nonce_guard=SignatureNonceGuard(
            InMemoryReplayStore(capacity=8, time_source=_Clock()),
            profile_tag=PROFILE_TAG,
            ttl_seconds=60,
        ),
    )
    signed2, _ = _signed(private_key=private_key, nonce="bind-n1")
    with pytest.raises(HttpSignatureVerificationError) as bindexc:
        await only_pub.verify(signed2, context=_context())
    assert bindexc.value.code is HttpSignatureFailureCode.KEY_BINDING_MISMATCH

    # duplicate required header
    dup = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(
            ("content-type", "application/json"),
            ("Content-Type", "application/json"),
            ("idempotency-key", "i"),
            ("content-digest", content_digest_sha256(b"{}")),
        ),
        body=b"{}",
    )
    with pytest.raises(HttpSignatureVerificationError) as dupexc:
        await verifier.verify(dup, context=_context())
    assert dupexc.value.code is HttpSignatureFailureCode.MALFORMED
    # structured-fields single-label profile enforcement
    signed_sf, _ = _signed(private_key=private_key, nonce="sf-dup")
    si = signed_sf.header("signature-input")
    sig = signed_sf.header("signature")
    assert si is not None
    assert sig is not None
    dup_label = HttpMessageView(
        method=signed_sf.method,
        target_uri=signed_sf.target_uri,
        headers=(
            ("content-type", signed_sf.header("content-type") or ""),
            ("idempotency-key", signed_sf.header("idempotency-key") or ""),
            ("content-digest", signed_sf.header("content-digest") or ""),
            ("signature-input", f"{si}, {si}"),
            ("signature", f"{sig}, {sig}"),
        ),
        body=signed_sf.body,
    )
    with pytest.raises(HttpSignatureVerificationError) as sf_dup_exc:
        await verifier.verify(dup_label, context=_context())
    assert sf_dup_exc.value.code is HttpSignatureFailureCode.MALFORMED

    wrong_label = HttpMessageView(
        method=signed_sf.method,
        target_uri=signed_sf.target_uri,
        headers=(
            ("content-type", signed_sf.header("content-type") or ""),
            ("idempotency-key", signed_sf.header("idempotency-key") or ""),
            ("content-digest", signed_sf.header("content-digest") or ""),
            ("signature-input", si.replace(f"{SIGNATURE_LABEL}=", "other=", 1)),
            ("signature", sig.replace(f"{SIGNATURE_LABEL}=", "other=", 1)),
        ),
        body=signed_sf.body,
    )
    with pytest.raises(HttpSignatureVerificationError) as sf_label_exc:
        await verifier.verify(wrong_label, context=_context())
    assert sf_label_exc.value.code is HttpSignatureFailureCode.PROFILE_MISMATCH

    from unittest.mock import patch

    base_view = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(
            ("content-type", "application/json"),
            ("idempotency-key", "i"),
            ("content-digest", content_digest_sha256(b"{}")),
            (
                "Signature-Input",
                f'{SIGNATURE_LABEL}=("@method");created=1;keyid="merchant-key-1";nonce="n";tag="{PROFILE_TAG}"',
            ),
            ("Signature", f"{SIGNATURE_LABEL}=:AA==:"),
        ),
        body=b"{}",
    )
    now_ts = int(datetime.now(UTC).timestamp())

    def _result(**params: object) -> list[object]:
        covered = {
            '"@method"': "POST",
            '"@target-uri"': "https://api.example/v1/payments",
            '"content-digest"': content_digest_sha256(b"{}"),
            '"content-type"': "application/json",
            '"idempotency-key"': "i",
            '"@signature-params"': "...",
        }
        return [SimpleNamespace(parameters=params, covered_components=covered)]

    mock_verifier = PaymentHttpSignatureVerifier(
        policy=policy,
        public_keys={"merchant-key-1": private_key.public_key()},
        bindings={"merchant-key-1": _binding()},
        nonce_guard=SignatureNonceGuard(
            InMemoryReplayStore(capacity=8, time_source=_Clock()),
            profile_tag=PROFILE_TAG,
            ttl_seconds=60,
        ),
        time_source=lambda: datetime.fromtimestamp(now_ts, tz=UTC),
    )

    with patch("authweave_http_signatures.verify.HTTPMessageVerifier.verify", return_value=[]):
        with pytest.raises(HttpSignatureVerificationError) as empty_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert empty_exc.value.code is HttpSignatureFailureCode.MALFORMED

    with patch(
        "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
        return_value=_result(keyid=1, nonce="n", tag=PROFILE_TAG, created=now_ts, expires=now_ts + 10),
    ):
        with pytest.raises(HttpSignatureVerificationError) as profile_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert profile_exc.value.code is HttpSignatureFailureCode.PROFILE_MISMATCH

    with patch(
        "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
        return_value=_result(
            keyid="merchant-key-1",
            nonce="n",
            tag=PROFILE_TAG,
            created=["bad"],
            expires=now_ts + 10,
        ),
    ):
        with pytest.raises(HttpSignatureVerificationError) as created_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert created_exc.value.code is HttpSignatureFailureCode.MALFORMED

    with patch(
        "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
        return_value=_result(
            keyid="merchant-key-1",
            nonce="n-bad-exp",
            tag=PROFILE_TAG,
            created=now_ts,
            expires=["not-an-int"],
        ),
    ):
        with pytest.raises(HttpSignatureVerificationError) as expires_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert expires_exc.value.code is HttpSignatureFailureCode.MALFORMED

    for invalid_created in (True, float(now_ts), str(now_ts)):
        with (
            patch(
                "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
                return_value=_result(
                    keyid="merchant-key-1",
                    nonce="n-non-integer",
                    tag=PROFILE_TAG,
                    created=invalid_created,
                    expires=now_ts + 10,
                ),
            ),
            pytest.raises(HttpSignatureVerificationError) as integer_exc,
        ):
            await mock_verifier.verify(base_view, context=_context())
        assert integer_exc.value.code is HttpSignatureFailureCode.MALFORMED

    with patch(
        "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
        return_value=_result(
            keyid="merchant-key-1",
            nonce="n-future",
            tag=PROFILE_TAG,
            created=now_ts + 120,
            expires=now_ts + 200,
        ),
    ):
        with pytest.raises(HttpSignatureVerificationError) as future_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert future_exc.value.code is HttpSignatureFailureCode.NOT_YET_VALID

    with patch(
        "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
        return_value=_result(
            keyid="merchant-key-1",
            nonce="n-expired",
            tag=PROFILE_TAG,
            created=now_ts - 400,
            expires=now_ts - 200,
        ),
    ):
        with pytest.raises(HttpSignatureVerificationError) as expired_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert expired_exc.value.code is HttpSignatureFailureCode.SIGNATURE_EXPIRED

    with patch(
        "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
        return_value=_result(
            keyid="merchant-key-1",
            nonce="n-inverted",
            tag=PROFILE_TAG,
            created=now_ts + 10,
            expires=now_ts + 5,
        ),
    ):
        with pytest.raises(HttpSignatureVerificationError) as inverted_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert inverted_exc.value.code is HttpSignatureFailureCode.MALFORMED

    wrong_covered = {
        '"@method"': "POST",
        '"@signature-params"': "...",
    }
    with patch(
        "authweave_http_signatures.verify.HTTPMessageVerifier.verify",
        return_value=[
            SimpleNamespace(
                parameters={
                    "keyid": "merchant-key-1",
                    "nonce": "n-cov",
                    "tag": PROFILE_TAG,
                    "created": now_ts,
                    "expires": now_ts + 10,
                },
                covered_components=wrong_covered,
            )
        ],
    ):
        with pytest.raises(HttpSignatureVerificationError) as cov_exc:
            await mock_verifier.verify(base_view, context=_context())
        assert cov_exc.value.code is HttpSignatureFailureCode.PROFILE_MISMATCH

    from authweave_http_signatures.verify import _sf_dictionary_member_count

    assert _sf_dictionary_member_count("") == 0
    assert _sf_dictionary_member_count(r'a="b\"c,d", e=1') == _SF_MEMBER_COUNT
    assert _sf_dictionary_member_count("a=(1, 2), b=3") == _SF_MEMBER_COUNT

    with pytest.raises(HttpSignatureVerificationError) as parse_exc:
        await mock_verifier.verify(
            HttpMessageView(
                method="POST",
                target_uri="https://api.example/v1/payments",
                headers=(
                    ("content-type", "application/json"),
                    ("idempotency-key", "i"),
                    ("content-digest", content_digest_sha256(b"{}")),
                    ("signature-input", "("),
                    ("signature", f"{SIGNATURE_LABEL}=:AA==:"),
                ),
                body=b"{}",
            ),
            context=_context(),
        )
    assert parse_exc.value.code is HttpSignatureFailureCode.MALFORMED

    bad_sig = HttpMessageView(
        method="POST",
        target_uri="https://api.example/v1/payments",
        headers=(
            ("content-type", "application/json"),
            ("idempotency-key", "i"),
            ("content-digest", content_digest_sha256(b"{}")),
            (
                "Signature-Input",
                (
                    f'{SIGNATURE_LABEL}=("@method" "@target-uri" "content-digest" "content-type" "idempotency-key");'
                    f'created={now_ts};keyid="merchant-key-1";expires={now_ts + 10};nonce="bad-sig";tag="{PROFILE_TAG}"'
                ),
            ),
            (
                "Signature",
                f"{SIGNATURE_LABEL}=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:",
            ),
        ),
        body=b"{}",
    )
    with pytest.raises(HttpSignatureVerificationError) as inv_exc:
        await mock_verifier.verify(bad_sig, context=_context())
    assert inv_exc.value.code is HttpSignatureFailureCode.SIGNATURE_INVALID
