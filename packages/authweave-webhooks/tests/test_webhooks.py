"""Import isolation and happy-path/negative matrix for authweave-webhooks."""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Self

import pytest
from authweave_core import InMemoryReplayStore, ReplayOutcome
from authweave_webhooks import (
    MAX_BODY_BYTES,
    Ed25519PublicKey,
    LocalEd25519KeyringSigner,
    PublicKeyDocument,
    StandardWebhooksVerifier,
    StaticPublicKeyResolver,
    WebhookFailureCode,
    WebhookVerificationError,
    create_delivery,
    format_signature_header,
    parse_headers,
)
from authweave_webhooks.litestar_adapter import verify_litestar_request
from authweave_webhooks.redis_store import RedisReplayStore
from authweave_webhooks.sender import HttpxWebhookSender, validate_https_endpoint
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from litestar.datastructures import Headers

pytestmark = pytest.mark.unit

_NOW = 1_700_000_000

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class _StreamingResponse:
    def __init__(
        self,
        *,
        status_code: int,
        headers: dict[str, str] | None = None,
        chunks: tuple[bytes, ...] = (),
    ) -> None:
        self.status_code = status_code
        self.headers = {} if headers is None else headers
        self._chunks = chunks
        self.closed = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object,
    ) -> None:
        self.closed = True

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


class _StreamingClient:
    def __init__(self, response: _StreamingResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def stream(self, method: str, url: str, **kwargs: Any) -> _StreamingResponse:
        self.calls.append((method, url, kwargs))
        return self.response


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes_raw()


def _document(public_key: bytes, **overrides: Any) -> PublicKeyDocument:
    payload = {
        "version": "1",
        "environment": "sandbox",
        "owner": "merchant-1",
        "endpoint": "https://merchant.example/hooks/payments",
        "not_before": 0,
        "retire_after": None,
        "keys": (Ed25519PublicKey(public_key),),
    }
    payload.update(overrides)
    return PublicKeyDocument(**payload)


@pytest.fixture
def clock() -> dict[str, int]:
    return {"now": _NOW}


def _replay_store(clock: dict[str, int], *, capacity: int = 64) -> InMemoryReplayStore:
    return InMemoryReplayStore(capacity=capacity, time_source=lambda: float(clock["now"]))


async def _signed_delivery(
    private: Ed25519PrivateKey,
    *,
    body: bytes = b'{"ok":true}',
    webhook_id: str = "msg_123",
    timestamp: int = _NOW,
    key_ref: str = "active",
) -> Any:
    signer = LocalEd25519KeyringSigner({key_ref: private})
    return await create_delivery(
        signer=signer,
        key_refs=[key_ref],
        webhook_id=webhook_id,
        timestamp=timestamp,
        body=body,
    )


def test_import_does_not_load_litestar_or_redis() -> None:
    script = """
import json, sys, authweave_webhooks
blocked = ("litestar", "redis", "httpx")
loaded = sorted(name for name in sys.modules if name.split(".", 1)[0] in blocked)
print(json.dumps(loaded))
"""
    completed = subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, text=True)
    assert json.loads(completed.stdout) == []


async def test_sign_and_verify_roundtrip(clock: dict[str, int]) -> None:
    private, public = _keypair()
    delivery = await _signed_delivery(private)
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public)),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    verified = await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert verified.webhook_id == "msg_123"
    assert verified.body == b'{"ok":true}'
    assert "body=" not in repr(verified)
    assert "signature_header=" not in repr(delivery) or "..." in repr(delivery)


async def test_rotation_overlap_accepts_next_key(clock: dict[str, int]) -> None:
    active, active_pub = _keypair()
    nxt, next_pub = _keypair()
    delivery = await create_delivery(
        signer=LocalEd25519KeyringSigner({"next": nxt}),
        key_refs=["next"],
        webhook_id="msg_rot",
        timestamp=_NOW,
        body=b"{}",
    )
    document = _document(
        active_pub,
        keys=(Ed25519PublicKey(active_pub), Ed25519PublicKey(next_pub)),
    )
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(document),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    verified = await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert verified.key_document_version == "1"
    del active


async def test_refresh_allows_one_controlled_retry(clock: dict[str, int]) -> None:
    old_private, old_pub = _keypair()
    new_private, new_pub = _keypair()
    delivery = await _signed_delivery(new_private, webhook_id="msg_refresh")
    resolver = StaticPublicKeyResolver(_document(old_pub), refresh_document=_document(new_pub, version="2"))
    verifier = StandardWebhooksVerifier(
        resolver,
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    verified = await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert verified.key_document_version == "2"
    refreshed = await resolver.refresh()
    assert refreshed is not None
    assert refreshed.version == "2"
    del old_private


async def test_concurrent_refresh_losers_re_resolve_winning_snapshot(clock: dict[str, int]) -> None:
    old_private, old_public = _keypair()
    next_private, next_public = _keypair()
    old_document = _document(old_public, version="1")
    next_document = _document(
        next_public,
        version="2",
        keys=(Ed25519PublicKey(old_public), Ed25519PublicKey(next_public)),
    )
    callers = 16
    deliveries = await asyncio.gather(
        *(_signed_delivery(next_private, webhook_id=f"msg_rotation_race_{index}") for index in range(callers)),
    )

    class _RacingResolver:
        def __init__(self) -> None:
            self.current = old_document
            self.initial_resolves = 0
            self.initial_resolves_ready = asyncio.Event()
            self.refresh_lock = asyncio.Lock()
            self.refreshed = False

        async def resolve(self) -> PublicKeyDocument:
            if self.current is next_document:
                return self.current
            snapshot = self.current
            self.initial_resolves += 1
            if self.initial_resolves == callers:
                self.initial_resolves_ready.set()
            await self.initial_resolves_ready.wait()
            return snapshot

        async def refresh(self) -> PublicKeyDocument | None:
            async with self.refresh_lock:
                if self.refreshed:
                    return None
                self.refreshed = True
                self.current = next_document
                return self.current

    resolver = _RacingResolver()
    verifier = StandardWebhooksVerifier(
        resolver,
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    verified = await asyncio.gather(
        *(verifier.verify(headers=delivery.headers(), body=delivery.body) for delivery in deliveries),
    )
    assert {result.key_document_version for result in verified} == {"2"}
    del old_private


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda d, h: (d.body + b"x", h), WebhookFailureCode.SIGNATURE_INVALID),
        (
            lambda d, h: (d.body, {**h, "webhook-timestamp": str(_NOW - 10_000)}),
            WebhookFailureCode.TIMESTAMP_OUT_OF_TOLERANCE,
        ),
        (lambda d, h: (d.body, {**h, "webhook-id": "bad.id"}), WebhookFailureCode.MALFORMED_HEADERS),
        (
            lambda d, h: (d.body, [(k, v) for k, v in h.items()] + [("webhook-id", "dup")]),
            WebhookFailureCode.DUPLICATE_HEADER,
        ),
        (lambda d, h: (d.body, {**h, "webhook-signature": "v1,abcd"}), WebhookFailureCode.SIGNATURE_INVALID),
        (lambda d, h: (d.body, {**h, "webhook-timestamp": "1.5"}), WebhookFailureCode.TIMESTAMP_INVALID),
    ],
)
async def test_negative_matrix(clock: dict[str, int], mutate: Any, code: WebhookFailureCode) -> None:
    private, public = _keypair()
    delivery = await _signed_delivery(private)
    body, headers = mutate(delivery, delivery.headers())
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public)),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=headers, body=body)
    assert exc_info.value.code is code
    assert "eyJ" not in repr(exc_info.value)


async def test_environment_owner_and_endpoint_mismatch(clock: dict[str, int]) -> None:
    private, public = _keypair()
    delivery = await _signed_delivery(private)
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public, environment="live")),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.ENVIRONMENT_MISMATCH

    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public, owner="merchant-2")),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.OWNER_MISMATCH

    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public, endpoint="https://other.example/hook")),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.ENDPOINT_MISMATCH


async def test_key_document_validity_window(clock: dict[str, int]) -> None:
    private, public = _keypair()
    delivery = await _signed_delivery(private)
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public, not_before=_NOW + 10)),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.KEY_UNAVAILABLE

    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public, retire_after=_NOW - 1)),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.KEY_UNAVAILABLE


async def test_replay_namespace_binds_full_onboarding_identity(clock: dict[str, int]) -> None:
    private, public = _keypair()
    delivery = await _signed_delivery(private)
    store = _replay_store(clock, capacity=8)
    bindings = (
        ("sandbox", "merchant-1", "https://merchant.example/hooks/payments"),
        ("live", "merchant-1", "https://merchant.example/hooks/payments"),
        ("sandbox", "merchant-2", "https://merchant.example/hooks/payments"),
        ("sandbox", "merchant-1", "https://merchant.example/hooks/refunds"),
    )
    verifiers = [
        StandardWebhooksVerifier(
            StaticPublicKeyResolver(
                _document(public, environment=environment, owner=owner, endpoint=endpoint),
            ),
            replay_store=store,
            expected_environment=environment,
            expected_owner=owner,
            expected_endpoint=endpoint,
            time_source=lambda: clock["now"],
        )
        for environment, owner, endpoint in bindings
    ]

    for verifier in verifiers:
        verified = await verifier.verify(headers=delivery.headers(), body=delivery.body)
        assert verified.replay_detected is False

    retry = await verifiers[0].verify(headers=delivery.headers(), body=delivery.body)
    assert retry.replay_detected is True
    assert retry.body == delivery.body


@pytest.mark.parametrize("outcome", [ReplayOutcome.CAPACITY_EXCEEDED, ReplayOutcome.UNAVAILABLE])
async def test_verifier_maps_replay_store_failure(outcome: ReplayOutcome, clock: dict[str, int]) -> None:
    class _Store:
        async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
            assert key.startswith("webhook:v1:")
            assert ttl_seconds == 601
            return outcome

    private, public = _keypair()
    delivery = await _signed_delivery(private)
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public)),
        replay_store=_Store(),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )

    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.STORE_UNAVAILABLE


async def test_replay_ttl_covers_inclusive_timestamp_window(clock: dict[str, int]) -> None:
    tolerance = 5
    private, public = _keypair()
    delivery = await _signed_delivery(private, timestamp=_NOW + tolerance)
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public)),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        timestamp_tolerance_seconds=tolerance,
        time_source=lambda: clock["now"],
    )
    first = await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert first.replay_detected is False

    clock["now"] = _NOW + 2 * tolerance
    duplicate = await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert duplicate.replay_detected is True

    clock["now"] += 1
    with pytest.raises(WebhookVerificationError) as expired:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert expired.value.code is WebhookFailureCode.TIMESTAMP_OUT_OF_TOLERANCE


async def test_invalid_signature_does_not_claim_replay_key(clock: dict[str, int]) -> None:
    class _Store:
        def __init__(self) -> None:
            self.calls = 0

        async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
            assert key.startswith("webhook:v1:")
            assert ttl_seconds > 0
            self.calls += 1
            return ReplayOutcome.STORED

    private, public = _keypair()
    delivery = await _signed_delivery(private)
    store = _Store()
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public)),
        replay_store=store,
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )

    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body + b"forged")
    assert exc_info.value.code is WebhookFailureCode.SIGNATURE_INVALID
    assert store.calls == 0

    await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert store.calls == 1


async def test_redis_store_outcomes() -> None:
    class _Redis:
        def __init__(self) -> None:
            self.values: set[str] = set()
            self.fail = False

        async def set(self, name: str, _value: str, *, nx: bool, ex: int) -> bool:
            assert nx
            assert ex > 0
            if self.fail:
                msg = "down"
                raise RuntimeError(msg)
            if name in self.values:
                return False
            self.values.add(name)
            return True

    redis = _Redis()
    store = RedisReplayStore(redis)
    assert await store.check_and_store("k1", ttl_seconds=30) is ReplayOutcome.STORED
    assert await store.check_and_store("k1", ttl_seconds=30) is ReplayOutcome.REPLAY
    redis.fail = True
    assert await store.check_and_store("k2", ttl_seconds=30) is ReplayOutcome.UNAVAILABLE


async def test_httpx_sender_and_endpoint_policy() -> None:
    private, _public = _keypair()
    delivery = await _signed_delivery(private)
    endpoint = "https://hooks.example/receive"
    response = _StreamingResponse(
        status_code=503,
        headers={"retry-after": "12"},
        chunks=(b"busy" * 10,),
    )
    client = _StreamingClient(response)
    sender = HttpxWebhookSender(client, allowed_endpoints={endpoint})
    result = await sender.send(endpoint=endpoint, delivery=delivery)
    assert result.status_code == 503
    assert result.retry_after_seconds == 12
    assert "busy" not in repr(result)
    assert response.closed
    assert client.calls[0][0:2] == ("POST", endpoint)
    assert client.calls[0][2]["follow_redirects"] is False

    with pytest.raises(ValueError, match="HTTPS"):
        validate_https_endpoint("http://hooks.example/receive")
    with pytest.raises(ValueError, match="HTTPS"):
        validate_https_endpoint("https://user:pass@hooks.example/receive")
    with pytest.raises(ValueError, match="allowlist"):
        await sender.send(endpoint="https://other.example/receive", delivery=delivery)


async def test_litestar_adapter(clock: dict[str, int]) -> None:
    private, public = _keypair()
    delivery = await _signed_delivery(private)
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public)),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )

    class _Request:
        def __init__(self) -> None:
            self.headers = delivery.headers()

        async def body(self) -> bytes:
            return delivery.body

    verified = await verify_litestar_request(verifier, _Request())
    assert verified.webhook_id == "msg_123"

    class _DuplicateRequest(_Request):
        def __init__(self) -> None:
            self.headers = Headers([
                (b"webhook-id", b"attacker-value"),
                *((name.encode(), value.encode()) for name, value in delivery.headers().items()),
            ])

    with pytest.raises(WebhookVerificationError) as exc_info:
        await verify_litestar_request(verifier, _DuplicateRequest())
    assert exc_info.value.code is WebhookFailureCode.DUPLICATE_HEADER


def test_parse_and_format_guards() -> None:
    with pytest.raises(WebhookVerificationError) as exc_info:
        parse_headers({"webhook-id": "a"}, body=b"x" * (MAX_BODY_BYTES + 1))
    assert exc_info.value.code is WebhookFailureCode.BODY_TOO_LARGE

    with pytest.raises(ValueError, match="signature count"):
        format_signature_header([])
    with pytest.raises(ValueError, match="64 bytes"):
        format_signature_header([b"short"])

    private = Ed25519PrivateKey.generate()
    signature = private.sign(b"msg")
    header = format_signature_header([signature, signature])
    assert header.count("v1a,") == 2
    assert base64.b64encode(signature).decode() in header


def test_model_and_signer_guards() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519PublicKey(b"nope")
    with pytest.raises(ValueError, match="required"):
        PublicKeyDocument(
            version="",
            environment="sandbox",
            owner="o",
            endpoint="e",
            not_before=0,
            retire_after=None,
            keys=(Ed25519PublicKey(b"\x00" * 32),),
        )
    with pytest.raises(ValueError, match="keyring"):
        LocalEd25519KeyringSigner({})
    signer = LocalEd25519KeyringSigner({"a": Ed25519PrivateKey.generate()})
    assert "private" not in repr(signer).lower()


async def test_create_delivery_validation() -> None:
    signer = LocalEd25519KeyringSigner({"a": Ed25519PrivateKey.generate()})
    with pytest.raises(ValueError, match="webhook_id"):
        await create_delivery(signer=signer, key_refs=["a"], webhook_id="bad.id", timestamp=1, body=b"{}")
    with pytest.raises(ValueError, match="timestamp"):
        await create_delivery(signer=signer, key_refs=["a"], webhook_id="ok", timestamp=-1, body=b"{}")
    with pytest.raises(KeyError, match="unknown key reference"):
        await create_delivery(signer=signer, key_refs=["missing"], webhook_id="ok", timestamp=1, body=b"{}")


async def test_refresh_exhaustion_and_forged_signature(clock: dict[str, int]) -> None:
    private, public = _keypair()
    other, _ = _keypair()
    delivery = await _signed_delivery(other, webhook_id="msg_forged")
    verifier = StandardWebhooksVerifier(
        StaticPublicKeyResolver(_document(public)),
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.SIGNATURE_INVALID
    del private


def test_constructor_guards() -> None:
    with pytest.raises(ValueError, match="positive"):
        StandardWebhooksVerifier(
            StaticPublicKeyResolver(_document(b"\x00" * 32)),
            replay_store=InMemoryReplayStore(capacity=1, time_source=lambda: float(_NOW)),
            expected_environment="sandbox",
            expected_owner="merchant-1",
            expected_endpoint="https://merchant.example/hooks/payments",
            timestamp_tolerance_seconds=0,
            time_source=lambda: _NOW,
        )

    class _BrokenClient:
        def stream(
            self,
            _method: str,
            _url: str,
            **_kwargs: object,
        ) -> object:
            msg = "unreachable"
            raise AssertionError(msg)

    with pytest.raises(ValueError, match="positive"):
        HttpxWebhookSender(_BrokenClient(), allowed_endpoints={"https://hooks.example/x"}, timeout_seconds=0)
    with pytest.raises(ValueError, match="at least one"):
        HttpxWebhookSender(_BrokenClient(), allowed_endpoints=set())


async def test_redis_ttl_guard() -> None:
    class _Redis:
        async def set(self, name: str, value: str, *, nx: bool, ex: int) -> bool:
            return True

    store = RedisReplayStore(_Redis())
    with pytest.raises(ValueError, match="positive"):
        await store.check_and_store("k", ttl_seconds=0)


async def test_sender_retry_after_invalid() -> None:
    private, _ = _keypair()
    delivery = await _signed_delivery(private)
    endpoint = "https://hooks.example/x"
    response = _StreamingResponse(status_code=200, headers={"retry-after": "soon"}, chunks=(b"ok",))
    result = await HttpxWebhookSender(_StreamingClient(response), allowed_endpoints={endpoint}).send(
        endpoint=endpoint,
        delivery=delivery,
    )
    assert result.retry_after_seconds is None


def test_public_key_document_retire_order() -> None:
    with pytest.raises(ValueError, match="retire_after"):
        PublicKeyDocument(
            version="1",
            environment="sandbox",
            owner="o",
            endpoint="e",
            not_before=10,
            retire_after=5,
            keys=(Ed25519PublicKey(b"\x00" * 32),),
        )


def test_public_key_document_cardinality() -> None:
    key = Ed25519PublicKey(b"\x00" * 32)
    with pytest.raises(ValueError, match="1..3"):
        PublicKeyDocument(
            version="1",
            environment="sandbox",
            owner="o",
            endpoint="e",
            not_before=0,
            retire_after=None,
            keys=(),
        )
    with pytest.raises(ValueError, match="1..3"):
        PublicKeyDocument(
            version="1",
            environment="sandbox",
            owner="o",
            endpoint="e",
            not_before=0,
            retire_after=None,
            keys=(key, key, key, key),
        )


def test_endpoint_rejects_fragment() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        validate_https_endpoint("https://hooks.example/receive#frag")


def test_error_repr_is_secret_free() -> None:
    err = WebhookVerificationError(WebhookFailureCode.SIGNATURE_INVALID)
    assert "SIGNATURE_INVALID" in repr(err)
    assert repr(Ed25519PublicKey(b"\x00" * 32)) == "Ed25519PublicKey(public_key=...)"


def test_header_edge_cases() -> None:
    with pytest.raises(WebhookVerificationError) as missing:
        parse_headers({"content-type": "application/json", "webhook-id": "only"}, body=b"{}")
    assert missing.value.code is WebhookFailureCode.MALFORMED_HEADERS

    with pytest.raises(WebhookVerificationError) as many_sigs:
        parse_headers(
            {
                "webhook-id": "msg",
                "webhook-timestamp": "1",
                "webhook-signature": " ".join(["v1a,AAAA"] * 4),
            },
            body=b"{}",
        )
    assert many_sigs.value.code is WebhookFailureCode.SIGNATURE_INVALID

    with pytest.raises(WebhookVerificationError) as bad_b64:
        parse_headers(
            {
                "webhook-id": "msg",
                "webhook-timestamp": "1",
                "webhook-signature": "v1a,@@@not-base64@@@",
            },
            body=b"{}",
        )
    assert bad_b64.value.code is WebhookFailureCode.SIGNATURE_INVALID

    short = base64.b64encode(b"short").decode()
    with pytest.raises(WebhookVerificationError) as short_sig:
        parse_headers(
            {
                "webhook-id": "msg",
                "webhook-timestamp": "1",
                "webhook-signature": f"v1a,{short}",
            },
            body=b"{}",
        )
    assert short_sig.value.code is WebhookFailureCode.SIGNATURE_INVALID


async def test_refresh_then_still_invalid(clock: dict[str, int]) -> None:
    _private, public = _keypair()
    other, _ = _keypair()
    delivery = await _signed_delivery(other, webhook_id="msg_still_bad")
    resolver = StaticPublicKeyResolver(_document(public), refresh_document=_document(public, version="2"))
    verifier = StandardWebhooksVerifier(
        resolver,
        replay_store=_replay_store(clock),
        expected_environment="sandbox",
        expected_owner="merchant-1",
        expected_endpoint="https://merchant.example/hooks/payments",
        time_source=lambda: clock["now"],
    )
    with pytest.raises(WebhookVerificationError) as exc_info:
        await verifier.verify(headers=delivery.headers(), body=delivery.body)
    assert exc_info.value.code is WebhookFailureCode.SIGNATURE_INVALID


async def test_sender_negative_retry_after() -> None:
    private, _ = _keypair()
    delivery = await _signed_delivery(private)
    endpoint = "https://hooks.example/x"
    response = _StreamingResponse(status_code=429, headers={"retry-after": "-1"}, chunks=(b"no",))
    result = await HttpxWebhookSender(_StreamingClient(response), allowed_endpoints={endpoint}).send(
        endpoint=endpoint,
        delivery=delivery,
    )
    assert result.retry_after_seconds is None


async def test_sender_missing_retry_after() -> None:
    private, _ = _keypair()
    delivery = await _signed_delivery(private)
    endpoint = "https://hooks.example/x"
    response = _StreamingResponse(status_code=200, chunks=(b"ok",))
    result = await HttpxWebhookSender(_StreamingClient(response), allowed_endpoints={endpoint}).send(
        endpoint=endpoint,
        delivery=delivery,
    )
    assert result.retry_after_seconds is None


async def test_sender_streams_and_caps_response_body() -> None:
    private, _ = _keypair()
    delivery = await _signed_delivery(private)
    endpoint = "https://hooks.example/x"
    response = _StreamingResponse(status_code=200, chunks=(b"a" * 40_000, b"b" * 40_000, b"unread"))
    result = await HttpxWebhookSender(_StreamingClient(response), allowed_endpoints={endpoint}).send(
        endpoint=endpoint,
        delivery=delivery,
    )
    assert len(result.body) == 65_536
    assert result.body == b"a" * 40_000 + b"b" * 25_536
    assert response.closed
