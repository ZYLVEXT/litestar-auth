"""Tests for API-key HMAC request signing."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from litestar.connection import ASGIConnection
from litestar.exceptions import ClientException

from litestar_auth._secrets_at_rest import FernetKeyring
from litestar_auth.authentication.middleware import (
    _DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES,
    _buffer_body_for_signature,
)
from litestar_auth.authentication.strategy._api_key_format import digest_api_key_secret
from litestar_auth.authentication.strategy._api_key_nonce_store import ApiKeyNonceStoreResult, InMemoryApiKeyNonceStore
from litestar_auth.authentication.strategy.api_key import ApiKeyContext, ApiKeyStrategy
from litestar_auth.authentication.transport._api_key_signing import (
    API_KEY_HMAC_BODY_SHA256_HEADER,
    API_KEY_HMAC_DATE_HEADER,
    API_KEY_HMAC_NONCE_HEADER,
    API_KEY_HMAC_SCHEME,
    _invalid_required_signing_headers,
    _parse_request_datetime,
    build_canonical_request,
    classify_signed_request_skew,
    clear_current_signed_api_key_request,
    get_current_signed_api_key_request,
    read_signed_api_key_request,
    sign_canonical_request,
)
from litestar_auth.exceptions import ErrorCode
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit

HTTP_REQUEST_ENTITY_TOO_LARGE = 413
API_KEY_HASH_SECRET = "api-key-hash-secret-0123456789abcdef"


@dataclass(slots=True)
class SignedApiKeyRow:
    """API-key row fixture for signing tests."""

    user_id: UUID
    key_id: str
    hashed_secret: bytes
    encrypted_secret: bytes | None
    scopes: list[str]
    signing_required: bool
    prefix_env: str = "prod"
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class SignedApiKeyStore:
    """In-memory API-key store fixture."""

    def __init__(self, row: SignedApiKeyRow) -> None:
        """Store the row returned by matching lookups."""
        self.row = row

    async def get_by_key_id(self, key_id: str, *, include_inactive: bool = False) -> SignedApiKeyRow | None:
        """Return the fixture row when ``key_id`` matches."""
        del include_inactive
        if key_id == self.row.key_id:
            return self.row
        return None


class MissingApiKeyStore(SignedApiKeyStore):
    """API-key store fixture that never returns rows."""

    async def get_by_key_id(self, key_id: str, *, include_inactive: bool = False) -> SignedApiKeyRow | None:
        """Return no rows."""
        del key_id, include_inactive
        return None


class UserManager:
    """User manager fixture."""

    def __init__(self, user: ExampleUser) -> None:
        """Store the resolved user."""
        self.user = user

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Return the user when ``user_id`` matches."""
        if user_id == self.user.id:
            return self.user
        return None


class MissingUserManager(UserManager):
    """User manager fixture that never returns a user."""

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Return no user."""
        del user_id
        return None


class TrackingNonceStore:
    """Nonce store fixture that records attempted writes."""

    def __init__(self, result: ApiKeyNonceStoreResult | None = None) -> None:
        """Store the result returned from every mark attempt."""
        self.result = result or ApiKeyNonceStoreResult(stored=True)
        self.calls: list[tuple[str, str, int]] = []

    async def mark_used(self, *, key_id: str, nonce: str, ttl_seconds: int) -> ApiKeyNonceStoreResult:
        """Record mark arguments and return the configured outcome.

        Returns:
            The configured nonce-store result.
        """
        self.calls.append((key_id, nonce, ttl_seconds))
        return self.result


def _keyring() -> FernetKeyring:
    return FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})


def _signed_row(*, user_id: UUID, secret: str, keyring: FernetKeyring, key_id: str = "keyid") -> SignedApiKeyRow:
    """Build a signing-required API-key row.

    Returns:
        Row fixture with encrypted signing secret.
    """
    return SignedApiKeyRow(
        user_id=user_id,
        key_id=key_id,
        hashed_secret=digest_api_key_secret(api_key_hash_secret=API_KEY_HASH_SECRET.encode(), secret=secret),
        encrypted_secret=keyring.encrypt(secret).encode(),
        scopes=["read"],
        signing_required=True,
    )


def _strategy_for_row(
    row: SignedApiKeyRow,
    *,
    keyring: FernetKeyring,
    nonce_store: InMemoryApiKeyNonceStore | None = None,
) -> ApiKeyStrategy[ExampleUser, UUID]:
    """Build a signing-enabled strategy for ``row``.

    Returns:
        Strategy configured with signing support.
    """
    return ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=cast("Any", SignedApiKeyStore(row)),
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        nonce_store=InMemoryApiKeyNonceStore() if nonce_store is None else nonce_store,
        secret_encryption_keyring=keyring,
    )


async def test_body_buffer_replays_request_messages_and_empty_fallback() -> None:
    """Signed-request body buffering preserves raw body bytes and replays messages."""
    messages = [
        {"type": "http.request", "body": b"one-", "more_body": True},
        {"type": "http.request", "body": b"two", "more_body": False},
    ]

    async def receive() -> object:
        await asyncio.sleep(0)
        return messages.pop(0)

    body, replay = await _buffer_body_for_signature(cast("Any", receive))

    assert body == b"one-two"
    assert await replay() == {"type": "http.request", "body": b"one-", "more_body": True}
    assert await replay() == {"type": "http.request", "body": b"two", "more_body": False}
    assert await replay() == {"type": "http.request", "body": b"", "more_body": False}


async def test_body_buffer_allows_body_at_configured_limit() -> None:
    """Signed-request body buffering accepts payloads exactly at the configured byte limit."""
    messages = [
        {"type": "http.request", "body": b"one-", "more_body": True},
        {"type": "http.request", "body": b"two", "more_body": False},
    ]

    async def receive() -> object:
        await asyncio.sleep(0)
        return messages.pop(0)

    body, replay = await _buffer_body_for_signature(cast("Any", receive), max_body_bytes=len(b"one-two"))

    assert body == b"one-two"
    assert await replay() == {"type": "http.request", "body": b"one-", "more_body": True}
    assert await replay() == {"type": "http.request", "body": b"two", "more_body": False}


async def test_body_buffer_rejects_body_over_configured_limit() -> None:
    """Signed-request body buffering fails closed before unbounded pre-auth accumulation."""
    messages = [
        {"type": "http.request", "body": b"one-", "more_body": True},
        {"type": "http.request", "body": b"two", "more_body": False},
    ]

    async def receive() -> object:
        await asyncio.sleep(0)
        return messages.pop(0)

    with pytest.raises(ClientException) as exc_info:
        await _buffer_body_for_signature(cast("Any", receive), max_body_bytes=len(b"one-tw"))

    assert exc_info.value.status_code == HTTP_REQUEST_ENTITY_TOO_LARGE
    assert exc_info.value.detail == "Signed API-key request body is too large."
    assert exc_info.value.extra == {"code": ErrorCode.REQUEST_BODY_INVALID}


async def test_body_buffer_enforces_configured_message_limit() -> None:
    """Signed-request body buffering caps empty frame accumulation independent of bytes."""
    max_messages = _DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES
    call_count = 0

    async def receive() -> object:
        nonlocal call_count
        await asyncio.sleep(0)
        call_count += 1
        return {"type": "http.request", "body": b"", "more_body": call_count <= max_messages}

    with pytest.raises(ClientException) as exc_info:
        await _buffer_body_for_signature(cast("Any", receive), max_messages=max_messages)

    assert call_count == max_messages + 1
    assert exc_info.value.status_code == HTTP_REQUEST_ENTITY_TOO_LARGE
    assert exc_info.value.detail == "Signed API-key request body is too large."
    assert exc_info.value.extra == {"code": ErrorCode.REQUEST_BODY_INVALID}


async def test_body_buffer_stops_on_disconnect() -> None:
    """Signed-request body buffering tolerates non-request ASGI messages."""

    async def receive() -> object:
        await asyncio.sleep(0)
        return {"type": "http.disconnect"}

    body, replay = await _buffer_body_for_signature(cast("Any", receive))

    assert body == b""
    assert await replay() == {"type": "http.disconnect"}


async def test_body_buffer_ignores_non_bytes_body_chunks() -> None:
    """Signed-request body buffering ignores malformed non-byte body chunks."""

    async def receive() -> object:
        await asyncio.sleep(0)
        return {"type": "http.request", "body": "not-bytes", "more_body": False}

    body, replay = await _buffer_body_for_signature(cast("Any", receive))

    assert body == b""
    assert await replay() == {"type": "http.request", "body": "not-bytes", "more_body": False}


def _signed_scope(*, body: bytes = b'{"ok":true}', nonce: str = "nonce-1", date: datetime | None = None) -> HTTPScope:
    request_date = date or datetime.now(tz=UTC)
    return cast(
        "HTTPScope",
        {
            "type": "http",
            "method": "POST",
            "path": "/protected",
            "raw_path": b"/protected",
            "query_string": b"b=2&a=1",
            "headers": [
                (b"host", b"example.test"),
                (API_KEY_HMAC_DATE_HEADER.lower().encode(), request_date.isoformat().encode()),
                (API_KEY_HMAC_NONCE_HEADER.lower().encode(), nonce.encode()),
            ],
            "litestar_auth_body": body,
        },
    )


def _authorize_scope(scope: HTTPScope, *, key_id: str, secret: str) -> None:
    connection = ASGIConnection(scope)
    canonical_request = build_canonical_request(
        connection,
        signed_headers=("host", "x-auth-date", "x-auth-nonce"),
    )
    signature = sign_canonical_request(secret=secret, canonical_request=canonical_request)
    cast("list[tuple[bytes, bytes]]", scope["headers"]).append(
        (
            b"authorization",
            (
                f"{API_KEY_HMAC_SCHEME} Credential={key_id}, "
                "SignedHeaders=host;x-auth-date;x-auth-nonce, "
                f"Signature={signature}"
            ).encode(),
        ),
    )
    cast("dict[str, Any]", scope).pop("state", None)


def test_signing_transport_ignores_non_hmac_authorization() -> None:
    """Non-HMAC authorization headers are ignored by the signing parser."""
    scope = _signed_scope()
    cast("list[tuple[bytes, bytes]]", scope["headers"]).append((b"authorization", b"Bearer token"))

    assert read_signed_api_key_request(ASGIConnection(scope)) is None


@pytest.mark.parametrize(
    "authorization",
    [
        f"{API_KEY_HMAC_SCHEME} Credential=keyid, SignedHeaders=host;x-auth-date;x-auth-nonce",
        f"{API_KEY_HMAC_SCHEME} Credential=, SignedHeaders=host;x-auth-date;x-auth-nonce, Signature=sig",
        f"{API_KEY_HMAC_SCHEME} Credential=keyid, SignedHeaders=host;x-auth-date;x-auth-nonce, Signature={'a' * 257}",
    ],
)
def test_signing_transport_marks_malformed_authorization_as_hmac_attempt(authorization: str) -> None:
    """Malformed HMAC authorization still marks the request as an API-key signing attempt."""
    scope = _signed_scope()
    cast("list[tuple[bytes, bytes]]", scope["headers"]).append((b"authorization", authorization.encode()))

    assert read_signed_api_key_request(ASGIConnection(scope)) == API_KEY_HMAC_SCHEME


def test_signing_transport_ignores_parameter_without_separator() -> None:
    """Authorization parser ignores comma parts that are not key-value pairs."""
    scope = _signed_scope()
    cast("list[tuple[bytes, bytes]]", scope["headers"]).append(
        (
            b"authorization",
            f"{API_KEY_HMAC_SCHEME} Broken, Credential=keyid, SignedHeaders=host;x-auth-date;x-auth-nonce, Signature=sig".encode(),
        ),
    )

    assert read_signed_api_key_request(ASGIConnection(scope)) == API_KEY_HMAC_SCHEME
    assert get_current_signed_api_key_request() is not None


def test_signing_required_headers_require_host_in_signed_headers() -> None:
    """Required signed headers include host, date, and nonce."""
    assert (
        _invalid_required_signing_headers(
            datetime.now(tz=UTC).isoformat(),
            "nonce",
            ("x-auth-date", "x-auth-nonce"),
        )
        is True
    )
    assert (
        _invalid_required_signing_headers(
            datetime.now(tz=UTC).isoformat(),
            "nonce",
            ("host", "x-auth-date", "x-auth-nonce"),
        )
        is False
    )


def test_signing_transport_rejects_authorization_that_omits_host_signed_header() -> None:
    """Omitting host from SignedHeaders marks HMAC auth but stores no signed request."""
    scope = _signed_scope()
    cast("list[tuple[bytes, bytes]]", scope["headers"]).append(
        (
            b"authorization",
            f"{API_KEY_HMAC_SCHEME} Credential=keyid, SignedHeaders=x-auth-date;x-auth-nonce, Signature=sig".encode(),
        ),
    )

    assert read_signed_api_key_request(ASGIConnection(scope)) == API_KEY_HMAC_SCHEME
    assert get_current_signed_api_key_request() is None


@pytest.mark.parametrize(
    "headers",
    [
        (),
        ((API_KEY_HMAC_DATE_HEADER.lower().encode(), b"not-a-date"),),
        (
            (API_KEY_HMAC_DATE_HEADER.lower().encode(), datetime.now(tz=UTC).isoformat().encode()),
            (API_KEY_HMAC_NONCE_HEADER.lower().encode(), b""),
        ),
    ],
)
def test_signing_transport_rejects_missing_or_bad_required_headers(headers: tuple[tuple[bytes, bytes], ...]) -> None:
    """Missing date, nonce, or parseable date prevents signed context creation."""
    scope = _signed_scope()
    scope["headers"] = [
        (
            b"authorization",
            f"{API_KEY_HMAC_SCHEME} Credential=keyid, SignedHeaders=host;x-auth-date;x-auth-nonce, Signature=sig".encode(),
        ),
        *headers,
    ]

    assert read_signed_api_key_request(ASGIConnection(scope)) == API_KEY_HMAC_SCHEME


def test_signing_transport_rejects_unparseable_date_with_nonce_present() -> None:
    """Unparseable dates fail after required header validation."""
    scope = _signed_scope()
    scope["headers"] = [
        (API_KEY_HMAC_DATE_HEADER.lower().encode(), b"not-a-date"),
        (API_KEY_HMAC_NONCE_HEADER.lower().encode(), b"nonce"),
        (
            b"authorization",
            f"{API_KEY_HMAC_SCHEME} Credential=keyid, SignedHeaders=host;x-auth-date;x-auth-nonce, Signature=sig".encode(),
        ),
    ]

    assert read_signed_api_key_request(ASGIConnection(scope)) == API_KEY_HMAC_SCHEME
    assert get_current_signed_api_key_request() is None


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("2026-05-09T18:00:00Z", datetime(2026, 5, 9, 18, 0, tzinfo=UTC)),
        ("2026-05-09T18:00:00+00:00", datetime(2026, 5, 9, 18, 0, tzinfo=UTC)),
        ("2026-05-09T18:00:00", datetime(2026, 5, 9, 18, 0, tzinfo=UTC)),
    ],
)
def test_parse_request_datetime_accepts_iso8601_values(raw_value: str, expected: datetime) -> None:
    """Request date parsing normalizes supported ISO-8601 shapes to UTC."""
    parsed = _parse_request_datetime(raw_value)

    assert parsed is not None
    assert parsed == expected
    assert parsed.tzinfo is UTC


def test_parse_request_datetime_rejects_rfc5322_values() -> None:
    """Request date parsing rejects legacy HTTP-date values."""
    assert _parse_request_datetime("Mon, 09 May 2026 23:36:35 GMT") is None


def test_canonical_request_signs_declared_body_digest_header_but_hashes_actual_body() -> None:
    """Canonical request construction signs the digest header but hashes the buffered body."""
    body_digest = "f" * 64
    actual_body = b"actual body"
    scope = cast(
        "HTTPScope",
        {
            "type": "http",
            "method": "get",
            "path": "/space path",
            "query_string": "b=2&a=1",
            "headers": [(API_KEY_HMAC_BODY_SHA256_HEADER.lower().encode(), body_digest.encode())],
            "litestar_auth_body": actual_body,
        },
    )

    canonical_request = build_canonical_request(
        ASGIConnection(scope),
        signed_headers=(API_KEY_HMAC_BODY_SHA256_HEADER.lower(),),
    )

    assert canonical_request.splitlines() == [
        "GET",
        "/space%20path",
        "a=1&b=2",
        f"x-auth-content-sha256:{body_digest}",
        "x-auth-content-sha256",
        hashlib.sha256(actual_body).hexdigest(),
    ]


def test_signed_request_skew_accepts_boundary() -> None:
    """Timestamp skew accepts exactly-on-boundary requests."""
    now = datetime.now(tz=UTC)
    scope = _signed_scope(date=now - timedelta(seconds=60))
    _authorize_scope(scope, key_id="keyid", secret="secret")
    assert read_signed_api_key_request(ASGIConnection(scope)) == API_KEY_HMAC_SCHEME
    signed_request = get_current_signed_api_key_request()
    assert signed_request is not None
    assert classify_signed_request_skew(signed_request, now=now, skew_seconds=60) is None


async def test_signing_required_key_authenticates_hmac_request() -> None:
    """Signing-required keys authenticate through the LSA1 HMAC form."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = SignedApiKeyRow(
        user_id=user.id,
        key_id="keyid",
        hashed_secret=digest_api_key_secret(api_key_hash_secret=API_KEY_HASH_SECRET.encode(), secret=secret),
        encrypted_secret=keyring.encrypt(secret).encode(),
        scopes=["read"],
        signing_required=True,
    )
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=cast("Any", SignedApiKeyStore(row)),
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        nonce_store=InMemoryApiKeyNonceStore(),
        secret_encryption_keyring=keyring,
    )
    scope = _signed_scope()
    _authorize_scope(scope, key_id=row.key_id, secret=secret)

    token = read_signed_api_key_request(ASGIConnection(scope))
    result = await strategy.read_token_with_context(token, UserManager(user))

    assert result is not None
    assert result.user is user
    assert result.context == ApiKeyContext(key_id="keyid", scopes=("read",), prefix_env="prod")


async def test_signing_rejects_body_tampering_and_bearer_fallback() -> None:
    """Body changes and bearer use both invalidate signing-required keys."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = SignedApiKeyRow(
        user_id=user.id,
        key_id="keyid",
        hashed_secret=digest_api_key_secret(api_key_hash_secret=API_KEY_HASH_SECRET.encode(), secret=secret),
        encrypted_secret=keyring.encrypt(secret).encode(),
        scopes=[],
        signing_required=True,
    )
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=cast("Any", SignedApiKeyStore(row)),
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        nonce_store=InMemoryApiKeyNonceStore(),
        secret_encryption_keyring=keyring,
    )
    scope = _signed_scope(body=b"original")
    _authorize_scope(scope, key_id=row.key_id, secret=secret)
    cast("dict[str, Any]", scope)["litestar_auth_body"] = b"tampered"

    token = read_signed_api_key_request(ASGIConnection(scope))

    assert await strategy.read_token_with_context(token, UserManager(user)) is None
    assert await strategy.classify_failure_code(token) == ErrorCode.API_KEY_SIGNATURE_INVALID
    assert await strategy.read_token(f"ak_prod_{row.key_id}.{secret}", UserManager(user)) is None


async def test_signing_rejects_mismatched_content_sha256_header() -> None:
    """Signed requests cannot replace the canonical body digest with a caller-supplied header."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = _signed_row(user_id=user.id, secret=secret, keyring=keyring)
    strategy = _strategy_for_row(row, keyring=keyring)
    scope = _signed_scope(body=b'{"actual":true}')
    wrong_body_digest = hashlib.sha256(b'{"signed":true}').hexdigest()
    cast("list[tuple[bytes, bytes]]", scope["headers"]).append(
        (API_KEY_HMAC_BODY_SHA256_HEADER.lower().encode(), wrong_body_digest.encode()),
    )
    canonical_request = "\n".join(
        (
            "POST",
            "/protected",
            "a=1&b=2",
            "\n".join(
                (
                    "host:example.test",
                    f"x-auth-date:{dict(scope['headers'])[API_KEY_HMAC_DATE_HEADER.lower().encode()].decode()}",
                    "x-auth-nonce:nonce-1",
                    f"x-auth-content-sha256:{wrong_body_digest}",
                ),
            ),
            "host;x-auth-date;x-auth-nonce;x-auth-content-sha256",
            wrong_body_digest,
        ),
    )
    signature = sign_canonical_request(secret=secret, canonical_request=canonical_request)
    cast("list[tuple[bytes, bytes]]", scope["headers"]).append(
        (
            b"authorization",
            (
                f"{API_KEY_HMAC_SCHEME} Credential={row.key_id}, "
                "SignedHeaders=host;x-auth-date;x-auth-nonce;x-auth-content-sha256, "
                f"Signature={signature}"
            ).encode(),
        ),
    )

    token = read_signed_api_key_request(ASGIConnection(scope))

    assert await strategy.read_token_with_context(token, UserManager(user)) is None
    assert await strategy.classify_failure_code(token) == ErrorCode.API_KEY_SIGNATURE_INVALID


async def test_signing_classifies_timestamp_skew_and_nonce_replay() -> None:
    """Timestamp and nonce failures expose structured API-key signing codes."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = SignedApiKeyRow(
        user_id=user.id,
        key_id="keyid",
        hashed_secret=digest_api_key_secret(api_key_hash_secret=API_KEY_HASH_SECRET.encode(), secret=secret),
        encrypted_secret=keyring.encrypt(secret).encode(),
        scopes=[],
        signing_required=True,
    )
    nonce_store = InMemoryApiKeyNonceStore()
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=cast("Any", SignedApiKeyStore(row)),
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        signing_skew_seconds=60,
        nonce_store=nonce_store,
        secret_encryption_keyring=keyring,
    )
    stale_scope = _signed_scope(date=datetime.now(tz=UTC) - timedelta(seconds=61))
    _authorize_scope(stale_scope, key_id=row.key_id, secret=secret)

    stale_token = read_signed_api_key_request(ASGIConnection(stale_scope))

    assert await strategy.classify_failure_code(stale_token) == ErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW

    replay_scope = _signed_scope(nonce="replay")
    _authorize_scope(replay_scope, key_id=row.key_id, secret=secret)
    replay_token = read_signed_api_key_request(ASGIConnection(replay_scope))
    assert await strategy.read_token_with_context(replay_token, UserManager(user)) is not None
    replay_token = read_signed_api_key_request(ASGIConnection(replay_scope))

    assert await strategy.read_token_with_context(replay_token, UserManager(user)) is None
    assert await strategy.classify_failure_code(replay_token) == ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY


async def test_signing_read_skips_nonce_store_when_user_is_missing() -> None:
    """Orphaned signing keys fail before nonce consumption."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = _signed_row(user_id=user.id, secret=secret, keyring=keyring)
    nonce_store = TrackingNonceStore()
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=cast("Any", SignedApiKeyStore(row)),
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        nonce_store=cast("Any", nonce_store),
        secret_encryption_keyring=keyring,
    )
    scope = _signed_scope()
    _authorize_scope(scope, key_id=row.key_id, secret=secret)
    token = read_signed_api_key_request(ASGIConnection(scope))

    result = await strategy.read_token_with_context(token, MissingUserManager(user))

    assert result is None
    assert nonce_store.calls == []


async def test_signing_failure_classification_never_marks_nonce_used() -> None:
    """Signed failure classification reports read-path replay state without writing nonce state."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = _signed_row(user_id=user.id, secret=secret, keyring=keyring)
    nonce_store = TrackingNonceStore(ApiKeyNonceStoreResult(stored=False, rejected_as_replay=True))
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=cast("Any", SignedApiKeyStore(row)),
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        nonce_store=cast("Any", nonce_store),
        secret_encryption_keyring=keyring,
    )
    scope = _signed_scope(nonce="replayed")
    _authorize_scope(scope, key_id=row.key_id, secret=secret)
    token = read_signed_api_key_request(ASGIConnection(scope))

    assert await strategy.read_token_with_context(token, UserManager(user)) is None
    assert nonce_store.calls == [("keyid", "replayed", 600)]

    assert await strategy.classify_failure_code(token) == ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY
    assert nonce_store.calls == [("keyid", "replayed", 600)]


async def test_signing_read_returns_none_for_defensive_failure_paths() -> None:
    """Signed authentication fails closed for missing dependencies and stale row state."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = _signed_row(user_id=user.id, secret=secret, keyring=keyring)
    scope = _signed_scope()
    _authorize_scope(scope, key_id=row.key_id, secret=secret)
    token = read_signed_api_key_request(ASGIConnection(scope))

    clear_current_signed_api_key_request()
    assert (
        await _strategy_for_row(row, keyring=keyring).read_token_with_context(
            API_KEY_HMAC_SCHEME,
            UserManager(user),
        )
        is None
    )
    read_signed_api_key_request(ASGIConnection(scope))
    assert (
        await _strategy_for_row(row, keyring=keyring).read_token_with_context(token, MissingUserManager(user)) is None
    )
    assert (
        await _strategy_for_row(
            SignedApiKeyRow(
                user_id=user.id,
                key_id=row.key_id,
                hashed_secret=row.hashed_secret,
                encrypted_secret=row.encrypted_secret,
                scopes=[],
                signing_required=True,
                prefix_env="dev",
            ),
            keyring=keyring,
        ).read_token_with_context(token, UserManager(user))
        is None
    )
    assert (
        await _strategy_for_row(
            SignedApiKeyRow(
                user_id=user.id,
                key_id=row.key_id,
                hashed_secret=row.hashed_secret,
                encrypted_secret=row.encrypted_secret,
                scopes=[],
                signing_required=False,
            ),
            keyring=keyring,
        ).read_token_with_context(token, UserManager(user))
        is None
    )
    assert (
        await _strategy_for_row(
            SignedApiKeyRow(
                user_id=user.id,
                key_id=row.key_id,
                hashed_secret=row.hashed_secret,
                encrypted_secret=None,
                scopes=[],
                signing_required=True,
            ),
            keyring=keyring,
        ).read_token_with_context(token, UserManager(user))
        is None
    )
    assert (
        await ApiKeyStrategy[ExampleUser, UUID](
            api_key_store=cast("Any", MissingApiKeyStore(row)),
            api_key_hash_secret=API_KEY_HASH_SECRET,
            prefix_env="prod",
            nonce_store=InMemoryApiKeyNonceStore(),
            secret_encryption_keyring=keyring,
        ).read_token_with_context(token, UserManager(user))
        is None
    )

    stale_scope = _signed_scope(date=datetime.now(tz=UTC) - timedelta(seconds=301), nonce="stale-read")
    _authorize_scope(stale_scope, key_id=row.key_id, secret=secret)
    stale_token = read_signed_api_key_request(ASGIConnection(stale_scope))
    assert await _strategy_for_row(row, keyring=keyring).read_token_with_context(stale_token, UserManager(user)) is None
    assert (
        await ApiKeyStrategy[ExampleUser, UUID](
            api_key_store=cast("Any", SignedApiKeyStore(row)),
            api_key_hash_secret=API_KEY_HASH_SECRET,
            prefix_env="prod",
            secret_encryption_keyring=keyring,
        ).read_token_with_context(token, UserManager(user))
        is None
    )

    no_nonce_scope = _signed_scope(nonce="no-nonce")
    _authorize_scope(no_nonce_scope, key_id=row.key_id, secret=secret)
    no_nonce_token = read_signed_api_key_request(ASGIConnection(no_nonce_scope))
    assert (
        await ApiKeyStrategy[ExampleUser, UUID](
            api_key_store=cast("Any", SignedApiKeyStore(row)),
            api_key_hash_secret=API_KEY_HASH_SECRET,
            prefix_env="prod",
            secret_encryption_keyring=keyring,
        ).read_token_with_context(no_nonce_token, UserManager(user))
        is None
    )


async def test_signing_read_returns_none_for_invalid_signature_and_nonce_capacity() -> None:
    """Signed authentication fails when signature verification or nonce storage fails."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = _signed_row(user_id=user.id, secret=secret, keyring=keyring)
    bad_signature_scope = _signed_scope(nonce="bad-signature")
    _authorize_scope(bad_signature_scope, key_id=row.key_id, secret="wrong-secret")
    bad_signature_token = read_signed_api_key_request(ASGIConnection(bad_signature_scope))

    assert (
        await _strategy_for_row(row, keyring=keyring).read_token_with_context(
            bad_signature_token,
            UserManager(user),
        )
        is None
    )

    full_nonce_store = InMemoryApiKeyNonceStore(max_entries=1)
    assert (await full_nonce_store.mark_used(key_id="other", nonce="used", ttl_seconds=60)).stored
    capacity_scope = _signed_scope(nonce="capacity")
    _authorize_scope(capacity_scope, key_id=row.key_id, secret=secret)
    capacity_token = read_signed_api_key_request(ASGIConnection(capacity_scope))

    assert (
        await _strategy_for_row(row, keyring=keyring, nonce_store=full_nonce_store).read_token_with_context(
            capacity_token,
            UserManager(user),
        )
        is None
    )


async def test_signing_failure_classification_covers_row_state() -> None:
    """Signed failure classification distinguishes revoked, expired, and malformed states."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = _signed_row(user_id=user.id, secret=secret, keyring=keyring)
    scope = _signed_scope()
    _authorize_scope(scope, key_id=row.key_id, secret=secret)
    token = read_signed_api_key_request(ASGIConnection(scope))

    clear_current_signed_api_key_request()
    assert (
        await _strategy_for_row(row, keyring=keyring).classify_failure_code(API_KEY_HMAC_SCHEME)
        == ErrorCode.API_KEY_SIGNATURE_INVALID
    )
    read_signed_api_key_request(ASGIConnection(scope))
    assert (
        await ApiKeyStrategy[ExampleUser, UUID](
            api_key_store=cast("Any", MissingApiKeyStore(row)),
            api_key_hash_secret=API_KEY_HASH_SECRET,
            prefix_env="prod",
            nonce_store=InMemoryApiKeyNonceStore(),
            secret_encryption_keyring=keyring,
        ).classify_failure_code(token)
        == ErrorCode.API_KEY_SIGNATURE_INVALID
    )
    assert (
        await _strategy_for_row(
            SignedApiKeyRow(
                user_id=user.id,
                key_id=row.key_id,
                hashed_secret=row.hashed_secret,
                encrypted_secret=row.encrypted_secret,
                scopes=[],
                signing_required=True,
                revoked_at=datetime.now(tz=UTC),
            ),
            keyring=keyring,
        ).classify_failure_code(token)
        == ErrorCode.API_KEY_REVOKED
    )
    assert (
        await _strategy_for_row(
            SignedApiKeyRow(
                user_id=user.id,
                key_id=row.key_id,
                hashed_secret=row.hashed_secret,
                encrypted_secret=row.encrypted_secret,
                scopes=[],
                signing_required=True,
                expires_at=datetime.now(tz=UTC) - timedelta(seconds=1),
            ),
            keyring=keyring,
        ).classify_failure_code(token)
        == ErrorCode.API_KEY_EXPIRED
    )
    assert (
        await _strategy_for_row(
            SignedApiKeyRow(
                user_id=user.id,
                key_id=row.key_id,
                hashed_secret=row.hashed_secret,
                encrypted_secret=row.encrypted_secret,
                scopes=[],
                signing_required=False,
            ),
            keyring=keyring,
        ).classify_failure_code(token)
        == ErrorCode.API_KEY_SIGNATURE_INVALID
    )
    assert (
        await ApiKeyStrategy[ExampleUser, UUID](
            api_key_store=cast("Any", SignedApiKeyStore(row)),
            api_key_hash_secret=API_KEY_HASH_SECRET,
            prefix_env="dev",
            secret_encryption_keyring=keyring,
        ).classify_failure_code(token)
        == ErrorCode.API_KEY_SIGNATURE_INVALID
    )

    fresh_scope = _signed_scope(nonce="fresh-classify")
    _authorize_scope(fresh_scope, key_id=row.key_id, secret=secret)
    fresh_token = read_signed_api_key_request(ASGIConnection(fresh_scope))
    assert (
        await _strategy_for_row(row, keyring=keyring).classify_failure_code(fresh_token)
        == ErrorCode.API_KEY_SIGNATURE_INVALID
    )
    assert (
        await _strategy_for_row(
            SignedApiKeyRow(
                user_id=user.id,
                key_id=row.key_id,
                hashed_secret=row.hashed_secret,
                encrypted_secret=b"not-utf8-\xff",
                scopes=[],
                signing_required=True,
            ),
            keyring=keyring,
        ).classify_failure_code(token)
        == ErrorCode.API_KEY_SIGNATURE_INVALID
    )


async def test_bearer_failure_classification_handles_none_and_signing_row() -> None:
    """Bearer classification handles missing token and signing-required row attempts."""
    secret = "request-signing-secret"
    keyring = _keyring()
    user = ExampleUser(id=uuid4())
    row = _signed_row(user_id=user.id, secret=secret, keyring=keyring)
    strategy = _strategy_for_row(row, keyring=keyring)

    assert await strategy.classify_failure_code(None) == ErrorCode.API_KEY_INVALID
    assert await strategy.classify_failure_code(f"ak_prod_{row.key_id}.{secret}") == ErrorCode.API_KEY_SIGNATURE_INVALID
