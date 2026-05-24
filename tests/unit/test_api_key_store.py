"""Unit tests for API-key persistence contracts and SQLAlchemy store behavior."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from litestar_auth._locks import _BoundedAsyncLockRegistry
from litestar_auth.db import ApiKeyData, BaseApiKeyStore
from litestar_auth.db.sqlalchemy import SQLAlchemyApiKeyStore
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.models import ApiKey, User

if TYPE_CHECKING:
    from sqlalchemy.orm import Session as SASession

pytestmark = pytest.mark.unit


def create_store(session: SASession) -> SQLAlchemyApiKeyStore[ApiKey]:
    """Create an API-key store backed by the shared sync-session adapter.

    Returns:
        SQLAlchemy API-key store bound to ``session``.
    """
    from tests.integration.test_db_sqlalchemy import AsyncSessionAdapter  # noqa: PLC0415

    return SQLAlchemyApiKeyStore(session=cast("Any", AsyncSessionAdapter(session)), api_key_model=ApiKey)


def make_api_key_data(user_id: UUID, *, key_id: str, expires_at: datetime | None = None) -> ApiKeyData[UUID]:
    """Build API-key creation data for store tests.

    Returns:
        API-key creation payload.
    """
    return ApiKeyData(
        key_id=key_id,
        user_id=user_id,
        hashed_secret=f"hashed-{key_id}".encode(),
        encrypted_secret=None,
        name=f"Key {key_id}",
        scopes=["read"],
        prefix_env="prod",
        signing_required=False,
        expires_at=expires_at,
        created_via="unit-test",
        client_metadata={"user_agent": "Store Unit Test/1.0"},
    )


def make_signing_api_key_data(
    user_id: UUID,
    *,
    key_id: str,
    encrypted_secret: bytes | None,
    expires_at: datetime | None = None,
) -> ApiKeyData[UUID]:
    """Build signing API-key creation data for rotation tests.

    Returns:
        API-key creation payload with signing enabled.
    """
    return ApiKeyData(
        key_id=key_id,
        user_id=user_id,
        hashed_secret=f"hashed-{key_id}".encode(),
        encrypted_secret=encrypted_secret,
        name=f"Signing key {key_id}",
        scopes=["sign"],
        prefix_env="prod",
        signing_required=True,
        expires_at=expires_at,
        created_via="unit-test",
        client_metadata={"user_agent": "Store Unit Test/1.0"},
    )


async def test_sqlalchemy_api_key_store_crud_active_filters(session: SASession) -> None:
    """The store creates, looks up, lists, revokes, and records active API keys."""
    user = User(email="api-key-store@example.com", hashed_password="hashed-password")
    session.add(user)
    session.commit()
    store = create_store(session)

    active = await store.create(make_api_key_data(user.id, key_id="akid_active"))
    expired = await store.create(
        make_api_key_data(user.id, key_id="akid_expired", expires_at=datetime.now(tz=UTC) - timedelta(seconds=1)),
    )

    assert isinstance(store, BaseApiKeyStore)
    assert active.id is not None
    assert active.user_id == user.id
    assert active.hashed_secret == b"hashed-akid_active"
    assert active.encrypted_secret is None
    assert active.scopes == ["read"]
    assert active.client_metadata == {"user_agent": "Store Unit Test/1.0"}
    assert await store.get_by_key_id("missing") is None
    assert await store.get_by_key_id(expired.key_id) is None
    assert await store.get_by_key_id(expired.key_id, include_inactive=True) == expired
    assert await store.list_for_user(user.id) == [active]
    assert await store.list_for_user(user.id, include_inactive=True) == [active, expired]

    renamed = await store.update(active.key_id, name="Renamed key", scopes=["read", "write"])
    assert renamed is active
    assert renamed.name == "Renamed key"
    assert renamed.scopes == ["read", "write"]
    name_only = await store.update(active.key_id, name="Name only")
    assert name_only is active
    assert name_only.name == "Name only"
    assert name_only.scopes == ["read", "write"]
    scopes_only = await store.update(active.key_id, scopes=["read"])
    assert scopes_only is active
    assert scopes_only.name == "Name only"
    assert scopes_only.scopes == ["read"]
    unchanged = await store.update(active.key_id)
    assert unchanged is active
    assert unchanged.name == "Name only"
    assert unchanged.scopes == ["read"]
    assert await store.update(expired.key_id, name="Expired key") is None

    used_at = datetime.now(tz=UTC)
    updated = await store.update_last_used_at(active.key_id, last_used_at=used_at)
    assert updated is active
    assert updated.last_used_at == used_at.replace(tzinfo=None)
    assert await store.update_last_used_at(expired.key_id, last_used_at=used_at) is None

    revoked_at = used_at + timedelta(seconds=1)
    revoked = await store.revoke(active.key_id, revoked_at=revoked_at)
    assert revoked is active
    assert revoked.revoked_at == revoked_at.replace(tzinfo=None)
    assert await store.get_by_key_id(active.key_id) is None
    assert await store.get_by_key_id(active.key_id, include_inactive=True) == active
    assert await store.revoke("missing", revoked_at=revoked_at) is None


async def test_sqlalchemy_api_key_store_preserves_first_revoke_timestamp(session: SASession) -> None:
    """Repeated soft revocation is idempotent and keeps the original timestamp."""
    user = User(email="api-key-revoke@example.com", hashed_password="hashed-password")
    session.add(user)
    session.commit()
    store = create_store(session)
    api_key = await store.create(make_api_key_data(user.id, key_id="akid_revoke"))

    first_revoked_at = datetime.now(tz=UTC)
    second_revoked_at = first_revoked_at + timedelta(minutes=5)

    assert await store.revoke(api_key.key_id, revoked_at=first_revoked_at) == api_key
    assert await store.revoke(api_key.key_id, revoked_at=second_revoked_at) == api_key
    assert api_key.revoked_at == first_revoked_at.replace(tzinfo=None)


async def test_sqlalchemy_api_key_store_rejects_encrypted_secret_without_signing(session: SASession) -> None:
    """Encrypted API-key secret storage is reserved for signing-required rows."""
    user = User(email="api-key-encrypted-secret@example.com", hashed_password="hashed-password")
    session.add(user)
    session.commit()
    store = create_store(session)
    data = make_api_key_data(user.id, key_id="akid_encrypted_without_signing")

    with pytest.raises(ValueError, match="encrypted_secret is only valid"):
        await store.create(
            ApiKeyData(
                key_id=data.key_id,
                user_id=data.user_id,
                hashed_secret=data.hashed_secret,
                encrypted_secret=b"encrypted-secret",
                name=data.name,
                scopes=data.scopes,
                prefix_env=data.prefix_env,
                signing_required=False,
                expires_at=data.expires_at,
                created_via=data.created_via,
                client_metadata=data.client_metadata,
            ),
        )


async def test_sqlalchemy_api_key_store_create_for_user_with_limit(session: SASession) -> None:
    """The SQLAlchemy store checks the active-key limit inside the create operation."""
    user = User(email="api-key-limit@example.com", hashed_password="hashed-password")
    session.add(user)
    session.commit()
    store = create_store(session)

    first = await store.create_for_user_with_limit(
        make_api_key_data(user.id, key_id="akid_limited_1"),
        max_keys_per_user=1,
    )
    second = await store.create_for_user_with_limit(
        make_api_key_data(user.id, key_id="akid_limited_2"),
        max_keys_per_user=1,
    )

    assert first is not None
    assert second is None
    assert [row.key_id for row in await store.list_for_user(user.id)] == ["akid_limited_1"]


async def test_sqlalchemy_api_key_store_locks_owner_before_limited_create(
    session: SASession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Limited API-key creation serializes on the owner before reading active keys."""
    user = User(email="api-key-limit-lock-order@example.com", hashed_password="hashed-password")
    session.add(user)
    session.commit()
    store = create_store(session)
    events: list[str] = []
    lock_owner = store._lock_api_key_owner
    list_for_user = store.list_for_user

    async def record_lock_owner(user_id: UUID) -> None:
        events.append("lock")
        await lock_owner(user_id)

    async def record_list_for_user(user_id: UUID, *, include_inactive: bool = False) -> list[ApiKey]:
        events.append("list")
        return await list_for_user(user_id, include_inactive=include_inactive)

    monkeypatch.setattr(store, "_lock_api_key_owner", record_lock_owner)
    monkeypatch.setattr(store, "list_for_user", record_list_for_user)

    created = await store.create_for_user_with_limit(
        make_api_key_data(user.id, key_id="akid_limited_lock_order"),
        max_keys_per_user=1,
    )

    assert created is not None
    assert events[:2] == ["lock", "list"]


async def test_sqlalchemy_api_key_create_locks_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Limited API-key creation retains only the most recent idle create locks."""
    registry = _BoundedAsyncLockRegistry[tuple[type[object], UUID]](max_size=2)
    store = SQLAlchemyApiKeyStore(session=cast("Any", object()), api_key_model=ApiKey)

    async def lock_api_key_owner(user_id: UUID) -> None:
        await asyncio.sleep(0)

    async def list_for_user(user_id: UUID, *, include_inactive: bool = False) -> list[ApiKey]:
        await asyncio.sleep(0)
        return []

    async def create(data: ApiKeyData[UUID]) -> ApiKey:
        await asyncio.sleep(0)
        return cast("ApiKey", object())

    monkeypatch.setattr("litestar_auth.db._sqlalchemy_api_keys._API_KEY_CREATE_LOCKS", registry)
    monkeypatch.setattr(store, "_lock_api_key_owner", lock_api_key_owner)
    monkeypatch.setattr(store, "list_for_user", list_for_user)
    monkeypatch.setattr(store, "create", create)

    for index in range(5):
        await store.create_for_user_with_limit(
            make_api_key_data(uuid4(), key_id=f"akid_bounded_lock_{index}"),
            max_keys_per_user=1,
        )

    assert len(registry) == registry.max_size


async def test_sqlalchemy_api_key_create_locks_keep_in_flight_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """A held API-key create lock is not evicted by create attempts for other users."""
    registry = _BoundedAsyncLockRegistry[tuple[type[object], UUID]](max_size=1)
    store = SQLAlchemyApiKeyStore(session=cast("Any", object()), api_key_model=ApiKey)
    locked_user_id = uuid4()
    lock_key = (cast("type[object]", ApiKey), locked_user_id)
    first_create_entered_owner_lock = asyncio.Event()
    release_first_create = asyncio.Event()

    async def lock_api_key_owner(user_id: UUID) -> None:
        if user_id == locked_user_id:
            first_create_entered_owner_lock.set()
            await release_first_create.wait()

    async def list_for_user(user_id: UUID, *, include_inactive: bool = False) -> list[ApiKey]:
        await asyncio.sleep(0)
        return []

    async def create(data: ApiKeyData[UUID]) -> ApiKey:
        await asyncio.sleep(0)
        return cast("ApiKey", object())

    monkeypatch.setattr("litestar_auth.db._sqlalchemy_api_keys._API_KEY_CREATE_LOCKS", registry)
    monkeypatch.setattr(store, "_lock_api_key_owner", lock_api_key_owner)
    monkeypatch.setattr(store, "list_for_user", list_for_user)
    monkeypatch.setattr(store, "create", create)

    first_create = asyncio.create_task(
        store.create_for_user_with_limit(
            make_api_key_data(locked_user_id, key_id="akid_locked_create"),
            max_keys_per_user=1,
        ),
    )
    try:
        await first_create_entered_owner_lock.wait()
        for index in range(3):
            await store.create_for_user_with_limit(
                make_api_key_data(uuid4(), key_id=f"akid_other_user_{index}"),
                max_keys_per_user=1,
            )

        assert lock_key in registry._locks
    finally:
        release_first_create.set()
        assert await first_create is not None


async def test_sqlalchemy_api_key_store_owner_lock_targets_user_row_for_update() -> None:
    """The owner lock uses the API-key foreign-key parent row with ``FOR UPDATE`` semantics."""

    class RecordingSession:
        """Capture SQL statements issued by the SQLAlchemy store."""

        def __init__(self) -> None:
            """Initialize an empty statement log."""
            self.statements: list[object] = []

        async def execute(self, statement: object) -> object:
            """Record the statement and return an inert result.

            Returns:
                Placeholder execution result.
            """
            self.statements.append(statement)
            return object()

    recording_session = RecordingSession()
    store = SQLAlchemyApiKeyStore(session=cast("Any", recording_session), api_key_model=ApiKey)

    await store._lock_api_key_owner(uuid4())

    statement = recording_session.statements[0]
    compiled = str(cast("Any", statement).compile(dialect=postgresql.dialect()))
    assert 'FROM "user"' in compiled
    assert "FOR UPDATE" in compiled
    assert getattr(statement, "_for_update_arg", None) is not None


def test_sqlalchemy_api_key_store_rejects_owner_lock_models_without_one_user_fk() -> None:
    """Fail closed when an API-key model cannot identify the owner row to lock."""

    class ContractBase(DeclarativeBase):
        """Isolated declarative base for malformed API-key model contracts."""

    class MissingUserId(ContractBase):
        """Model without the required ``user_id`` column."""

        __tablename__ = "missing_user_id"

        id: Mapped[int] = mapped_column(primary_key=True)

    class UserIdWithoutForeignKey(ContractBase):
        """Model with ``user_id`` but without an owner foreign key."""

        __tablename__ = "user_id_without_foreign_key"

        id: Mapped[int] = mapped_column(primary_key=True)
        user_id: Mapped[UUID] = mapped_column()

    for model, match in (
        (MissingUserId, "must map a user_id column"),
        (UserIdWithoutForeignKey, "must reference exactly one user table foreign key"),
    ):
        store = SQLAlchemyApiKeyStore(session=cast("Any", object()), api_key_model=cast("Any", model))
        with pytest.raises(ConfigurationError, match=match):
            store._api_key_owner_id_column()


async def test_sqlalchemy_api_key_store_lists_only_requested_user(session: SASession) -> None:
    """User listings are scoped by owner and ordered by creation timestamp/key id."""
    first_user = User(email="api-key-owner-1@example.com", hashed_password="hashed-password")
    second_user = User(email="api-key-owner-2@example.com", hashed_password="hashed-password")
    session.add_all([first_user, second_user])
    session.commit()
    store = create_store(session)

    first = await store.create(make_api_key_data(first_user.id, key_id="akid_first"))
    await store.create(make_api_key_data(second_user.id, key_id="akid_other"))
    second = await store.create(make_api_key_data(first_user.id, key_id="akid_second"))

    assert await store.list_for_user(first_user.id) == [first, second]
    assert [row.key_id for row in session.execute(select(ApiKey).order_by(ApiKey.key_id)).scalars()] == [
        "akid_first",
        "akid_other",
        "akid_second",
    ]


async def test_sqlalchemy_api_key_store_accepts_uuid_user_id(session: SASession) -> None:
    """ApiKeyData keeps the user identifier generic while the bundled store uses UUIDs."""
    user = User(email="api-key-uuid@example.com", hashed_password="hashed-password")
    user.id = uuid4()
    session.add(user)
    session.commit()
    store = create_store(session)

    api_key = await store.create(make_api_key_data(user.id, key_id="akid_uuid"))

    assert api_key.user_id == user.id


async def test_sqlalchemy_api_key_store_lists_signing_rotation_candidates(session: SASession) -> None:
    """Rotation scans include only signing rows with encrypted secrets requiring rewrite."""
    user = User(email="api-key-rotation-candidates@example.com", hashed_password="hashed-password")
    session.add(user)
    session.commit()
    store = create_store(session)

    active_old = await store.create(
        make_signing_api_key_data(user.id, key_id="akid_active_old", encrypted_secret=b"old:active"),
    )
    revoked_old = await store.create(
        make_signing_api_key_data(user.id, key_id="akid_revoked_old", encrypted_secret=b"old:revoked"),
    )
    await store.revoke(revoked_old.key_id, revoked_at=datetime.now(tz=UTC))
    await store.create(make_signing_api_key_data(user.id, key_id="akid_current", encrypted_secret=b"current:active"))
    await store.create(make_signing_api_key_data(user.id, key_id="akid_missing_secret", encrypted_secret=None))
    await store.create(make_api_key_data(user.id, key_id="akid_bearer"))

    seen_rows: list[str] = []

    def requires_reencrypt(api_key: ApiKey) -> bool:
        seen_rows.append(api_key.key_id)
        return api_key.encrypted_secret is not None and api_key.encrypted_secret.startswith(b"old:")

    active_candidates = await store.list_signing_keys_requiring_reencrypt(requires_reencrypt)
    all_candidates = await store.list_signing_keys_requiring_reencrypt(requires_reencrypt, include_inactive=True)

    assert active_candidates == [active_old]
    assert all_candidates == [active_old, revoked_old]
    assert seen_rows == [
        "akid_active_old",
        "akid_current",
        "akid_active_old",
        "akid_current",
        "akid_revoked_old",
    ]


async def test_sqlalchemy_api_key_store_replaces_only_existing_signing_encrypted_secret(session: SASession) -> None:
    """Encrypted-secret replacement is constrained to signing rows with existing encrypted storage."""
    user = User(email="api-key-rotation-replace@example.com", hashed_password="hashed-password")
    session.add(user)
    session.commit()
    store = create_store(session)
    signing = await store.create(
        make_signing_api_key_data(user.id, key_id="akid_signing_replace", encrypted_secret=b"old:secret"),
    )
    missing_secret = await store.create(
        make_signing_api_key_data(user.id, key_id="akid_signing_missing", encrypted_secret=None),
    )
    bearer = await store.create(make_api_key_data(user.id, key_id="akid_bearer_replace"))

    replaced = await store.replace_signing_key_encrypted_secret(signing.key_id, encrypted_secret=b"current:secret")

    assert replaced is signing
    assert signing.encrypted_secret == b"current:secret"
    assert missing_secret.encrypted_secret is None
    assert bearer.encrypted_secret is None
    assert await store.replace_signing_key_encrypted_secret(missing_secret.key_id, encrypted_secret=b"current") is None
    assert await store.replace_signing_key_encrypted_secret(bearer.key_id, encrypted_secret=b"current") is None
    assert await store.replace_signing_key_encrypted_secret("missing", encrypted_secret=b"current") is None
