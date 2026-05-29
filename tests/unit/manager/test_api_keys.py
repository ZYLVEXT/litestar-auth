"""Tests for manager-level API-key operations."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal, cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from cryptography.fernet import Fernet

import litestar_auth._manager as manager_exports
from litestar_auth._manager.api_key_config import (
    ApiKeyConfigProtocol,
    ApiKeyManagerConfig,
)
from litestar_auth._manager.api_key_row import ApiKeyRowProtocol
from litestar_auth._manager.api_key_secrets import ApiKeyCreateResult, ApiKeySecret
from litestar_auth._manager.api_key_secrets import (
    secrets as api_key_secrets,
)
from litestar_auth._manager.api_key_service import ApiKeyManagerService
from litestar_auth._plugin.features import DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS
from litestar_auth._secrets_at_rest import FernetKeyring
from litestar_auth.authentication.strategy._api_key_format import api_key_secret_matches, parse_api_key
from litestar_auth.exceptions import (
    ApiKeyError,
    ApiKeyLimitReachedError,
    ApiKeyNotFoundError,
    ApiKeyScopeDeniedError,
    InvalidPasswordError,
)
from litestar_auth.manager import FernetKeyringConfig
from litestar_auth.password import PasswordHelper
from tests._helpers import ExampleUser
from tests.unit.test_manager import TrackingUserManager

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth._manager.api_key_creation import ApiKeyCreateOptions
    from litestar_auth.db import ApiKeyData

pytestmark = pytest.mark.unit

API_KEY_HASH_SECRET = "api-key-hash-secret-0123456789abcdef"
MIN_GENERATED_SECRET_LENGTH = 32


def test_api_key_manager_public_symbols_remain_importable_from_prior_paths() -> None:
    """API-key refactors keep existing internal public import paths stable."""
    assert manager_exports.ApiKeyConfigProtocol is ApiKeyConfigProtocol
    assert manager_exports.ApiKeyCreateResult is ApiKeyCreateResult
    assert manager_exports.ApiKeyManagerConfig is ApiKeyManagerConfig
    assert manager_exports.ApiKeyManagerService is ApiKeyManagerService
    assert manager_exports.ApiKeyRowProtocol is ApiKeyRowProtocol
    assert manager_exports.ApiKeySecret is ApiKeySecret


def test_api_key_manager_config_uses_canonical_last_used_throttle_default() -> None:
    """Standalone manager config uses the plugin API-key throttle default."""
    assert ApiKeyManagerConfig().last_used_throttle_seconds == DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS


@dataclass(slots=True)
class ApiKeyRow:
    """In-memory API-key row used by manager tests."""

    key_id: str
    user_id: UUID
    hashed_secret: bytes
    name: str
    scopes: list[str]
    prefix_env: str = "prod"
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    encrypted_secret: bytes | None = None
    signing_required: bool = False
    created_via: str = "unit-test"
    client_metadata: dict[str, str] | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))


class ApiKeyStore:
    """In-memory API-key store with active filtering."""

    def __init__(self) -> None:
        """Initialize an empty in-memory API-key store."""
        self.rows: dict[str, ApiKeyRow] = {}
        self.create_calls = 0
        self.last_used_writes: list[datetime] = []
        self._create_lock = asyncio.Lock()

    async def create(self, data: ApiKeyData[UUID]) -> ApiKeyRow:
        """Persist and return a newly created API-key row.

        Returns:
            The created in-memory API-key row.
        """
        self.create_calls += 1
        await asyncio.sleep(0)
        row = ApiKeyRow(
            key_id=data.key_id,
            user_id=data.user_id,
            hashed_secret=data.hashed_secret,
            encrypted_secret=data.encrypted_secret,
            name=data.name,
            scopes=list(data.scopes),
            prefix_env=data.prefix_env,
            signing_required=data.signing_required,
            expires_at=data.expires_at,
            created_via=data.created_via,
            client_metadata=data.client_metadata,
        )
        self.rows[row.key_id] = row
        return row

    async def create_for_user_with_limit(
        self,
        data: ApiKeyData[UUID],
        *,
        max_keys_per_user: int,
    ) -> ApiKeyRow | None:
        """Persist a row only when the active-key count remains below the limit.

        Returns:
            Created row, or ``None`` when the active-key limit has been reached.
        """
        async with self._create_lock:
            active_keys = await self.list_for_user(data.user_id)
            if len(active_keys) >= max_keys_per_user:
                return None
            return await self.create(data)

    async def get_by_key_id(self, key_id: str, *, include_inactive: bool = False) -> ApiKeyRow | None:
        """Return an API key by public key id."""
        row = self.rows.get(key_id)
        if row is None or (not include_inactive and not self._is_active(row)):
            return None
        return row

    async def list_for_user(self, user_id: UUID, *, include_inactive: bool = False) -> list[ApiKeyRow]:
        """Return API keys owned by a user."""
        return [
            row for row in self.rows.values() if row.user_id == user_id and (include_inactive or self._is_active(row))
        ]

    async def delete_for_user(self, user_id: UUID) -> int:
        """Delete all API-key rows owned by a user.

        Returns:
            Number of deleted rows.
        """
        deleted_keys = [key_id for key_id, row in self.rows.items() if row.user_id == user_id]
        for key_id in deleted_keys:
            del self.rows[key_id]
        return len(deleted_keys)

    async def revoke(self, key_id: str, *, revoked_at: datetime) -> ApiKeyRow | None:
        """Soft-revoke an API key.

        Returns:
            The updated row when found, otherwise ``None``.
        """
        row = self.rows.get(key_id)
        if row is None:
            return None
        if row.revoked_at is None:
            row.revoked_at = revoked_at
        return row

    async def update(
        self,
        key_id: str,
        *,
        name: str | None = None,
        scopes: list[str] | None = None,
    ) -> ApiKeyRow | None:
        """Update mutable API-key metadata.

        Returns:
            The updated row when found and active, otherwise ``None``.
        """
        row = await self.get_by_key_id(key_id)
        if row is None:
            return None
        if name is not None:
            row.name = name
        if scopes is not None:
            row.scopes = scopes
        return row

    async def update_last_used_at(self, key_id: str, *, last_used_at: datetime) -> ApiKeyRow | None:
        """Update an active API key's last-used timestamp.

        Returns:
            The updated row when found and active, otherwise ``None``.
        """
        row = await self.get_by_key_id(key_id)
        if row is None:
            return None
        row.last_used_at = last_used_at
        self.last_used_writes.append(last_used_at)
        return row

    async def list_signing_keys_requiring_reencrypt(
        self,
        requires_reencrypt: Callable[[ApiKeyRow], bool],
        *,
        include_inactive: bool = False,
    ) -> list[ApiKeyRow]:
        """Return signing API keys with encrypted secrets requiring rotation."""
        return [
            row
            for row in self.rows.values()
            if row.signing_required
            and row.encrypted_secret is not None
            and (include_inactive or self._is_active(row))
            and requires_reencrypt(row)
        ]

    async def replace_signing_key_encrypted_secret(
        self,
        key_id: str,
        *,
        encrypted_secret: bytes,
    ) -> ApiKeyRow | None:
        """Replace one signing API-key row's encrypted secret.

        Returns:
            Updated row when found and eligible, otherwise ``None``.
        """
        row = self.rows.get(key_id)
        if row is None or not row.signing_required or row.encrypted_secret is None:
            return None
        row.encrypted_secret = encrypted_secret
        return row

    @staticmethod
    def _is_active(row: ApiKeyRow) -> bool:
        if row.revoked_at is not None:
            return False
        if row.expires_at is None:
            return True
        return row.expires_at > datetime.now(tz=UTC)


class NoneUpdatingApiKeyStore(ApiKeyStore):
    """Store variant that loses rows during update/write operations."""

    async def update(
        self,
        key_id: str,
        *,
        name: str | None = None,
        scopes: list[str] | None = None,
    ) -> ApiKeyRow | None:
        """Return ``None`` after the pre-update lookup succeeds."""
        return None

    async def update_last_used_at(self, key_id: str, *, last_used_at: datetime) -> ApiKeyRow | None:
        """Return ``None`` after the pre-write lookup succeeds."""
        return None


class ForeignRevokingApiKeyStore(ApiKeyStore):
    """Store variant that returns a foreign row from revoke."""

    async def revoke(self, key_id: str, *, revoked_at: datetime) -> ApiKeyRow | None:
        """Return a row owned by another user."""
        return ApiKeyRow(
            key_id="foreign",
            user_id=UUID("00000000-0000-0000-0000-000000000099"),
            hashed_secret=b"digest",
            name="foreign",
            scopes=[],
        )


class NoneReplacingApiKeyStore(ApiKeyStore):
    """Store variant that loses rows during signing-secret replacement."""

    async def replace_signing_key_encrypted_secret(
        self,
        key_id: str,
        *,
        encrypted_secret: bytes,
    ) -> ApiKeyRow | None:
        """Return ``None`` after the rotation preconditions have succeeded."""
        return None


class StringSecretManager:
    """Small service test double exposing a plain string hash secret."""

    def __init__(self, password_helper: PasswordHelper) -> None:
        """Initialize hook tracking for direct service tests."""
        self.api_key_hash_secret = API_KEY_HASH_SECRET
        self.password_helper = password_helper
        self.created: list[object] = []
        self.revoked: list[object] = []
        self.used: list[object] = []

    async def on_after_api_key_created(self, user: ExampleUser, api_key: object) -> None:
        """Record API-key creation."""
        self.created.append(api_key)

    async def on_after_api_key_revoked(self, user: ExampleUser, api_key: object) -> None:
        """Record API-key revocation."""
        self.revoked.append(api_key)

    async def on_after_api_key_used(self, api_key: object) -> None:
        """Record API-key use."""
        self.used.append(api_key)


def _build_user(password_helper: PasswordHelper) -> ExampleUser:
    return ExampleUser(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        email="api-key-user@example.com",
        hashed_password=password_helper.hash("current-password"),
    )


def _build_manager(
    store: ApiKeyStore,
    password_helper: PasswordHelper,
    *,
    config: ApiKeyManagerConfig | None = None,
) -> TrackingUserManager:
    return TrackingUserManager(
        user_db=AsyncMock(),
        password_helper=password_helper,
        api_key_store=store,
        api_key_config=config
        or ApiKeyManagerConfig(
            allowed_scopes=("read", "write"),
            max_keys_per_user=2,
            default_ttl=timedelta(days=1),
        ),
        api_key_hash_secret=API_KEY_HASH_SECRET,
    )


async def test_create_api_key_returns_raw_secret_once_and_persists_only_digest() -> None:
    """Creation returns a masked one-time secret while the store keeps only the digest."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    manager = _build_manager(store, password_helper)
    user = _build_user(password_helper)

    created = await manager.create_api_key(
        user,
        name="CI",
        scopes=("read", "write", "read"),
        current_password="current-password",
        client_metadata={"user_agent": "tests"},
    )

    assert isinstance(created.secret, ApiKeySecret)
    raw_key = created.secret.get_secret_value()
    parsed = parse_api_key(raw_key, expected_prefix_env="prod")
    assert parsed is not None
    assert parsed.key_id == created.api_key.key_id
    assert len(parsed.secret) >= MIN_GENERATED_SECRET_LENGTH
    assert str(created.secret) == "**********"
    assert raw_key not in repr(created)
    assert raw_key not in repr(created.secret)
    assert api_key_secret_matches(
        stored_digest=created.api_key.hashed_secret,
        api_key_hash_secret=API_KEY_HASH_SECRET.encode(),
        secret=parsed.secret,
    )
    assert created.api_key.scopes == ["read", "write"]
    assert created.api_key.encrypted_secret is None
    assert created.api_key.client_metadata == {"user_agent": "tests"}
    assert manager.created_api_key_events == [(user, created.api_key)]
    assert all(raw_key not in repr(row) for row in store.rows.values())


async def test_create_signing_api_key_encrypts_secret_at_rest() -> None:
    """Signing-required API keys keep an encrypted copy of the signing secret."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(
            allowed_scopes=("read",),
            max_keys_per_user=2,
            default_ttl=timedelta(days=1),
            secret_encryption_keyring=keyring,
        ),
    )
    user = _build_user(password_helper)

    created = await manager.create_api_key(user, name="CI", scopes=("read",), signing_required=True)
    parsed = parse_api_key(created.secret.get_secret_value(), expected_prefix_env="prod")
    api_key = cast("ApiKeyRow", created.api_key)

    assert parsed is not None
    assert api_key.signing_required is True
    assert api_key.encrypted_secret is not None
    assert keyring.decrypt(api_key.encrypted_secret.decode()) == parsed.secret


async def test_structural_config_keyring_is_coerced_for_signing() -> None:
    """Plugin-like keyring config is converted to the runtime Fernet keyring."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    user = _build_user(password_helper)

    @dataclass(slots=True)
    class _PluginKeyringConfig:
        prefix: str = "ak"
        environment_marker: str = "prod"
        max_keys_per_user: int = 2
        default_ttl: timedelta | None = timedelta(days=1)
        allowed_scopes: tuple[str, ...] = ("read",)
        scope_subset_check: bool = True
        last_used_write_strategy: Literal["immediate"] = "immediate"
        last_used_throttle_seconds: int = 0
        secret_encryption_keyring: object = FernetKeyringConfig(
            active_key_id="current",
            keys={"current": Fernet.generate_key().decode()},
        )

    service = ApiKeyManagerService[ExampleUser, UUID](
        StringSecretManager(password_helper),
        api_key_store=store,
        config=cast("ApiKeyConfigProtocol", _PluginKeyringConfig()),
    )

    created = await service.create_api_key(user, name="CI", scopes=("read",), signing_required=True)

    assert created.api_key.encrypted_secret is not None


async def test_create_signing_api_key_requires_encryption_keyring() -> None:
    """Signing-required key creation fails closed without encryption material."""
    password_helper = PasswordHelper()
    manager = _build_manager(ApiKeyStore(), password_helper)
    user = _build_user(password_helper)

    with pytest.raises(ApiKeyError, match="secret_encryption_keyring"):
        await manager.create_api_key(user, name="CI", scopes=("read",), signing_required=True)


async def test_api_key_signing_secret_rotation_reencrypts_one_row_by_key_id() -> None:
    """One signing-secret row is explicitly rewritten under the active key without hook calls."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    old_key = Fernet.generate_key().decode()
    current_key = Fernet.generate_key().decode()
    user = _build_user(password_helper)
    old_manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(
            allowed_scopes=("read",),
            secret_encryption_keyring=FernetKeyring(active_key_id="old", keys={"old": old_key}),
        ),
    )
    created = await old_manager.create_api_key(user, name="signing", scopes=("read",), signing_required=True)
    parsed = parse_api_key(created.secret.get_secret_value(), expected_prefix_env="prod")
    assert parsed is not None

    rotation_manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(
            allowed_scopes=("read",),
            secret_encryption_keyring=FernetKeyring(
                active_key_id="current",
                keys={"old": old_key, "current": current_key},
            ),
        ),
    )
    rotation_manager.created_api_key_events.clear()

    assert rotation_manager.api_key_signing_secret_requires_reencrypt(created.api_key) is True
    updated = await rotation_manager.reencrypt_api_key_signing_secret(created.api_key.key_id)

    assert updated is created.api_key
    assert created.api_key.encrypted_secret is not None
    rewritten = created.api_key.encrypted_secret.decode()
    assert rewritten.startswith("fernet:v1:current:")
    assert rotation_manager.api_key_signing_secret_requires_reencrypt(created.api_key) is False
    current_keyring = FernetKeyring(active_key_id="current", keys={"old": old_key, "current": current_key})
    assert current_keyring.decrypt(rewritten) == parsed.secret
    assert parsed.secret not in repr(updated)
    assert rotation_manager.created_api_key_events == []
    assert rotation_manager.revoked_api_key_events == []
    assert rotation_manager.used_api_key_events == []


async def test_api_key_signing_secret_rotation_rejects_bearer_and_missing_keyring() -> None:
    """Rotation helpers fail closed for bearer rows and missing encryption configuration."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    user = _build_user(password_helper)
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    bearer_manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), secret_encryption_keyring=keyring),
    )
    bearer = await bearer_manager.create_api_key(user, name="bearer", scopes=("read",))

    with pytest.raises(ApiKeyError, match="encrypted signing API key"):
        bearer_manager.api_key_signing_secret_requires_reencrypt(bearer.api_key)
    with pytest.raises(ApiKeyError, match="encrypted signing API key"):
        await bearer_manager.reencrypt_api_key_signing_secret(bearer.api_key)

    signing_row = ApiKeyRow(
        key_id="akid_signing",
        user_id=user.id,
        hashed_secret=b"digest",
        name="signing",
        scopes=[],
        encrypted_secret=b"fernet:v1:old:ciphertext",
        signing_required=True,
    )
    store.rows[signing_row.key_id] = signing_row
    missing_keyring_manager = _build_manager(store, password_helper)
    with pytest.raises(ApiKeyError, match="secret_encryption_keyring"):
        missing_keyring_manager.api_key_signing_secret_requires_reencrypt(cast("ApiKeyRowProtocol", signing_row))
    with pytest.raises(ApiKeyError, match="secret_encryption_keyring"):
        await missing_keyring_manager.reencrypt_api_key_signing_secret(cast("ApiKeyRowProtocol", signing_row))


async def test_api_key_signing_secret_rotation_rejects_raw_bearer_input() -> None:
    """The key-id helper does not parse or accept raw API-key credentials."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), secret_encryption_keyring=keyring),
    )
    user = _build_user(password_helper)
    created = await manager.create_api_key(user, name="signing", scopes=("read",), signing_required=True)

    with pytest.raises(ApiKeyError, match="row or key_id") as exc_info:
        await manager.reencrypt_api_key_signing_secret(created.secret.get_secret_value())

    assert created.secret.get_secret_value() not in str(exc_info.value)
    assert created.secret.get_secret_value() not in repr(exc_info.value)


async def test_api_key_signing_secret_rotation_raises_not_found_for_missing_or_lost_rows() -> None:
    """Key-id rotation reports not-found when lookup or replacement cannot resolve a row."""
    password_helper = PasswordHelper()
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    missing_manager = _build_manager(
        ApiKeyStore(),
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), secret_encryption_keyring=keyring),
    )

    with pytest.raises(ApiKeyNotFoundError):
        await missing_manager.reencrypt_api_key_signing_secret("missing")

    lost_store = NoneReplacingApiKeyStore()
    lost_manager = _build_manager(
        lost_store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), secret_encryption_keyring=keyring),
    )
    user = _build_user(password_helper)
    created = await lost_manager.create_api_key(user, name="signing", scopes=("read",), signing_required=True)

    with pytest.raises(ApiKeyNotFoundError):
        await lost_manager.reencrypt_api_key_signing_secret(created.api_key.key_id)


async def test_api_key_signing_secret_rotation_wraps_unknown_key_and_malformed_values() -> None:
    """Malformed storage and unknown key ids become generic manager errors without secret disclosure."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), secret_encryption_keyring=keyring),
    )
    user = _build_user(password_helper)
    unknown_key_row = ApiKeyRow(
        key_id="akid_unknown",
        user_id=user.id,
        hashed_secret=b"digest",
        name="unknown",
        scopes=[],
        encrypted_secret=b"fernet:v1:missing:gAAAAABlbadciphertext",
        signing_required=True,
    )
    malformed_row = ApiKeyRow(
        key_id="akid_malformed",
        user_id=user.id,
        hashed_secret=b"digest",
        name="malformed",
        scopes=[],
        encrypted_secret=b"not-a-versioned-fernet-envelope",
        signing_required=True,
    )
    store.rows[unknown_key_row.key_id] = unknown_key_row
    store.rows[malformed_row.key_id] = malformed_row

    for row in (unknown_key_row, malformed_row):
        with pytest.raises(ApiKeyError) as requires_exc_info:
            manager.api_key_signing_secret_requires_reencrypt(cast("ApiKeyRowProtocol", row))
        with pytest.raises(ApiKeyError) as reencrypt_exc_info:
            await manager.reencrypt_api_key_signing_secret(cast("ApiKeyRowProtocol", row))
        for exc in (requires_exc_info.value, reencrypt_exc_info.value):
            assert exc.args == ("API-key signing secret cannot be processed for rotation.",)
            assert "missing" not in repr(exc)
            assert "gAAAAABlbadciphertext" not in repr(exc)
            assert "not-a-versioned-fernet-envelope" not in repr(exc)


def test_api_key_manager_config_rejects_invalid_keyring_shape() -> None:
    """Structural config keyring values must expose the Fernet keyring shape."""
    password_helper = PasswordHelper()

    @dataclass(slots=True)
    class _BadKeyringConfig:
        prefix: str = "ak"
        environment_marker: str = "dev"
        max_keys_per_user: int = 1
        default_ttl: timedelta | None = None
        allowed_scopes: tuple[str, ...] = ("read",)
        scope_subset_check: bool = True
        last_used_write_strategy: Literal["immediate"] = "immediate"
        last_used_throttle_seconds: int = 0
        secret_encryption_keyring: object = object()

    with pytest.raises(ApiKeyError, match="secret_encryption_keyring"):
        ApiKeyManagerService[ExampleUser, UUID](
            StringSecretManager(password_helper),
            api_key_store=ApiKeyStore(),
            config=cast("ApiKeyConfigProtocol", _BadKeyringConfig()),
        )


async def test_direct_api_key_service_accepts_plain_string_secret_and_structural_config() -> None:
    """The service accepts plugin-like config objects and direct string hash secrets."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    user = _build_user(password_helper)

    @dataclass(slots=True)
    class _PluginLikeConfig:
        prefix: str = "ak"
        environment_marker: str = "dev"
        max_keys_per_user: int = 1
        default_ttl: timedelta | None = None
        allowed_scopes: tuple[str, ...] = ("read",)
        scope_subset_check: bool = True
        last_used_write_strategy: Literal["immediate"] = "immediate"
        last_used_throttle_seconds: int = 0
        secret_encryption_keyring: None = None

    service = ApiKeyManagerService[ExampleUser, UUID](
        StringSecretManager(password_helper),
        api_key_store=store,
        config=cast("ApiKeyConfigProtocol", _PluginLikeConfig()),
    )

    created = await service.create_api_key(user, name="dev", scopes=("read",))
    parsed = parse_api_key(created.secret.get_secret_value(), expected_prefix_env="dev")

    assert parsed is not None
    assert created.api_key.expires_at is None


def test_api_key_id_generation_rewrites_non_alnum_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generated public key ids always satisfy the parser's leading-character contract."""
    monkeypatch.setattr(api_key_secrets, "token_urlsafe", lambda _bytes: "_invalid-prefix")

    assert ApiKeyManagerService._generate_key_id() == "kinvalid-prefix"


async def test_create_api_key_rejects_disallowed_scopes_without_secret_leakage() -> None:
    """Scope policy is enforced server-side before persistence."""
    password_helper = PasswordHelper()
    manager = _build_manager(ApiKeyStore(), password_helper)
    user = _build_user(password_helper)

    with pytest.raises(ApiKeyScopeDeniedError) as exc_info:
        await manager.create_api_key(user, name="bad", scopes=("read", "admin"))

    assert exc_info.value.denied_scopes == frozenset({"admin"})
    assert "ak_prod" not in repr(exc_info.value)
    assert exc_info.value.__cause__ is None


async def test_create_api_key_enforces_max_keys_under_concurrent_request_managers() -> None:
    """Concurrent request-scoped managers cannot exceed ``max_keys_per_user``."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    first_manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), max_keys_per_user=1),
    )
    second_manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), max_keys_per_user=1),
    )
    user = _build_user(password_helper)

    results = await asyncio.gather(
        first_manager.create_api_key(user, name="first", scopes=("read",)),
        second_manager.create_api_key(user, name="second", scopes=("read",)),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, ApiKeyLimitReachedError) for result in results) == 1
    assert len(await first_manager.list_api_keys(user)) == 1
    assert store.create_calls == 1


async def test_update_api_key_applies_name_scope_policy_and_current_password_step_up() -> None:
    """Updates verify optional current password and re-run scope allow-list checks."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    manager = _build_manager(store, password_helper)
    user = _build_user(password_helper)
    created = await manager.create_api_key(user, name="old", scopes=("read",))

    with pytest.raises(InvalidPasswordError):
        await manager.update_api_key(user, created.api_key.key_id, name="bad", current_password="wrong-password")
    with pytest.raises(ApiKeyScopeDeniedError):
        await manager.update_api_key(user, created.api_key.key_id, scopes=("admin",))

    updated = await manager.update_api_key(
        user,
        created.api_key.key_id,
        name="new",
        scopes=("write",),
        current_password="current-password",
    )

    assert updated.name == "new"
    assert updated.scopes == ["write"]


async def test_get_update_and_revoke_raise_for_missing_or_foreign_rows() -> None:
    """Manager operations fail closed for missing and cross-user key ids."""
    password_helper = PasswordHelper()
    store = NoneUpdatingApiKeyStore()
    manager = _build_manager(store, password_helper)
    user = _build_user(password_helper)
    created = await manager.create_api_key(user, name="owned", scopes=("read",))
    other_user = ExampleUser(id=UUID("00000000-0000-0000-0000-000000000099"))

    with pytest.raises(ApiKeyNotFoundError):
        await manager.get_api_key(user, "missing")
    with pytest.raises(ApiKeyNotFoundError):
        await manager.get_api_key(other_user, created.api_key.key_id, include_inactive=True)
    assert await manager.update_api_key(user, created.api_key.key_id) is created.api_key
    with pytest.raises(ApiKeyNotFoundError):
        await manager.update_api_key(user, created.api_key.key_id, name="lost")

    foreign_store = ForeignRevokingApiKeyStore()
    foreign_manager = _build_manager(foreign_store, password_helper)
    await foreign_manager.create_api_key(user, name="owned", scopes=("read",))
    with pytest.raises(ApiKeyNotFoundError):
        await foreign_manager.revoke_api_key(user, next(iter(foreign_store.rows)))


async def test_revoke_api_key_is_idempotent_and_list_filters_inactive_rows() -> None:
    """Repeated revoke returns the same row and preserves the first timestamp."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    manager = _build_manager(store, password_helper)
    user = _build_user(password_helper)
    active = await manager.create_api_key(user, name="active", scopes=("read",))
    expired = await manager.create_api_key(
        user,
        name="expired",
        scopes=("read",),
        expires_at=datetime.now(tz=UTC) - timedelta(seconds=1),
    )

    first_revoked_at = datetime.now(tz=UTC)
    second_revoked_at = first_revoked_at + timedelta(minutes=5)
    revoked = await manager.revoke_api_key(user, active.api_key.key_id, revoked_at=first_revoked_at)
    revoked_again = await manager.revoke_api_key(user, active.api_key.key_id, revoked_at=second_revoked_at)

    assert revoked is active.api_key
    assert revoked_again is active.api_key
    assert active.api_key.revoked_at == first_revoked_at
    assert await manager.list_api_keys(user) == []
    assert await manager.list_api_keys(user, include_inactive=True) == [active.api_key, expired.api_key]
    assert manager.revoked_api_key_events == [(user, active.api_key), (user, active.api_key)]


async def test_record_api_key_used_honors_throttle_window() -> None:
    """Last-used writes and hooks run no more often than the configured throttle."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(
            allowed_scopes=("read",),
            last_used_write_strategy="throttled",
            last_used_throttle_seconds=60,
        ),
    )
    user = _build_user(password_helper)
    created = await manager.create_api_key(user, name="usage", scopes=("read",))
    first_used_at = datetime(2026, 5, 9, 12, 0, tzinfo=UTC)

    first = await manager.record_api_key_used(created.api_key.key_id, used_at=first_used_at)
    throttled = await manager.record_api_key_used(created.api_key.key_id, used_at=first_used_at + timedelta(seconds=30))
    second = await manager.record_api_key_used(created.api_key.key_id, used_at=first_used_at + timedelta(seconds=61))

    assert first is created.api_key
    assert throttled is created.api_key
    assert second is created.api_key
    assert store.last_used_writes == [first_used_at, first_used_at + timedelta(seconds=61)]
    assert manager.used_api_key_events == [created.api_key, created.api_key]

    created.api_key.last_used_at = datetime(2026, 5, 9, 12, 2, tzinfo=UTC).replace(tzinfo=None)
    third_used_at = datetime(2026, 5, 9, 12, 3, tzinfo=UTC)
    assert await manager.record_api_key_used(created.api_key.key_id, used_at=third_used_at) is created.api_key
    assert store.last_used_writes[-1] == third_used_at


async def test_record_api_key_used_disabled_missing_immediate_and_lost_update_paths() -> None:
    """Use tracking handles disabled, missing, immediate, and lost-update outcomes."""
    password_helper = PasswordHelper()
    disabled_manager = _build_manager(
        ApiKeyStore(),
        password_helper,
        config=ApiKeyManagerConfig(last_used_write_strategy="disabled"),
    )
    assert await disabled_manager.record_api_key_used("missing") is None

    immediate_store = ApiKeyStore()
    immediate_manager = _build_manager(
        immediate_store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), last_used_write_strategy="immediate"),
    )
    user = _build_user(password_helper)
    created = await immediate_manager.create_api_key(user, name="immediate", scopes=("read",))
    first_used_at = datetime(2026, 5, 9, 12, 0, tzinfo=UTC)
    second_used_at = first_used_at + timedelta(seconds=1)

    assert await immediate_manager.record_api_key_used("missing") is None
    assert await immediate_manager.record_api_key_used(created.api_key.key_id, used_at=first_used_at) is created.api_key
    assert (
        await immediate_manager.record_api_key_used(created.api_key.key_id, used_at=second_used_at) is created.api_key
    )
    assert immediate_store.last_used_writes == [first_used_at, second_used_at]

    lost_store = NoneUpdatingApiKeyStore()
    lost_manager = _build_manager(
        lost_store,
        password_helper,
        config=ApiKeyManagerConfig(allowed_scopes=("read",), last_used_write_strategy="immediate"),
    )
    lost = await lost_manager.create_api_key(user, name="lost", scopes=("read",))
    assert await lost_manager.record_api_key_used(lost.api_key.key_id) is None


async def test_scope_subset_can_be_disabled_and_missing_dependencies_fail_closed() -> None:
    """Manager API-key service covers explicit unsafe policy opt-outs and missing dependency errors."""
    password_helper = PasswordHelper()
    store = ApiKeyStore()
    manager = _build_manager(
        store,
        password_helper,
        config=ApiKeyManagerConfig(scope_subset_check=False, default_ttl=None),
    )
    user = _build_user(password_helper)

    created = await manager.create_api_key(user, name="unbounded", scopes=("admin", "admin", " read "))
    api_key_service = manager.api_keys

    assert created.api_key.scopes == ["admin", "read"]
    assert created.api_key.expires_at is None
    assert manager.api_keys is api_key_service
    assert await manager.get_api_key(user, created.api_key.key_id) is created.api_key

    missing_store_manager = TrackingUserManager(
        user_db=AsyncMock(),
        password_helper=password_helper,
        api_key_hash_secret=API_KEY_HASH_SECRET,
    )
    with pytest.raises(ApiKeyError, match="api_key_store"):
        await missing_store_manager.create_api_key(user, name="missing-store")

    missing_secret_manager = TrackingUserManager(
        user_db=AsyncMock(),
        password_helper=password_helper,
        api_key_store=ApiKeyStore(),
        api_key_config=ApiKeyManagerConfig(),
    )
    with pytest.raises(ApiKeyError, match="api_key_hash_secret"):
        await missing_secret_manager.create_api_key(user, name="missing-secret")


async def test_create_api_key_requires_name_keyword_at_runtime() -> None:
    """Creation reports a precise TypeError when dynamic options omit the required name."""
    password_helper = PasswordHelper()
    manager = _build_manager(ApiKeyStore(), password_helper)
    user = _build_user(password_helper)
    empty_options = cast("ApiKeyCreateOptions", {})

    with pytest.raises(TypeError, match="missing required keyword argument: 'name'"):
        await manager.create_api_key(user, **empty_options)
