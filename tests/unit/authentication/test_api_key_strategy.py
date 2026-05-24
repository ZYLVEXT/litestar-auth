"""Tests for API-key format parsing and authentication strategy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy._api_key_format import (
    api_key_secret_matches,
    digest_api_key_secret,
    parse_api_key,
)
from litestar_auth.authentication.strategy.api_key import (
    ApiKeyContext,
    ApiKeyFailureReason,
    ApiKeyStrategy,
    ApiKeyStrategyConfig,
    api_key_failure_reason_to_error_code,
)
from litestar_auth.authentication.transport.api_key import ApiKeyTransport
from litestar_auth.exceptions import ConfigurationError, ErrorCode, TokenError
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit
API_KEY_HASH_SECRET = "api-key-hash-secret-1234567890abcdef"


@dataclass(slots=True)
class ApiKeyRow:
    """API-key row fixture matching the strategy's persistence contract."""

    user_id: UUID
    key_id: str
    hashed_secret: bytes
    scopes: list[str]
    prefix_env: str = "prod"
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiKeyStore:
    """In-memory indexed API-key store fixture."""

    def __init__(self, rows: dict[str, ApiKeyRow]) -> None:
        """Store API-key rows by public key id."""
        self.rows = rows
        self.seen_lookups: list[tuple[str, bool]] = []

    async def create(self, data: object) -> ApiKeyRow:
        """Unused protocol method for this strategy-only fixture."""
        del data
        raise NotImplementedError

    async def create_for_user_with_limit(self, data: object, *, max_keys_per_user: int) -> ApiKeyRow | None:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            ``None`` because tests never exercise API-key creation through this fixture.
        """
        del data, max_keys_per_user
        return None

    async def get_by_key_id(self, key_id: str, *, include_inactive: bool = False) -> ApiKeyRow | None:
        """Return a row by public key id."""
        self.seen_lookups.append((key_id, include_inactive))
        return self.rows.get(key_id)

    async def list_for_user(self, user_id: UUID, *, include_inactive: bool = False) -> list[ApiKeyRow]:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            Empty list because tests never exercise listing through this fixture.
        """
        del user_id, include_inactive
        return []

    async def delete_for_user(self, user_id: UUID) -> int:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            ``0`` because tests never exercise hard-delete cleanup through this fixture.
        """
        del user_id
        return 0

    async def revoke(self, key_id: str, *, revoked_at: datetime) -> ApiKeyRow | None:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            ``None`` because tests never exercise revocation through this fixture.
        """
        del key_id, revoked_at
        return None

    async def update(
        self,
        key_id: str,
        *,
        name: str | None = None,
        scopes: list[str] | None = None,
    ) -> ApiKeyRow | None:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            ``None`` because tests never exercise metadata updates through this fixture.
        """
        del key_id, name, scopes
        return None

    async def update_last_used_at(self, key_id: str, *, last_used_at: datetime) -> ApiKeyRow | None:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            ``None`` because tests never exercise last-used writes through this fixture.
        """
        del key_id, last_used_at
        return None

    async def list_signing_keys_requiring_reencrypt(
        self,
        requires_reencrypt: Callable[[ApiKeyRow], bool],
        *,
        include_inactive: bool = False,
    ) -> list[ApiKeyRow]:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            Empty list because tests never exercise rotation scans through this fixture.
        """
        del requires_reencrypt, include_inactive
        return []

    async def replace_signing_key_encrypted_secret(
        self,
        key_id: str,
        *,
        encrypted_secret: bytes,
    ) -> ApiKeyRow | None:
        """Unused protocol method for this strategy-only fixture.

        Returns:
            ``None`` because tests never exercise secret replacement through this fixture.
        """
        del key_id, encrypted_secret
        return None


class UserManager:
    """User manager fixture recording user-id lookups."""

    def __init__(self, user: ExampleUser | None) -> None:
        """Store the user returned by matching lookups."""
        self.user = user
        self.seen_user_ids: list[object] = []

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Return the configured user only when ids match."""
        self.seen_user_ids.append(user_id)
        if self.user is None or self.user.id != user_id:
            return None
        return self.user


def _digest(secret: str = "raw-secret") -> bytes:
    return digest_api_key_secret(api_key_hash_secret=API_KEY_HASH_SECRET.encode(), secret=secret)


def _strategy(
    row: ApiKeyRow | None,
    *,
    prefix_env: str | None = "prod",
) -> tuple[ApiKeyStrategy[ExampleUser, UUID], ApiKeyStore]:
    rows = {} if row is None else {row.key_id: row}
    store = ApiKeyStore(rows)
    return (
        ApiKeyStrategy[ExampleUser, UUID](
            api_key_store=store,
            api_key_hash_secret=API_KEY_HASH_SECRET,
            prefix_env=prefix_env,
        ),
        store,
    )


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("bk_prod_keyid.secret", id="malformed-prefix"),
        pytest.param("ak_dev_keyid.secret", id="wrong-env-marker"),
        pytest.param("ak_prod_keyid", id="missing-dot"),
        pytest.param("ak_prod_keyid.", id="empty-secret"),
        pytest.param(f"ak_prod_keyid.{'x' * 4097}", id="oversized"),
        pytest.param("ak_prod_.secret", id="empty-key-id"),
        pytest.param("ak__keyid.secret", id="empty-env"),
    ],
)
def test_parse_api_key_rejects_malformed_inputs(token: str) -> None:
    """Malformed API-key values are rejected before store lookup."""
    assert parse_api_key(token, expected_prefix_env="prod") is None


def test_parse_api_key_returns_canonical_fields() -> None:
    """Canonical API-key values parse into public lookup fields plus raw secret."""
    parsed = parse_api_key("ak_prod_key_01.raw-secret", expected_prefix_env="prod")

    assert parsed is not None
    assert parsed.prefix_env == "prod"
    assert parsed.key_id == "key_01"
    assert parsed.secret == "raw-secret"


def test_api_key_secret_matches_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    """The helper delegates final equality to ``hmac.compare_digest``."""
    calls: list[tuple[bytes, bytes]] = []

    def compare_digest(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return left == right

    monkeypatch.setattr("litestar_auth.authentication.strategy._api_key_format.hmac.compare_digest", compare_digest)
    stored_digest = _digest()

    assert api_key_secret_matches(
        stored_digest=stored_digest,
        api_key_hash_secret=API_KEY_HASH_SECRET.encode(),
        secret="raw-secret",
    )
    assert calls == [(stored_digest, stored_digest)]


async def test_api_key_strategy_resolves_valid_key_and_context() -> None:
    """Valid API keys resolve the user and expose request auth context."""
    user = ExampleUser(id=uuid4())
    strategy, store = _strategy(
        ApiKeyRow(user_id=user.id, key_id="keyid", hashed_secret=_digest(), scopes=["read", "write"]),
    )

    result = await strategy.read_token_with_context("ak_prod_keyid.raw-secret", UserManager(user))

    assert result is not None
    assert result.user is user
    assert result.context == ApiKeyContext(key_id="keyid", scopes=("read", "write"), prefix_env="prod")
    assert await strategy.read_token("ak_prod_keyid.raw-secret", UserManager(user)) is user
    assert store.seen_lookups == [("keyid", True), ("keyid", True)]


async def test_api_key_strategy_carries_scope_subset_policy_in_context() -> None:
    """API-key auth context carries the configured guard downscoping policy."""
    user = ExampleUser(id=uuid4())
    row = ApiKeyRow(user_id=user.id, key_id="keyid", hashed_secret=_digest(), scopes=["read"])
    store = ApiKeyStore({row.key_id: row})
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=store,
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        scope_subset_check=False,
    )

    result = await strategy.read_token_with_context("ak_prod_keyid.raw-secret", UserManager(user))

    assert result is not None
    assert result.context.scope_subset_check is False


async def test_api_key_strategy_accepts_unexpired_aware_expiry() -> None:
    """Aware future expiry timestamps keep API keys active."""
    user = ExampleUser(id=uuid4())
    strategy, _store = _strategy(
        ApiKeyRow(
            user_id=user.id,
            key_id="keyid",
            hashed_secret=_digest(),
            scopes=[],
            expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
        ),
    )

    assert await strategy.read_token("ak_prod_keyid.raw-secret", UserManager(user)) is user


async def test_api_key_strategy_returns_none_without_token_or_parseable_key() -> None:
    """Missing or malformed tokens fail before store lookup."""
    strategy, store = _strategy(None)

    assert await strategy.read_token(None, UserManager(None)) is None
    assert await strategy.read_token("not-an-api-key", UserManager(None)) is None
    assert store.seen_lookups == []


@pytest.mark.parametrize(
    ("row", "token"),
    [
        pytest.param(None, "ak_prod_keyid.raw-secret", id="unknown-key-id"),
        pytest.param(
            ApiKeyRow(user_id=uuid4(), key_id="keyid", hashed_secret=_digest("other"), scopes=[]),
            "ak_prod_keyid.raw-secret",
            id="wrong-digest",
        ),
        pytest.param(
            ApiKeyRow(
                user_id=uuid4(),
                key_id="keyid",
                hashed_secret=_digest(),
                scopes=[],
                revoked_at=datetime.now(tz=UTC),
            ),
            "ak_prod_keyid.raw-secret",
            id="revoked",
        ),
        pytest.param(
            ApiKeyRow(
                user_id=uuid4(),
                key_id="keyid",
                hashed_secret=_digest(),
                scopes=[],
                expires_at=datetime.now(tz=UTC).replace(tzinfo=None) - timedelta(seconds=1),
            ),
            "ak_prod_keyid.raw-secret",
            id="expired",
        ),
        pytest.param(
            ApiKeyRow(user_id=uuid4(), key_id="keyid", hashed_secret=_digest(), scopes=[], prefix_env="dev"),
            "ak_prod_keyid.raw-secret",
            id="wrong-prefix-env",
        ),
    ],
)
async def test_api_key_strategy_rejects_invalid_revoked_expired_or_unknown_keys(
    row: ApiKeyRow | None,
    token: str,
) -> None:
    """Invalid API-key states fail closed without resolving a user."""
    user = ExampleUser(id=uuid4())
    strategy, _store = _strategy(row)

    assert await strategy.read_token(token, UserManager(user)) is None


@pytest.mark.parametrize(
    ("row", "token", "expected_reason"),
    [
        pytest.param(None, "ak_prod_keyid.raw-secret", ApiKeyFailureReason.INVALID, id="unknown-key-id"),
        pytest.param(
            ApiKeyRow(user_id=uuid4(), key_id="keyid", hashed_secret=_digest("other"), scopes=[]),
            "ak_prod_keyid.raw-secret",
            ApiKeyFailureReason.INVALID,
            id="wrong-digest",
        ),
        pytest.param(
            ApiKeyRow(
                user_id=uuid4(),
                key_id="keyid",
                hashed_secret=_digest(),
                scopes=[],
                revoked_at=datetime.now(tz=UTC),
            ),
            "ak_prod_keyid.raw-secret",
            ApiKeyFailureReason.REVOKED,
            id="revoked",
        ),
        pytest.param(
            ApiKeyRow(
                user_id=uuid4(),
                key_id="keyid",
                hashed_secret=_digest(),
                scopes=[],
                expires_at=datetime.now(tz=UTC).replace(tzinfo=None) - timedelta(seconds=1),
            ),
            "ak_prod_keyid.raw-secret",
            ApiKeyFailureReason.EXPIRED,
            id="expired",
        ),
        pytest.param(
            ApiKeyRow(user_id=uuid4(), key_id="keyid", hashed_secret=_digest(), scopes=[], prefix_env="dev"),
            "ak_prod_keyid.raw-secret",
            ApiKeyFailureReason.INVALID,
            id="wrong-prefix-env",
        ),
    ],
)
async def test_api_key_strategy_attempt_returns_failure_reason_for_bearer_rejections(
    row: ApiKeyRow | None,
    token: str,
    expected_reason: ApiKeyFailureReason,
) -> None:
    """Bearer API-key attempts expose a deterministic typed failure reason."""
    strategy, _store = _strategy(row)

    attempt = await strategy.read_token_attempt(token, UserManager(ExampleUser(id=uuid4())))

    assert attempt.result is None
    assert attempt.failure_reason == expected_reason


def test_api_key_failure_reason_mapping_preserves_public_error_codes() -> None:
    """Internal API-key failure reasons map to the stable public error-code taxonomy."""
    assert api_key_failure_reason_to_error_code(ApiKeyFailureReason.INVALID) == ErrorCode.API_KEY_INVALID
    assert api_key_failure_reason_to_error_code(ApiKeyFailureReason.REVOKED) == ErrorCode.API_KEY_REVOKED
    assert api_key_failure_reason_to_error_code(ApiKeyFailureReason.EXPIRED) == ErrorCode.API_KEY_EXPIRED
    assert (
        api_key_failure_reason_to_error_code(ApiKeyFailureReason.SIGNATURE_INVALID)
        == ErrorCode.API_KEY_SIGNATURE_INVALID
    )
    assert (
        api_key_failure_reason_to_error_code(ApiKeyFailureReason.SIGNATURE_TIMESTAMP_SKEW)
        == ErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW
    )
    assert (
        api_key_failure_reason_to_error_code(ApiKeyFailureReason.SIGNATURE_NONCE_REPLAY)
        == ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY
    )


@pytest.mark.parametrize(
    ("row", "token", "expected_reason"),
    [
        pytest.param(None, None, ApiKeyFailureReason.INVALID, id="missing-token"),
        pytest.param(None, "not-an-api-key", ApiKeyFailureReason.INVALID, id="malformed-token"),
        pytest.param(None, "ak_prod_keyid.raw-secret", ApiKeyFailureReason.INVALID, id="unknown-key-id"),
        pytest.param(
            ApiKeyRow(user_id=uuid4(), key_id="keyid", hashed_secret=_digest(), scopes=[], prefix_env="dev"),
            "ak_prod_keyid.raw-secret",
            ApiKeyFailureReason.INVALID,
            id="wrong-prefix-env",
        ),
        pytest.param(
            ApiKeyRow(user_id=uuid4(), key_id="keyid", hashed_secret=_digest(), scopes=[]),
            "ak_prod_keyid.wrong-secret",
            ApiKeyFailureReason.INVALID,
            id="wrong-secret",
        ),
        pytest.param(
            ApiKeyRow(
                user_id=uuid4(),
                key_id="keyid",
                hashed_secret=_digest(),
                scopes=[],
                revoked_at=datetime.now(tz=UTC),
            ),
            "ak_prod_keyid.raw-secret",
            ApiKeyFailureReason.REVOKED,
            id="revoked",
        ),
        pytest.param(
            ApiKeyRow(
                user_id=uuid4(),
                key_id="keyid",
                hashed_secret=_digest(),
                scopes=[],
                expires_at=datetime.now(tz=UTC) - timedelta(seconds=1),
            ),
            "ak_prod_keyid.raw-secret",
            ApiKeyFailureReason.EXPIRED,
            id="expired",
        ),
    ],
)
async def test_api_key_strategy_classifies_bearer_failure_reasons(
    row: ApiKeyRow | None,
    token: str | None,
    expected_reason: ApiKeyFailureReason,
) -> None:
    """Bearer failure classification covers each stable rejection branch."""
    strategy, _store = _strategy(row)

    assert await strategy.classify_failure_reason(token) == expected_reason


async def test_api_key_strategy_rejects_user_lookup_miss() -> None:
    """A matching key row still fails closed when the owning user no longer resolves."""
    strategy, _store = _strategy(ApiKeyRow(user_id=uuid4(), key_id="keyid", hashed_secret=_digest(), scopes=[]))

    assert await strategy.read_token("ak_prod_keyid.raw-secret", UserManager(None)) is None


async def test_api_key_strategy_rejects_login_token_issuance() -> None:
    """API keys are not issued through Strategy.write_token."""
    strategy, _store = _strategy(None)

    with pytest.raises(TokenError, match="does not issue login tokens"):
        await strategy.write_token(ExampleUser(id=uuid4()))


async def test_api_key_strategy_destroy_token_is_noop() -> None:
    """API-key revocation is intentionally outside the strategy logout path."""
    strategy, _store = _strategy(None)

    assert await strategy.destroy_token("ak_prod_keyid.raw-secret", ExampleUser(id=uuid4())) is None


def test_api_key_strategy_rejects_config_combined_with_keyword_options() -> None:
    """ApiKeyStrategy accepts either a config object or keyword options."""
    config = ApiKeyStrategyConfig(api_key_store=ApiKeyStore({}), api_key_hash_secret=API_KEY_HASH_SECRET)

    with pytest.raises(ValueError, match="ApiKeyStrategyConfig or keyword options"):
        ApiKeyStrategy[ExampleUser, UUID](
            config=config,
            api_key_store=ApiKeyStore({}),
            api_key_hash_secret=API_KEY_HASH_SECRET,
        )


def test_api_key_strategy_validates_hash_secret_strength() -> None:
    """API-key HMAC secrets must satisfy production secret requirements."""
    with pytest.raises(ConfigurationError, match="ApiKeyStrategy api_key_hash_secret"):
        ApiKeyStrategy[ExampleUser, UUID](api_key_store=ApiKeyStore({}), api_key_hash_secret="short")


async def test_api_key_backend_exposes_context_while_non_contextual_backend_uses_name() -> None:
    """API-key backends return ``ApiKeyContext`` and existing backends keep name auth context."""
    user = ExampleUser(id=uuid4())
    strategy, _store = _strategy(ApiKeyRow(user_id=user.id, key_id="keyid", hashed_secret=_digest(), scopes=["read"]))
    api_key_backend = AuthenticationBackend[ExampleUser, UUID](
        name="api-key",
        transport=ApiKeyTransport(),
        strategy=strategy,
    )
    api_key_connection = _connection(authorization="Bearer ak_prod_keyid.raw-secret")

    assert await api_key_backend.authenticate_with_context(api_key_connection, UserManager(user)) == (
        user,
        ApiKeyContext(key_id="keyid", scopes=("read",), prefix_env="prod"),
    )

    missing_context_connection = _connection(authorization="Bearer ak_prod_missing.raw-secret")
    assert await api_key_backend.authenticate_with_context(missing_context_connection, UserManager(user)) is None

    class StaticStrategy:
        async def read_token(self, token: str | None, user_manager: object) -> ExampleUser:
            del token, user_manager
            return user

        async def write_token(self, user: ExampleUser) -> str:
            del user
            return "token"

        async def destroy_token(self, token: str, user: ExampleUser) -> None:
            del token, user

    bearer_backend = AuthenticationBackend[ExampleUser, UUID](
        name="bearer-jwt",
        transport=ApiKeyTransport(),
        strategy=StaticStrategy(),
    )

    assert await bearer_backend.authenticate_with_context(api_key_connection, UserManager(user)) == (user, "bearer-jwt")


def _connection(*, authorization: str) -> ASGIConnection[Any, Any, Any, Any]:
    scope = {
        "type": "http",
        "headers": [(b"authorization", authorization.encode())],
        "path_params": {},
        "query_string": b"",
    }
    return ASGIConnection(scope=cast("HTTPScope", scope))
