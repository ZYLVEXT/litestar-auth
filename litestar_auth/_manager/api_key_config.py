"""API-key manager configuration contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol

from litestar_auth._plugin.features import DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS, ApiKeyLastUsedWriteStrategy
from litestar_auth._secrets_at_rest import FernetKeyring
from litestar_auth.authentication.strategy._api_key_format import API_KEY_PREFIX
from litestar_auth.exceptions import ApiKeyError

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class ApiKeyManagerConfig:
    """Manager-owned API-key policy inputs."""

    prefix: str = API_KEY_PREFIX
    environment_marker: str = "prod"
    max_keys_per_user: int = 5
    default_ttl: timedelta | None = timedelta(days=365)
    allowed_scopes: Sequence[str] = ()
    scope_subset_check: bool = True
    last_used_write_strategy: ApiKeyLastUsedWriteStrategy = "throttled"
    last_used_throttle_seconds: int = DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS
    secret_encryption_keyring: FernetKeyring | None = None


class ApiKeyConfigProtocol(Protocol):
    """Structural subset of plugin API-key config consumed by the manager."""

    @property
    def prefix(self) -> str:
        """The API-key credential prefix."""
        ...

    @property
    def environment_marker(self) -> str:
        """The deployment/environment marker embedded in issued keys."""
        ...

    @property
    def max_keys_per_user(self) -> int:
        """The maximum active API-key count per user."""
        ...

    @property
    def default_ttl(self) -> timedelta | None:
        """The default issued-key lifetime."""
        ...

    @property
    def allowed_scopes(self) -> Sequence[str]:
        """Configured API-key scopes."""
        ...

    @property
    def scope_subset_check(self) -> bool:
        """Whether requested scopes must be a subset of allowed scopes."""
        ...

    @property
    def last_used_write_strategy(
        self,
    ) -> ApiKeyLastUsedWriteStrategy:
        """The last-used timestamp write strategy."""
        ...

    @property
    def last_used_throttle_seconds(self) -> int:
        """The last-used timestamp throttle interval."""
        ...

    @property
    def secret_encryption_keyring(
        self,
    ) -> object | None:
        """Optional secret-at-rest keyring configuration."""
        ...


def coerce_api_key_manager_config(config: ApiKeyManagerConfig | ApiKeyConfigProtocol | None) -> ApiKeyManagerConfig:
    """Return the concrete manager API-key config."""
    if config is None:
        return ApiKeyManagerConfig()
    if isinstance(config, ApiKeyManagerConfig):
        return config
    return ApiKeyManagerConfig(
        prefix=config.prefix,
        environment_marker=config.environment_marker,
        max_keys_per_user=config.max_keys_per_user,
        default_ttl=config.default_ttl,
        allowed_scopes=config.allowed_scopes,
        scope_subset_check=config.scope_subset_check,
        last_used_write_strategy=config.last_used_write_strategy,
        last_used_throttle_seconds=config.last_used_throttle_seconds,
        secret_encryption_keyring=_coerce_fernet_keyring(getattr(config, "secret_encryption_keyring", None)),
    )


def resolve_api_key_expires_at(config: ApiKeyManagerConfig, expires_at: datetime | None) -> datetime | None:
    """Return the explicit expiry or the configured default expiry."""
    if expires_at is not None:
        return expires_at
    if config.default_ttl is None:
        return None
    return datetime.now(tz=UTC) + config.default_ttl


def _coerce_fernet_keyring(configured: object) -> FernetKeyring | None:
    if configured is None:
        return None
    if isinstance(configured, FernetKeyring):
        return configured
    active_key_id = getattr(configured, "active_key_id", None)
    keys = getattr(configured, "keys", None)
    if isinstance(active_key_id, str) and keys is not None:
        return FernetKeyring(active_key_id=active_key_id, keys=keys)
    msg = "api_keys.secret_encryption_keyring must be a FernetKeyringConfig."
    raise ApiKeyError(msg)
