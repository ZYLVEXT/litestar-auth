"""API-key backend construction for the Litestar auth plugin."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Never, cast, override

from litestar_auth._secrets_at_rest import FernetKeyring
from litestar_auth.authentication.strategy.base import Strategy
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin._protocols import StrategyProto
    from litestar_auth._plugin.config import StartupBackendTemplate
    from litestar_auth._plugin.features import ApiKeyConfig, ApiKeyScopeAuthority, ApiKeyStoreFactory
    from litestar_auth.authentication.strategy.base import UserManagerProtocol
    from litestar_auth.db import BaseApiKeyStore


def _build_default_api_key_store(session: AsyncSession) -> BaseApiKeyStore[Any, Any]:
    """Build the bundled SQLAlchemy API-key store with deferred imports.

    Returns:
        API-key store bound to ``session``.
    """
    from litestar_auth.db.sqlalchemy import SQLAlchemyApiKeyStore  # noqa: PLC0415
    from litestar_auth.models import ApiKey  # noqa: PLC0415

    return SQLAlchemyApiKeyStore(session=session, api_key_model=ApiKey)


def resolve_api_key_store_factory(api_key_config: ApiKeyConfig) -> ApiKeyStoreFactory:
    """Return the configured API-key store factory or the lazy SQLAlchemy default."""
    if api_key_config.store_factory is not None:
        return api_key_config.store_factory
    return _build_default_api_key_store


def _raise_startup_only_api_key_runtime_error() -> Never:
    msg = (
        "LitestarAuthConfig.resolve_startup_backends() yields startup-only API-key backends that cannot "
        "run request-time authentication work without a request AsyncSession. Use "
        "LitestarAuthConfig.resolve_backends(session) to obtain request-scoped backend instances."
    )
    raise RuntimeError(msg)


@dataclass(slots=True)
class _StartupOnlyApiKeyStrategy[UP: UserProtocol[Any], ID](Strategy[UP, ID]):
    """Startup-only API-key strategy metadata holder."""

    api_key_config: ApiKeyConfig
    api_key_hash_secret: str = field(repr=False)
    store_factory: ApiKeyStoreFactory = field(repr=False)
    unsafe_testing: bool = False
    _api_key_hash_secret: bytes = field(init=False, repr=False)
    prefix_env: str = field(init=False)
    prefix: str = field(init=False)
    signing_skew_seconds: int = field(init=False)
    scope_authority: ApiKeyScopeAuthority | None = field(init=False, default=None, repr=False)
    nonce_store: object | None = field(init=False, default=None)
    secret_encryption_keyring: FernetKeyring | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        """Expose metadata used by validation and OpenAPI without binding a session."""
        self._api_key_hash_secret = self.api_key_hash_secret.encode()
        self.prefix_env = self.api_key_config.environment_marker
        self.prefix = self.api_key_config.prefix
        self.signing_skew_seconds = self.api_key_config.signing_skew_seconds
        self.scope_authority = self.api_key_config.scope_authority or _default_scope_authority()
        self.nonce_store = self.api_key_config.nonce_store
        keyring_config = self.api_key_config.secret_encryption_keyring
        if keyring_config is not None:
            self.secret_encryption_keyring = FernetKeyring(
                active_key_id=keyring_config.active_key_id,
                keys=keyring_config.keys,
            )

    def with_session(self, session: AsyncSession) -> StrategyProto[UP, ID]:
        """Return a request-bound API-key strategy for ``session``."""
        from litestar_auth.authentication.strategy.api_key import ApiKeyStrategy  # noqa: PLC0415

        return cast(
            "StrategyProto[UP, ID]",
            ApiKeyStrategy[UP, ID](
                api_key_store=self.store_factory(session),
                api_key_hash_secret=self.api_key_hash_secret,
                prefix_env=self.api_key_config.environment_marker,
                prefix=self.api_key_config.prefix,
                scope_subset_check=self.api_key_config.scope_subset_check,
                scope_authority=self.api_key_config.scope_authority or _default_scope_authority(),
                signing_skew_seconds=self.api_key_config.signing_skew_seconds,
                nonce_store=cast("Any", self.api_key_config.nonce_store),
                secret_encryption_keyring=self.secret_encryption_keyring,
                unsafe_testing=self.unsafe_testing,
            ),
        )

    @override
    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> UP | None:
        """Reject request-time reads until a request ``AsyncSession`` is bound."""
        del token, user_manager
        _raise_startup_only_api_key_runtime_error()

    @override
    async def write_token(self, user: UP) -> str:
        """Reject login-token issuance for startup-only API-key backends."""
        del user
        _raise_startup_only_api_key_runtime_error()

    @override
    async def destroy_token(self, token: str, user: UP) -> None:
        """Reject token destruction for startup-only API-key backends."""
        del token, user
        _raise_startup_only_api_key_runtime_error()


def build_api_key_backend_template[UP: UserProtocol[Any], ID](
    api_key_config: ApiKeyConfig,
    *,
    api_key_hash_secret: str,
    unsafe_testing: bool = False,
) -> StartupBackendTemplate[UP, ID]:
    """Build the startup-only template for the API-key backend.

    Returns:
        Startup backend template for API-key authentication.
    """
    from litestar_auth._plugin.config import StartupBackendTemplate  # noqa: PLC0415
    from litestar_auth.authentication.backend import AuthenticationBackend  # noqa: PLC0415
    from litestar_auth.authentication.transport.api_key import ApiKeyTransport  # noqa: PLC0415

    startup_backend = AuthenticationBackend[UP, ID](
        name=api_key_config.backend_name,
        transport=ApiKeyTransport(prefix=api_key_config.prefix),
        strategy=cast(
            "StrategyProto[UP, ID]",
            _StartupOnlyApiKeyStrategy[UP, ID](
                api_key_config=api_key_config,
                api_key_hash_secret=api_key_hash_secret,
                store_factory=resolve_api_key_store_factory(api_key_config),
                unsafe_testing=unsafe_testing,
            ),
        ),
    )
    return StartupBackendTemplate.from_runtime_backend(startup_backend)


def _default_scope_authority() -> ApiKeyScopeAuthority:
    """Return the default API-key scope authority without importing guards at module import time."""
    from litestar_auth.guards._api_key_guards import default_api_key_scope_authority  # noqa: PLC0415

    return default_api_key_scope_authority
