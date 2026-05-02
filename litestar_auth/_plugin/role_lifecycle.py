"""Manager lifecycle wiring for plugin role administration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.session_binding import _ScopedUserDatabaseProxy
from litestar_auth._plugin.user_manager_builder import resolve_user_manager_factory
from litestar_auth.oauth_encryption import OAuthTokenEncryption
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig, UserDatabaseFactory, UserManagerFactory
    from litestar_auth.manager import BaseUserManager


@dataclass(frozen=True, slots=True)
class _ManagerLifecycleRoleUpdater[UP: UserProtocol[Any]]:
    """Build request-scoped user managers for CLI role mutations."""

    config: LitestarAuthConfig[UP, Any]
    _user_db_factory: UserDatabaseFactory[UP, Any]
    _user_manager_factory: UserManagerFactory[UP, Any]
    _oauth_token_encryption: OAuthTokenEncryption | None

    @classmethod
    def from_config(
        cls,
        config: LitestarAuthConfig[UP, Any],
    ) -> _ManagerLifecycleRoleUpdater[UP]:
        """Build the manager-backed role updater from plugin configuration.

        Returns:
            The configured lifecycle-preserving role updater.
        """
        return cls(
            config=config,
            _user_db_factory=config.resolve_user_db_factory(),
            _user_manager_factory=resolve_user_manager_factory(config),
            _oauth_token_encryption=_build_oauth_token_encryption(config),
        )

    def build_manager(self, session: AsyncSession) -> BaseUserManager[UP, Any]:
        """Return a request-scoped manager bound to ``session``."""
        user_db = _ScopedUserDatabaseProxy(
            self._user_db_factory(session),
            oauth_token_encryption=self._oauth_token_encryption,
        )
        bound_backends = self.config.resolve_backends(session)
        return self._user_manager_factory(
            session=session,
            user_db=user_db,
            config=self.config,
            backends=bound_backends,
        )


def _build_oauth_token_encryption[UP: UserProtocol[Any]](
    config: LitestarAuthConfig[UP, Any],
) -> OAuthTokenEncryption | None:
    """Return the OAuth token encryption policy for role-admin manager lifecycles."""
    oauth_config = config.oauth_config
    if oauth_config is None:
        return None
    keyring = oauth_config.oauth_token_encryption_keyring
    if keyring is not None:
        return OAuthTokenEncryption(
            unsafe_testing=config.unsafe_testing,
            active_key_id=keyring.active_key_id,
            keys=keyring.keys,
        )
    return OAuthTokenEncryption(
        oauth_config.oauth_token_encryption_key,
        unsafe_testing=config.unsafe_testing,
    )
