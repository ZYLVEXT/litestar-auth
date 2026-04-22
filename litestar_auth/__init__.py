"""Core Litestar authentication and authorization entry points.

The root package exports the plugin, configuration dataclasses, primary backend
and transport types, the base user manager, core guards, user protocols, and the
base auth exception. Import controllers, strategies, token stores, TOTP helpers,
payloads, schemas, ORM models, and optional Redis helpers from their dedicated
submodules.

Examples:
    Wire the database-backed bearer preset when building a Litestar application::

        from uuid import UUID

        from litestar import Litestar
        from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig, UserManagerSecurity
        from litestar_auth.models import User

        config = LitestarAuthConfig[User, UUID](
            database_token_auth=DatabaseTokenAuthConfig(
                token_hash_secret="replace-with-32+-char-db-token-secret",
            ),
            user_model=User,
            user_manager_class=YourUserManager,
            session_maker=session_maker,  # e.g. async_sessionmaker(...)
            user_manager_security=UserManagerSecurity(
                verification_token_secret="replace-with-32+-char-secret",
                reset_password_token_secret="replace-with-32+-char-secret",
            ),
        )
        app = Litestar(plugins=[LitestarAuth(config)])
"""

import logging

from litestar_auth.authentication import AuthenticationBackend, Authenticator
from litestar_auth.authentication.transport import BearerTransport, CookieTransport
from litestar_auth.exceptions import ErrorCode, LitestarAuthError
from litestar_auth.guards import has_all_roles, has_any_role, is_active, is_authenticated, is_superuser, is_verified
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.plugin import (
    DatabaseTokenAuthConfig,
    LitestarAuth,
    LitestarAuthConfig,
    OAuthConfig,
    OAuthProviderConfig,
    TotpConfig,
)
from litestar_auth.types import (
    GuardedUserProtocol,
    RoleCapableUserProtocol,
    TotpUserProtocol,
    UserProtocol,
    UserProtocolStrict,
)

logging.getLogger(__name__).addHandler(logging.NullHandler())  # noqa: RUF067

__version__ = "2.0.0"

__all__ = (
    "AuthenticationBackend",
    "Authenticator",
    "BaseUserManager",
    "BearerTransport",
    "CookieTransport",
    "DatabaseTokenAuthConfig",
    "ErrorCode",
    "GuardedUserProtocol",
    "LitestarAuth",
    "LitestarAuthConfig",
    "LitestarAuthError",
    "OAuthConfig",
    "OAuthProviderConfig",
    "RoleCapableUserProtocol",
    "TotpConfig",
    "TotpUserProtocol",
    "UserManagerSecurity",
    "UserProtocol",
    "UserProtocolStrict",
    "__version__",
    "has_all_roles",
    "has_any_role",
    "is_active",
    "is_authenticated",
    "is_superuser",
    "is_verified",
)
