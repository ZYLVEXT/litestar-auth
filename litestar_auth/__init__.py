"""Litestar authentication and authorization helpers for ASGI apps.

This package re-exports controllers, strategies, transports, the ``LitestarAuth``
plugin, user manager base types, guards, and shared schemas. Import stable symbols
from ``litestar_auth`` for compatibility, but prefer the more specific public
submodules when guidance names one canonical entrypoint. For OAuth,
plugin-managed apps typically configure ``OAuthConfig`` on ``LitestarAuthConfig``;
``litestar_auth.oauth.create_provider_oauth_controller`` plus
``litestar_auth.controllers.create_oauth_controller`` /
``create_oauth_associate_controller`` remain the advanced escape hatch for
custom route tables.

Examples:
    Wire the canonical database-backed bearer preset when building a Litestar application::

        from uuid import UUID

        from litestar import Litestar
        from litestar_auth import DatabaseTokenAuthConfig, LitestarAuth, LitestarAuthConfig
        from litestar_auth.manager import UserManagerSecurity
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
from litestar_auth.authentication.strategy import (
    DatabaseTokenStrategy,
    JWTStrategy,
    RedisTokenStrategy,
    Strategy,
)
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.strategy.jwt import (
    InMemoryJWTDenylistStore,
    JWTDenylistStore,
    RedisJWTDenylistStore,
)
from litestar_auth.authentication.transport import BearerTransport, CookieTransport, Transport
from litestar_auth.controllers import (
    TotpUserManagerProtocol,
    create_auth_controller,
    create_oauth_associate_controller,
    create_oauth_controller,
    create_register_controller,
    create_reset_password_controller,
    create_totp_controller,
    create_users_controller,
    create_verify_controller,
)
from litestar_auth.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ErrorCode,
    InactiveUserError,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    LitestarAuthError,
    OAuthAccountAlreadyLinkedError,
    TokenError,
    UnverifiedUserError,
    UserAlreadyExistsError,
    UserNotExistsError,
)
from litestar_auth.guards import has_all_roles, has_any_role, is_active, is_authenticated, is_superuser, is_verified
from litestar_auth.manager import BaseUserManager, require_password_length
from litestar_auth.oauth import create_provider_oauth_controller, load_httpx_oauth_client
from litestar_auth.password import PasswordHelper
from litestar_auth.payloads import (
    ForgotPassword,
    LoginCredentials,
    RefreshTokenRequest,
    RequestVerifyToken,
    ResetPassword,
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableResponse,
    TotpVerifyRequest,
    UserCreate,
    UserRead,
    UserUpdate,
    VerifyToken,
)
from litestar_auth.plugin import (
    DatabaseTokenAuthConfig,
    LitestarAuth,
    LitestarAuthConfig,
    OAuthConfig,
    OAuthProviderConfig,
    TotpConfig,
)
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    EndpointRateLimit,
    InMemoryRateLimiter,
    RedisRateLimiter,
)
from litestar_auth.totp import (
    InMemoryUsedTotpCodeStore,
    RedisUsedTotpCodeStore,
    generate_totp_secret,
    generate_totp_uri,
    verify_totp,
    verify_totp_with_store,
)
from litestar_auth.types import GuardedUserProtocol, RoleCapableUserProtocol, TotpUserProtocol, UserProtocol

logging.getLogger(__name__).addHandler(logging.NullHandler())  # noqa: RUF067

__version__ = "1.7.0"

__all__ = (
    "AccessToken",
    "AuthRateLimitConfig",
    "AuthenticationBackend",
    "AuthenticationError",
    "Authenticator",
    "AuthorizationError",
    "BaseUserManager",
    "BearerTransport",
    "ConfigurationError",
    "CookieTransport",
    "DatabaseTokenAuthConfig",
    "DatabaseTokenStrategy",
    "EndpointRateLimit",
    "ErrorCode",
    "ForgotPassword",
    "GuardedUserProtocol",
    "InMemoryJWTDenylistStore",
    "InMemoryRateLimiter",
    "InMemoryUsedTotpCodeStore",
    "InactiveUserError",
    "InvalidPasswordError",
    "InvalidResetPasswordTokenError",
    "InvalidVerifyTokenError",
    "JWTDenylistStore",
    "JWTStrategy",
    "LitestarAuth",
    "LitestarAuthConfig",
    "LitestarAuthError",
    "LoginCredentials",
    "OAuthAccountAlreadyLinkedError",
    "OAuthConfig",
    "OAuthProviderConfig",
    "PasswordHelper",
    "RedisJWTDenylistStore",
    "RedisRateLimiter",
    "RedisTokenStrategy",
    "RedisUsedTotpCodeStore",
    "RefreshToken",
    "RefreshTokenRequest",
    "RequestVerifyToken",
    "ResetPassword",
    "RoleCapableUserProtocol",
    "Strategy",
    "TokenError",
    "TotpConfig",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableResponse",
    "TotpUserManagerProtocol",
    "TotpUserProtocol",
    "TotpVerifyRequest",
    "Transport",
    "UnverifiedUserError",
    "UserAlreadyExistsError",
    "UserCreate",
    "UserNotExistsError",
    "UserProtocol",
    "UserRead",
    "UserUpdate",
    "VerifyToken",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_provider_oauth_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
    "generate_totp_secret",
    "generate_totp_uri",
    "has_all_roles",
    "has_any_role",
    "is_active",
    "is_authenticated",
    "is_superuser",
    "is_verified",
    "load_httpx_oauth_client",
    "require_password_length",
    "verify_totp",
    "verify_totp_with_store",
)
