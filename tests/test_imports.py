"""Integration coverage for the root package public API."""

from __future__ import annotations

import logging

import pytest

import litestar_auth
import litestar_auth._plugin as plugin_internals
import litestar_auth.plugin as plugin_module
from litestar_auth import (
    AccessToken,
    AuthenticationBackend,
    AuthenticationError,
    Authenticator,
    AuthorizationError,
    AuthRateLimitConfig,
    BaseUserManager,
    BearerTransport,
    ConfigurationError,
    CookieTransport,
    DatabaseTokenStrategy,
    EndpointRateLimit,
    ErrorCode,
    ForgotPassword,
    GuardedUserProtocol,
    InMemoryJWTDenylistStore,
    InMemoryRateLimiter,
    InMemoryUsedTotpCodeStore,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    JWTDenylistStore,
    JWTStrategy,
    LitestarAuthConfig,
    LitestarAuthError,
    LoginCredentials,
    OAuthAccount,
    OAuthAccountAlreadyLinkedError,
    PasswordHelper,
    RedisJWTDenylistStore,
    RedisRateLimiter,
    RedisTokenStrategy,
    RedisUsedTotpCodeStore,
    RefreshToken,
    RefreshTokenRequest,
    RequestVerifyToken,
    ResetPassword,
    SQLAlchemyUserDatabase,
    Strategy,
    TokenError,
    TotpDisableRequest,
    TotpEnableResponse,
    TotpUserManagerProtocol,
    TotpUserProtocol,
    TotpVerifyRequest,
    Transport,
    User,
    UserAlreadyExistsError,
    UserCreate,
    UserNotExistsError,
    UserProtocol,
    UserRead,
    UserUpdate,
    VerifyToken,
    __all__,
    __version__,
    create_auth_controller,
    create_oauth_associate_controller,
    create_oauth_controller,
    create_provider_oauth_controller,
    create_register_controller,
    create_reset_password_controller,
    create_totp_controller,
    create_users_controller,
    create_verify_controller,
    generate_totp_secret,
    generate_totp_uri,
    is_active,
    is_authenticated,
    is_superuser,
    is_verified,
    load_httpx_oauth_client,
    require_password_length,
    verify_totp,
    verify_totp_with_store,
)
from litestar_auth.db import BaseUserStore

pytestmark = [pytest.mark.unit, pytest.mark.imports]


def test_root_package_reexports_public_api() -> None:
    """The package root exposes the documented public auth API."""
    assert __version__ == "0.0.0"
    assert LitestarAuthConfig is not None
    assert User is not None
    assert OAuthAccount is not None
    assert AccessToken is not None
    assert RefreshToken is not None
    assert PasswordHelper is not None
    assert AuthenticationBackend is not None
    assert Authenticator is not None
    assert Transport is not None
    assert Strategy is not None
    assert UserProtocol is not None
    assert GuardedUserProtocol is not None
    assert TotpUserProtocol is not None
    assert BearerTransport is not None
    assert CookieTransport is not None
    assert JWTStrategy is not None
    assert DatabaseTokenStrategy is not None
    assert RedisTokenStrategy is not None
    assert InMemoryRateLimiter is not None
    assert RedisRateLimiter is not None
    assert EndpointRateLimit is not None
    assert AuthRateLimitConfig is not None
    assert InMemoryJWTDenylistStore is not None
    assert InMemoryUsedTotpCodeStore is not None
    assert JWTDenylistStore is not None
    assert RedisJWTDenylistStore is not None
    assert RedisUsedTotpCodeStore is not None
    assert callable(generate_totp_secret)
    assert callable(generate_totp_uri)
    assert callable(verify_totp)
    assert callable(verify_totp_with_store)
    assert BaseUserStore is not None
    assert SQLAlchemyUserDatabase is not None
    assert BaseUserManager is not None
    assert UserRead.__struct_fields__ == ("id", "email", "is_active", "is_verified", "is_superuser")
    assert UserCreate.__struct_fields__ == ("email", "password")
    assert UserUpdate.__struct_fields__ == ("password", "email", "is_active", "is_verified", "is_superuser")
    assert callable(is_authenticated)
    assert callable(is_active)
    assert callable(is_verified)
    assert callable(is_superuser)
    assert callable(create_provider_oauth_controller)
    assert callable(create_oauth_associate_controller)
    assert callable(load_httpx_oauth_client)
    assert callable(require_password_length)
    assert ErrorCode is not None


def test_root_package_reexports_controller_factories_and_payloads() -> None:
    """The package root exposes controller factories and their public payload structs."""
    assert LoginCredentials.__struct_fields__ == ("identifier", "password")
    assert RefreshTokenRequest.__struct_fields__ == ("refresh_token",)
    assert ForgotPassword.__struct_fields__ == ("email",)
    assert ResetPassword.__struct_fields__ == ("token", "password")
    assert VerifyToken.__struct_fields__ == ("token",)
    assert RequestVerifyToken.__struct_fields__ == ("email",)
    assert TotpEnableResponse.__struct_fields__ == ("secret", "uri", "enrollment_token")
    assert TotpVerifyRequest.__struct_fields__ == ("pending_token", "code")
    assert TotpDisableRequest.__struct_fields__ == ("code",)
    assert TotpUserManagerProtocol is not None
    assert callable(create_auth_controller)
    assert callable(create_register_controller)
    assert callable(create_verify_controller)
    assert callable(create_reset_password_controller)
    assert callable(create_users_controller)
    assert callable(create_totp_controller)
    assert callable(create_oauth_controller)


def test_root_package_reexports_exception_hierarchy() -> None:
    """The package root exposes all public exception types."""
    assert issubclass(AuthenticationError, LitestarAuthError)
    assert issubclass(AuthorizationError, LitestarAuthError)
    assert issubclass(ConfigurationError, LitestarAuthError)
    assert issubclass(OAuthAccountAlreadyLinkedError, AuthenticationError)
    assert issubclass(OAuthAccountAlreadyLinkedError, LitestarAuthError)
    assert issubclass(TokenError, LitestarAuthError)
    assert issubclass(UserAlreadyExistsError, AuthenticationError)
    assert issubclass(UserNotExistsError, AuthenticationError)
    assert issubclass(InvalidPasswordError, AuthenticationError)
    assert issubclass(InvalidVerifyTokenError, TokenError)
    assert issubclass(InvalidResetPasswordTokenError, TokenError)


def test_root_package_all_excludes_private_symbols() -> None:
    """`__all__` lists only public names."""
    assert all(not symbol.startswith("_") for symbol in __all__)
    assert len(__all__) == len(set(__all__))
    assert "_UserManagerProxy" not in __all__
    assert "AuthRateLimitConfig" in __all__
    assert "EndpointRateLimit" in __all__
    assert "ErrorCode" in __all__
    assert "InMemoryRateLimiter" in __all__
    assert "RedisRateLimiter" in __all__
    assert "generate_totp_secret" in __all__
    assert "generate_totp_uri" in __all__
    assert "verify_totp" in __all__
    assert "verify_totp_with_store" in __all__
    assert "InMemoryJWTDenylistStore" in __all__
    assert "InMemoryUsedTotpCodeStore" in __all__
    assert "JWTDenylistStore" in __all__
    assert "RedisJWTDenylistStore" in __all__
    assert "RedisUsedTotpCodeStore" in __all__
    assert "UserProtocol" in __all__
    assert "GuardedUserProtocol" in __all__
    assert "TotpUserProtocol" in __all__
    assert "TotpUserManagerProtocol" in __all__
    assert "Authenticator" in __all__
    assert "RefreshToken" in __all__
    assert "LoginCredentials" in __all__
    assert "RefreshTokenRequest" in __all__
    assert "ForgotPassword" in __all__
    assert "ResetPassword" in __all__
    assert "VerifyToken" in __all__
    assert "RequestVerifyToken" in __all__
    assert "TotpEnableResponse" in __all__
    assert "TotpVerifyRequest" in __all__
    assert "TotpDisableRequest" in __all__
    assert "create_auth_controller" in __all__
    assert "create_oauth_associate_controller" in __all__
    assert "create_register_controller" in __all__
    assert "create_verify_controller" in __all__
    assert "create_reset_password_controller" in __all__
    assert "create_users_controller" in __all__
    assert "create_totp_controller" in __all__
    assert "create_oauth_controller" in __all__
    assert "OAuthAccountAlreadyLinkedError" in __all__
    assert "require_password_length" in __all__


def test_root_package_all_entries_resolve_to_attributes() -> None:
    """Each declared public export resolves from the package root."""
    for symbol in __all__:
        assert hasattr(litestar_auth, symbol)
        assert getattr(litestar_auth, symbol) is not None


def test_root_package_does_not_export_compat_aliases() -> None:
    """Backward-compat root aliases were removed; import from ``litestar_auth.plugin`` or ``litestar_auth.db``."""
    assert "AuthPlugin" not in __all__
    assert "BaseUserDatabase" not in __all__
    assert not hasattr(litestar_auth, "AuthPlugin")
    assert not hasattr(litestar_auth, "BaseUserDatabase")


def test_plugin_module_public_exports_no_compat_shims() -> None:
    """Plugin module exposes ``LitestarAuth``, ``LitestarAuthConfig``, config dataclasses; legacy shims removed."""
    assert plugin_module.__all__ == ("LitestarAuth", "LitestarAuthConfig", "OAuthConfig", "TotpConfig")
    assert plugin_module.LitestarAuthConfig is plugin_internals.LitestarAuthConfig
    assert "AuthPlugin" not in plugin_module.__all__
    assert not hasattr(plugin_module, "AuthPlugin")
    for name in (
        "DEFAULT_CONFIG_DEPENDENCY_KEY",
        "DEFAULT_USER_MANAGER_DEPENDENCY_KEY",
        "DEFAULT_BACKENDS_DEPENDENCY_KEY",
        "DEFAULT_USER_MODEL_DEPENDENCY_KEY",
        "DEFAULT_CSRF_COOKIE_NAME",
        "OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY",
        "_ScopedUserDatabaseProxy",
    ):
        assert not hasattr(plugin_module, name)


def test_root_package_installs_null_handler() -> None:
    """The package root configures a NullHandler for library-safe logging."""
    assert any(
        isinstance(handler, logging.NullHandler) for handler in logging.getLogger(litestar_auth.__name__).handlers
    )
