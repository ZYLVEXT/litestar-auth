"""Reload-based coverage tests for re-export ``__init__`` modules."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, get_args

import pytest

import litestar_auth as litestar_auth_module
import litestar_auth._plugin as plugin_module
import litestar_auth.authentication as authentication_module
import litestar_auth.authentication.strategy as strategy_module
import litestar_auth.authentication.transport as transport_module
import litestar_auth.controllers as controllers_module
import litestar_auth.db as db_module
import litestar_auth.guards as guards_module
import litestar_auth.models as models_module
import litestar_auth.ratelimit as ratelimit_module
import litestar_auth.ratelimit._endpoint as ratelimit_endpoint_module
import litestar_auth.ratelimit._slot_catalog as ratelimit_slot_catalog_module
from litestar_auth.authentication.strategy.db_models import AccessToken, DatabaseTokenModels, RefreshToken
from litestar_auth.ratelimit import AuthRateLimitEndpointGroup, AuthRateLimitSlot
from tests.conftest import project_version_from_pyproject

pytestmark = [pytest.mark.unit, pytest.mark.imports]

if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import ModuleType


class _CapturingLogger:
    """Collect handlers added during reload."""

    def __init__(self) -> None:
        self.handlers: list[logging.Handler] = []

    def addHandler(self, handler: logging.Handler) -> None:
        """Record the attached handler."""
        self.handlers.append(handler)


def _assert_exported_symbols(module: ModuleType, *, expected_names: Iterable[str] | None = None) -> None:
    """Assert that the module exposes the expected public names."""
    export_names = tuple(expected_names or getattr(module, "__all__", ()))

    assert export_names

    for name in export_names:
        assert hasattr(module, name)


@pytest.mark.parametrize(
    ("module", "expected_names"),
    [
        pytest.param(
            plugin_module,
            (
                "DEFAULT_BACKENDS_DEPENDENCY_KEY",
                "LitestarAuthConfig",
            ),
            id="_plugin",
        ),
        pytest.param(
            authentication_module,
            ("AuthenticationBackend", "Authenticator", "LitestarAuthMiddleware"),
            id="authentication",
        ),
        pytest.param(
            strategy_module,
            (
                "DatabaseTokenModels",
                "DatabaseTokenStrategy",
                "DatabaseTokenStrategyConfig",
                "JWTStrategy",
                "JWTStrategyConfig",
                "RedisTokenStrategy",
                "RedisTokenStrategyConfig",
                "RefreshableStrategy",
                "Strategy",
                "UserManagerProtocol",
            ),
            id="authentication.strategy",
        ),
        pytest.param(
            transport_module,
            ("BearerTransport", "CookieTransport", "CookieTransportConfig", "Transport"),
            id="authentication.transport",
        ),
        pytest.param(
            controllers_module,
            (
                "AuthControllerConfig",
                "OAuthAssociateControllerConfig",
                "OAuthControllerConfig",
                "RegisterControllerConfig",
                "UsersControllerConfig",
                "create_auth_controller",
                "create_totp_controller",
                "create_users_controller",
            ),
            id="controllers",
        ),
        pytest.param(
            db_module,
            ("BaseOAuthAccountStore", "BaseUserStore", "OAuthAccountData"),
            id="db",
        ),
        pytest.param(
            guards_module,
            ("is_active", "is_authenticated", "is_superuser", "is_verified"),
            id="guards",
        ),
    ],
)
def test_reexport_module_exposes_documented_public_surface(
    module: ModuleType,
    expected_names: tuple[str, ...],
) -> None:
    """Re-export modules continue to expose their documented public names."""
    _assert_exported_symbols(module, expected_names=expected_names)


def test_root_package_exposes_documented_public_surface_and_null_logger() -> None:
    """Root package exposes the documented public symbols and configures a null logger."""
    assert litestar_auth_module.__version__ == project_version_from_pyproject()
    _assert_exported_symbols(
        litestar_auth_module,
        expected_names=(
            "AuthenticationBackend",
            "Authenticator",
            "BaseUserManager",
            "BaseUserManagerConfig",
            "BearerTransport",
            "CookieTransport",
            "CookieTransportConfig",
            "DatabaseTokenAuthConfig",
            "DEFAULT_SUPERUSER_ROLE_NAME",
            "ErrorCode",
            "FernetKeyringConfig",
            "LitestarAuth",
            "LitestarAuthConfig",
            "LitestarAuthError",
            "OAuthConfig",
            "OAuthProviderConfig",
            "TotpConfig",
            "UserManagerSecurity",
            "is_authenticated",
        ),
    )
    null_handlers = [
        handler
        for handler in logging.getLogger(litestar_auth_module.__name__).handlers
        if isinstance(handler, logging.NullHandler)
    ]
    assert null_handlers


def test_models_package_owns_token_registration_helper_and_strategy_keeps_db_token_contract() -> None:
    """The models package owns the token bootstrap helper while strategy keeps its runtime contract."""
    assert models_module.__all__ == (
        "AccessTokenMixin",
        "OAuthAccount",
        "OAuthAccountMixin",
        "RefreshTokenMixin",
        "Role",
        "RoleMixin",
        "User",
        "UserAuthRelationshipMixin",
        "UserModelMixin",
        "UserRole",
        "UserRoleAssociationMixin",
        "UserRoleRelationshipMixin",
        "import_token_orm_models",
    )
    assert strategy_module.__all__ == (
        "DatabaseTokenModels",
        "DatabaseTokenStrategy",
        "DatabaseTokenStrategyConfig",
        "JWTStrategy",
        "JWTStrategyConfig",
        "RedisTokenStrategy",
        "RedisTokenStrategyConfig",
        "RefreshableStrategy",
        "Strategy",
        "UserManagerProtocol",
    )
    assert models_module.import_token_orm_models.__module__ == "litestar_auth.models.tokens"
    assert not hasattr(litestar_auth_module, "import_token_orm_models")
    assert not hasattr(strategy_module, "import_token_orm_models")
    assert strategy_module.DatabaseTokenModels is DatabaseTokenModels
    assert models_module.import_token_orm_models() == (AccessToken, RefreshToken)


def test_ratelimit_reexport_module_keeps_private_helpers_internal() -> None:
    """The public ratelimit module keeps helper internals off the package surface."""
    _assert_exported_symbols(
        ratelimit_module,
        expected_names=(
            "AuthRateLimitConfig",
            "AuthRateLimitEndpointGroup",
            "AuthRateLimitSlot",
            "EndpointRateLimit",
            "InMemoryRateLimiter",
            "RateLimitScope",
            "RedisRateLimiter",
            "TotpRateLimitOrchestrator",
            "TotpSensitiveEndpoint",
        ),
    )
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES")
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT")
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_SLOTS")
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_GROUPS")
    assert ratelimit_endpoint_module.EndpointRateLimit is ratelimit_module.EndpointRateLimit
    assert ratelimit_endpoint_module.RateLimitScope is ratelimit_module.RateLimitScope
    assert get_args(ratelimit_module.AuthRateLimitEndpointGroup.__value__) == get_args(
        AuthRateLimitEndpointGroup.__value__,
    )
    assert tuple(ratelimit_module.AuthRateLimitSlot) == tuple(AuthRateLimitSlot)
    assert not hasattr(ratelimit_module, "AuthRateLimitEndpointSlot")
    assert not hasattr(ratelimit_module, "_DEFAULT_TRUSTED_HEADERS")
    assert not hasattr(ratelimit_module, "_client_host")
    assert not hasattr(ratelimit_module, "_extract_email")
    assert not hasattr(ratelimit_module, "_load_redis_asyncio")
    assert not hasattr(ratelimit_module, "_safe_key_part")
    assert not hasattr(ratelimit_module, "_validate_configuration")
    assert not hasattr(ratelimit_module, "importlib")
    assert not hasattr(ratelimit_module, "logger")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_SLOTS")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_GROUPS")
