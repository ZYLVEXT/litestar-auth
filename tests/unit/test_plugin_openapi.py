"""Tests for OpenAPI security scheme derivation and registration."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from litestar.config.app import AppConfig
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.spec import Components, SecurityScheme

from litestar_auth._plugin.config import StartupBackendTemplate
from litestar_auth._plugin.openapi import (
    build_openapi_security_schemes,
    build_security_requirement,
    register_openapi_security,
    security_scheme_for_transport,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport

_EXPECTED_PAIR = 2


def _bearer_backend(name: str = "jwt") -> StartupBackendTemplate[Any, Any]:
    strategy = JWTStrategy(secret="s" * 32, algorithm="HS256")
    backend = AuthenticationBackend(name=name, transport=BearerTransport(), strategy=strategy)  # ty:ignore[invalid-argument-type]
    return StartupBackendTemplate.from_runtime_backend(backend)


def _cookie_backend(name: str = "cookie", cookie_name: str = "auth_token") -> StartupBackendTemplate[Any, Any]:
    strategy = MagicMock()
    backend = AuthenticationBackend(
        name=name,
        transport=CookieTransport(cookie_name=cookie_name),
        strategy=strategy,
    )
    return StartupBackendTemplate.from_runtime_backend(backend)


def _bearer_non_jwt_backend(name: str = "token") -> StartupBackendTemplate[Any, Any]:
    strategy = MagicMock()
    backend = AuthenticationBackend(name=name, transport=BearerTransport(), strategy=strategy)
    return StartupBackendTemplate.from_runtime_backend(backend)


class TestSecuritySchemeForTransport:
    """Test deriving SecurityScheme from transport types."""

    def test_bearer_transport_with_jwt_strategy(self) -> None:
        """Bearer transport with JWT strategy sets bearer_format to JWT."""
        transport = BearerTransport()
        strategy = JWTStrategy(secret="s" * 32, algorithm="HS256")
        scheme = security_scheme_for_transport(transport, strategy=strategy)  # ty:ignore[invalid-argument-type]

        assert scheme.type == "http"
        assert scheme.scheme == "Bearer"
        assert scheme.bearer_format == "JWT"

    def test_bearer_transport_without_jwt_strategy(self) -> None:
        """Bearer transport with non-JWT strategy omits bearer_format."""
        transport = BearerTransport()
        scheme = security_scheme_for_transport(transport, strategy=MagicMock())

        assert scheme.type == "http"
        assert scheme.scheme == "Bearer"
        assert scheme.bearer_format is None

    def test_bearer_transport_without_strategy(self) -> None:
        """Bearer transport without strategy omits bearer_format."""
        transport = BearerTransport()
        scheme = security_scheme_for_transport(transport)

        assert scheme.type == "http"
        assert scheme.scheme == "Bearer"
        assert scheme.bearer_format is None

    def test_cookie_transport(self) -> None:
        """Cookie transport produces apiKey scheme in cookie."""
        transport = CookieTransport(cookie_name="my_auth")
        scheme = security_scheme_for_transport(transport)

        assert scheme.type == "apiKey"
        assert scheme.name == "my_auth"
        assert scheme.security_scheme_in == "cookie"

    def test_unsupported_transport_raises(self) -> None:
        """Unknown transport type raises TypeError."""
        transport = MagicMock()
        transport.__class__.__name__ = "CustomTransport"

        with pytest.raises(TypeError, match="Unsupported transport type"):
            security_scheme_for_transport(transport)


class TestBuildOpenApiSecuritySchemes:
    """Test building scheme dicts from backend inventories."""

    def test_single_bearer_backend(self) -> None:
        """Single bearer backend produces one http/Bearer scheme."""
        backends = (_bearer_backend("jwt"),)
        schemes = build_openapi_security_schemes(backends)

        assert "jwt" in schemes
        assert schemes["jwt"].type == "http"
        assert schemes["jwt"].scheme == "Bearer"
        assert schemes["jwt"].bearer_format == "JWT"

    def test_single_cookie_backend(self) -> None:
        """Single cookie backend produces one apiKey scheme."""
        backends = (_cookie_backend("session", "sess_token"),)
        schemes = build_openapi_security_schemes(backends)

        assert "session" in schemes
        assert schemes["session"].type == "apiKey"
        assert schemes["session"].name == "sess_token"

    def test_multiple_backends(self) -> None:
        """Multiple backends produce one scheme per backend."""
        backends = (_bearer_backend("jwt"), _cookie_backend("cookie"))
        schemes = build_openapi_security_schemes(backends)

        assert len(schemes) == _EXPECTED_PAIR
        assert "jwt" in schemes
        assert "cookie" in schemes

    def test_empty_backends(self) -> None:
        """Empty backends produce an empty dict."""
        schemes = build_openapi_security_schemes(())
        assert schemes == {}


class TestBuildSecurityRequirement:
    """Test building the OpenAPI security requirement."""

    def test_single_scheme(self) -> None:
        """Single scheme produces one requirement entry."""
        schemes = {"jwt": SecurityScheme(type="http", scheme="Bearer")}
        requirement = build_security_requirement(schemes)

        assert requirement == [{"jwt": []}]

    def test_multiple_schemes_or_semantics(self) -> None:
        """Multiple schemes are emitted as alternative requirement entries."""
        schemes = {
            "jwt": SecurityScheme(type="http", scheme="Bearer"),
            "cookie": SecurityScheme(type="apiKey", name="auth", security_scheme_in="cookie"),
        }
        requirement = build_security_requirement(schemes)

        assert requirement == [{"jwt": []}, {"cookie": []}]

    def test_empty_schemes(self) -> None:
        """Empty schemes produce an empty list."""
        assert build_security_requirement({}) == []


class TestRegisterOpenApiSecurity:
    """Test OpenAPI security registration into AppConfig."""

    def test_registers_components(self) -> None:
        """Schemes are registered as Components in the openapi config."""
        app_config = AppConfig()
        app_config.openapi_config = OpenAPIConfig(title="Test", version="1.0.0")
        backends = (_bearer_backend("jwt"),)

        schemes = register_openapi_security(app_config, backends)

        assert "jwt" in schemes
        components_list = app_config.openapi_config.components
        assert isinstance(components_list, list)
        assert any(
            isinstance(c, Components) and c.security_schemes and "jwt" in c.security_schemes for c in components_list
        )

    def test_no_openapi_config_is_noop(self) -> None:
        """When openapi_config is None, schemes are returned but config is untouched."""
        app_config = AppConfig()
        app_config.openapi_config = None
        backends = (_bearer_backend("jwt"),)

        schemes = register_openapi_security(app_config, backends)

        assert "jwt" in schemes
        assert app_config.openapi_config is None

    def test_no_backends_returns_empty(self) -> None:
        """No backends produce an empty scheme dict."""
        app_config = AppConfig()
        app_config.openapi_config = OpenAPIConfig(title="Test", version="1.0.0")

        schemes = register_openapi_security(app_config, ())

        assert schemes == {}

    def test_does_not_set_global_security(self) -> None:
        """Registration does not add a global security requirement."""
        app_config = AppConfig()
        app_config.openapi_config = OpenAPIConfig(title="Test", version="1.0.0")
        backends = (_bearer_backend("jwt"),)

        register_openapi_security(app_config, backends)

        assert app_config.openapi_config.security is None or app_config.openapi_config.security == []

    def test_preserves_existing_components(self) -> None:
        """Existing scalar components are wrapped into a list alongside the new one."""
        existing = Components(schemas={"User": cast("Any", {"type": "object"})})
        app_config = AppConfig()
        app_config.openapi_config = OpenAPIConfig(title="Test", version="1.0.0", components=existing)
        backends = (_bearer_backend("jwt"),)

        register_openapi_security(app_config, backends)

        components_list = app_config.openapi_config.components
        assert isinstance(components_list, list)
        assert len(components_list) == _EXPECTED_PAIR

    def test_appends_to_existing_components_list(self) -> None:
        """When components is already a list, the new entry is appended."""
        existing = [Components(schemas={"User": cast("Any", {"type": "object"})})]
        app_config = AppConfig()
        app_config.openapi_config = OpenAPIConfig(title="Test", version="1.0.0", components=existing)
        backends = (_bearer_backend("jwt"),)

        register_openapi_security(app_config, backends)

        components_list = app_config.openapi_config.components
        assert isinstance(components_list, list)
        assert len(components_list) == _EXPECTED_PAIR
        assert any(
            isinstance(c, Components) and c.security_schemes and "jwt" in c.security_schemes for c in components_list
        )
