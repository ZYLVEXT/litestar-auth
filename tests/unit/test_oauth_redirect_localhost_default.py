"""Unit tests for OAuth redirect-base-url validation in the plugin."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

import pytest
from litestar.config.app import AppConfig

from litestar_auth._plugin.config import OAuthConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit


def _minimal_config() -> LitestarAuthConfig[ExampleUser, UUID]:
    user_db = InMemoryUserDatabase([])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="oauth-redirect")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={},
    )


def test_oauth_redirect_localhost_fails_closed_in_production() -> None:
    """Production startup rejects plugin-owned localhost OAuth redirect origins."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        oauth_redirect_base_url="http://localhost/auth",
    )
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match="public HTTPS origin"):
        plugin.on_app_init(AppConfig(debug=False))


def test_oauth_redirect_localhost_is_allowed_in_debug() -> None:
    """Debug mode preserves explicit localhost plugin OAuth recipes."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        oauth_redirect_base_url="http://localhost/auth",
    )
    plugin = LitestarAuth(config)

    result = plugin.on_app_init(AppConfig(debug=True))

    assert result is not None
