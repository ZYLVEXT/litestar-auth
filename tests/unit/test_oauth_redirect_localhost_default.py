"""Unit tests for OAuth redirect-base-url validation in the plugin."""

from __future__ import annotations

import logging
from typing import Any, cast
from uuid import UUID

import pytest
from litestar.config.app import AppConfig

from litestar_auth._plugin.config import OAuthConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
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


def test_oauth_redirect_localhost_warns_in_production(caplog: pytest.LogCaptureFixture) -> None:
    """Warn when localhost redirect base URL is used with debug=False."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        include_oauth_associate=True,
        oauth_associate_providers=[("example", object())],
        oauth_token_encryption_key="a" * 44,
        oauth_associate_redirect_base_url="",
    )
    plugin = LitestarAuth(config)

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        plugin.on_app_init(AppConfig(debug=False))

    assert "localhost" in caplog.text
    assert "oauth_associate_redirect_base_url" in caplog.text


def test_oauth_redirect_localhost_does_not_warn_in_debug(caplog: pytest.LogCaptureFixture) -> None:
    """Do not warn when running in debug mode."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        include_oauth_associate=True,
        oauth_associate_providers=[("example", object())],
        oauth_token_encryption_key="a" * 44,
        oauth_associate_redirect_base_url="",
    )
    plugin = LitestarAuth(config)

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        plugin.on_app_init(AppConfig(debug=True))

    assert not caplog.text
