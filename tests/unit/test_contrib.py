"""Tests for contrib package re-exports."""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy as BaseRedisTokenStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.contrib.oauth import __all__ as oauth_all
from litestar_auth.contrib.oauth import create_provider_oauth_controller
from litestar_auth.contrib.redis import RedisTokenStrategy
from litestar_auth.contrib.redis import __all__ as redis_all
from litestar_auth.controllers.oauth import OAuthControllerUserManagerProtocol
from litestar_auth.oauth.router import create_provider_oauth_controller as base_create_provider_oauth_controller
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit
REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"


class ExampleStrategy:
    """Minimal strategy implementation for backend construction."""

    async def read_token(self, token: str | None, user_manager: object) -> ExampleUser | None:
        """Return no user because this test never authenticates."""
        del token, user_manager
        return None

    async def write_token(self, user: ExampleUser) -> str:
        """Return a deterministic token string."""
        return str(user.id)

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """No-op token invalidation for tests."""
        del token, user


class ExampleUserManager(OAuthControllerUserManagerProtocol[ExampleUser, str]):
    """Minimal typed user manager for lazy-import tests."""

    user_db: object = object()

    async def create(
        self,
        user_create: object,
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> ExampleUser:
        """Return a placeholder user because this path is never reached."""
        del user_create, safe, allow_privileged
        return ExampleUser(id=uuid4())

    async def update(self, user_update: object, user: ExampleUser) -> ExampleUser:
        """Return the provided user because this path is never reached."""
        del user_update
        return user

    async def on_after_login(self, user: ExampleUser) -> None:
        """No-op login hook for protocol conformance."""
        del user


def test_contrib_packages_reexport_public_symbols() -> None:
    """Contrib packages expose the documented convenience imports."""
    assert RedisTokenStrategy is BaseRedisTokenStrategy
    assert create_provider_oauth_controller is base_create_provider_oauth_controller


def test_contrib_packages_define_all() -> None:
    """Contrib packages publish only their intended public symbols."""
    assert redis_all == ("RedisTokenStrategy", "RedisUsedTotpCodeStore")
    assert oauth_all == ("create_provider_oauth_controller",)


def test_contrib_redis_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib Redis alias preserves the strategy's optional dependency guard."""

    def fail_import(name: str) -> None:
        raise ImportError(name)

    monkeypatch.setattr("litestar_auth.authentication.strategy.redis.importlib.import_module", fail_import)

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisTokenStrategy"):
        RedisTokenStrategy(redis=AsyncMock(), token_hash_secret=REDIS_TOKEN_HASH_SECRET)


def test_contrib_oauth_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib OAuth alias preserves the router's optional dependency guard."""

    def fail_import(module_name: str) -> None:
        message = f"No module named {module_name!r}"
        raise ModuleNotFoundError(
            message,
            name="httpx_oauth.clients.github",
        )

    monkeypatch.setattr("litestar_auth.oauth.router.import_module", fail_import)
    backend = AuthenticationBackend[ExampleUser, str](
        name="oauth",
        transport=BearerTransport(),
        strategy=ExampleStrategy(),
    )
    user_manager = ExampleUserManager()

    with pytest.raises(ImportError, match=r"Install litestar-auth\[oauth\] to use OAuth controllers\."):
        create_provider_oauth_controller(
            provider_name="github",
            backend=backend,
            user_manager=user_manager,
            oauth_client_class="httpx_oauth.clients.github.GitHubOAuth2",
            redirect_base_url="http://testserver.local/auth/oauth",
        )
