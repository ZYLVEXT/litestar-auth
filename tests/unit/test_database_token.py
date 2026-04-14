"""Unit tests for ``litestar_auth._plugin.database_token`` (extracted DB-token builders)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest

import litestar_auth._plugin.database_token as database_token_module

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
from litestar_auth._plugin.config import DatabaseTokenAuthConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.db_models import AccessToken
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.plugin import LitestarAuthConfig
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import DummySession, DummySessionMaker, ExampleUser, InMemoryUserDatabase
from tests.unit.test_plugin_config import (
    PluginUserManager,
    _current_database_token_strategy_type,
    _minimal_config,
)

_REQUEST_BACKEND_GUIDANCE = re.escape("LitestarAuthConfig.resolve_request_backends(session)")


def test_public_build_database_token_backend_uses_module_local_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``build_database_token_backend`` routes through this module's ``_build_database_token_backend``."""
    active_session = DummySession()
    real_build = database_token_module._build_database_token_backend
    calls: list[tuple[object, object | None, bool]] = []

    def _spy(
        auth: DatabaseTokenAuthConfig,
        *,
        session: AsyncSession | None = None,
        unsafe_testing: bool = False,
    ) -> AuthenticationBackend[Any, Any]:
        calls.append((auth, session, unsafe_testing))
        return real_build(auth, session=session, unsafe_testing=unsafe_testing)

    monkeypatch.setattr(database_token_module, "_build_database_token_backend", _spy)
    backend = database_token_module.build_database_token_backend(
        DatabaseTokenAuthConfig(token_hash_secret="x" * 40),
        session=cast("AsyncSession", active_session),
        unsafe_testing=True,
    )
    assert len(calls) == 1
    assert cast("Any", calls[0][0]).token_hash_secret == "x" * 40
    assert calls[0][1] is active_session
    assert calls[0][2] is True
    assert backend.name == "database"
    assert cast("Any", backend.strategy).session is active_session


def test_build_database_token_backend_template_and_internal_builder() -> None:
    """Startup template and internal builder materialize expected backend shapes."""
    auth = DatabaseTokenAuthConfig(token_hash_secret="y" * 40, backend_name="dbtok")
    template = database_token_module._build_database_token_backend_template(
        auth,
        unsafe_testing=True,
    )
    assert template.name == "dbtok"

    startup_backend = database_token_module._build_database_token_backend(
        auth,
        unsafe_testing=True,
    )
    assert startup_backend.name == "dbtok"
    DatabaseTokenStrategy = _current_database_token_strategy_type()
    assert isinstance(startup_backend.strategy, DatabaseTokenStrategy)

    bound = database_token_module._build_database_token_backend(
        auth,
        session=cast("Any", DummySession()),
        unsafe_testing=True,
    )
    assert isinstance(cast("Any", bound.strategy), DatabaseTokenStrategy)


def test_resolve_database_token_strategy_session() -> None:
    """Without a session, return a placeholder that fails closed on attribute access."""
    session = database_token_module.resolve_database_token_strategy_session(cast("Any", DummySession()))
    assert session is not None

    placeholder = database_token_module.resolve_database_token_strategy_session()
    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        _ = cast("Any", placeholder).execute


@pytest.mark.asyncio
async def test_startup_only_strategy_runtime_methods_fail_closed() -> None:
    """Startup-only strategies reject token operations until session binding."""
    auth = DatabaseTokenAuthConfig(token_hash_secret="z" * 40, accept_legacy_plaintext_tokens=True)
    strategy = cast(
        "Any",
        database_token_module._build_startup_only_database_token_strategy(
            auth,
            unsafe_testing=True,
        ),
    )
    user_manager = object()
    user = cast("Any", object())

    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        await strategy.read_token("t", user_manager)
    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        await strategy.write_token(user)
    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        await strategy.destroy_token("t", user)
    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        await strategy.write_refresh_token(user)
    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        await strategy.rotate_refresh_token("r", user_manager)
    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        await strategy.invalidate_all_tokens(user)
    with pytest.raises(RuntimeError, match=_REQUEST_BACKEND_GUIDANCE):
        await strategy.cleanup_expired_tokens(cast("Any", DummySession()))


def test_startup_only_strategy_with_session_returns_runtime_strategy() -> None:
    """``with_session`` yields a normal session-bound strategy."""
    auth = DatabaseTokenAuthConfig(token_hash_secret="w" * 40)
    strategy = cast(
        "Any",
        database_token_module._build_startup_only_database_token_strategy(
            auth,
            unsafe_testing=True,
        ),
    )
    session = DummySession()
    bound = strategy.with_session(cast("Any", session))
    assert bound.session is session


def test_lazy_introspection_helpers() -> None:
    """Bundled-model and isinstance helpers match the lazy-import contract."""
    DatabaseTokenStrategy = _current_database_token_strategy_type()
    strategy = DatabaseTokenStrategy(
        session=cast("Any", DummySession()),
        token_hash_secret="q" * 40,
    )
    assert database_token_module._is_database_token_strategy_instance(strategy) is True
    assert database_token_module._is_bundled_token_model(AccessToken, attribute_name="AccessToken") is True

    backend = AuthenticationBackend[ExampleUser, UUID](
        name="database",
        transport=BearerTransport(),
        strategy=strategy,
    )
    assert database_token_module._backend_uses_bundled_database_token_models(backend) is True

    config = _minimal_config()
    assert database_token_module._uses_bundled_database_token_models(config) is False

    session_maker = assert_structural_session_factory(DummySessionMaker())
    preset = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(token_hash_secret="a" * 40),
        session_maker=cast("Any", session_maker),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )
    assert database_token_module._uses_bundled_database_token_models(preset) is True


def test_raise_startup_only_database_token_runtime_error() -> None:
    """Fail-closed guidance names canonical startup vs request backend APIs."""
    with pytest.raises(RuntimeError) as excinfo:
        database_token_module._raise_startup_only_database_token_runtime_error()
    msg = str(excinfo.value)
    assert "LitestarAuthConfig.resolve_startup_backends()" in msg
    assert "LitestarAuthConfig.resolve_request_backends(session)" in msg
