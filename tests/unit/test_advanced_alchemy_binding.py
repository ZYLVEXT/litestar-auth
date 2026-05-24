"""Unit tests for Advanced Alchemy session binding helpers."""

from __future__ import annotations

import pytest
from advanced_alchemy.config import AsyncSessionConfig
from advanced_alchemy.extensions.litestar import SQLAlchemyAsyncConfig
from advanced_alchemy.extensions.litestar.plugins.init.config.common import SESSION_SCOPE_KEY
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from litestar_auth._plugin.advanced_alchemy import bind_auth_session_to_alchemy
from litestar_auth._plugin.scoped_session import SESSION_SCOPE_KEY as AUTH_SESSION_SCOPE_KEY
from tests.e2e.conftest import assert_structural_session_factory

pytestmark = pytest.mark.unit


def test_session_scope_key_matches_advanced_alchemy_constant() -> None:
    """LitestarAuth re-exports Advanced Alchemy's default scope key."""
    assert AUTH_SESSION_SCOPE_KEY is SESSION_SCOPE_KEY


def test_bind_auth_session_to_alchemy_uses_post_init_scope_key() -> None:
    """The binding reads Advanced Alchemy's effective scope key after config construction."""
    first = SQLAlchemyAsyncConfig(connection_string="sqlite+aiosqlite:///:memory:")
    second = SQLAlchemyAsyncConfig(connection_string="sqlite+aiosqlite:///:memory:")

    first_binding = bind_auth_session_to_alchemy(first)
    second_binding = bind_auth_session_to_alchemy(second)

    assert first_binding.session_scope_key == SESSION_SCOPE_KEY
    assert second_binding.session_scope_key != first_binding.session_scope_key


async def test_bind_auth_session_to_alchemy_honors_session_maker_override() -> None:
    """Callers can supply an existing session factory while still inheriting the AA scope key."""
    alchemy = SQLAlchemyAsyncConfig(connection_string="sqlite+aiosqlite:///:memory:")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        session_maker = assert_structural_session_factory(
            async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False),
        )
        binding = bind_auth_session_to_alchemy(
            alchemy,
            session_maker=session_maker,
        )
    finally:
        await engine.dispose()

    assert binding.session_scope_key == alchemy.session_scope_key
    assert binding.session_maker is session_maker


def test_bind_auth_session_to_alchemy_uses_alchemy_session_maker_by_default() -> None:
    """When no override is supplied, the binding delegates to ``create_session_maker``."""
    alchemy = SQLAlchemyAsyncConfig(
        connection_string="sqlite+aiosqlite:///:memory:",
        session_config=AsyncSessionConfig(expire_on_commit=False),
    )

    binding = bind_auth_session_to_alchemy(alchemy)

    assert binding.session_scope_key == alchemy.session_scope_key
    assert binding.session_maker is alchemy.create_session_maker()
