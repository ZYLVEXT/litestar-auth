"""Unit tests for request-scoped SQLAlchemy session sharing helpers."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar.datastructures.state import State

import litestar_auth._plugin.scoped_session as scoped_session_module
from litestar_auth._plugin.scoped_session import (
    _AA_SCOPE_NAMESPACE,
    SESSION_SCOPE_KEY,
    _get_aa_namespace,
    get_or_create_scoped_session,
)
from tests.e2e.conftest import assert_structural_session_factory

if TYPE_CHECKING:
    from litestar.types import Scope
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.unit


class DummySession:
    """Minimal test session object."""

    async def commit(self) -> None:
        """No-op commit for lifecycle parity."""

    async def rollback(self) -> None:
        """No-op rollback for lifecycle parity."""

    async def close(self) -> None:
        """No-op close for lifecycle parity."""


class DummySessionMaker:
    """Callable session factory that tracks invocation count."""

    def __init__(self) -> None:
        """Initialize call counter."""
        self.call_count = 0

    def __call__(self) -> DummySession:
        """Create and return a new dummy session.

        Returns:
            Fresh dummy session object.
        """
        self.call_count += 1
        return DummySession()


def _build_scope() -> Scope:
    """Create a minimal HTTP ASGI scope for unit tests.

    Returns:
        Minimal ASGI scope with mutable ``state`` mapping.
    """
    return cast(
        "Scope",
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "state": {},
        },
    )


def _scope_dict(scope: Scope) -> dict[str, Any]:
    """Return the ASGI scope as a plain dict for dynamic-key assertions."""
    return cast("dict[str, Any]", scope)


def test_get_or_create_scoped_session_creates_session_for_empty_scope() -> None:
    """It creates one request-scoped session when scope has no session yet."""
    session_maker = assert_structural_session_factory(DummySessionMaker())
    scope = _build_scope()

    session = get_or_create_scoped_session(State(), scope, cast("async_sessionmaker[AsyncSession]", session_maker))

    assert isinstance(session, DummySession)
    assert session_maker.call_count == 1
    assert cast("dict[str, Any]", _scope_dict(scope)[_AA_SCOPE_NAMESPACE])[SESSION_SCOPE_KEY] is session


def test_get_or_create_scoped_session_reuses_existing_scoped_session() -> None:
    """It reuses the same request-scoped session across repeated calls for structural factories."""
    session_maker = assert_structural_session_factory(DummySessionMaker())
    scope = _build_scope()
    state = State()

    first = get_or_create_scoped_session(state, scope, cast("async_sessionmaker[AsyncSession]", session_maker))
    second = get_or_create_scoped_session(state, scope, cast("async_sessionmaker[AsyncSession]", session_maker))

    assert first is second
    assert session_maker.call_count == 1


def test_get_aa_namespace_creates_namespace_when_absent() -> None:
    """It creates the Advanced Alchemy namespace on demand."""
    scope = _build_scope()

    namespace = _get_aa_namespace(scope)

    assert namespace == {}
    assert cast("dict[str, Any]", _scope_dict(scope)[_AA_SCOPE_NAMESPACE]) is namespace


def test_get_aa_namespace_returns_existing_namespace() -> None:
    """It reuses the existing Advanced Alchemy namespace mapping."""
    namespace: dict[str, Any] = {"existing": "value"}
    scope = _build_scope()
    cast("dict[str, Any]", scope)[_AA_SCOPE_NAMESPACE] = namespace

    resolved_namespace = _get_aa_namespace(scope)

    assert resolved_namespace is namespace


def test_scoped_session_module_reload_preserves_scope_constants() -> None:
    """It reloads cleanly with the expected Advanced Alchemy scope keys."""
    reloaded_module = importlib.reload(scoped_session_module)

    assert reloaded_module._AA_SCOPE_NAMESPACE == _AA_SCOPE_NAMESPACE
    assert reloaded_module.SESSION_SCOPE_KEY == SESSION_SCOPE_KEY
