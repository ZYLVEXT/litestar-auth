"""Unit tests for dependency-key identifier guards used by DI providers."""

from __future__ import annotations

from typing import Any, cast

import pytest

from litestar_auth._plugin.dependencies import _make_user_manager_dependency_provider

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_make_user_manager_dependency_provider_accepts_valid_identifier() -> None:
    """Provider generation succeeds and yields a manager for valid DI keys."""
    marker = object()

    def build_user_manager(session: object) -> object:
        return (marker, session)

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    generator = cast("Any", provider(db_session=marker))
    try:
        manager = await anext(generator)
    finally:
        await generator.aclose()

    assert manager == (marker, marker)
