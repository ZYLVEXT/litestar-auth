"""Focused password-helper contract tests for `LitestarAuthConfig`."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

import pytest

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuthConfig
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit


def _as_any(value: object) -> Any:  # noqa: ANN401
    """Return a value through the test-only dynamic type boundary."""
    return cast("Any", value)


def _make_config(
    *,
    user_manager_security: UserManagerSecurity[UUID] | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal config for password-helper tests.

    Returns:
        A config that exercises the current typed password-helper contract.
    """
    security = user_manager_security or UserManagerSecurity[UUID](
        verification_token_secret="x" * 32,
        reset_password_token_secret="y" * 32,
    )
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=_as_any(InMemoryTokenStrategy(token_prefix="plugin-config-password-helper")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "Any",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=security,
    )


def test_resolve_password_helper_memoizes_default_helper() -> None:
    """The config exposes one shared default helper when no explicit helper is configured."""
    config = _make_config()

    first = config.resolve_password_helper()
    second = config.resolve_password_helper()

    assert first is second
    assert config.get_default_password_helper() is first
    assert len(first.password_hash.hashers) == 1
    assert first.password_hash.hashers[0].__class__.__name__ == "Argon2Hasher"


def test_resolve_password_helper_uses_typed_security_helper() -> None:
    """The typed security bundle is the only explicit password-helper input."""
    explicit_password_helper = PasswordHelper()
    config = _make_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
            password_helper=explicit_password_helper,
        ),
    )

    assert config.resolve_password_helper() is explicit_password_helper
    assert config.get_default_password_helper() is None
