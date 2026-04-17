"""Unit tests for LitestarAuth CLI plugin wiring."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Protocol, cast
from uuid import UUID

import pytest
from click.testing import CliRunner
from litestar.config.app import AppConfig
from litestar.plugins import CLIPlugin, InitPlugin

try:
    import rich_click as click
except ImportError:
    import click  # type: ignore[no-redef]

from litestar.cli._utils import LitestarGroup

from litestar_auth._plugin.role_cli import (
    _ROLE_CLI_CONTEXT_KEY,
    RoleCLIContext,
    _resolve_role_cli_context,
    register_roles_cli,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.types import StrategyProtocol, UserProtocol
from tests._helpers import ExampleUser
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.conftest import DummySessionMaker, InMemoryUserDatabase

if TYPE_CHECKING:
    from click import Group

    from litestar_auth._plugin.scoped_session import SessionFactory

pytestmark = pytest.mark.unit


class _EmailUserProtocol(UserProtocol[UUID], Protocol):
    """User contract needed by the CLI wiring test helpers."""

    email: str


class _CLIUserManager[UP: _EmailUserProtocol](BaseUserManager[UP, UUID]):
    """Minimal manager implementation for plugin CLI wiring tests."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Delegate pagination to the configured user store.

        Returns:
            The selected user page and total count from the backing store.
        """
        return await self.user_db.list_users(offset=offset, limit=limit)


class _CLIInMemoryTokenStrategy[UP: _EmailUserProtocol](Strategy[UP, UUID]):
    """Minimal token strategy for plugin CLI wiring tests."""

    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, UUID],
    ) -> UP | None:
        """Return no user; CLI wiring tests do not authenticate requests."""
        del token, user_manager
        return None

    async def write_token(self, user: UP) -> str:
        """Return a deterministic placeholder token."""
        del user
        return "plugin-cli-token"

    async def destroy_token(self, token: str, user: UP) -> None:
        """Discard token-destruction inputs for test coverage."""
        del token, user


def _build_root_cli() -> Group:
    """Return a Litestar-like root CLI group for plugin registration tests."""

    @click.group(cls=LitestarGroup)
    def root() -> None:
        """Root CLI group used in plugin CLI tests."""

    return root


def _minimal_config[UP: _EmailUserProtocol](
    *,
    user_model: type[UP],
) -> LitestarAuthConfig[UP, UUID]:
    """Build the smallest plugin config needed to test CLI registration.

    Returns:
        A plugin config suitable for CLI registration and lazy role validation tests.
    """
    user_db = InMemoryUserDatabase[UP]([])
    backend = AuthenticationBackend[UP, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("StrategyProtocol[UP, UUID]", _CLIInMemoryTokenStrategy[UP]()),
    )
    return LitestarAuthConfig[UP, UUID](
        backends=[backend],
        user_model=user_model,
        user_manager_class=_CLIUserManager,
        session_maker=cast("SessionFactory", assert_structural_session_factory(DummySessionMaker())),
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verification-secret-123456789012",
            reset_password_token_secret="reset-password-secret-1234567890",
            id_parser=UUID,
        ),
    )


def test_on_cli_init_registers_roles_group_without_changing_on_app_init(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI registration is additive and preserves existing app-init orchestration."""
    plugin = LitestarAuth(_minimal_config(user_model=User))
    root_cli = _build_root_cli()
    app_config = AppConfig()
    calls: list[str] = []

    assert isinstance(plugin, InitPlugin)
    assert isinstance(plugin, CLIPlugin)

    plugin.on_cli_init(root_cli)

    assert "roles" in root_cli.commands

    monkeypatch.setattr(
        "litestar_auth.plugin.warn_insecure_plugin_startup_defaults",
        lambda _config: calls.append("warn"),
    )
    monkeypatch.setattr(
        "litestar_auth.plugin.require_oauth_token_encryption_for_configured_providers",
        lambda **_kwargs: calls.append("require-oauth-key"),
    )
    monkeypatch.setattr(
        "litestar_auth.plugin.require_secure_oauth_redirect_in_production",
        lambda **_kwargs: calls.append("require-oauth-redirect"),
    )
    monkeypatch.setattr(
        "litestar_auth.plugin.bootstrap_bundled_token_orm_models",
        lambda _config: calls.append("bootstrap-token-models"),
    )
    monkeypatch.setattr(plugin, "_register_dependencies", lambda _app_config: calls.append("dependencies"))
    monkeypatch.setattr(plugin, "_register_middleware", lambda _app_config: calls.append("middleware"))
    monkeypatch.setattr(
        plugin,
        "_register_openapi_security",
        lambda _app_config: (calls.append("openapi-security"), None)[1],
    )
    monkeypatch.setattr(
        plugin,
        "_register_controllers",
        lambda _app_config, *, security=None: calls.append("controllers") or [],  # noqa: ARG005
    )
    monkeypatch.setattr(plugin, "_register_exception_handlers", lambda _route_handlers: calls.append("exceptions"))

    result = plugin.on_app_init(app_config)

    assert result is app_config
    assert calls == [
        "warn",
        "require-oauth-key",
        "require-oauth-redirect",
        "bootstrap-token-models",
        "dependencies",
        "middleware",
        "openapi-security",
        "controllers",
        "exceptions",
    ]


def test_on_cli_init_keeps_role_admin_import_lazy_until_roles_group_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI registration does not import role-admin helpers until the group is invoked."""
    monkeypatch.delitem(sys.modules, "litestar_auth._plugin.role_admin", raising=False)
    plugin = LitestarAuth(_minimal_config(user_model=User))
    root_cli = _build_root_cli()

    plugin.on_cli_init(root_cli)

    assert "litestar_auth._plugin.role_admin" not in sys.modules

    result = CliRunner().invoke(root_cli, ["roles"])

    assert result.exit_code == 0
    assert "litestar_auth._plugin.role_admin" in sys.modules
    assert "Manage relational roles" in result.output


def test_register_roles_cli_is_idempotent_when_group_already_exists() -> None:
    """Registering the CLI group twice preserves the first plugin-owned command."""
    root_cli = _build_root_cli()
    config = _minimal_config(user_model=User)

    register_roles_cli(root_cli, config)
    first_group = root_cli.commands["roles"]

    register_roles_cli(root_cli, config)

    assert root_cli.commands["roles"] is first_group


def test_roles_group_subcommand_invocation_skips_help_output() -> None:
    """Invoking a subcommand uses the group callback without printing the group help text."""
    root_cli = _build_root_cli()
    plugin = LitestarAuth(_minimal_config(user_model=User))

    plugin.on_cli_init(root_cli)
    roles_group = cast("Group", root_cli.commands["roles"])

    @roles_group.command("inspect")
    def inspect_roles() -> None:
        click.echo("inspected")

    result = CliRunner().invoke(root_cli, ["roles", "inspect"])

    assert result.exit_code == 0
    assert result.output == "inspected\n"


def test_resolve_role_cli_context_reuses_cached_role_admin() -> None:
    """CLI context resolution caches the role-admin helper within one invocation tree."""
    root_cli = _build_root_cli()
    config = _minimal_config(user_model=User)
    sentinel = object()

    register_roles_cli(root_cli, config)
    roles_group = cast("Group", root_cli.commands["roles"])
    cached_context = RoleCLIContext(config=config, role_admin=cast("Any", sentinel))

    with click.Context(roles_group) as ctx:
        ctx.meta[_ROLE_CLI_CONTEXT_KEY] = cached_context
        resolved_context = _resolve_role_cli_context(ctx, config)

    assert resolved_context is cached_context
    assert resolved_context.config is config
    assert resolved_context.role_admin is sentinel


def test_roles_group_emits_click_error_for_incompatible_role_management_config() -> None:
    """Incompatible role config failures surface as Click errors instead of raw tracebacks."""
    plugin = LitestarAuth(_minimal_config(user_model=ExampleUser))
    root_cli = _build_root_cli()

    plugin.on_cli_init(root_cli)
    result = CliRunner().invoke(root_cli, ["roles"])

    assert result.exit_code == 1
    assert "Role admin requires LitestarAuthConfig.user_model 'ExampleUser'" in result.output
    assert "Expected a SQLAlchemy mapped class, but mapper inspection is unavailable." in result.output
    assert "Traceback" not in result.output


def test_role_commands_delegate_to_role_admin_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI commands delegate role mutations through the role-admin surface."""
    root_cli = _build_root_cli()
    config = _minimal_config(user_model=User)
    plugin = LitestarAuth(config)
    calls: list[tuple[str, object, object]] = []

    class FakeRoleAdmin:
        """Minimal role-admin stub capturing CLI command delegation."""

        async def assign_user_roles(self, *, email: str, roles: tuple[str, ...]) -> object:
            calls.append(("assign", email, roles))
            return SimpleNamespace(email=email, roles=["admin", "billing"])

        async def unassign_user_roles(self, *, email: str, roles: tuple[str, ...]) -> object:
            calls.append(("unassign", email, roles))
            return SimpleNamespace(email=email, roles=["admin"])

        async def delete_role(self, *, role: str, force: bool = False) -> list[str]:
            calls.append(("delete", role, force))
            return ["billing"]

    fake_role_admin = FakeRoleAdmin()
    monkeypatch.setattr(
        "litestar_auth._plugin.role_cli._resolve_role_cli_context",
        lambda _ctx, cfg: RoleCLIContext(config=cfg, role_admin=cast("Any", fake_role_admin)),
    )
    plugin.on_cli_init(root_cli)
    runner = CliRunner()

    assign_result = runner.invoke(root_cli, ["roles", "assign", "--email", "member@example.com", " Billing ", "ADMIN"])
    unassign_result = runner.invoke(
        root_cli,
        ["roles", "unassign", "--email", "member@example.com", " Billing ", "support"],
    )
    delete_result = runner.invoke(root_cli, ["roles", "delete", "--force", "admin"])

    assert assign_result.exit_code == 0
    assert assign_result.output == "member@example.com: ['admin', 'billing']\n"
    assert unassign_result.exit_code == 0
    assert unassign_result.output == "member@example.com: ['admin']\n"
    assert delete_result.exit_code == 0
    assert delete_result.output == "['billing']\n"
    assert calls == [
        ("assign", "member@example.com", (" Billing ", "ADMIN")),
        ("unassign", "member@example.com", (" Billing ", "support")),
        ("delete", "admin", True),
    ]
