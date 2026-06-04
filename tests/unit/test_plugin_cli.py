"""Unit tests for LitestarAuth CLI plugin wiring."""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Protocol, Self, cast
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

import litestar_auth._plugin.startup as startup_module
from litestar_auth._plugin.organization_cli import (
    _ORGANIZATION_CLI_CONTEXT_KEY,
    OrganizationCLIContext,
    _parse_cli_id,
    _resolve_organization_cli_context,
    _run_organization_cli_operation,
    _run_organization_invitation_cli_operation,
    build_organizations_group,
)
from litestar_auth._plugin.role_admin_contracts import SystemManagedRoleError
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
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig, OrganizationConfig
from litestar_auth.types import UserProtocol
from tests._helpers import ExampleUser
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.conftest import DummySessionMaker, InMemoryUserDatabase

if TYPE_CHECKING:
    from click import Group

pytestmark = pytest.mark.unit


def _as_any(value: object) -> Any:  # noqa: ANN401
    """Return a value through the test-only dynamic type boundary."""
    return cast("Any", value)


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
        return None

    async def write_token(self, user: UP) -> str:
        """Return a deterministic placeholder token."""
        return "plugin-cli-token"

    async def destroy_token(self, token: str, user: UP) -> None:
        """Discard token-destruction inputs for test coverage."""


def _build_root_cli() -> Group:
    """Return a Litestar-like root CLI group for plugin registration tests."""

    @click.group(cls=LitestarGroup)
    def root() -> None:
        """Root CLI group used in plugin CLI tests."""

    return root


def _minimal_config[UP: _EmailUserProtocol](
    *,
    user_model: type[UP],
    organization_config: OrganizationConfig | None = None,
) -> LitestarAuthConfig[UP, UUID]:
    """Build the smallest plugin config needed to test CLI registration.

    Returns:
        A plugin config suitable for CLI registration and lazy role validation tests.
    """
    user_db = InMemoryUserDatabase[UP]([])
    backend = AuthenticationBackend[UP, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=_as_any(_CLIInMemoryTokenStrategy[UP]()),
    )
    return LitestarAuthConfig[UP, UUID](
        backends=[backend],
        user_model=user_model,
        user_manager_class=_CLIUserManager,
        session_maker=_as_any(assert_structural_session_factory(DummySessionMaker())),
        user_db_factory=lambda _session: user_db,
        organization_config=organization_config or OrganizationConfig(),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verification-secret-123456789012",
            reset_password_token_secret="reset-password-secret-1234567890",
            id_parser=UUID,
        ),
    )


def _enabled_organization_config() -> OrganizationConfig:
    """Build the smallest organization config needed for CLI registration tests.

    Returns:
        Organization config with administration enabled and an inert store factory.
    """
    return OrganizationConfig(
        enabled=True,
        include_organization_admin=True,
        store_factory=lambda _session: cast("Any", object()),
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
    assert "organizations" not in root_cli.commands

    monkeypatch.setattr(
        startup_module,
        "warn_insecure_plugin_startup_defaults",
        lambda _config: calls.append("warn"),
    )
    monkeypatch.setattr(
        startup_module,
        "require_oauth_token_encryption_for_configured_providers",
        lambda **_kwargs: calls.append("require-oauth-key"),
    )
    monkeypatch.setattr(
        startup_module,
        "require_secure_oauth_redirect_in_production",
        lambda **_kwargs: calls.append("require-oauth-redirect"),
    )
    monkeypatch.setattr(
        startup_module,
        "bootstrap_bundled_token_orm_models",
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


def test_on_cli_init_registers_organizations_group_only_for_org_admin_config() -> None:
    """Organization CLI registration is opt-in through the organization-admin feature flag."""
    default_cli = _build_root_cli()
    LitestarAuth(_minimal_config(user_model=User)).on_cli_init(default_cli)
    assert "organizations" not in default_cli.commands

    configured_cli = _build_root_cli()
    LitestarAuth(
        _minimal_config(
            user_model=User,
            organization_config=_enabled_organization_config(),
        ),
    ).on_cli_init(configured_cli)

    assert "organizations" in configured_cli.commands


def test_on_cli_init_does_not_clobber_existing_organizations_group() -> None:
    """Organization CLI registration preserves an existing command with the same name."""
    root_cli = _build_root_cli()

    @root_cli.command("organizations")
    def existing_organizations() -> None:
        click.echo("existing")

    first_group = root_cli.commands["organizations"]
    LitestarAuth(
        _minimal_config(
            user_model=User,
            organization_config=_enabled_organization_config(),
        ),
    ).on_cli_init(root_cli)

    result = CliRunner().invoke(root_cli, ["organizations"])

    assert root_cli.commands["organizations"] is first_group
    assert result.exit_code == 0
    assert result.output == "existing\n"


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


def test_organizations_group_emits_click_error_for_incompatible_config() -> None:
    """Organization CLI config failures surface as Click errors instead of raw tracebacks."""
    root_cli = _build_root_cli()
    config = _minimal_config(
        user_model=User,
        organization_config=_enabled_organization_config(),
    )
    config.session_maker = None
    root_cli.add_command(build_organizations_group(root_cli, config))

    result = CliRunner().invoke(root_cli, ["organizations"])

    assert result.exit_code == 1
    assert "Organization admin CLI requires LitestarAuthConfig.session_maker" in result.output
    assert "Traceback" not in result.output


def test_resolve_organization_cli_context_reuses_cached_context() -> None:
    """Organization CLI context resolution caches prerequisites within one invocation tree."""
    root_cli = _build_root_cli()
    config = _minimal_config(
        user_model=User,
        organization_config=_enabled_organization_config(),
    )
    group = build_organizations_group(root_cli, config)
    cached_context = OrganizationCLIContext(
        config=config,
        session_maker=cast("Any", DummySessionMaker()),
        store_factory=lambda _session: cast("Any", object()),
        id_parser=UUID,
    )

    with click.Context(group) as ctx:
        ctx.meta[_ORGANIZATION_CLI_CONTEXT_KEY] = cached_context
        resolved_context = _resolve_organization_cli_context(ctx, config)

    assert resolved_context is cached_context
    assert resolved_context.config is config


def test_resolve_organization_cli_context_reports_missing_store_factory() -> None:
    """Manual organization group construction still fails closed when store wiring is absent."""
    root_cli = _build_root_cli()
    config = _minimal_config(user_model=User)
    config.organization_config.enabled = True
    config.organization_config.include_organization_admin = True
    group = build_organizations_group(root_cli, config)

    with click.Context(group) as ctx, pytest.raises(click.ClickException, match="store_factory"):
        _resolve_organization_cli_context(ctx, config)


def test_resolve_organization_cli_context_builds_uncached_context_and_rejects_disabled_config() -> None:
    """Organization CLI context resolution validates feature flags before building prerequisites."""
    root_cli = _build_root_cli()
    disabled_config = _minimal_config(user_model=User)
    disabled_group = build_organizations_group(root_cli, disabled_config)

    with click.Context(disabled_group) as ctx, pytest.raises(click.ClickException, match="include_organization_admin"):
        _resolve_organization_cli_context(ctx, disabled_config)

    enabled_config = _minimal_config(
        user_model=User,
        organization_config=_enabled_organization_config(),
    )
    enabled_group = build_organizations_group(root_cli, enabled_config)

    with click.Context(enabled_group) as ctx:
        resolved_context = _resolve_organization_cli_context(ctx, enabled_config)

    assert resolved_context.config is enabled_config
    assert resolved_context.session_maker is enabled_config.session_maker
    assert resolved_context.id_parser is UUID


def test_organization_commands_delegate_to_admin_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI commands delegate organization mutations through the organization-admin operation surface."""
    root_cli = _build_root_cli()
    config = _minimal_config(
        user_model=User,
        organization_config=_enabled_organization_config(),
    )
    plugin = LitestarAuth(config)
    organization_id = UUID("00000000-0000-0000-0000-000000000001")
    user_id = UUID("00000000-0000-0000-0000-000000000002")
    calls: list[tuple[str, object, object]] = []

    class FakeOrganizationAdmin:
        """Minimal organization-admin stub capturing CLI command delegation."""

        async def create_organization(self, *, slug: str, name: str) -> object:
            calls.append(("create", slug, name))
            return SimpleNamespace(id=organization_id, slug="acme", name=name)

        async def get_organization(self, organization_id: UUID) -> object:
            calls.append(("get", organization_id, None))
            return SimpleNamespace(id=organization_id, slug="acme", name="Acme")

        async def list_organizations_for_user(
            self,
            user_id: UUID,
            *,
            offset: int,
            limit: int,
        ) -> tuple[list[object], int]:
            calls.append(("list", user_id, None))
            organizations: list[object] = [SimpleNamespace(id=organization_id, slug="acme", name="Acme")]
            return organizations, len(organizations)

        async def update_organization(self, organization_id: UUID, *, slug: str, name: str) -> object:
            calls.append(("update", organization_id, (slug, name)))
            return SimpleNamespace(id=organization_id, slug="acme-labs", name=name)

        async def delete_organization(self, organization_id: UUID) -> None:
            calls.append(("delete", organization_id, None))

        async def add_member(self, *, organization_id: UUID, user_id: UUID, roles: tuple[str, ...]) -> object:
            calls.append(("add-member", organization_id, (user_id, roles)))
            return SimpleNamespace(organization_id=organization_id, user_id=user_id, roles=["owner"])

        async def remove_member(self, *, organization_id: UUID, user_id: UUID) -> None:
            calls.append(("remove-member", organization_id, user_id))

        async def list_members(self, organization_id: UUID, *, offset: int, limit: int) -> tuple[list[object], int]:
            calls.append(("list-members", organization_id, None))
            memberships: list[object] = [
                SimpleNamespace(organization_id=organization_id, user_id=user_id, roles=["owner"]),
            ]
            return memberships, len(memberships)

        async def set_member_roles(self, *, organization_id: UUID, user_id: UUID, roles: tuple[str, ...]) -> object:
            calls.append(("set-member-roles", organization_id, (user_id, roles)))
            return SimpleNamespace(organization_id=organization_id, user_id=user_id, roles=["admin"])

    fake_admin = FakeOrganizationAdmin()
    monkeypatch.setattr(
        "litestar_auth._plugin.organization_cli._run_organization_cli_operation",
        lambda _context, operation_factory: asyncio.run(operation_factory(fake_admin)),
    )
    monkeypatch.setattr(
        "litestar_auth._plugin.organization_cli._resolve_organization_cli_context",
        lambda _ctx, cfg: OrganizationCLIContext(
            config=cfg,
            session_maker=cast("Any", DummySessionMaker()),
            store_factory=lambda _session: cast("Any", object()),
            id_parser=UUID,
        ),
    )
    plugin.on_cli_init(root_cli)
    runner = CliRunner()

    help_result = runner.invoke(root_cli, ["organizations"])
    create_result = runner.invoke(root_cli, ["organizations", "create", "--slug", " Acme ", "--name", "Acme"])
    get_result = runner.invoke(root_cli, ["organizations", "get", str(organization_id)])
    unscoped_list_result = runner.invoke(root_cli, ["organizations", "list"])
    list_result = runner.invoke(root_cli, ["organizations", "list", "--user-id", str(user_id)])
    update_result = runner.invoke(
        root_cli,
        ["organizations", "update", str(organization_id), "--slug", "Acme Labs", "--name", "Acme Labs"],
    )
    delete_result = runner.invoke(root_cli, ["organizations", "delete", str(organization_id)])
    add_member_result = runner.invoke(
        root_cli,
        ["organizations", "add-member", str(organization_id), str(user_id), " Owner "],
    )
    list_members_result = runner.invoke(root_cli, ["organizations", "list-members", str(organization_id)])
    remove_member_result = runner.invoke(
        root_cli,
        ["organizations", "remove-member", str(organization_id), str(user_id)],
    )
    set_roles_result = runner.invoke(
        root_cli,
        ["organizations", "set-member-roles", str(organization_id), str(user_id), " Admin "],
    )

    assert help_result.exit_code == 0
    assert "Manage organizations" in help_result.output
    assert create_result.exit_code == 0
    assert create_result.output == f"{organization_id}: 'acme' 'Acme'\n"
    assert get_result.exit_code == 0
    assert get_result.output == f"{organization_id}: 'acme' 'Acme'\n"
    assert unscoped_list_result.exit_code == 1
    # Normalize rich panel output: strip ANSI codes and collapse whitespace so
    # assertions are not sensitive to terminal-width-dependent line wrapping.
    unscoped_list_output = " ".join(click.unstyle(unscoped_list_result.output).split())
    assert "Organization CLI list requires" in unscoped_list_output
    assert "--user-id" in unscoped_list_output
    assert list_result.exit_code == 0
    assert list_result.output == f"{organization_id}: 'acme' 'Acme'\n"
    assert update_result.exit_code == 0
    assert update_result.output == f"{organization_id}: 'acme-labs' 'Acme Labs'\n"
    assert delete_result.exit_code == 0
    assert delete_result.output == "deleted\n"
    assert add_member_result.exit_code == 0
    assert add_member_result.output == f"{organization_id} {user_id}: ['owner']\n"
    assert list_members_result.exit_code == 0
    assert list_members_result.output == f"{organization_id} {user_id}: ['owner']\n"
    assert remove_member_result.exit_code == 0
    assert remove_member_result.output == "removed\n"
    assert set_roles_result.exit_code == 0
    assert set_roles_result.output == f"{organization_id} {user_id}: ['admin']\n"
    assert calls == [
        ("create", " Acme ", "Acme"),
        ("get", organization_id, None),
        ("list", user_id, None),
        ("update", organization_id, ("Acme Labs", "Acme Labs")),
        ("delete", organization_id, None),
        ("add-member", organization_id, (user_id, (" Owner ",))),
        ("list-members", organization_id, None),
        ("remove-member", organization_id, user_id),
        ("set-member-roles", organization_id, (user_id, (" Admin ",))),
    ]


def test_organization_invitation_commands_delegate_without_echoing_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invitation CLI commands delegate to admin operations without printing raw tokens."""
    root_cli = _build_root_cli()
    config = _minimal_config(
        user_model=User,
        organization_config=_enabled_organization_config(),
    )
    organization_id = UUID("00000000-0000-0000-0000-000000000001")
    invitation_id = UUID("00000000-0000-0000-0000-000000000003")
    calls: list[tuple[str, object, object]] = []
    invitation_row = SimpleNamespace(
        id=invitation_id,
        organization_id=organization_id,
        invited_email="invited@example.com",
        roles=["member"],
        expires_at="2026-06-05T00:00:00+00:00",
        status="pending",
    )

    class FakeOrganizationAdmin:
        """Minimal organization-admin stub capturing invitation command delegation."""

        async def invite_member(
            self,
            *,
            organization_id: UUID,
            invited_email: str,
            roles: tuple[str, ...],
            user_manager: object,
        ) -> object:
            calls.append(("invite-member", organization_id, (invited_email, roles, user_manager)))
            return SimpleNamespace(invitation=invitation_row, token="raw-invitation-token")

        async def list_pending_invitations(
            self,
            organization_id: UUID,
            *,
            offset: int,
            limit: int,
        ) -> tuple[list[object], int]:
            calls.append(("list-pending-invitations", organization_id, None))
            return [invitation_row], 1

        async def revoke_invitation(self, invitation_id: UUID) -> object:
            calls.append(("revoke-invitation", invitation_id, None))
            return SimpleNamespace(id=invitation_id)

    fake_admin = FakeOrganizationAdmin()
    monkeypatch.setattr(
        "litestar_auth._plugin.organization_cli._run_organization_cli_operation",
        lambda _context, operation_factory: asyncio.run(operation_factory(fake_admin)),
    )
    monkeypatch.setattr(
        "litestar_auth._plugin.organization_cli._run_organization_invitation_cli_operation",
        lambda _context, operation_factory: asyncio.run(operation_factory(fake_admin, "user-manager")),
    )
    monkeypatch.setattr(
        "litestar_auth._plugin.organization_cli._resolve_organization_cli_context",
        lambda _ctx, cfg: OrganizationCLIContext(
            config=cfg,
            session_maker=cast("Any", DummySessionMaker()),
            store_factory=lambda _session: cast("Any", object()),
            id_parser=UUID,
        ),
    )
    LitestarAuth(config).on_cli_init(root_cli)
    runner = CliRunner()

    invite_member_result = runner.invoke(
        root_cli,
        ["organizations", "invite-member", str(organization_id), "Invited@example.com", " Member "],
    )
    list_invitations_result = runner.invoke(
        root_cli,
        ["organizations", "list-pending-invitations", str(organization_id)],
    )
    revoke_invitation_result = runner.invoke(
        root_cli,
        ["organizations", "revoke-invitation", str(invitation_id)],
    )

    expected_invitation_output = (
        f"{invitation_id} {organization_id}: 'invited@example.com' ['member'] "
        "'pending' expires_at=2026-06-05T00:00:00+00:00\n"
    )
    assert invite_member_result.exit_code == 0
    assert invite_member_result.output == expected_invitation_output
    assert "raw-invitation-token" not in invite_member_result.output
    assert list_invitations_result.exit_code == 0
    assert list_invitations_result.output == expected_invitation_output
    assert "raw-invitation-token" not in list_invitations_result.output
    assert revoke_invitation_result.exit_code == 0
    assert revoke_invitation_result.output == "revoked\n"
    assert calls == [
        ("invite-member", organization_id, ("Invited@example.com", (" Member ",), "user-manager")),
        ("list-pending-invitations", organization_id, None),
        ("revoke-invitation", invitation_id, None),
    ]


def test_organization_command_helper_failures_surface_click_errors() -> None:
    """Organization CLI helper failures are converted to non-traceback Click errors."""
    config = _minimal_config(
        user_model=User,
        organization_config=_enabled_organization_config(),
    )
    parsed_context = OrganizationCLIContext(
        config=config,
        session_maker=cast("Any", DummySessionMaker()),
        store_factory=lambda _session: cast("Any", object()),
        id_parser=UUID,
    )
    raw_context = OrganizationCLIContext(
        config=config,
        session_maker=cast("Any", DummySessionMaker()),
        store_factory=lambda _session: cast("Any", object()),
        id_parser=None,
    )

    assert _parse_cli_id(raw_context, "tenant-1") == "tenant-1"
    with pytest.raises(click.ClickException, match="Invalid identifier"):
        _parse_cli_id(parsed_context, "not-a-uuid")

    class BadSessionMaker:
        """Session maker that returns an invalid non-context-manager object."""

        def __call__(self) -> object:
            """Return an invalid session object."""
            return object()

    bad_session_context = OrganizationCLIContext(
        config=config,
        session_maker=cast("Any", BadSessionMaker()),
        store_factory=lambda _session: cast("Any", object()),
        id_parser=UUID,
    )

    async def operation(_admin: object) -> object:
        await asyncio.sleep(0)
        return object()

    with pytest.raises(click.ClickException, match="async context manager"):
        _run_organization_cli_operation(bad_session_context, operation)
    with pytest.raises(click.ClickException, match="async context manager"):
        _run_organization_invitation_cli_operation(
            bad_session_context,
            lambda _admin, _user_manager: operation(_admin),
        )

    class FakeSession:
        """Async context manager with the commit hook required by the CLI runner."""

        committed = False

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(
            self,
            _exc_type: type[BaseException] | None,
            _exc: BaseException | None,
            _traceback: object,
        ) -> None:
            return None

        async def commit(self) -> None:
            self.committed = True

    fake_session = FakeSession()

    class FakeSessionMaker:
        """Session maker returning the same fake async context manager."""

        def __call__(self) -> FakeSession:
            """Return the fake session context."""
            return fake_session

    good_session_context = OrganizationCLIContext(
        config=config,
        session_maker=cast("Any", FakeSessionMaker()),
        store_factory=lambda _session: cast("Any", object()),
        id_parser=UUID,
    )

    assert _run_organization_cli_operation(good_session_context, operation) is not None
    assert fake_session.committed is True

    async def invitation_operation(_admin: object, user_manager: object) -> object:
        await asyncio.sleep(0)
        return user_manager

    fake_session.committed = False
    assert _run_organization_invitation_cli_operation(good_session_context, invitation_operation) is not None
    assert fake_session.committed is True

    async def failing_operation(_admin: object) -> object:
        await asyncio.sleep(0)
        msg = "operation failed"
        raise ValueError(msg)

    with pytest.raises(click.ClickException, match="operation failed"):
        _run_organization_cli_operation(good_session_context, failing_operation)

    async def failing_invitation_operation(_admin: object, _user_manager: object) -> object:
        await asyncio.sleep(0)
        msg = "invitation operation failed"
        raise ValueError(msg)

    with pytest.raises(click.ClickException, match="invitation operation failed"):
        _run_organization_invitation_cli_operation(good_session_context, failing_invitation_operation)


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


@pytest.mark.parametrize(
    ("command", "expected_call"),
    [
        pytest.param(
            ["delete", "--force", "admin"],
            ("delete", "admin", True),
            id="delete-system-role",
        ),
        pytest.param(
            ["unassign", "--email", "admin@example.com", "admin"],
            ("unassign", "admin@example.com", ("admin",)),
            id="unassign-final-superuser",
        ),
    ],
)
def test_role_commands_surface_system_managed_role_errors(
    monkeypatch: pytest.MonkeyPatch,
    command: list[str],
    expected_call: tuple[str, object, object],
) -> None:
    """System-managed role invariants surface as clear non-zero CLI failures."""
    root_cli = _build_root_cli()
    config = _minimal_config(user_model=User)
    plugin = LitestarAuth(config)
    calls: list[tuple[str, object, object]] = []

    class FakeRoleAdmin:
        """Minimal role-admin stub raising the invariant error through CLI commands."""

        async def unassign_user_roles(self, *, email: str, roles: tuple[str, ...]) -> object:
            calls.append(("unassign", email, roles))
            msg = "Role admin will not remove the final assignment of system-managed superuser role 'admin'."
            raise SystemManagedRoleError(msg)

        async def delete_role(self, *, role: str, force: bool = False) -> list[str]:
            calls.append(("delete", role, force))
            msg = "Role admin will not modify system-managed superuser role 'admin'."
            raise SystemManagedRoleError(msg)

    fake_role_admin = FakeRoleAdmin()
    monkeypatch.setattr(
        "litestar_auth._plugin.role_cli._resolve_role_cli_context",
        lambda _ctx, cfg: RoleCLIContext(config=cfg, role_admin=cast("Any", fake_role_admin)),
    )
    plugin.on_cli_init(root_cli)

    result = CliRunner().invoke(root_cli, ["roles", *command])

    assert result.exit_code == 1
    assert "system-managed" in result.output
    assert "Traceback" not in result.output
    assert calls == [expected_call]
