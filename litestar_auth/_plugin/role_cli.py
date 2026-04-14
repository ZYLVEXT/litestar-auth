"""Lazy CLI registration for plugin-managed role administration."""

from __future__ import annotations

import asyncio
import importlib
import sys
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Any, cast

from litestar.cli._utils import ClickException, Context, Group  # noqa: PLC2701

from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Coroutine
    from types import ModuleType

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth._plugin.role_admin import SQLAlchemyRoleAdmin, UserRoleMembership

_ROLE_CLI_CONTEXT_KEY = "litestar_auth.role_cli"


@dataclass(frozen=True, slots=True)
class RoleCLIContext[UP: UserProtocol[Any]]:
    """Resolved CLI context for the active plugin-owned roles command group."""

    config: LitestarAuthConfig[UP, Any]
    role_admin: SQLAlchemyRoleAdmin[UP]


def register_roles_cli[UP: UserProtocol[Any]](
    cli: Group,
    config: LitestarAuthConfig[UP, Any],
) -> None:
    """Register the plugin-owned ``roles`` group on the active Litestar CLI."""
    if cli.commands.get("roles") is None:
        cli.add_command(build_roles_group(cli, config))


def build_roles_group[UP: UserProtocol[Any]](
    cli: Group,
    config: LitestarAuthConfig[UP, Any],
) -> Group:
    """Build the lazily validated ``roles`` command group for one plugin config.

    Returns:
        The plugin-owned Click group bound to the active Litestar CLI class.
    """
    group_class = getattr(cli, "group_class", type(cli))
    help_text = "Manage relational roles through the active LitestarAuth plugin configuration."

    def roles_group(ctx: Context) -> None:
        _resolve_role_cli_context(ctx, config)
        if ctx.invoked_subcommand is None:
            sys.stdout.write(ctx.command.get_help(ctx))

    group = cast(
        "Group",
        group_class(
            name="roles",
            callback=roles_group,
            invoke_without_command=True,
            help=help_text,
        ),
    )
    _register_role_catalog_commands(group, config)
    _register_role_user_commands(group, config)
    return group


def _resolve_role_cli_context[UP: UserProtocol[Any]](
    ctx: Context,
    config: LitestarAuthConfig[UP, Any],
) -> RoleCLIContext[UP]:
    """Resolve and cache the role-admin context for the current CLI invocation.

    Returns:
        The resolved plugin-owned role CLI context for this command tree.

    Raises:
        ClickException: If the plugin configuration cannot support CLI role management.
    """
    cached_context = ctx.meta.get(_ROLE_CLI_CONTEXT_KEY)
    if cached_context is not None:
        return cast("RoleCLIContext[UP]", cached_context)

    from litestar_auth._plugin.role_admin import SQLAlchemyRoleAdmin  # noqa: PLC0415

    try:
        role_admin = SQLAlchemyRoleAdmin.from_config(config)
    except ConfigurationError as exc:
        raise ClickException(str(exc)) from exc

    role_cli_context = RoleCLIContext(config=config, role_admin=role_admin)
    ctx.meta[_ROLE_CLI_CONTEXT_KEY] = role_cli_context
    return role_cli_context


def _register_role_user_commands[UP: UserProtocol[Any]](
    group: Group,
    config: LitestarAuthConfig[UP, Any],
) -> None:
    """Register user-role mutation commands on the plugin-owned group."""
    click_module = cast("Any", _load_click_module())

    @group.command("assign", help="Assign normalized roles to a user selected by email.")
    @click_module.option("--email", "email", required=True, help="Target user email.")
    @click_module.argument("roles", nargs=-1, required=True)
    def assign_command(email: str, roles: tuple[str, ...]) -> None:
        ctx = cast("Context", click_module.get_current_context())
        role_cli_context = _resolve_role_cli_context(ctx, config)
        membership = _run_role_cli_operation(role_cli_context.role_admin.assign_user_roles(email=email, roles=roles))
        click_module.echo(_format_user_role_membership(membership))

    @group.command("unassign", help="Remove normalized roles from a user selected by email.")
    @click_module.option("--email", "email", required=True, help="Target user email.")
    @click_module.argument("roles", nargs=-1, required=True)
    def unassign_command(email: str, roles: tuple[str, ...]) -> None:
        ctx = cast("Context", click_module.get_current_context())
        role_cli_context = _resolve_role_cli_context(ctx, config)
        membership = _run_role_cli_operation(role_cli_context.role_admin.unassign_user_roles(email=email, roles=roles))
        click_module.echo(_format_user_role_membership(membership))

    @group.command("show-user", help="Show the normalized roles for a user selected by email.")
    @click_module.option("--email", "email", required=True, help="Target user email.")
    def show_user_command(email: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        role_cli_context = _resolve_role_cli_context(ctx, config)
        membership = _run_role_cli_operation(role_cli_context.role_admin.show_user_roles(email=email))
        click_module.echo(_format_user_role_membership(membership))


def _register_role_catalog_commands[UP: UserProtocol[Any]](
    group: Group,
    config: LitestarAuthConfig[UP, Any],
) -> None:
    """Register role-catalog commands on the plugin-owned group."""
    click_module = cast("Any", _load_click_module())

    @group.command("list", help="List normalized roles from the active relational catalog.")
    def list_command() -> None:
        ctx = cast("Context", click_module.get_current_context())
        role_cli_context = _resolve_role_cli_context(ctx, config)
        role_names = _run_role_cli_operation(role_cli_context.role_admin.list_roles())
        click_module.echo(_format_role_catalog_snapshot(role_names))

    @group.command("create", help="Create one normalized role in the active relational catalog.")
    @click_module.argument("role")
    def create_command(role: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        role_cli_context = _resolve_role_cli_context(ctx, config)
        role_names = _run_role_cli_operation(role_cli_context.role_admin.create_role(role=role))
        click_module.echo(_format_role_catalog_snapshot(role_names))

    @group.command("delete", help="Delete one normalized role from the active relational catalog.")
    @click_module.option(
        "--force",
        is_flag=True,
        help="Also remove dependent user-role assignments for the deleted role.",
    )
    @click_module.argument("role")
    def delete_command(role: str, *, force: bool) -> None:
        ctx = cast("Context", click_module.get_current_context())
        role_cli_context = _resolve_role_cli_context(ctx, config)
        role_names = _run_role_cli_operation(role_cli_context.role_admin.delete_role(role=role, force=force))
        click_module.echo(_format_role_catalog_snapshot(role_names))


@cache
def _load_click_module() -> ModuleType:
    """Return the active Click-compatible module used by Litestar's CLI surface."""
    try:
        return importlib.import_module("rich_click")
    except ImportError:
        return importlib.import_module("click")


def _run_role_cli_operation[T](operation: Coroutine[Any, Any, T]) -> T:
    """Run one async role-admin operation and surface operator-facing failures.

    Returns:
        The result returned by the async role-admin operation.

    Raises:
        ClickException: If the role-admin operation fails with an operator-facing error.
    """
    try:
        return asyncio.run(operation)
    except (ConfigurationError, LookupError, ValueError) as exc:
        raise ClickException(str(exc)) from exc


def _format_user_role_membership(membership: UserRoleMembership) -> str:
    """Return one deterministic text snapshot for CLI output."""
    return f"{membership.email}: {membership.roles!r}"


def _format_role_catalog_snapshot(role_names: list[str]) -> str:
    """Return one deterministic text snapshot for role-catalog CLI output."""
    return f"{role_names!r}"
