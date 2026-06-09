"""Lazy CLI registration for plugin-managed organization administration."""

from __future__ import annotations

import asyncio
import importlib
import sys
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Any, Protocol, cast

from litestar.cli._utils import ClickException, Context, Group  # noqa: PLC2701

from litestar_auth.exceptions import ConfigurationError, OrganizationAdminError

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from types import ModuleType

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth._plugin.scoped_session import SessionFactory
    from litestar_auth.db import BaseOrganizationStore
    from litestar_auth.extensions import AuthExtensionRegistrationContext, AuthExtensionValidationContext

_ORGANIZATION_CLI_CONTEXT_KEY = "litestar_auth.organization_cli"
_CLI_LIST_LIMIT = 2_147_483_647


class _OrganizationCLIRow(Protocol):
    """Minimal organization row surface used by CLI output formatting."""

    id: object
    slug: str
    name: str


class _MembershipCLIRow(Protocol):
    """Minimal membership row surface used by CLI output formatting."""

    organization_id: object
    user_id: object
    roles: list[str]


class _InvitationCLIRow(Protocol):
    """Minimal invitation row surface used by CLI output formatting."""

    id: object
    organization_id: object
    invited_email: str
    roles: list[str]
    expires_at: object
    status: str


@dataclass(frozen=True, slots=True)
class OrganizationCLIContext[ID]:
    """Resolved CLI context for the active plugin-owned organizations command group."""

    config: LitestarAuthConfig[Any, ID]
    session_maker: SessionFactory
    store_factory: Callable[[Any], BaseOrganizationStore[Any, Any, Any, ID]]
    id_parser: Callable[[str], ID] | None


def register_organizations_cli[ID](
    cli: Group,
    config: LitestarAuthConfig[Any, ID],
) -> None:
    """Register the plugin-owned ``organizations`` group when org administration is enabled."""
    organization_config = config.organization_config
    if (
        not organization_config.enabled
        or not organization_config.include_organization_admin
        or organization_config.store_factory is None
        or cli.commands.get("organizations") is not None
    ):
        return
    cli.add_command(build_organizations_group(cli, config))


class _OrganizationCliExtension:
    """Internal extension that owns plugin-managed organization CLI commands."""

    name = "organization_cli"
    enabled = True

    @staticmethod
    def validate(context: AuthExtensionValidationContext) -> None:
        """CLI registration validates lazily when the command group is invoked."""

    @staticmethod
    def register(context: AuthExtensionRegistrationContext) -> None:
        """CLI registration is separate from app-startup wiring."""

    @staticmethod
    def register_cli[ID](cli: Group, config: LitestarAuthConfig[Any, ID]) -> None:
        """Register the organization CLI group through the extension CLI contract."""
        register_organizations_cli(cli, config)


def build_organizations_group[ID](
    cli: Group,
    config: LitestarAuthConfig[Any, ID],
) -> Group:
    """Build the lazily validated ``organizations`` command group for one plugin config.

    Returns:
        The plugin-owned Click group bound to the active Litestar CLI class.
    """
    group_class = getattr(cli, "group_class", type(cli))
    help_text = "Manage organizations and memberships through the active LitestarAuth plugin configuration."

    def organizations_group(ctx: Context) -> None:
        _resolve_organization_cli_context(ctx, config)
        if ctx.invoked_subcommand is None:
            sys.stdout.write(ctx.command.get_help(ctx))

    group = cast(
        "Group",
        group_class(
            name="organizations",
            callback=organizations_group,
            invoke_without_command=True,
            help=help_text,
        ),
    )
    _register_organization_commands(group, config)
    _register_membership_commands(group, config)
    _register_invitation_commands(group, config)
    return group


def _resolve_organization_cli_context[ID](
    ctx: Context,
    config: LitestarAuthConfig[Any, ID],
) -> OrganizationCLIContext[ID]:
    """Resolve and cache organization-admin CLI prerequisites for one invocation.

    Returns:
        The resolved plugin-owned organization CLI context.

    Raises:
        ClickException: If the plugin configuration cannot support CLI organization management.
    """
    cached_context = ctx.meta.get(_ORGANIZATION_CLI_CONTEXT_KEY)
    if cached_context is not None:
        return cast("OrganizationCLIContext[ID]", cached_context)

    organization_config = config.organization_config
    if not organization_config.enabled or not organization_config.include_organization_admin:
        msg = "Organization admin CLI requires OrganizationConfig(enabled=True, include_organization_admin=True)."
        raise ClickException(msg)
    if organization_config.store_factory is None:
        msg = "Organization admin CLI requires organization_config.store_factory."
        raise ClickException(msg)
    if config.session_maker is None:
        msg = "Organization admin CLI requires LitestarAuthConfig.session_maker."
        raise ClickException(msg)

    organization_cli_context = OrganizationCLIContext(
        config=config,
        session_maker=config.session_maker,
        store_factory=organization_config.store_factory,
        id_parser=config.id_parser,
    )
    ctx.meta[_ORGANIZATION_CLI_CONTEXT_KEY] = organization_cli_context
    return organization_cli_context


def _register_organization_commands[ID](group: Group, config: LitestarAuthConfig[Any, ID]) -> None:
    """Register organization catalog commands on the plugin-owned group."""
    click_module = cast("Any", _load_click_module())

    @group.command("create", help="Create one organization.")
    @click_module.option("--slug", "slug", required=True, help="Organization slug.")
    @click_module.option("--name", "name", required=True, help="Organization display name.")
    def create_command(slug: str, name: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        organization = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.create_organization(slug=slug, name=name),
        )
        click_module.echo(_format_organization(organization))

    @group.command("get", help="Show one organization by identifier.")
    @click_module.argument("organization_id")
    def get_command(organization_id: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        organization = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.get_organization(parsed_organization_id),
        )
        click_module.echo(_format_organization(organization))

    @group.command("list", help="List organizations, optionally scoped to one user.")
    @click_module.option("--user-id", "user_id", default=None, help="List only organizations for this user id.")
    def list_command(user_id: str | None) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        if user_id is None:
            msg = "Organization CLI list requires --user-id until the store contract exposes catalog-wide listing."
            raise ClickException(msg)
        parsed_user_id = _parse_cli_id(organization_cli_context, user_id)
        organizations, _total = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.list_organizations_for_user(parsed_user_id, offset=0, limit=_CLI_LIST_LIMIT),
        )
        click_module.echo(_format_organizations(organizations))

    @group.command("update", help="Update one organization.")
    @click_module.option("--slug", "slug", required=True, help="Replacement organization slug.")
    @click_module.option("--name", "name", required=True, help="Replacement organization display name.")
    @click_module.argument("organization_id")
    def update_command(organization_id: str, slug: str, name: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        organization = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.update_organization(parsed_organization_id, slug=slug, name=name),
        )
        click_module.echo(_format_organization(organization))

    @group.command("delete", help="Delete one organization and its memberships.")
    @click_module.argument("organization_id")
    def delete_command(organization_id: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.delete_organization(parsed_organization_id),
        )
        click_module.echo("deleted")


def _register_membership_commands[ID](group: Group, config: LitestarAuthConfig[Any, ID]) -> None:
    """Register organization-membership commands on the plugin-owned group."""
    click_module = cast("Any", _load_click_module())

    @group.command("add-member", help="Add one organization member.")
    @click_module.argument("organization_id")
    @click_module.argument("user_id")
    @click_module.argument("roles", nargs=-1, required=True)
    def add_member_command(organization_id: str, user_id: str, roles: tuple[str, ...]) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        parsed_user_id = _parse_cli_id(organization_cli_context, user_id)
        membership = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.add_member(
                organization_id=parsed_organization_id,
                user_id=parsed_user_id,
                roles=roles,
            ),
        )
        click_module.echo(_format_membership(membership))

    @group.command("remove-member", help="Remove one organization member.")
    @click_module.argument("organization_id")
    @click_module.argument("user_id")
    def remove_member_command(organization_id: str, user_id: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        parsed_user_id = _parse_cli_id(organization_cli_context, user_id)
        _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.remove_member(organization_id=parsed_organization_id, user_id=parsed_user_id),
        )
        click_module.echo("removed")

    @group.command("list-members", help="List memberships for one organization.")
    @click_module.argument("organization_id")
    def list_members_command(organization_id: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        memberships, _total = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.list_members(parsed_organization_id, offset=0, limit=_CLI_LIST_LIMIT),
        )
        click_module.echo(_format_memberships(memberships))

    @group.command("set-member-roles", help="Replace roles for one organization member.")
    @click_module.argument("organization_id")
    @click_module.argument("user_id")
    @click_module.argument("roles", nargs=-1, required=True)
    def set_member_roles_command(organization_id: str, user_id: str, roles: tuple[str, ...]) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        parsed_user_id = _parse_cli_id(organization_cli_context, user_id)
        membership = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.set_member_roles(
                organization_id=parsed_organization_id,
                user_id=parsed_user_id,
                roles=roles,
            ),
        )
        click_module.echo(_format_membership(membership))


def _register_invitation_commands[ID](group: Group, config: LitestarAuthConfig[Any, ID]) -> None:
    """Register organization-invitation commands on the plugin-owned group."""
    click_module = cast("Any", _load_click_module())

    @group.command("invite-member", help="Invite one email address to an organization.")
    @click_module.argument("organization_id")
    @click_module.argument("invited_email")
    @click_module.argument("roles", nargs=-1, required=True)
    def invite_member_command(organization_id: str, invited_email: str, roles: tuple[str, ...]) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        invitation = _run_organization_invitation_cli_operation(
            organization_cli_context,
            lambda admin, user_manager: admin.invite_member(
                organization_id=parsed_organization_id,
                invited_email=invited_email,
                roles=roles,
                user_manager=user_manager,
            ),
        )
        click_module.echo(_format_invitation(invitation.invitation))

    @group.command("list-pending-invitations", help="List pending invitations for one organization.")
    @click_module.argument("organization_id")
    def list_pending_invitations_command(organization_id: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_organization_id = _parse_cli_id(organization_cli_context, organization_id)
        invitations, _total = _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.list_pending_invitations(parsed_organization_id, offset=0, limit=_CLI_LIST_LIMIT),
        )
        click_module.echo(_format_invitations(invitations))

    @group.command("revoke-invitation", help="Revoke one pending organization invitation.")
    @click_module.argument("invitation_id")
    def revoke_invitation_command(invitation_id: str) -> None:
        ctx = cast("Context", click_module.get_current_context())
        organization_cli_context = _resolve_organization_cli_context(ctx, config)
        parsed_invitation_id = _parse_cli_id(organization_cli_context, invitation_id)
        _run_organization_cli_operation(
            organization_cli_context,
            lambda admin: admin.revoke_invitation(parsed_invitation_id),
        )
        click_module.echo("revoked")


@cache
def _load_click_module() -> ModuleType:
    """Return the active Click-compatible module used by Litestar's CLI surface."""
    try:
        return importlib.import_module("rich_click")
    except ImportError:
        return importlib.import_module("click")


def _parse_cli_id[ID](context: OrganizationCLIContext[ID], raw_id: str) -> ID:
    """Parse a CLI identifier through the configured application id parser.

    Returns:
        Parsed identifier, or the raw string when no parser is configured.

    Raises:
        ClickException: If the configured id parser rejects the value.
    """
    if context.id_parser is None:
        return cast("ID", raw_id)
    try:
        return context.id_parser(raw_id)
    except (TypeError, ValueError) as exc:
        msg = f"Invalid identifier {raw_id!r}."
        raise ClickException(msg) from exc


def _run_organization_cli_operation[T, ID](
    context: OrganizationCLIContext[ID],
    operation_factory: Callable[[Any], Coroutine[Any, Any, T]],
) -> T:
    """Run one async organization-admin operation and surface operator-facing failures.

    Returns:
        The result returned by the async organization-admin operation.

    Raises:
        ClickException: If the organization-admin operation fails with an operator-facing error.
    """

    async def _run() -> T:
        from litestar_auth._plugin.organization_admin import SQLAlchemyOrganizationAdmin  # noqa: PLC0415

        session_context = cast("Any", context.session_maker())
        if not hasattr(session_context, "__aenter__") or not hasattr(session_context, "__aexit__"):
            msg = "Organization admin CLI requires session_maker() to return an async context manager."
            raise ConfigurationError(msg)
        async with session_context as session:
            admin = SQLAlchemyOrganizationAdmin(store=context.store_factory(session))
            result = await operation_factory(admin)
            await session.commit()
            return result

    try:
        return asyncio.run(_run())
    except (ConfigurationError, OrganizationAdminError, LookupError, ValueError) as exc:
        raise ClickException(str(exc)) from exc


def _run_organization_invitation_cli_operation[T, ID](
    context: OrganizationCLIContext[ID],
    operation_factory: Callable[[Any, Any], Coroutine[Any, Any, T]],
) -> T:
    """Run one async invitation operation with a plugin-built user manager.

    Returns:
        The invitation operation result.

    Raises:
        ClickException: If configuration or operation validation fails.
    """

    async def _run() -> T:
        from litestar_auth._plugin.organization_admin import SQLAlchemyOrganizationAdmin  # noqa: PLC0415
        from litestar_auth._plugin.user_manager_builder import resolve_user_manager_factory  # noqa: PLC0415

        session_context = cast("Any", context.session_maker())
        if not hasattr(session_context, "__aenter__") or not hasattr(session_context, "__aexit__"):
            msg = "Organization admin CLI requires session_maker() to return an async context manager."
            raise ConfigurationError(msg)
        async with session_context as session:
            admin = SQLAlchemyOrganizationAdmin(store=context.store_factory(session))
            user_db = context.config.resolve_user_db_factory()(session)
            user_manager = resolve_user_manager_factory(context.config)(
                session=session,
                user_db=user_db,
                config=context.config,
                backends=tuple(context.config.resolve_backends(session)),
            )
            result = await operation_factory(admin, user_manager)
            await session.commit()
            return result

    try:
        return asyncio.run(_run())
    except (ConfigurationError, OrganizationAdminError, LookupError, ValueError) as exc:
        raise ClickException(str(exc)) from exc


def _format_organization(organization: object) -> str:
    """Return one deterministic text snapshot for a CLI organization row."""
    organization_row = cast("_OrganizationCLIRow", organization)
    return f"{organization_row.id}: {organization_row.slug!r} {organization_row.name!r}"


def _format_organizations(organizations: list[object]) -> str:
    """Return one deterministic text snapshot for CLI organization rows."""
    return "\n".join(_format_organization(organization) for organization in organizations)


def _format_membership(membership: object) -> str:
    """Return one deterministic text snapshot for a CLI membership row."""
    membership_row = cast("_MembershipCLIRow", membership)
    return f"{membership_row.organization_id} {membership_row.user_id}: {list(membership_row.roles)!r}"


def _format_memberships(memberships: list[object]) -> str:
    """Return one deterministic text snapshot for CLI membership rows."""
    return "\n".join(_format_membership(membership) for membership in memberships)


def _format_invitation(invitation: object) -> str:
    """Return one deterministic text snapshot for a CLI invitation row."""
    invitation_row = cast("_InvitationCLIRow", invitation)
    return (
        f"{invitation_row.id} {invitation_row.organization_id}: "
        f"{invitation_row.invited_email!r} {list(invitation_row.roles)!r} "
        f"{invitation_row.status!r} expires_at={invitation_row.expires_at}"
    )


def _format_invitations(invitations: list[object]) -> str:
    """Return one deterministic text snapshot for CLI invitation rows."""
    return "\n".join(_format_invitation(invitation) for invitation in invitations)
