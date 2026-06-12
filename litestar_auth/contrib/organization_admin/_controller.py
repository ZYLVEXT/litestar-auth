"""Opt-in factory for the contrib organization-administration controller surface."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Protocol, TypedDict, Unpack, cast, overload

import msgspec
from litestar import Controller, Request, delete, get, patch, post
from litestar.di import NamedDependency
from litestar.exceptions import PermissionDeniedException
from litestar.params import PathParameter, QueryParameter
from litestar.status_codes import HTTP_200_OK, HTTP_204_NO_CONTENT

from litestar_auth._plugin.organization_admin import SQLAlchemyOrganizationAdmin
from litestar_auth._superuser_role import is_global_superuser
from litestar_auth.contrib.organization_admin._error_responses import _map_organization_admin_error
from litestar_auth.contrib.organization_admin._schemas import (
    MembershipCreate,
    MembershipRead,
    MembershipRolesUpdate,
    OrganizationCreate,
    OrganizationInvitationCreate,
    OrganizationInvitationRead,
    OrganizationInvitationTokenRequest,
    OrganizationRead,
    OrganizationUpdate,
)
from litestar_auth.controllers._utils import (
    RequestBodyErrorConfig,
    RequestHandler,
    _build_controller_name,
    _configure_request_body_handler,
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _create_request_body_exception_handlers,
    _finalize_route_handler,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.db import BaseOrganizationStore
from litestar_auth.exceptions import (
    ConfigurationError,
    ErrorCode,
    InvalidOrganizationInvitationTokenError,
    OrganizationAdminError,
    OrganizationMembershipNotFoundError,
    OrganizationNotFoundError,
)
from litestar_auth.guards import is_active, is_superuser, is_verified

if TYPE_CHECKING:
    from datetime import datetime

    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import Guard

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth._plugin.organization_admin._mutations import _OrganizationInvitationManager
    from litestar_auth.ratelimit import AuthRateLimitConfig

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 100
_LimitQuery = Annotated[int, QueryParameter(name="limit", ge=1, le=_MAX_LIMIT)]
_OffsetQuery = Annotated[int, QueryParameter(name="offset", ge=0)]
_OrganizationIdPath = Annotated[str, PathParameter()]
_InvitationIdPath = Annotated[str, PathParameter()]
_UserIdPath = Annotated[str, PathParameter()]
_UserIdQuery = Annotated[str, QueryParameter(name="user_id")]
_OrganizationStoreDep = NamedDependency[BaseOrganizationStore[Any, Any, Any, Any]]
_UserManagerDep = NamedDependency[object]
type IdParser[ID] = Callable[[str], ID]


@dataclass(frozen=True, slots=True)
class OrganizationAdminControllerConfig[ID]:
    """Configuration for :func:`create_organization_admin_controller`."""

    config: LitestarAuthConfig[Any, ID] | None = None
    id_parser: IdParser[ID] | None = None
    route_prefix: str = "organizations"
    guards: Sequence[Guard] | None = None


class OrganizationAdminControllerOptions[ID](TypedDict, total=False):
    """Keyword options accepted by :func:`create_organization_admin_controller`."""

    config: LitestarAuthConfig[Any, ID] | None
    id_parser: IdParser[ID] | None
    route_prefix: str
    guards: Sequence[Guard] | None


@dataclass(frozen=True, slots=True)
class _OrganizationAdminControllerContext[ID]:
    id_parser: IdParser[ID]
    organization_page_schema_type: type[msgspec.Struct]
    membership_page_schema_type: type[msgspec.Struct]
    invitation_page_schema_type: type[msgspec.Struct]


class _OrganizationAdminControllerBase(Controller):
    organization_admin_context: ClassVar[object]


@dataclass(frozen=True, slots=True)
class OrganizationInvitationControllerConfig:
    """Configuration for :func:`create_organization_invitation_controller`."""

    config: LitestarAuthConfig[Any, Any] | None = None
    path: str = "/auth"
    rate_limit_config: AuthRateLimitConfig | None = None
    security: Sequence[SecurityRequirement] | None = None


class _OrganizationInvitationControllerBase(Controller):
    organization_invitation_context: ClassVar[object]


@dataclass(frozen=True, slots=True)
class _OrganizationInvitationControllerContext:
    accept_before_request: RequestHandler | None
    accept_increment: RequestHandler
    accept_reset: RequestHandler
    decline_before_request: RequestHandler | None
    decline_increment: RequestHandler
    decline_reset: RequestHandler
    security: Sequence[SecurityRequirement] | None


class _OrganizationReadRow(Protocol):
    id: object
    slug: str
    name: str


class _MembershipReadRow(Protocol):
    organization_id: object
    user_id: object
    roles: Sequence[str]


class _InvitationReadRow(Protocol):
    id: object
    organization_id: object
    invited_email: str
    roles: Sequence[str]
    expires_at: datetime
    status: str


def _normalize_route_prefix(route_prefix: str) -> str:
    normalized_route_prefix = route_prefix.strip("/")
    if normalized_route_prefix:
        return normalized_route_prefix

    msg = "create_organization_admin_controller route_prefix must not be empty."
    raise ConfigurationError(msg)


def _resolve_settings[ID](
    *,
    controller_config: OrganizationAdminControllerConfig[ID] | None,
    options: OrganizationAdminControllerOptions[ID],
) -> OrganizationAdminControllerConfig[ID]:
    if controller_config is not None and options:
        msg = "Pass either OrganizationAdminControllerConfig or keyword options, not both."
        raise ValueError(msg)
    return OrganizationAdminControllerConfig(**options) if controller_config is None else controller_config


def _resolve_id_parser[ID](settings: OrganizationAdminControllerConfig[ID]) -> IdParser[ID]:
    if settings.id_parser is not None:
        return settings.id_parser
    if settings.config is not None and settings.config.id_parser is not None:
        return settings.config.id_parser

    msg = "create_organization_admin_controller requires id_parser directly or on the provided config."
    raise ConfigurationError(msg)


def _resolve_admin_guards(settings: OrganizationAdminControllerConfig[Any]) -> list[Guard]:
    """Resolve the controller-level guards, defaulting to global superuser.

    Custom guards MUST express *global* administrative authority (e.g. ``is_superuser``).
    Do not pass the org-scoped guards ``has_organization_role`` / ``has_organization_permission``
    here: those authorize the tenant-resolved *current* organization, not the ``organization_id``
    in the request path, so using them on these routes would not scope authority to the addressed
    organization. Path-scoped routes additionally enforce per-organization authority in depth via
    :func:`_require_path_organization_authority`. The org-less catalog routes (create organization,
    list a user's organizations) additionally enforce :func:`_require_global_organization_catalog_admin`.
    Revoke-by-invitation id verifies authority against the invitation's organization.

    Returns:
        The resolved controller-level guard list.

    Raises:
        ConfigurationError: If an empty guard sequence is supplied.
    """
    if settings.guards is None:
        return [is_superuser]
    if not settings.guards:
        msg = "create_organization_admin_controller guards must not be empty."
        raise ConfigurationError(msg)
    return list(settings.guards)


def _create_organization_page_schema_type() -> type[msgspec.Struct]:
    return msgspec.defstruct(
        "OrganizationPageSchema",
        [
            ("items", list[OrganizationRead]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )


def _create_membership_page_schema_type() -> type[msgspec.Struct]:
    return msgspec.defstruct(
        "OrganizationMembershipPageSchema",
        [
            ("items", list[MembershipRead]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )


def _create_invitation_page_schema_type() -> type[msgspec.Struct]:
    return msgspec.defstruct(
        "OrganizationInvitationPageSchema",
        [
            ("items", list[OrganizationInvitationRead]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )


def _context[ID](controller: _OrganizationAdminControllerBase) -> _OrganizationAdminControllerContext[ID]:
    return cast("_OrganizationAdminControllerContext[ID]", controller.organization_admin_context)


def _admin[ORG, MEMBERSHIP, INVITATION, ID](
    store: BaseOrganizationStore[ORG, MEMBERSHIP, INVITATION, ID],
) -> SQLAlchemyOrganizationAdmin[ORG, MEMBERSHIP, INVITATION, ID]:
    return SQLAlchemyOrganizationAdmin(store=store)


def _organization_read(organization: object) -> OrganizationRead:
    row = cast("_OrganizationReadRow", organization)
    return OrganizationRead(
        id=str(row.id),
        slug=row.slug,
        name=row.name,
    )


def _membership_read(membership: object) -> MembershipRead:
    row = cast("_MembershipReadRow", membership)
    return MembershipRead(
        organization_id=str(row.organization_id),
        user_id=str(row.user_id),
        roles=list(row.roles),
    )


def _invitation_read(invitation: object) -> OrganizationInvitationRead:
    row = cast("_InvitationReadRow", invitation)
    return OrganizationInvitationRead(
        id=str(row.id),
        organization_id=str(row.organization_id),
        invited_email=row.invited_email,
        roles=list(row.roles),
        expires_at=row.expires_at.isoformat(),
        status=row.status,
    )


def _to_organization_invitation_manager(user_manager: object) -> _OrganizationInvitationManager:
    return cast("_OrganizationInvitationManager", user_manager)


def _parse_id[ID](context: _OrganizationAdminControllerContext[ID], raw_id: str) -> ID:
    try:
        return context.id_parser(raw_id)
    except (TypeError, ValueError) as exc:
        raise _map_organization_admin_error(OrganizationNotFoundError()) from exc


def _parse_user_id[ID](context: _OrganizationAdminControllerContext[ID], raw_id: str) -> ID:
    try:
        return context.id_parser(raw_id)
    except (TypeError, ValueError) as exc:
        raise _map_organization_admin_error(OrganizationMembershipNotFoundError()) from exc


def _parse_invitation_id[ID](context: _OrganizationAdminControllerContext[ID], raw_id: str) -> ID:
    try:
        return context.id_parser(raw_id)
    except (TypeError, ValueError) as exc:
        raise _map_organization_admin_error(InvalidOrganizationInvitationTokenError()) from exc


def _map_error(exc: OrganizationAdminError) -> None:
    raise _map_organization_admin_error(exc) from exc


_PATH_ORGANIZATION_AUTHORITY_DENIED_DETAIL = (
    "The authenticated user lacks administrative authority over the target organization."
)
_GLOBAL_ORGANIZATION_CATALOG_DENIED_DETAIL = "Global organization catalog administration is required for this route."


def _require_global_organization_catalog_admin(request: Request[Any, Any, Any]) -> None:
    """Fail closed on org-less catalog routes unless the caller is a global superuser.

    Org-scoped guards such as ``has_organization_role`` authorize the tenant-resolved current
    organization, not global catalog operations such as creating organizations or listing another
    user's organization memberships.

    Raises:
        PermissionDeniedException: When the caller is not a global superuser.
    """
    if is_global_superuser(request):
        return
    raise PermissionDeniedException(
        detail=_GLOBAL_ORGANIZATION_CATALOG_DENIED_DETAIL,
        extra={"code": ErrorCode.AUTHORIZATION_DENIED},
    )


async def _require_path_organization_authority(
    *,
    request: Request[Any, Any, Any],
    organization_id: object,
    admin: SQLAlchemyOrganizationAdmin[Any, Any, Any, Any],
) -> None:
    """Fail closed unless the caller has authority over the *path* organization.

    Defense in depth: the controller class guard is the primary access gate, but it is
    configurable. Notably the org-scoped guards ``has_organization_role`` and
    ``has_organization_permission`` authorize the tenant-resolved *current* organization,
    not the ``organization_id`` taken from the request path. Without this backstop a member
    privileged in one organization could administer another by addressing it via path id.

    Raises:
        PermissionDeniedException: When the caller is neither a global superuser nor a
            privileged member of the path organization.
    """
    # Global superusers administer every organization and hold no per-organization
    # membership, so the default ``is_superuser`` admin flow is preserved unchanged.
    if is_global_superuser(request):
        return
    user_id = getattr(request.user, "id", None)
    if user_id is not None and await admin.caller_has_organization_authority(
        organization_id=organization_id,
        user_id=user_id,
    ):
        return
    raise PermissionDeniedException(
        detail=_PATH_ORGANIZATION_AUTHORITY_DENIED_DETAIL,
        extra={"code": ErrorCode.AUTHORIZATION_DENIED},
    )


def _create_controller_type(controller_name: str) -> type[_OrganizationAdminControllerBase]:  # noqa: C901
    exception_handlers = _create_request_body_exception_handlers(
        RequestBodyErrorConfig(
            validation_detail="Invalid organization-admin payload.",
            validation_code=ErrorCode.REQUEST_BODY_INVALID,
        ),
    )

    class OrganizationAdminController(_OrganizationAdminControllerBase):
        @get()
        async def list_user_organizations(
            self,
            request: Request[Any, Any, Any],
            user_id: _UserIdQuery,
            litestar_auth_organization_store: _OrganizationStoreDep,
            limit: _LimitQuery = _DEFAULT_LIMIT,
            offset: _OffsetQuery = 0,
        ) -> msgspec.Struct:
            _require_global_organization_catalog_admin(request)
            context = _context(self)
            parsed_user_id = _parse_user_id(context, user_id)
            organizations, total = await _admin(litestar_auth_organization_store).list_organizations_for_user(
                parsed_user_id,
                offset=offset,
                limit=limit,
            )
            return context.organization_page_schema_type(
                items=[_organization_read(organization) for organization in organizations],
                total=total,
                limit=limit,
                offset=offset,
            )

        @post(status_code=201, exception_handlers=exception_handlers)
        async def create_organization(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: msgspec.Struct,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> OrganizationRead:
            _require_global_organization_catalog_admin(request)
            payload = cast("OrganizationCreate", data)
            try:
                organization = await _admin(litestar_auth_organization_store).create_organization(
                    slug=payload.slug,
                    name=payload.name,
                )
            except OrganizationAdminError as exc:
                _map_error(exc)
            return _organization_read(organization)

        @get("/{organization_id:str}")
        async def get_organization(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> OrganizationRead:
            context = _context(self)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            try:
                organization = await _admin(litestar_auth_organization_store).get_organization(parsed_organization_id)
            except OrganizationAdminError as exc:
                _map_error(exc)
            return _organization_read(organization)

        @patch("/{organization_id:str}", exception_handlers=exception_handlers)
        async def update_organization(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            data: msgspec.Struct,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> OrganizationRead:
            context = _context(self)
            payload = cast("OrganizationUpdate", data)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            try:
                organization = await _admin(litestar_auth_organization_store).update_organization(
                    parsed_organization_id,
                    slug=payload.slug,
                    name=payload.name,
                )
            except OrganizationAdminError as exc:
                _map_error(exc)
            return _organization_read(organization)

        @delete("/{organization_id:str}", status_code=204)
        async def delete_organization(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> None:
            context = _context(self)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            try:
                await _admin(litestar_auth_organization_store).delete_organization(parsed_organization_id)
            except OrganizationAdminError as exc:
                _map_error(exc)

        @post("/{organization_id:str}/members/{user_id:str}", status_code=201, exception_handlers=exception_handlers)
        async def add_member(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            user_id: _UserIdPath,
            data: msgspec.Struct,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> MembershipRead:
            context = _context(self)
            payload = cast("MembershipCreate", data)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            parsed_user_id = _parse_user_id(context, user_id)
            try:
                membership = await _admin(litestar_auth_organization_store).add_member(
                    organization_id=parsed_organization_id,
                    user_id=parsed_user_id,
                    roles=payload.roles,
                )
            except OrganizationAdminError as exc:
                _map_error(exc)
            return _membership_read(membership)

        @post("/{organization_id:str}/invitations", status_code=201, exception_handlers=exception_handlers)
        async def invite_member(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            data: msgspec.Struct,
            litestar_auth_organization_store: _OrganizationStoreDep,
            litestar_auth_user_manager: _UserManagerDep,
        ) -> OrganizationInvitationRead:
            context = _context(self)
            payload = cast("OrganizationInvitationCreate", data)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            try:
                issue = await _admin(litestar_auth_organization_store).invite_member(
                    organization_id=parsed_organization_id,
                    invited_email=payload.invited_email,
                    roles=payload.roles,
                    user_manager=_to_organization_invitation_manager(litestar_auth_user_manager),
                )
            except OrganizationAdminError as exc:
                _map_error(exc)
            return _invitation_read(issue.invitation)

        @get("/{organization_id:str}/invitations")
        async def list_pending_invitations(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            litestar_auth_organization_store: _OrganizationStoreDep,
            limit: _LimitQuery = _DEFAULT_LIMIT,
            offset: _OffsetQuery = 0,
        ) -> msgspec.Struct:
            context = _context(self)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            try:
                invitations, total = await _admin(litestar_auth_organization_store).list_pending_invitations(
                    parsed_organization_id,
                    offset=offset,
                    limit=limit,
                )
            except OrganizationAdminError as exc:
                _map_error(exc)
            return context.invitation_page_schema_type(
                items=[_invitation_read(invitation) for invitation in invitations],
                total=total,
                limit=limit,
                offset=offset,
            )

        @delete("/invitations/{invitation_id:str}", status_code=204)
        async def revoke_invitation(
            self,
            request: Request[Any, Any, Any],
            invitation_id: _InvitationIdPath,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> None:
            context = _context(self)
            parsed_invitation_id = _parse_invitation_id(context, invitation_id)
            admin = _admin(litestar_auth_organization_store)
            # The route addresses an invitation by id, so authority is verified against the
            # invitation's own organization. A missing invitation yields no organization id,
            # which denies non-superusers without leaking invitation existence.
            invitation = await admin.get_invitation(parsed_invitation_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=getattr(invitation, "organization_id", None),
                admin=admin,
            )
            try:
                await admin.revoke_invitation(parsed_invitation_id)
            except OrganizationAdminError as exc:
                _map_error(exc)

        @get("/{organization_id:str}/members")
        async def list_members(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            litestar_auth_organization_store: _OrganizationStoreDep,
            limit: _LimitQuery = _DEFAULT_LIMIT,
            offset: _OffsetQuery = 0,
        ) -> msgspec.Struct:
            context = _context(self)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            try:
                memberships, total = await _admin(litestar_auth_organization_store).list_members(
                    parsed_organization_id,
                    offset=offset,
                    limit=limit,
                )
            except OrganizationAdminError as exc:
                _map_error(exc)
            return context.membership_page_schema_type(
                items=[_membership_read(membership) for membership in memberships],
                total=total,
                limit=limit,
                offset=offset,
            )

        @patch(
            "/{organization_id:str}/members/{user_id:str}/roles",
            status_code=200,
            exception_handlers=exception_handlers,
        )
        async def set_member_roles(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            user_id: _UserIdPath,
            data: msgspec.Struct,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> MembershipRead:
            context = _context(self)
            payload = cast("MembershipRolesUpdate", data)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            parsed_user_id = _parse_user_id(context, user_id)
            try:
                membership = await _admin(litestar_auth_organization_store).set_member_roles(
                    organization_id=parsed_organization_id,
                    user_id=parsed_user_id,
                    roles=payload.roles,
                )
            except OrganizationAdminError as exc:
                _map_error(exc)
            return _membership_read(membership)

        @delete("/{organization_id:str}/members/{user_id:str}", status_code=204)
        async def remove_member(
            self,
            request: Request[Any, Any, Any],
            organization_id: _OrganizationIdPath,
            user_id: _UserIdPath,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> None:
            context = _context(self)
            parsed_organization_id = _parse_id(context, organization_id)
            await _require_path_organization_authority(
                request=request,
                organization_id=parsed_organization_id,
                admin=_admin(litestar_auth_organization_store),
            )
            parsed_user_id = _parse_user_id(context, user_id)
            try:
                await _admin(litestar_auth_organization_store).remove_member(
                    organization_id=parsed_organization_id,
                    user_id=parsed_user_id,
                )
            except OrganizationAdminError as exc:
                _map_error(exc)

    OrganizationAdminController.__name__ = controller_name
    OrganizationAdminController.__qualname__ = controller_name
    return OrganizationAdminController


def _finalize_controller[ID](
    controller_cls: type[_OrganizationAdminControllerBase],
    *,
    settings: OrganizationAdminControllerConfig[ID],
    normalized_route_prefix: str,
) -> type[Controller]:
    controller_cls.path = f"/{normalized_route_prefix}"
    controller_cls.guards = _resolve_admin_guards(settings)
    controller_cls.organization_admin_context = _OrganizationAdminControllerContext(
        id_parser=_resolve_id_parser(settings),
        organization_page_schema_type=_create_organization_page_schema_type(),
        membership_page_schema_type=_create_membership_page_schema_type(),
        invitation_page_schema_type=_create_invitation_page_schema_type(),
    )
    controller_for_body_config = cast("Any", controller_cls)
    _configure_request_body_handler(controller_for_body_config.create_organization, schema=OrganizationCreate)
    _configure_request_body_handler(controller_for_body_config.update_organization, schema=OrganizationUpdate)
    _configure_request_body_handler(controller_for_body_config.add_member, schema=MembershipCreate)
    _configure_request_body_handler(controller_for_body_config.invite_member, schema=OrganizationInvitationCreate)
    _configure_request_body_handler(controller_for_body_config.set_member_roles, schema=MembershipRolesUpdate)
    for handler_name in (
        "list_user_organizations",
        "create_organization",
        "get_organization",
        "update_organization",
        "delete_organization",
        "add_member",
        "invite_member",
        "list_pending_invitations",
        "revoke_invitation",
        "list_members",
        "set_member_roles",
        "remove_member",
    ):
        setattr(controller_cls, handler_name, _finalize_route_handler(getattr(controller_cls, handler_name)))
    return _mark_litestar_auth_route_handler(cast("type[Controller]", controller_cls))


def _resolve_invitation_rate_limit_config(
    settings: OrganizationInvitationControllerConfig,
) -> AuthRateLimitConfig | None:
    if settings.rate_limit_config is not None:
        return settings.rate_limit_config
    if settings.config is not None:
        return settings.config.rate_limit_config
    return None


def _resolve_invitation_path(settings: OrganizationInvitationControllerConfig) -> str:
    if settings.config is not None and settings.path == "/auth":
        return settings.config.auth_path
    return settings.path


def _create_organization_invitation_controller_type(
    controller_name: str,
    *,
    ctx: _OrganizationInvitationControllerContext,
    security: Sequence[SecurityRequirement] | None,
) -> type[_OrganizationInvitationControllerBase]:
    exception_handlers = _create_request_body_exception_handlers(
        RequestBodyErrorConfig(
            validation_detail="Invalid organization-invitation payload.",
            validation_code=ErrorCode.REQUEST_BODY_INVALID,
        ),
    )

    class OrganizationInvitationController(_OrganizationInvitationControllerBase):
        @post(
            "/organization-invitations/accept",
            guards=[is_active, is_verified],
            status_code=HTTP_200_OK,
            before_request=ctx.accept_before_request,
            security=security,
            exception_handlers=exception_handlers,
        )
        async def accept_invitation(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: msgspec.Struct,
            litestar_auth_organization_store: _OrganizationStoreDep,
            litestar_auth_user_manager: _UserManagerDep,
        ) -> MembershipRead:
            try:
                membership = await _admin(litestar_auth_organization_store).accept_invitation(
                    token=cast("OrganizationInvitationTokenRequest", data).token,
                    user=request.user,
                    user_manager=_to_organization_invitation_manager(litestar_auth_user_manager),
                )
            except OrganizationAdminError as exc:
                await ctx.accept_increment(request)
                _map_error(exc)
            await ctx.accept_reset(request)
            return _membership_read(membership)

        @post(
            "/organization-invitations/decline",
            guards=[is_active, is_verified],
            status_code=HTTP_204_NO_CONTENT,
            before_request=ctx.decline_before_request,
            security=security,
            exception_handlers=exception_handlers,
        )
        async def decline_invitation(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: msgspec.Struct,
            litestar_auth_organization_store: _OrganizationStoreDep,
            litestar_auth_user_manager: _UserManagerDep,
        ) -> None:
            try:
                await _admin(litestar_auth_organization_store).decline_invitation(
                    token=cast("OrganizationInvitationTokenRequest", data).token,
                    user=request.user,
                    user_manager=_to_organization_invitation_manager(litestar_auth_user_manager),
                )
            except OrganizationAdminError as exc:
                await ctx.decline_increment(request)
                _map_error(exc)
            await ctx.decline_reset(request)

    OrganizationInvitationController.__name__ = controller_name
    OrganizationInvitationController.__qualname__ = controller_name
    return OrganizationInvitationController


def create_organization_invitation_controller(
    settings: OrganizationInvitationControllerConfig | None = None,
) -> type[Controller]:
    """Return a controller subclass for authenticated organization invitation use."""
    resolved_settings = settings or OrganizationInvitationControllerConfig()
    rate_limit_config = _resolve_invitation_rate_limit_config(resolved_settings)
    accept_rate_limit = rate_limit_config.organization_invitation_accept if rate_limit_config else None
    decline_rate_limit = rate_limit_config.organization_invitation_decline if rate_limit_config else None
    accept_increment, accept_reset = _create_rate_limit_handlers(accept_rate_limit)
    decline_increment, decline_reset = _create_rate_limit_handlers(decline_rate_limit)
    ctx = _OrganizationInvitationControllerContext(
        accept_before_request=_create_before_request_handler(accept_rate_limit),
        accept_increment=accept_increment,
        accept_reset=accept_reset,
        decline_before_request=_create_before_request_handler(decline_rate_limit),
        decline_increment=decline_increment,
        decline_reset=decline_reset,
        security=resolved_settings.security,
    )
    controller_cls = _create_organization_invitation_controller_type(
        "OrganizationInvitationController",
        ctx=ctx,
        security=resolved_settings.security,
    )
    controller_cls.path = _resolve_invitation_path(resolved_settings)
    controller_cls.organization_invitation_context = ctx
    controller_for_body_config = cast("Any", controller_cls)
    _configure_request_body_handler(
        controller_for_body_config.accept_invitation,
        schema=OrganizationInvitationTokenRequest,
    )
    _configure_request_body_handler(
        controller_for_body_config.decline_invitation,
        schema=OrganizationInvitationTokenRequest,
    )
    for handler_name in ("accept_invitation", "decline_invitation"):
        setattr(controller_cls, handler_name, _finalize_route_handler(getattr(controller_cls, handler_name)))
    return _mark_litestar_auth_route_handler(cast("type[Controller]", controller_cls))


@overload
def create_organization_admin_controller[ID](  # noqa: D418
    *,
    controller_config: OrganizationAdminControllerConfig[ID],
) -> type[Controller]:
    """Build an organization-admin controller from grouped settings."""


@overload
def create_organization_admin_controller[ID](  # noqa: D418
    **options: Unpack[OrganizationAdminControllerOptions[ID]],
) -> type[Controller]:
    """Build an organization-admin controller from keyword settings."""


def create_organization_admin_controller[ID](
    *,
    controller_config: OrganizationAdminControllerConfig[ID] | None = None,
    **options: Unpack[OrganizationAdminControllerOptions[ID]],
) -> type[Controller]:
    """Return a controller subclass scaffold for contrib organization administration."""
    settings = _resolve_settings(controller_config=controller_config, options=options)
    normalized_route_prefix = _normalize_route_prefix(settings.route_prefix)
    controller_name = f"{_build_controller_name(normalized_route_prefix)}OrganizationAdminController"
    return _finalize_controller(
        _create_controller_type(controller_name),
        settings=settings,
        normalized_route_prefix=normalized_route_prefix,
    )


__all__ = (
    "OrganizationAdminControllerConfig",
    "OrganizationInvitationControllerConfig",
    "create_organization_admin_controller",
    "create_organization_invitation_controller",
)
