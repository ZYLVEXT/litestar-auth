"""Opt-in factory for the contrib role-administration controller surface."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, cast

import msgspec
from litestar import Controller, Request, delete, get, patch, post
from litestar.exceptions import ClientException
from litestar.params import Parameter
from sqlalchemy import select

from litestar_auth._plugin.role_admin import (
    RoleAdminRoleNotFoundError,
    RoleAdminUserNotFoundError,
    RoleModelFamily,
    SQLAlchemyRoleAdmin,
    _ManagerLifecycleRoleUpdater,
    resolve_role_model_family,
)
from litestar_auth.contrib.role_admin._schemas import RoleCreate, RoleRead, RoleUpdate, UserBrief
from litestar_auth.controllers._utils import (
    _build_controller_name,
    _configure_request_body_handler,
    _mark_litestar_auth_route_handler,
)
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_superuser
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.types import Guard
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 100


@dataclass(frozen=True, slots=True)
class _RoleAdminControllerContext[UP: UserProtocol[Any]]:
    """Resolved controller assembly context for later role-admin handlers."""

    config: LitestarAuthConfig[UP, Any] | None
    model_family: RoleModelFamily[UP]
    route_prefix: str
    guards: tuple[Guard, ...]
    role_page_schema_type: type[msgspec.Struct]
    role_user_page_schema_type: type[msgspec.Struct]
    db_session_dependency_key: str


class _RoleAdminControllerBase(Controller):
    """Typed base class for generated role-admin controllers."""

    role_admin_context: ClassVar[object]


def _normalize_route_prefix(route_prefix: str) -> str:
    """Return a normalized controller path fragment for the supplied route prefix.

    Raises:
        ConfigurationError: If the normalized route prefix would be empty.
    """
    normalized_route_prefix = route_prefix.strip("/")
    if normalized_route_prefix:
        return normalized_route_prefix

    msg = "create_role_admin_controller route_prefix must not be empty."
    raise ConfigurationError(msg)


def _resolve_model_family[UP: UserProtocol[Any]](
    *,
    config: LitestarAuthConfig[UP, Any] | None,
    user_model: type[UP] | None,
    role_model: type[Any] | None,
    user_role_model: type[Any] | None,
) -> RoleModelFamily[UP]:
    """Return the explicit-or-configured role-admin model family.

    Raises:
        ConfigurationError: If config-driven resolution is requested without
            enough explicit model overrides to fill the gaps.
    """
    if config is None:
        if user_model is None or role_model is None or user_role_model is None:
            msg = (
                "create_role_admin_controller requires either explicit user_model, role_model, and "
                "user_role_model arguments or a LitestarAuthConfig for config-driven resolution."
            )
            raise ConfigurationError(msg)
        return RoleModelFamily(
            user_model=user_model,
            role_model=role_model,
            user_role_model=user_role_model,
        )

    resolved_family = resolve_role_model_family(config.user_model)
    return RoleModelFamily(
        user_model=user_model or resolved_family.user_model,
        role_model=role_model or resolved_family.role_model,
        user_role_model=user_role_model or resolved_family.user_role_model,
    )


class _RequestSessionContextManager:
    """Async context manager that reuses the current request-scoped session."""

    def __init__(self, session: AsyncSession) -> None:
        """Store the existing request-scoped session."""
        self._session = session

    async def __aenter__(self) -> AsyncSession:
        """Return the shared request session."""
        return self._session

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        """Leave session lifecycle management to the surrounding request scope."""
        del exc_type, exc, traceback


class _RequestSessionMaker:
    """Session-maker shim that reuses the active request-scoped session."""

    def __init__(self, session: AsyncSession) -> None:
        """Store the existing request-scoped session."""
        self._session = session

    def __call__(self) -> _RequestSessionContextManager:
        """Return an async context manager yielding the stored session."""
        return _RequestSessionContextManager(self._session)


class _UnusedRoleLifecycleUpdater:
    """Sentinel lifecycle updater for request-bound helpers that never force delete."""

    @staticmethod
    def build_manager(session: AsyncSession) -> object:
        """Fail closed if a code path unexpectedly requests lifecycle updates.

        Raises:
            AssertionError: Always, because the HTTP role-catalog surface does
                not support forced deletes.
        """
        del session
        msg = "HTTP role catalog handlers never build manager lifecycle updates without an explicit force operation."
        raise AssertionError(msg)


class _ProvidedUserManagerLifecycleUpdater:
    """Request-bound lifecycle updater that reuses an injected manager when present."""

    def __init__(self, user_manager: object | None) -> None:
        """Store the optional request-scoped user manager dependency."""
        self._user_manager = user_manager

    def build_manager(self, session: AsyncSession) -> object:
        """Return the injected manager or fail closed for assignment handlers.

        Raises:
            ConfigurationError: If no manager dependency was provided for an
                explicit-model request-bound controller.
        """
        del session
        if self._user_manager is not None:
            return self._user_manager

        msg = (
            "Role admin assignment handlers require a request-scoped litestar_auth_user_manager when "
            "create_role_admin_controller() is used without config."
        )
        raise ConfigurationError(msg)


def _role_admin_context[UP: UserProtocol[Any]](controller: _RoleAdminControllerBase) -> _RoleAdminControllerContext[UP]:
    """Return the typed role-admin controller context."""
    return cast("_RoleAdminControllerContext[UP]", controller.role_admin_context)


def _build_request_bound_role_admin[UP: UserProtocol[Any]](
    *,
    model_family: RoleModelFamily[UP],
    session: AsyncSession,
    role_lifecycle_updater: object,
) -> SQLAlchemyRoleAdmin[UP]:
    """Return a helper that reuses the current request-scoped session."""
    return SQLAlchemyRoleAdmin(
        model_family=model_family,
        _session_maker=cast("Any", _RequestSessionMaker(session)),
        _role_lifecycle_updater=cast("Any", role_lifecycle_updater),
    )


def _resolve_role_admin[UP: UserProtocol[Any]](
    context: _RoleAdminControllerContext[UP],
    *,
    db_session: AsyncSession | None = None,
    request_user_manager: object | None = None,
) -> SQLAlchemyRoleAdmin[UP]:
    """Return the configured role-admin helper for the current handler invocation.

    Raises:
        ConfigurationError: If no request-scoped session is available when the
            controller cannot open its own sessions from ``config``.
    """
    if context.config is not None and context.config.session_maker is not None:
        return SQLAlchemyRoleAdmin.from_config(context.config)

    if db_session is None:
        msg = "Role admin controller requires a request-scoped AsyncSession when config.session_maker is unavailable."
        raise ConfigurationError(msg)
    role_lifecycle_updater = (
        _ManagerLifecycleRoleUpdater.from_config(context.config)
        if context.config is not None
        else _ProvidedUserManagerLifecycleUpdater(request_user_manager)
    )
    return _build_request_bound_role_admin(
        model_family=context.model_family,
        session=db_session,
        role_lifecycle_updater=role_lifecycle_updater,
    )


def _invalid_role_name(detail: str) -> ClientException:
    """Return the invalid-role-name response."""
    return ClientException(status_code=422, detail=detail, extra={"code": ErrorCode.ROLE_NAME_INVALID})


def _role_not_found(detail: str) -> ClientException:
    """Return the missing-role response."""
    return ClientException(status_code=404, detail=detail, extra={"code": ErrorCode.ROLE_NOT_FOUND})


def _role_already_exists(detail: str) -> ClientException:
    """Return the duplicate-role response."""
    return ClientException(status_code=409, detail=detail, extra={"code": ErrorCode.ROLE_ALREADY_EXISTS})


def _role_still_assigned(detail: str) -> ClientException:
    """Return the assigned-role delete refusal response."""
    return ClientException(status_code=409, detail=detail, extra={"code": ErrorCode.ROLE_STILL_ASSIGNED})


def _role_assignment_user_not_found(detail: str) -> ClientException:
    """Return the missing-user response for role-assignment routes."""
    return ClientException(
        status_code=404,
        detail=detail,
        extra={"code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND},
    )


def _normalize_input_role_name(role_name: str) -> str:
    """Normalize one untrusted role name.

    Returns:
        The normalized role name.

    Raises:
        _invalid_role_name: If the normalized role name would be invalid.
    """
    try:
        return SQLAlchemyRoleAdmin.normalized_role_name(role_name)
    except ValueError as exc:
        raise _invalid_role_name(str(exc)) from exc


def _to_role_read(role: object) -> RoleRead:
    """Convert one ORM role row into the public response schema.

    Returns:
        The serialized public role payload.
    """
    role_name = cast("Any", role).name
    return RoleRead(
        name=cast("str", role_name),
        description=cast("str | None", getattr(role, "description", None)),
    )


def _to_user_brief(user: object) -> UserBrief:
    """Convert one ORM user row into the public role-user listing schema.

    Returns:
        The serialized public user payload.
    """
    return UserBrief(
        id=str(cast("Any", user).id),
        email=cast("str", cast("Any", user).email),
        is_active=cast("bool", cast("Any", user).is_active),
        is_verified=cast("bool", cast("Any", user).is_verified),
        is_superuser=cast("bool", cast("Any", user).is_superuser),
    )


async def _reject_role_name_mutation(request: Request[Any, Any, Any]) -> None:
    """Reject PATCH payloads that attempt to mutate the immutable role name.

    Raises:
        _invalid_role_name: If the request payload includes a ``name`` field.
    """
    payload = msgspec.json.decode(await request.body())
    if isinstance(payload, dict) and "name" in payload:
        msg = "Role names are immutable."
        raise _invalid_role_name(msg)


async def _load_role_row[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    normalized_role_name: str,
) -> object:
    """Load one role row by normalized name.

    Returns:
        The loaded ORM role row.

    Raises:
        _role_not_found: If the normalized role does not exist.
    """
    async with role_admin.session() as session:
        role = await session.scalar(
            select(role_admin.role_model).where(cast("Any", role_admin.role_model).name == normalized_role_name),
        )
        if role is not None:
            return role

    msg = f"Role {normalized_role_name!r} not found."
    raise _role_not_found(msg)


async def _list_role_page[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    page_schema_type: type[msgspec.Struct],
    limit: int,
    offset: int,
) -> msgspec.Struct:
    """Return the paginated role-catalog response."""
    role_names = await role_admin.list_roles()
    total = len(role_names)
    page_names = role_names[offset : offset + limit]
    if not page_names:
        return page_schema_type(items=[], total=total, limit=limit, offset=offset)

    async with role_admin.session() as session:
        statement = (
            select(role_admin.role_model)
            .where(cast("Any", role_admin.role_model).name.in_(page_names))
            .order_by(cast("Any", role_admin.role_model).name)
        )
        roles = list(cast("Any", await session.scalars(statement)))

    return page_schema_type(
        items=[_to_role_read(role) for role in roles],
        total=total,
        limit=limit,
        offset=offset,
    )


async def _assign_role_user[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    role_name: str,
    user_id: str,
) -> RoleRead:
    """Assign one normalized role to one user selected by the HTTP path id.

    Returns:
        The public role payload for the assigned role.

    Raises:
        _role_not_found: If the normalized role does not exist.
        _role_assignment_user_not_found: If the target user does not exist.
    """
    normalized_role_name = _normalize_input_role_name(role_name)
    parsed_user_id = role_admin.parse_user_id(user_id)
    try:
        await role_admin.assign_user_roles(
            user_id=parsed_user_id,
            roles=[normalized_role_name],
            require_existing_roles=True,
        )
    except RoleAdminRoleNotFoundError as exc:
        raise _role_not_found(str(exc)) from exc
    except RoleAdminUserNotFoundError as exc:
        raise _role_assignment_user_not_found(str(exc)) from exc

    role = await _load_role_row(role_admin, normalized_role_name=normalized_role_name)
    return _to_role_read(role)


async def _unassign_role_user[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    role_name: str,
    user_id: str,
) -> None:
    """Remove one normalized role from one user selected by the HTTP path id.

    Raises:
        _role_assignment_user_not_found: If the target user does not exist.
    """
    normalized_role_name = _normalize_input_role_name(role_name)
    parsed_user_id = role_admin.parse_user_id(user_id)
    try:
        await role_admin.unassign_user_roles(
            user_id=parsed_user_id,
            roles=[normalized_role_name],
        )
    except RoleAdminUserNotFoundError as exc:
        raise _role_assignment_user_not_found(str(exc)) from exc


async def _list_role_user_page[UP: UserProtocol[Any]](
    role_admin: SQLAlchemyRoleAdmin[UP],
    *,
    page_schema_type: type[msgspec.Struct],
    role_name: str,
    limit: int,
    offset: int,
) -> msgspec.Struct:
    """Return the paginated user listing for one normalized role.

    Raises:
        _role_not_found: If the normalized role does not exist.
    """
    normalized_role_name = _normalize_input_role_name(role_name)
    try:
        users = await role_admin.list_role_users(role=normalized_role_name)
    except RoleAdminRoleNotFoundError as exc:
        raise _role_not_found(str(exc)) from exc

    total = len(users)
    page_users = users[offset : offset + limit]
    return page_schema_type(
        items=[_to_user_brief(user) for user in page_users],
        total=total,
        limit=limit,
        offset=offset,
    )


def _set_dependency_parameter_name(
    handler_fn: object,
    *,
    current_name: str,
    parameter_name: str,
) -> None:
    """Rename one dependency parameter in the Litestar-visible handler signature.

    The rename is a no-op when the handler does not declare ``current_name``: the
    config+session_maker branch opens its own sessions and therefore never binds
    the request-scoped ``db_session`` dependency. Guarding on ``signature.parameters``
    keeps the factory safe for that branch even when the configured
    ``db_session_dependency_key`` differs from the default.
    """
    signature = inspect.signature(cast("Any", handler_fn))
    if current_name not in signature.parameters:
        return
    parameters: list[inspect.Parameter] = []
    for parameter in signature.parameters.values():
        if parameter.name == current_name:
            parameters.append(parameter.replace(name=parameter_name))
            continue
        parameters.append(parameter)

    adapted_handler = cast("Any", handler_fn)
    adapted_handler.__signature__ = inspect.Signature(
        parameters=parameters,
        return_annotation=signature.return_annotation,
    )
    adapted_handler.__annotations__ = {
        **getattr(handler_fn, "__annotations__", {}),
        parameter_name: adapted_handler.__annotations__.pop(current_name),
    }


def _configure_request_session_dependency(
    controller_cls: type[Controller],
    *,
    parameter_name: str,
) -> None:
    """Rename the request-scoped session dependency for all generated handlers."""
    if parameter_name == "db_session":
        return

    for handler_name in (
        "list_roles",
        "create_role",
        "get_role",
        "update_role",
        "delete_role",
        "assign_role",
        "unassign_role",
        "list_role_users",
    ):
        _set_dependency_parameter_name(
            getattr(controller_cls, handler_name).fn,
            current_name="db_session",
            parameter_name=parameter_name,
        )


def create_role_admin_controller[UP: UserProtocol[Any]](  # noqa: C901, PLR0913
    *,
    config: LitestarAuthConfig[UP, Any] | None = None,
    user_model: type[UP] | None = None,
    role_model: type[Any] | None = None,
    user_role_model: type[Any] | None = None,
    route_prefix: str = "roles",
    guards: Sequence[Guard] | None = None,
) -> type[Controller]:
    """Return a controller subclass scaffold for contrib role administration.

    Args:
        config: Optional plugin configuration used for config-driven model
            resolution when model overrides are omitted.
        user_model: Optional explicit user model override.
        role_model: Optional explicit role model override.
        user_role_model: Optional explicit association-model override.
        route_prefix: Route prefix mounted under the generated controller.
        guards: Optional guard override. Defaults to ``[is_superuser]``.

    Returns:
        Controller subclass carrying the resolved role-admin assembly metadata.
    """
    normalized_route_prefix = _normalize_route_prefix(route_prefix)
    resolved_guards = tuple((is_superuser,) if guards is None else guards)
    model_family = _resolve_model_family(
        config=config,
        user_model=user_model,
        role_model=role_model,
        user_role_model=user_role_model,
    )
    role_page_schema_type = msgspec.defstruct(
        "RolePageSchema",
        [
            ("items", list[RoleRead]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )
    role_user_page_schema_type = msgspec.defstruct(
        "RoleUserPageSchema",
        [
            ("items", list[UserBrief]),
            ("total", int),
            ("limit", int),
            ("offset", int),
        ],
    )
    controller_context = _RoleAdminControllerContext(
        config=config,
        model_family=model_family,
        route_prefix=normalized_route_prefix,
        guards=cast("tuple[Guard, ...]", resolved_guards),
        role_page_schema_type=role_page_schema_type,
        role_user_page_schema_type=role_user_page_schema_type,
        db_session_dependency_key="db_session" if config is None else config.db_session_dependency_key,
    )
    controller_name = f"{_build_controller_name(normalized_route_prefix)}RoleAdminController"

    if config is not None and config.session_maker is not None:

        class RoleAdminController(_RoleAdminControllerBase):
            """Generated contrib role-administration controller."""

            @get()
            async def list_roles(
                self,
                limit: int = Parameter(default=_DEFAULT_LIMIT, query="limit", ge=1, le=_MAX_LIMIT),
                offset: int = Parameter(default=0, query="offset", ge=0),
            ) -> msgspec.Struct:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                return await _list_role_page(
                    role_admin,
                    page_schema_type=context.role_page_schema_type,
                    limit=limit,
                    offset=offset,
                )

            @post(status_code=201)
            async def create_role(
                self,
                data: msgspec.Struct,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                payload = cast("RoleCreate", data)
                normalized_role_name = _normalize_input_role_name(payload.name)
                try:
                    await role_admin.create_role(
                        role=normalized_role_name,
                        description=payload.description,
                        fail_if_exists=True,
                    )
                except Exception as exc:
                    from sqlalchemy.exc import IntegrityError  # noqa: PLC0415

                    if isinstance(exc, IntegrityError):
                        msg = f"Role {normalized_role_name!r} already exists."
                        raise _role_already_exists(msg) from exc
                    raise
                role = await _load_role_row(role_admin, normalized_role_name=normalized_role_name)
                return _to_role_read(role)

            @get("/{role_name:str}")
            async def get_role(
                self,
                role_name: str,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                role = await _load_role_row(role_admin, normalized_role_name=_normalize_input_role_name(role_name))
                return _to_role_read(role)

            @patch("/{role_name:str}")
            async def update_role(
                self,
                request: Request[Any, Any, Any],
                role_name: str,
                data: msgspec.Struct,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                normalized_role_name = _normalize_input_role_name(role_name)
                payload = cast("RoleUpdate", data)
                await _reject_role_name_mutation(request)
                async with role_admin.session() as session:
                    role = await session.scalar(
                        select(role_admin.role_model).where(
                            cast("Any", role_admin.role_model).name == normalized_role_name,
                        ),
                    )
                    if role is None:
                        msg = f"Role {normalized_role_name!r} not found."
                        raise _role_not_found(msg)
                    if hasattr(role, "description"):
                        role.description = payload.description
                    elif payload.description is not None:
                        msg = (
                            "The configured role model does not expose a 'description' attribute required by "
                            "RoleUpdate."
                        )
                        raise ConfigurationError(msg)
                    await session.commit()
                return _to_role_read(role)

            @delete("/{role_name:str}", status_code=204)
            async def delete_role(
                self,
                role_name: str,
            ) -> None:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                normalized_role_name = _normalize_input_role_name(role_name)
                try:
                    await role_admin.delete_role(role=normalized_role_name)
                except LookupError as exc:
                    msg = f"Role {normalized_role_name!r} not found."
                    raise _role_not_found(msg) from exc
                except ValueError as exc:
                    raise _role_still_assigned(str(exc)) from exc

            @post("/{role_name:str}/users/{user_id:str}", status_code=200)
            async def assign_role(
                self,
                role_name: str,
                user_id: str,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                return await _assign_role_user(role_admin, role_name=role_name, user_id=user_id)

            @delete("/{role_name:str}/users/{user_id:str}", status_code=204)
            async def unassign_role(
                self,
                role_name: str,
                user_id: str,
            ) -> None:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                await _unassign_role_user(role_admin, role_name=role_name, user_id=user_id)

            @get("/{role_name:str}/users")
            async def list_role_users(
                self,
                role_name: str,
                limit: int = Parameter(default=_DEFAULT_LIMIT, query="limit", ge=1, le=_MAX_LIMIT),
                offset: int = Parameter(default=0, query="offset", ge=0),
            ) -> msgspec.Struct:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context)
                return await _list_role_user_page(
                    role_admin,
                    page_schema_type=context.role_user_page_schema_type,
                    role_name=role_name,
                    limit=limit,
                    offset=offset,
                )

    else:

        class RoleAdminController(_RoleAdminControllerBase):
            """Generated contrib role-administration controller."""

            @get()
            async def list_roles(
                self,
                db_session: AsyncSession,
                limit: int = Parameter(default=_DEFAULT_LIMIT, query="limit", ge=1, le=_MAX_LIMIT),
                offset: int = Parameter(default=0, query="offset", ge=0),
            ) -> msgspec.Struct:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context, db_session=db_session)
                return await _list_role_page(
                    role_admin,
                    page_schema_type=context.role_page_schema_type,
                    limit=limit,
                    offset=offset,
                )

            @post(status_code=201)
            async def create_role(
                self,
                db_session: AsyncSession,
                data: msgspec.Struct,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context, db_session=db_session)
                payload = cast("RoleCreate", data)
                normalized_role_name = _normalize_input_role_name(payload.name)
                try:
                    await role_admin.create_role(
                        role=normalized_role_name,
                        description=payload.description,
                        fail_if_exists=True,
                    )
                except Exception as exc:
                    from sqlalchemy.exc import IntegrityError  # noqa: PLC0415

                    if isinstance(exc, IntegrityError):
                        msg = f"Role {normalized_role_name!r} already exists."
                        raise _role_already_exists(msg) from exc
                    raise
                role = await _load_role_row(role_admin, normalized_role_name=normalized_role_name)
                return _to_role_read(role)

            @get("/{role_name:str}")
            async def get_role(
                self,
                db_session: AsyncSession,
                role_name: str,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context, db_session=db_session)
                role = await _load_role_row(role_admin, normalized_role_name=_normalize_input_role_name(role_name))
                return _to_role_read(role)

            @patch("/{role_name:str}")
            async def update_role(
                self,
                request: Request[Any, Any, Any],
                db_session: AsyncSession,
                role_name: str,
                data: msgspec.Struct,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context, db_session=db_session)
                normalized_role_name = _normalize_input_role_name(role_name)
                payload = cast("RoleUpdate", data)
                await _reject_role_name_mutation(request)
                async with role_admin.session() as session:
                    role = await session.scalar(
                        select(role_admin.role_model).where(
                            cast("Any", role_admin.role_model).name == normalized_role_name,
                        ),
                    )
                    if role is None:
                        msg = f"Role {normalized_role_name!r} not found."
                        raise _role_not_found(msg)
                    if hasattr(role, "description"):
                        role.description = payload.description
                    elif payload.description is not None:
                        msg = (
                            "The configured role model does not expose a 'description' attribute required by "
                            "RoleUpdate."
                        )
                        raise ConfigurationError(msg)
                    await session.commit()
                return _to_role_read(role)

            @delete("/{role_name:str}", status_code=204)
            async def delete_role(
                self,
                db_session: AsyncSession,
                role_name: str,
            ) -> None:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context, db_session=db_session)
                normalized_role_name = _normalize_input_role_name(role_name)
                try:
                    await role_admin.delete_role(role=normalized_role_name)
                except LookupError as exc:
                    msg = f"Role {normalized_role_name!r} not found."
                    raise _role_not_found(msg) from exc
                except ValueError as exc:
                    raise _role_still_assigned(str(exc)) from exc

            @post("/{role_name:str}/users/{user_id:str}", status_code=200)
            async def assign_role(
                self,
                db_session: AsyncSession,
                role_name: str,
                user_id: str,
                litestar_auth_user_manager: object | None = None,
            ) -> RoleRead:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(
                    context,
                    db_session=db_session,
                    request_user_manager=litestar_auth_user_manager,
                )
                return await _assign_role_user(role_admin, role_name=role_name, user_id=user_id)

            @delete("/{role_name:str}/users/{user_id:str}", status_code=204)
            async def unassign_role(
                self,
                db_session: AsyncSession,
                role_name: str,
                user_id: str,
                litestar_auth_user_manager: object | None = None,
            ) -> None:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(
                    context,
                    db_session=db_session,
                    request_user_manager=litestar_auth_user_manager,
                )
                await _unassign_role_user(role_admin, role_name=role_name, user_id=user_id)

            @get("/{role_name:str}/users")
            async def list_role_users(
                self,
                db_session: AsyncSession,
                role_name: str,
                limit: int = Parameter(default=_DEFAULT_LIMIT, query="limit", ge=1, le=_MAX_LIMIT),
                offset: int = Parameter(default=0, query="offset", ge=0),
            ) -> msgspec.Struct:
                context = _role_admin_context(self)
                role_admin = _resolve_role_admin(context, db_session=db_session)
                return await _list_role_user_page(
                    role_admin,
                    page_schema_type=context.role_user_page_schema_type,
                    role_name=role_name,
                    limit=limit,
                    offset=offset,
                )

    RoleAdminController.__name__ = controller_name
    RoleAdminController.__qualname__ = controller_name
    RoleAdminController.__module__ = __name__
    RoleAdminController.path = f"/{normalized_route_prefix}"
    RoleAdminController.guards = list(resolved_guards)
    RoleAdminController.role_admin_context = controller_context
    _configure_request_body_handler(RoleAdminController.create_role, schema=RoleCreate)
    _configure_request_body_handler(RoleAdminController.update_role, schema=RoleUpdate)
    _configure_request_session_dependency(
        RoleAdminController,
        parameter_name=controller_context.db_session_dependency_key,
    )
    return _mark_litestar_auth_route_handler(cast("type[Controller]", RoleAdminController))
