"""Focused unit coverage for the opt-in contrib role-admin surface."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import msgspec
import pytest
from litestar import Controller
from litestar.exceptions import ClientException

import litestar_auth.contrib.role_admin as role_admin_module
import litestar_auth.contrib.role_admin._controller as role_admin_controller_module
import litestar_auth.contrib.role_admin._controller_handler_utils as role_admin_controller_handler_utils_module
from litestar_auth._plugin.role_admin import RoleAdminRoleNotFoundError, RoleAdminUserNotFoundError
from litestar_auth.contrib.role_admin._schemas import RoleCreate, RoleRead, RoleUpdate, UserBrief
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_authenticated, is_superuser
from litestar_auth.models import Role, User, UserRole
from tests.unit.test_plugin_role_admin import (
    TrackingSessionMaker,
    _build_missing_roles_attribute_user_model,
    _minimal_config,
)

RoleAdminControllerConfig = role_admin_module.RoleAdminControllerConfig
create_role_admin_controller = role_admin_module.create_role_admin_controller
role_admin_all = role_admin_module.__all__

pytestmark = pytest.mark.unit


def _as_any(value: object) -> Any:  # noqa: ANN401
    """Return a value through the test-only dynamic type boundary."""
    return cast("Any", value)


def test_contrib_role_admin_package_exposes_only_its_documented_factory() -> None:
    """The contrib package preserves its narrow public surface."""
    assert role_admin_all == ("RoleAdminControllerConfig", "create_role_admin_controller")
    assert role_admin_module.RoleAdminControllerConfig is RoleAdminControllerConfig

    missing_name = "missing_factory"
    with pytest.raises(AttributeError, match="missing_factory"):
        getattr(_as_any(role_admin_module), missing_name)


def test_contrib_role_admin_factory_builds_controller_from_explicit_models() -> None:
    """The factory returns a controller scaffold wired to the explicit role models."""
    controller = create_role_admin_controller(
        user_model=User,
        role_model=Role,
        user_role_model=UserRole,
        route_prefix="admin/roles",
    )
    context = cast("Any", controller).role_admin_context

    assert issubclass(controller, Controller)
    assert controller.path == "/admin/roles"
    assert controller.guards == [is_superuser]
    assert context.model_family.user_model is User
    assert context.model_family.role_model is Role
    assert context.model_family.user_role_model is UserRole


def test_contrib_role_admin_factory_accepts_controller_config_object() -> None:
    """The factory can receive role-admin settings as one typed controller config."""
    controller = create_role_admin_controller(
        controller_config=RoleAdminControllerConfig(
            user_model=User,
            role_model=Role,
            user_role_model=UserRole,
            route_prefix="admin/roles",
            guards=[],
        ),
    )
    context = cast("Any", controller).role_admin_context

    assert controller.path == "/admin/roles"
    assert controller.guards == []
    assert context.model_family.user_model is User
    assert context.model_family.role_model is Role
    assert context.model_family.user_role_model is UserRole


def test_contrib_role_admin_factory_rejects_controller_config_combined_with_keyword_options() -> None:
    """The role-admin factory accepts either controller_config or keyword options."""
    factory = cast("Any", create_role_admin_controller)

    with pytest.raises(ValueError, match="RoleAdminControllerConfig or keyword options"):
        factory(
            controller_config=RoleAdminControllerConfig(user_model=User, role_model=Role, user_role_model=UserRole),
            route_prefix="admin/roles",
        )


def test_contrib_role_admin_factory_supports_config_driven_model_resolution_and_guard_overrides() -> None:
    """The factory resolves models from config and accepts both custom and empty guard overrides."""
    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())

    guarded_controller = create_role_admin_controller(
        config=config,
        route_prefix="roles",
        guards=[is_authenticated],
    )
    unguarded_controller = create_role_admin_controller(
        user_model=User,
        role_model=Role,
        user_role_model=UserRole,
        guards=[],
    )
    guarded_context = cast("Any", guarded_controller).role_admin_context

    assert issubclass(guarded_controller, Controller)
    assert guarded_controller.path == "/roles"
    assert guarded_controller.guards == [is_authenticated]
    assert guarded_context.config is config
    assert guarded_context.model_family.user_model is User
    assert guarded_context.model_family.role_model is Role
    assert guarded_context.model_family.user_role_model is UserRole
    assert unguarded_controller.guards == []


def test_contrib_role_admin_factory_tolerates_custom_db_session_dependency_key_with_session_maker() -> None:
    """A non-default ``db_session_dependency_key`` does not break the config+session_maker branch.

    Regression guard: earlier revisions always tried to rename ``db_session`` on every
    generated handler, even in the branch where handlers open their own sessions and never
    declare that dependency. The rename raised ``KeyError`` because the annotation was
    absent. The factory must now succeed without mutating the handlers and without raising.
    """
    import inspect  # noqa: PLC0415

    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())
    config.db_session_dependency_key = "custom_db_session"

    controller = cast("Any", create_role_admin_controller(config=config))

    assert controller.role_admin_context.db_session_dependency_key == "custom_db_session"
    role_admin_controller_module._configure_request_session_dependency(controller, parameter_name="another_session")
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
        handler = getattr(controller, handler_name).fn
        signature_parameters = inspect.signature(handler).parameters
        assert "custom_db_session" not in signature_parameters
        assert "db_session" not in signature_parameters
        assert "custom_db_session" not in handler.__annotations__
        assert "db_session" not in handler.__annotations__


def test_contrib_role_admin_factory_fails_closed_for_invalid_model_resolution_inputs() -> None:
    """Invalid config-driven or explicit model wiring is rejected before any DB access."""
    invalid_user_model = _build_missing_roles_attribute_user_model()
    invalid_config = _minimal_config(user_model=invalid_user_model, session_maker=TrackingSessionMaker())

    with pytest.raises(ConfigurationError, match=r"Role admin requires LitestarAuthConfig\.user_model"):
        create_role_admin_controller(config=invalid_config)

    with pytest.raises(ConfigurationError, match=r"requires either explicit user_model"):
        create_role_admin_controller(user_model=User)

    with pytest.raises(ConfigurationError, match=r"route_prefix must not be empty"):
        create_role_admin_controller(
            user_model=User,
            role_model=Role,
            user_role_model=UserRole,
            route_prefix="/",
        )


@pytest.mark.parametrize(
    ("schema_type", "payload"),
    [
        (RoleCreate, {"name": " Billing ", "description": "Receives invoices"}),
        (RoleUpdate, {"description": "Updated docs"}),
        (RoleRead, {"name": "billing", "description": "Receives invoices"}),
        (
            UserBrief,
            {
                "id": "user-123",
                "email": "member@example.com",
                "is_active": True,
                "is_verified": False,
            },
        ),
    ],
)
def test_contrib_role_admin_schemas_round_trip_with_msgspec(
    schema_type: type[msgspec.Struct],
    payload: dict[str, object],
) -> None:
    """Published schemas round-trip cleanly through the documented msgspec contract."""
    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=schema_type)

    assert msgspec.to_builtins(decoded) == payload


def test_contrib_role_admin_user_brief_exposes_only_non_sensitive_fields() -> None:
    """The user summary payload excludes password and TOTP material."""
    user = User(
        email="member@example.com",
        hashed_password="hash",
        is_active=True,
        is_verified=False,
        roles=["admin"],
    )
    user.totp_secret = "totp-secret"
    payload = UserBrief(
        id=str(user.id),
        email=user.email,
        is_active=user.is_active,
        is_verified=user.is_verified,
    )

    assert payload.id == str(user.id)
    assert payload.email == user.email
    assert payload.is_active is True
    assert payload.is_verified is False
    assert UserBrief.__struct_fields__ == ("id", "email", "is_active", "is_verified")


def test_contrib_role_admin_error_codes_keep_strenum_name_value_invariant() -> None:
    """Role-admin error codes preserve the repo-wide StrEnum contract."""
    expected_codes = (
        ErrorCode.ROLE_ALREADY_EXISTS,
        ErrorCode.ROLE_NOT_FOUND,
        ErrorCode.ROLE_STILL_ASSIGNED,
        ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND,
        ErrorCode.ROLE_NAME_INVALID,
    )

    assert [code.value for code in expected_codes] == [code.name for code in expected_codes]


async def test_contrib_role_admin_assignment_helpers_map_missing_role_and_user_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assignment helpers surface the documented contrib error codes without using a real session."""

    class RoleAdminStub:
        def parse_user_id(self, raw_user_id: str) -> object:
            return f"parsed:{raw_user_id}"

        async def assign_user_roles(self, **kwargs: object) -> object:
            if kwargs["roles"] == ["missing"]:
                msg = "Role admin could not find role 'missing' in the configured catalog."
                raise RoleAdminRoleNotFoundError(msg)
            msg = "Role admin could not find a user with id 'parsed:missing-user'."
            raise RoleAdminUserNotFoundError(msg)

        async def unassign_user_roles(self, **kwargs: object) -> object:
            del kwargs
            msg = "Role admin could not find a user with id 'parsed:missing-user'."
            raise RoleAdminUserNotFoundError(msg)

        async def list_role_users(self, *, role: str) -> list[object]:
            del role
            msg = "Role admin could not find role 'missing' in the configured catalog."
            raise RoleAdminRoleNotFoundError(msg)

    async def _load_role_row_stub(role_admin: object, normalized_role_name: str) -> object:
        await asyncio.sleep(0)
        del role_admin, normalized_role_name
        return SimpleNamespace(name="billing", description="Docs")

    monkeypatch.setattr(role_admin_controller_handler_utils_module, "_load_role_row", _load_role_row_stub)
    role_admin = RoleAdminStub()
    page_schema_type = msgspec.defstruct(
        "RoleUserPageCoverageSchema",
        [("items", list[UserBrief]), ("total", int), ("limit", int), ("offset", int)],
    )

    with pytest.raises(ClientException, match="configured catalog") as missing_role_exc:
        await role_admin_controller_handler_utils_module._assign_role_user(
            cast("Any", role_admin),
            role_name="missing",
            user_id="user-1",
        )
    assert missing_role_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    with pytest.raises(ClientException, match="could not find a user") as missing_user_exc:
        await role_admin_controller_handler_utils_module._assign_role_user(
            cast("Any", role_admin),
            role_name="billing",
            user_id="missing-user",
        )
    assert missing_user_exc.value.extra == {"code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND}

    with pytest.raises(ClientException, match="could not find a user") as missing_unassign_exc:
        await role_admin_controller_handler_utils_module._unassign_role_user(
            cast("Any", role_admin),
            role_name="billing",
            user_id="missing-user",
        )
    assert missing_unassign_exc.value.extra == {"code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND}

    with pytest.raises(ClientException, match="configured catalog") as missing_page_exc:
        await role_admin_controller_handler_utils_module._list_role_user_page(
            cast("Any", role_admin),
            page_schema_type=page_schema_type,
            role_name="missing",
            limit=1,
            offset=0,
        )
    assert missing_page_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}
