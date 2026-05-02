"""Tests for contrib package re-exports and opt-in controller surfaces."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import MappingProxyType, SimpleNamespace
from typing import TYPE_CHECKING, Any, cast, get_type_hints
from uuid import uuid4

import msgspec
import pytest
from litestar import Controller
from litestar.exceptions import ClientException
from sqlalchemy.exc import IntegrityError

import litestar_auth.contrib.redis as redis_module
import litestar_auth.contrib.redis._surface as redis_surface_module
import litestar_auth.contrib.role_admin as role_admin_module
import litestar_auth.contrib.role_admin._controller as role_admin_controller_module
import litestar_auth.contrib.role_admin._controller_handler_utils as role_admin_controller_handler_utils_module
import litestar_auth.contrib.role_admin._controller_handlers as role_admin_controller_handlers_module
import litestar_auth.contrib.role_admin._error_responses as role_admin_error_responses_module
import litestar_auth.contrib.role_admin._session_wiring as role_admin_session_wiring_module
import litestar_auth.ratelimit as ratelimit_module
from litestar_auth._plugin.role_admin import RoleAdminRoleNotFoundError, RoleAdminUserNotFoundError
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy as BaseRedisTokenStrategy
from litestar_auth.authentication.strategy.redis import RedisTokenStrategyConfig as BaseRedisTokenStrategyConfig
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.contrib.role_admin._schemas import RoleCreate, RoleRead, RoleUpdate, UserBrief
from litestar_auth.controllers.oauth import OAuthControllerUserManagerProtocol
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_authenticated, is_superuser
from litestar_auth.models import Role, User, UserRole
from litestar_auth.oauth import create_provider_oauth_controller
from litestar_auth.totp import RedisTotpEnrollmentStore as BaseRedisTotpEnrollmentStore
from litestar_auth.totp import RedisUsedTotpCodeStore as BaseRedisUsedTotpCodeStore
from tests._helpers import ExampleUser, cast_fakeredis
from tests.unit.test_plugin_role_admin import (
    TrackingAsyncSession,
    TrackingSessionMaker,
    _build_missing_roles_attribute_user_model,
    _minimal_config,
)

RedisAuthClientProtocol = redis_module.RedisAuthClientProtocol
RedisAuthPreset = redis_module.RedisAuthPreset
RedisAuthRateLimitConfigOptions = redis_module.RedisAuthRateLimitConfigOptions
RedisAuthRateLimitTier = redis_module.RedisAuthRateLimitTier
RedisTokenStrategy = redis_module.RedisTokenStrategy
RedisTokenStrategyConfig = redis_module.RedisTokenStrategyConfig
RedisTotpEnrollmentStore = redis_module.RedisTotpEnrollmentStore
RedisUsedTotpCodeStore = redis_module.RedisUsedTotpCodeStore
redis_all = redis_module.__all__
RoleAdminControllerConfig = role_admin_module.RoleAdminControllerConfig
create_role_admin_controller = role_admin_module.create_role_admin_controller
role_admin_all = role_admin_module.__all__
AuthRateLimitEndpointGroup = ratelimit_module.AuthRateLimitEndpointGroup
AuthRateLimitSlot = ratelimit_module.AuthRateLimitSlot

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from tests._helpers import AsyncFakeRedis

pytestmark = pytest.mark.unit
REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
SHARED_MAX_ATTEMPTS = 5
SHARED_WINDOW_SECONDS = 60
REFRESH_MAX_ATTEMPTS = 10
REFRESH_WINDOW_SECONDS = 300
TOTP_MAX_ATTEMPTS = 5
TOTP_WINDOW_SECONDS = 300
USED_TOTP_TTL_MS = 1_250
PENDING_JTI_TTL_SECONDS = 30
PENDING_JTI_TTL_FLOOR = PENDING_JTI_TTL_SECONDS - 1
AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS = frozenset(
    {AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN},
)


def _as_any(value: object) -> Any:  # noqa: ANN401
    """Return a value through the test-only dynamic type boundary."""
    return cast("Any", value)


class ExampleStrategy:
    """Minimal strategy implementation for backend construction."""

    async def read_token(self, token: str | None, user_manager: object) -> ExampleUser | None:
        """Return no user because this test never authenticates."""
        del token, user_manager
        return None

    async def write_token(self, user: ExampleUser) -> str:
        """Return a deterministic token string."""
        return str(user.id)

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """No-op token invalidation for tests."""
        del token, user


class ExampleUserManager(OAuthControllerUserManagerProtocol[ExampleUser, str]):
    """Minimal typed user manager for lazy-import tests."""

    user_db: object = object()

    async def create(
        self,
        user_create: object,
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> ExampleUser:
        """Return a placeholder user because this path is never reached."""
        del user_create, safe, allow_privileged
        return ExampleUser(id=uuid4())

    async def update(
        self,
        user_update: object,
        user: ExampleUser,
        *,
        allow_privileged: bool = False,
    ) -> ExampleUser:
        """Return the provided user because this path is never reached."""
        del user_update, allow_privileged
        return user

    async def on_after_login(self, user: ExampleUser) -> None:
        """No-op login hook for protocol conformance."""
        del user


def test_contrib_packages_reexport_public_symbols() -> None:
    """Contrib packages expose the documented convenience imports."""
    assert RedisTokenStrategy is BaseRedisTokenStrategy
    assert RedisTokenStrategyConfig is BaseRedisTokenStrategyConfig
    assert RedisTotpEnrollmentStore is BaseRedisTotpEnrollmentStore
    assert RedisUsedTotpCodeStore is BaseRedisUsedTotpCodeStore


def test_contrib_packages_define_all() -> None:
    """Contrib packages publish only their intended public symbols."""
    assert redis_all == (
        "RedisAuthClientProtocol",
        "RedisAuthPreset",
        "RedisAuthRateLimitConfigOptions",
        "RedisAuthRateLimitTier",
        "RedisTokenStrategy",
        "RedisTokenStrategyConfig",
        "RedisTotpEnrollmentStore",
        "RedisUsedTotpCodeStore",
    )
    assert role_admin_all == ("RoleAdminControllerConfig", "create_role_admin_controller")


def test_contrib_role_admin_factory_builds_controller_from_explicit_models() -> None:
    """The opt-in role-admin factory returns a controller scaffold with explicit model wiring."""
    controller = create_role_admin_controller(
        user_model=User,
        role_model=Role,
        user_role_model=UserRole,
        route_prefix="admin/roles",
    )
    context = _as_any(controller).role_admin_context

    assert issubclass(controller, Controller)
    assert controller.path == "/admin/roles"
    assert controller.guards == [is_superuser]
    assert context.model_family.user_model is User
    assert context.model_family.role_model is Role
    assert context.model_family.user_role_model is UserRole


def test_contrib_role_admin_factory_accepts_controller_config_object() -> None:
    """The opt-in role-admin factory accepts settings as one typed controller config."""
    controller = create_role_admin_controller(
        controller_config=RoleAdminControllerConfig(
            user_model=User,
            role_model=Role,
            user_role_model=UserRole,
            route_prefix="admin/roles",
        ),
    )
    context = cast("Any", controller).role_admin_context

    assert controller.path == "/admin/roles"
    assert context.model_family.user_model is User
    assert context.model_family.role_model is Role
    assert context.model_family.user_role_model is UserRole


def test_contrib_role_admin_factory_supports_config_driven_model_resolution_and_guard_overrides() -> None:
    """The factory resolves missing models from ``LitestarAuthConfig`` and accepts guard overrides."""
    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())

    controller = create_role_admin_controller(
        config=config,
        route_prefix="roles",
        guards=[is_authenticated],
    )
    context = cast("Any", controller).role_admin_context

    assert issubclass(controller, Controller)
    assert controller.path == "/roles"
    assert controller.guards == [is_authenticated]
    assert context.config is config
    assert context.model_family.user_model is User
    assert context.model_family.role_model is Role
    assert context.model_family.user_role_model is UserRole


def test_contrib_role_admin_factory_accepts_empty_guard_overrides() -> None:
    """Passing an explicit empty guard list disables the default superuser guard."""
    controller = create_role_admin_controller(
        user_model=User,
        role_model=Role,
        user_role_model=UserRole,
        guards=[],
    )

    assert controller.guards == []


def test_contrib_role_admin_factory_fails_closed_for_incompatible_configured_user_models() -> None:
    """Config-driven role-admin resolution preserves the internal fail-closed contract."""
    invalid_user_model = _build_missing_roles_attribute_user_model()
    config = _minimal_config(user_model=invalid_user_model, session_maker=TrackingSessionMaker())

    with pytest.raises(ConfigurationError, match=r"Role admin requires LitestarAuthConfig\.user_model"):
        create_role_admin_controller(config=config)


def test_contrib_role_admin_factory_requires_complete_explicit_models_without_config() -> None:
    """The factory fails closed when config-driven resolution is unavailable."""
    with pytest.raises(ConfigurationError, match=r"requires either explicit user_model"):
        create_role_admin_controller(user_model=User)


def test_contrib_role_admin_factory_rejects_empty_route_prefix() -> None:
    """The factory rejects empty route prefixes instead of mounting at the app root."""
    with pytest.raises(ConfigurationError, match=r"route_prefix must not be empty"):
        create_role_admin_controller(
            user_model=User,
            role_model=Role,
            user_role_model=UserRole,
            route_prefix="/",
        )


def test_contrib_role_admin_package_rejects_unknown_public_attributes() -> None:
    """The public package raises ``AttributeError`` for unknown exports."""
    missing_name = "missing_factory"
    with pytest.raises(AttributeError, match=r"missing_factory"):
        getattr(cast("Any", role_admin_module), missing_name)


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
    """Role-admin schemas round-trip through ``msgspec.json`` with only declared fields."""
    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=schema_type)

    assert msgspec.to_builtins(decoded) == payload


def test_contrib_role_admin_user_brief_exposes_only_non_sensitive_fields() -> None:
    """The internal user summary schema omits blocked secret-bearing fields."""
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
    """Role-admin error codes stay importable and keep the existing ``StrEnum`` contract."""
    expected_codes = (
        ErrorCode.ROLE_ALREADY_EXISTS,
        ErrorCode.ROLE_NOT_FOUND,
        ErrorCode.ROLE_STILL_ASSIGNED,
        ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND,
        ErrorCode.ROLE_NAME_INVALID,
    )

    assert [code.value for code in expected_codes] == [code.name for code in expected_codes]


async def test_contrib_role_admin_internal_request_session_helpers_cover_request_bound_mode() -> None:
    """Internal request-session helpers fail closed and preserve the response contract."""
    session = TrackingAsyncSession()
    manager = object()
    context_manager = role_admin_session_wiring_module._RequestSessionContextManager(cast("Any", session))
    async with context_manager as entered_session:
        assert entered_session is session
    await context_manager.__aexit__(None, None, None)

    session_maker = role_admin_session_wiring_module._RequestSessionMaker(cast("Any", session))
    async with session_maker() as session_from_maker:
        assert session_from_maker is session

    with pytest.raises(AssertionError, match="force operation"):
        role_admin_session_wiring_module._UnusedRoleLifecycleUpdater.build_manager(cast("Any", session))

    controller = create_role_admin_controller(user_model=User, role_model=Role, user_role_model=UserRole)
    context = cast("Any", controller).role_admin_context

    request_bound_admin = role_admin_controller_handler_utils_module._resolve_role_admin(
        context,
        db_session=cast("Any", session),
    )
    async with request_bound_admin.session() as session_from_helper:
        assert session_from_helper is session
    with pytest.raises(ConfigurationError, match="litestar_auth_user_manager"):
        request_bound_admin._role_lifecycle_updater.build_manager(cast("Any", session))

    with pytest.raises(ConfigurationError, match="request-scoped AsyncSession"):
        role_admin_controller_handler_utils_module._resolve_role_admin(context)

    provided_manager_request_bound_admin = role_admin_controller_handler_utils_module._resolve_role_admin(
        context,
        db_session=cast("Any", session),
        request_user_manager=manager,
    )
    assert provided_manager_request_bound_admin._role_lifecycle_updater.build_manager(cast("Any", session)) is manager

    config_without_session = _minimal_config(user_model=User, session_maker=None)
    config_without_session.user_db_factory = cast("Any", lambda _: object())
    config_without_session.user_manager_factory = cast("Any", lambda **_: manager)
    config_without_session_controller = create_role_admin_controller(config=config_without_session)
    config_without_session_context = cast("Any", config_without_session_controller).role_admin_context
    config_request_bound_admin = role_admin_controller_handler_utils_module._resolve_role_admin(
        config_without_session_context,
        db_session=cast("Any", session),
    )
    assert config_request_bound_admin._role_lifecycle_updater.build_manager(cast("Any", session)) is manager

    with pytest.raises(ClientException) as invalid_exc:
        role_admin_error_responses_module._normalize_input_role_name(" \t ")
    assert invalid_exc.value.extra == {"code": ErrorCode.ROLE_NAME_INVALID}

    assert role_admin_controller_handler_utils_module._to_role_read(
        SimpleNamespace(name="billing", description="Docs"),
    ) == RoleRead(name="billing", description="Docs")
    assert role_admin_controller_handler_utils_module._to_user_brief(
        SimpleNamespace(
            id="user-1",
            email="member@example.com",
            is_active=True,
            is_verified=False,
        ),
    ) == UserBrief(
        id="user-1",
        email="member@example.com",
        is_active=True,
        is_verified=False,
    )

    async def _rename_body() -> bytes:
        await asyncio.sleep(0)
        return msgspec.json.encode({"name": "renamed"})

    rename_request = cast("Any", SimpleNamespace(body=_rename_body))
    with pytest.raises(ClientException, match="immutable"):
        await role_admin_controller_handler_utils_module._reject_role_name_mutation(rename_request)

    async def _safe_body() -> bytes:
        await asyncio.sleep(0)
        return msgspec.json.encode({"description": "updated"})

    safe_request = cast("Any", SimpleNamespace(body=_safe_body))
    await role_admin_controller_handler_utils_module._reject_role_name_mutation(safe_request)


async def test_contrib_role_admin_internal_helpers_cover_listing_loading_and_signature_rename() -> None:
    """Internal helpers cover paginated listing, missing-role handling, and dependency-key renaming."""

    class SessionStub:
        async def scalar(self, statement: object) -> object:
            del statement
            return SimpleNamespace(name="billing", description="Docs")

        async def scalars(self, statement: object) -> list[object]:
            del statement
            return [
                SimpleNamespace(name="admin", description=None),
                SimpleNamespace(name="billing", description="Docs"),
            ]

    class RoleAdminStub:
        role_model = Role

        @asynccontextmanager
        async def session(self) -> AsyncIterator[SessionStub]:
            yield SessionStub()

        async def list_roles(self) -> list[str]:
            return ["admin", "billing", "support"]

    role_admin = RoleAdminStub()
    page_schema_type = msgspec.defstruct(
        "RolePageCoverageSchema",
        [("items", list[RoleRead]), ("total", int), ("limit", int), ("offset", int)],
    )

    paged = await role_admin_controller_handler_utils_module._list_role_page(
        cast("Any", role_admin),
        page_schema_type=page_schema_type,
        limit=2,
        offset=0,
    )
    empty_page = await role_admin_controller_handler_utils_module._list_role_page(
        cast("Any", role_admin),
        page_schema_type=page_schema_type,
        limit=2,
        offset=10,
    )
    loaded = await role_admin_controller_handler_utils_module._load_role_row(
        cast("Any", role_admin),
        normalized_role_name="billing",
    )

    assert msgspec.to_builtins(paged) == {
        "items": [
            {"name": "admin", "description": None},
            {"name": "billing", "description": "Docs"},
        ],
        "total": 3,
        "limit": 2,
        "offset": 0,
    }
    assert msgspec.to_builtins(empty_page) == {"items": [], "total": 3, "limit": 2, "offset": 10}
    assert loaded == SimpleNamespace(name="billing", description="Docs")

    class MissingSessionStub(SessionStub):
        async def scalar(self, statement: object) -> object | None:
            del statement
            return None

    class MissingRoleAdminStub(RoleAdminStub):
        @asynccontextmanager
        async def session(self) -> AsyncIterator[MissingSessionStub]:
            yield MissingSessionStub()

    with pytest.raises(ClientException, match="not found") as exc_info:
        await role_admin_controller_handler_utils_module._load_role_row(
            cast("Any", MissingRoleAdminStub()),
            normalized_role_name="missing",
        )
    assert exc_info.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    controller = cast(
        "Any",
        create_role_admin_controller(user_model=User, role_model=Role, user_role_model=UserRole),
    )
    role_admin_controller_module._configure_request_session_dependency(controller, parameter_name="custom_session")
    assert "custom_session" in controller.list_roles.fn.__signature__.parameters
    assert "custom_session" in controller.assign_role.fn.__signature__.parameters
    assert "custom_session" in controller.unassign_role.fn.__signature__.parameters
    assert "custom_session" in controller.list_role_users.fn.__signature__.parameters


async def test_contrib_role_admin_assignment_helpers_cover_success_and_paging(  # noqa: C901
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assignment helpers normalize ids and page ``UserBrief`` payloads."""

    class RoleAdminStub:
        def __init__(self) -> None:
            self.assign_calls: list[dict[str, object]] = []
            self.unassign_calls: list[dict[str, object]] = []
            self.list_calls: list[str] = []

        def parse_user_id(self, raw_user_id: str) -> object:
            return f"parsed:{raw_user_id}"

        async def assign_user_roles(self, **kwargs: object) -> object:
            self.assign_calls.append(dict(kwargs))
            if kwargs["roles"] == ["missing"]:
                msg = "Role admin could not find role 'missing' in the configured catalog."
                raise RoleAdminRoleNotFoundError(msg)
            if kwargs["user_id"] == "parsed:missing-user":
                msg = "Role admin could not find a user with id 'parsed:missing-user'."
                raise RoleAdminUserNotFoundError(msg)
            return object()

        async def unassign_user_roles(self, **kwargs: object) -> object:
            self.unassign_calls.append(dict(kwargs))
            if kwargs["user_id"] == "parsed:missing-user":
                msg = "Role admin could not find a user with id 'parsed:missing-user'."
                raise RoleAdminUserNotFoundError(msg)
            return object()

        async def list_role_users(self, *, role: str) -> list[object]:
            self.list_calls.append(role)
            if role == "missing":
                msg = "Role admin could not find role 'missing' in the configured catalog."
                raise RoleAdminRoleNotFoundError(msg)
            return [
                SimpleNamespace(
                    id="user-1",
                    email="auditor@example.com",
                    is_active=True,
                    is_verified=True,
                ),
                SimpleNamespace(
                    id="user-2",
                    email="member@example.com",
                    is_active=True,
                    is_verified=False,
                ),
            ]

    role_admin = RoleAdminStub()

    async def _load_role_row_stub(role_admin: object, normalized_role_name: str) -> object:
        await asyncio.sleep(0)
        del role_admin
        return SimpleNamespace(name=normalized_role_name, description="Docs")

    monkeypatch.setattr(role_admin_controller_handler_utils_module, "_load_role_row", _load_role_row_stub)

    assign_result = await role_admin_controller_handler_utils_module._assign_role_user(
        cast("Any", role_admin),
        role_name=" Billing ",
        user_id="user-1",
    )
    user_page_schema_type = msgspec.defstruct(
        "RoleUserPageCoverageSchema",
        [("items", list[UserBrief]), ("total", int), ("limit", int), ("offset", int)],
    )
    user_page = await role_admin_controller_handler_utils_module._list_role_user_page(
        cast("Any", role_admin),
        page_schema_type=user_page_schema_type,
        role_name="billing",
        limit=1,
        offset=1,
    )
    await role_admin_controller_handler_utils_module._unassign_role_user(
        cast("Any", role_admin),
        role_name="billing",
        user_id="user-1",
    )

    assert assign_result == RoleRead(name="billing", description="Docs")
    assert role_admin.assign_calls == [
        {
            "user_id": "parsed:user-1",
            "roles": ["billing"],
            "require_existing_roles": True,
        },
    ]
    assert msgspec.to_builtins(user_page) == {
        "items": [
            {
                "id": "user-2",
                "email": "member@example.com",
                "is_active": True,
                "is_verified": False,
            },
        ],
        "total": 2,
        "limit": 1,
        "offset": 1,
    }
    assert role_admin.unassign_calls == [
        {
            "user_id": "parsed:user-1",
            "roles": ["billing"],
        },
    ]


async def test_contrib_role_admin_assignment_helpers_cover_error_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assignment helpers map missing roles and users into the contrib error contract."""

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

    role_admin = RoleAdminStub()

    async def _load_role_row_stub(role_admin: object, normalized_role_name: str) -> object:
        await asyncio.sleep(0)
        del role_admin, normalized_role_name
        return SimpleNamespace(name="billing", description="Docs")

    monkeypatch.setattr(role_admin_controller_handler_utils_module, "_load_role_row", _load_role_row_stub)
    user_page_schema_type = msgspec.defstruct(
        "RoleUserPageCoverageErrorSchema",
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

    with pytest.raises(ClientException, match="could not find a user") as missing_unassign_user_exc:
        await role_admin_controller_handler_utils_module._unassign_role_user(
            cast("Any", role_admin),
            role_name="billing",
            user_id="missing-user",
        )
    assert missing_unassign_user_exc.value.extra == {"code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND}

    with pytest.raises(ClientException, match="configured catalog") as missing_page_role_exc:
        await role_admin_controller_handler_utils_module._list_role_user_page(
            cast("Any", role_admin),
            page_schema_type=user_page_schema_type,
            role_name="missing",
            limit=1,
            offset=0,
        )
    assert missing_page_role_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}


async def test_contrib_role_admin_controller_handlers_cover_config_and_request_bound_error_paths(  # noqa: C901, PLR0915
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generated handlers cover both config-backed and request-bound controller branches."""
    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())
    config_controller = cast("Any", create_role_admin_controller(config=config))
    config_instance = cast("Any", SimpleNamespace(role_admin_context=config_controller.role_admin_context))

    class RuntimeFailureRoleAdmin:
        async def create_role(self, **_: object) -> list[str]:
            msg = "boom"
            raise RuntimeError(msg)

    def _runtime_failure_resolver(
        context: object,
        db_session: object | None = None,
        request_user_manager: object | None = None,
    ) -> RuntimeFailureRoleAdmin:
        del context, db_session, request_user_manager
        return RuntimeFailureRoleAdmin()

    monkeypatch.setattr(
        role_admin_controller_handlers_module,
        "_resolve_role_admin",
        _runtime_failure_resolver,
    )
    with pytest.raises(RuntimeError, match="boom"):
        await config_controller.create_role.fn(
            config_instance,
            RoleCreate(name="ops", description="Ops"),
        )

    class ConfigBranchSessionStub:
        def __init__(self, role: object | None) -> None:
            self._role = role
            self.commit_calls = 0

        async def scalar(self, statement: object) -> object | None:
            del statement
            return self._role

        async def commit(self) -> None:
            self.commit_calls += 1

    class ConfigBranchRoleAdminStub:
        role_model = Role

        def __init__(self, session: ConfigBranchSessionStub) -> None:
            self._session = session

        @asynccontextmanager
        async def session(self) -> AsyncIterator[ConfigBranchSessionStub]:
            yield self._session

        async def delete_role(self, *, role: str) -> list[str]:
            del role
            msg = "missing"
            raise LookupError(msg)

    async def _empty_body() -> bytes:
        await asyncio.sleep(0)
        return msgspec.json.encode({"description": "Updated docs"})

    config_request = cast("Any", SimpleNamespace(body=_empty_body))
    config_branch_session = ConfigBranchSessionStub(None)
    config_branch_role_admin = ConfigBranchRoleAdminStub(config_branch_session)

    def _config_branch_resolver(
        context: object,
        db_session: object | None = None,
        request_user_manager: object | None = None,
    ) -> ConfigBranchRoleAdminStub:
        del context, db_session, request_user_manager
        return config_branch_role_admin

    monkeypatch.setattr(role_admin_controller_handlers_module, "_resolve_role_admin", _config_branch_resolver)

    with pytest.raises(ClientException, match="not found") as config_update_missing_exc:
        await config_controller.update_role.fn(
            config_instance,
            config_request,
            "missing",
            RoleUpdate(description="Updated docs"),
        )
    assert config_update_missing_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    config_branch_session._role = SimpleNamespace(name="admin")
    with pytest.raises(ConfigurationError, match="does not expose a 'description' attribute"):
        await config_controller.update_role.fn(
            config_instance,
            config_request,
            "admin",
            RoleUpdate(description="Updated docs"),
        )

    async def _empty_update_body() -> bytes:
        await asyncio.sleep(0)
        return msgspec.json.encode({})

    empty_update_request = cast("Any", SimpleNamespace(body=_empty_update_body))
    config_branch_session._role = SimpleNamespace(name="admin")
    config_update_result = await config_controller.update_role.fn(
        config_instance,
        empty_update_request,
        "admin",
        RoleUpdate(),
    )
    assert config_update_result == RoleRead(name="admin", description=None)

    with pytest.raises(ClientException, match="not found") as config_delete_missing_exc:
        await config_controller.delete_role.fn(
            config_instance,
            "missing",
        )
    assert config_delete_missing_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    no_config_controller = cast(
        "Any",
        create_role_admin_controller(
            user_model=User,
            role_model=Role,
            user_role_model=UserRole,
        ),
    )
    no_config_instance = cast("Any", SimpleNamespace(role_admin_context=no_config_controller.role_admin_context))

    class ConfigSessionStub:
        def __init__(self, role: object | None) -> None:
            self._role = role
            self.commit_calls = 0

        async def scalar(self, statement: object) -> object | None:
            del statement
            return self._role

        async def commit(self) -> None:
            self.commit_calls += 1

    class ConfigRoleAdminStub:
        role_model = Role

        def __init__(self, session: ConfigSessionStub) -> None:
            self._session = session
            self.create_calls: list[dict[str, object]] = []
            self.delete_calls: list[str] = []
            self.assign_calls: list[dict[str, object]] = []
            self.unassign_calls: list[dict[str, object]] = []
            self.list_role_user_calls: list[str] = []

        async def list_roles(self) -> list[str]:
            return []

        async def list_role_users(self, *, role: str) -> list[object]:
            self.list_role_user_calls.append(role)
            if role == "missing":
                msg = "Role admin could not find role 'missing' in the configured catalog."
                raise RoleAdminRoleNotFoundError(msg)
            return [
                SimpleNamespace(
                    id="user-1",
                    email="auditor@example.com",
                    is_active=True,
                    is_verified=True,
                ),
            ]

        @asynccontextmanager
        async def session(self) -> AsyncIterator[ConfigSessionStub]:
            yield self._session

        def parse_user_id(self, raw_user_id: str) -> object:
            return f"parsed:{raw_user_id}"

        async def create_role(self, **kwargs: object) -> list[str]:
            self.create_calls.append(dict(kwargs))
            if kwargs["role"] == "duplicate":
                msg = "duplicate"
                raise IntegrityError(msg, params=None, orig=RuntimeError(msg))
            return ["admin", cast("str", kwargs["role"])]

        async def assign_user_roles(self, **kwargs: object) -> object:
            self.assign_calls.append(dict(kwargs))
            if kwargs["roles"] == ["missing"]:
                msg = "Role admin could not find role 'missing' in the configured catalog."
                raise RoleAdminRoleNotFoundError(msg)
            if kwargs["user_id"] == "parsed:missing-user":
                msg = "Role admin could not find a user with id 'parsed:missing-user'."
                raise RoleAdminUserNotFoundError(msg)
            return object()

        async def delete_role(self, *, role: str) -> list[str]:
            self.delete_calls.append(role)
            if role == "missing":
                msg = "missing"
                raise LookupError(msg)
            msg = "assigned"
            raise ValueError(msg)

        async def unassign_user_roles(self, **kwargs: object) -> object:
            self.unassign_calls.append(dict(kwargs))
            if kwargs["user_id"] == "parsed:missing-user":
                msg = "Role admin could not find a user with id 'parsed:missing-user'."
                raise RoleAdminUserNotFoundError(msg)
            return object()

    role_session = ConfigSessionStub(SimpleNamespace(name="admin", description=None))
    role_admin_stub = ConfigRoleAdminStub(role_session)

    def _role_admin_resolver(
        context: object,
        db_session: object | None = None,
        request_user_manager: object | None = None,
    ) -> ConfigRoleAdminStub:
        del context, db_session, request_user_manager
        return role_admin_stub

    monkeypatch.setattr(role_admin_controller_handlers_module, "_resolve_role_admin", _role_admin_resolver)

    async def _load_role_row_stub(role_admin: object, normalized_role_name: str) -> object:
        await asyncio.sleep(0)
        del role_admin
        return SimpleNamespace(name=normalized_role_name, description="Docs")

    monkeypatch.setattr(role_admin_controller_handlers_module, "_load_role_row", _load_role_row_stub)
    monkeypatch.setattr(role_admin_controller_handler_utils_module, "_load_role_row", _load_role_row_stub)

    list_result = await no_config_controller.list_roles.fn(
        no_config_instance,
        db_session=cast("Any", TrackingAsyncSession()),
        limit=2,
        offset=0,
    )
    assert msgspec.to_builtins(list_result) == {"items": [], "total": 0, "limit": 2, "offset": 0}

    create_result = await no_config_controller.create_role.fn(
        no_config_instance,
        data=RoleCreate(name=" Support ", description="Docs"),
        db_session=cast("Any", TrackingAsyncSession()),
    )
    assert create_result == RoleRead(name="support", description="Docs")

    class NoConfigRuntimeFailureRoleAdmin:
        async def create_role(self, **_: object) -> list[str]:
            msg = "boom"
            raise RuntimeError(msg)

    def _no_config_runtime_failure_resolver(
        context: object,
        db_session: object | None = None,
        request_user_manager: object | None = None,
    ) -> NoConfigRuntimeFailureRoleAdmin:
        del context, db_session, request_user_manager
        return NoConfigRuntimeFailureRoleAdmin()

    monkeypatch.setattr(
        role_admin_controller_handlers_module,
        "_resolve_role_admin",
        _no_config_runtime_failure_resolver,
    )
    with pytest.raises(RuntimeError, match="boom"):
        await no_config_controller.create_role.fn(
            no_config_instance,
            data=RoleCreate(name="boom", description="Docs"),
            db_session=cast("Any", TrackingAsyncSession()),
        )

    monkeypatch.setattr(role_admin_controller_handlers_module, "_resolve_role_admin", _role_admin_resolver)

    with pytest.raises(ClientException, match="already exists") as duplicate_exc:
        await no_config_controller.create_role.fn(
            no_config_instance,
            data=RoleCreate(name="duplicate", description="Docs"),
            db_session=cast("Any", TrackingAsyncSession()),
        )
    assert duplicate_exc.value.extra == {"code": ErrorCode.ROLE_ALREADY_EXISTS}

    get_result = await no_config_controller.get_role.fn(
        no_config_instance,
        role_name="admin",
        db_session=cast("Any", TrackingAsyncSession()),
    )
    assert get_result == RoleRead(name="admin", description="Docs")

    async def _update_body() -> bytes:
        await asyncio.sleep(0)
        return msgspec.json.encode({"description": "Updated docs"})

    request = cast("Any", SimpleNamespace(body=_update_body))
    update_result = await no_config_controller.update_role.fn(
        no_config_instance,
        request,
        role_name="admin",
        data=RoleUpdate(description="Updated docs"),
        db_session=cast("Any", TrackingAsyncSession()),
    )
    assert update_result == RoleRead(name="admin", description="Updated docs")

    role_session._role = None
    with pytest.raises(ClientException, match="not found") as update_missing_exc:
        await no_config_controller.update_role.fn(
            no_config_instance,
            request,
            role_name="missing",
            data=RoleUpdate(description="Updated docs"),
            db_session=cast("Any", TrackingAsyncSession()),
        )
    assert update_missing_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    role_session._role = SimpleNamespace(name="admin")
    with pytest.raises(ConfigurationError, match="does not expose a 'description' attribute"):
        await no_config_controller.update_role.fn(
            no_config_instance,
            request,
            role_name="admin",
            data=RoleUpdate(description="Updated docs"),
            db_session=cast("Any", TrackingAsyncSession()),
        )

    await no_config_controller.update_role.fn(
        no_config_instance,
        request,
        role_name="admin",
        data=RoleUpdate(),
        db_session=cast("Any", TrackingAsyncSession()),
    )

    with pytest.raises(ClientException, match="not found") as delete_missing_exc:
        await no_config_controller.delete_role.fn(
            no_config_instance,
            role_name="missing",
            db_session=cast("Any", TrackingAsyncSession()),
        )
    assert delete_missing_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    with pytest.raises(ClientException, match="assigned") as delete_assigned_exc:
        await no_config_controller.delete_role.fn(
            no_config_instance,
            role_name="admin",
            db_session=cast("Any", TrackingAsyncSession()),
        )
    assert delete_assigned_exc.value.extra == {"code": ErrorCode.ROLE_STILL_ASSIGNED}

    assign_result = await no_config_controller.assign_role.fn(
        no_config_instance,
        role_name="admin",
        user_id="user-1",
        db_session=cast("Any", TrackingAsyncSession()),
        litestar_auth_user_manager=object(),
    )
    list_role_users_result = await no_config_controller.list_role_users.fn(
        no_config_instance,
        role_name="admin",
        db_session=cast("Any", TrackingAsyncSession()),
        limit=1,
        offset=0,
    )
    await no_config_controller.unassign_role.fn(
        no_config_instance,
        role_name="admin",
        user_id="user-1",
        db_session=cast("Any", TrackingAsyncSession()),
        litestar_auth_user_manager=object(),
    )

    assert assign_result == RoleRead(name="admin", description="Docs")
    assert msgspec.to_builtins(list_role_users_result) == {
        "items": [
            {
                "id": "user-1",
                "email": "auditor@example.com",
                "is_active": True,
                "is_verified": True,
            },
        ],
        "total": 1,
        "limit": 1,
        "offset": 0,
    }
    assert role_admin_stub.assign_calls == [
        {
            "user_id": "parsed:user-1",
            "roles": ["admin"],
            "require_existing_roles": True,
        },
    ]
    assert role_admin_stub.unassign_calls == [
        {
            "user_id": "parsed:user-1",
            "roles": ["admin"],
        },
    ]

    with pytest.raises(ClientException, match="configured catalog") as missing_assign_role_exc:
        await no_config_controller.assign_role.fn(
            no_config_instance,
            role_name="missing",
            user_id="user-1",
            db_session=cast("Any", TrackingAsyncSession()),
            litestar_auth_user_manager=object(),
        )
    assert missing_assign_role_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    with pytest.raises(ClientException, match="could not find a user") as missing_assign_user_exc:
        await no_config_controller.assign_role.fn(
            no_config_instance,
            role_name="admin",
            user_id="missing-user",
            db_session=cast("Any", TrackingAsyncSession()),
            litestar_auth_user_manager=object(),
        )
    assert missing_assign_user_exc.value.extra == {"code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND}

    with pytest.raises(ClientException, match="configured catalog") as missing_list_role_users_exc:
        await no_config_controller.list_role_users.fn(
            no_config_instance,
            role_name="missing",
            db_session=cast("Any", TrackingAsyncSession()),
            limit=1,
            offset=0,
        )
    assert missing_list_role_users_exc.value.extra == {"code": ErrorCode.ROLE_NOT_FOUND}

    with pytest.raises(ClientException, match="could not find a user") as missing_unassign_user_exc:
        await no_config_controller.unassign_role.fn(
            no_config_instance,
            role_name="admin",
            user_id="missing-user",
            db_session=cast("Any", TrackingAsyncSession()),
            litestar_auth_user_manager=object(),
        )
    assert missing_unassign_user_exc.value.extra == {"code": ErrorCode.ROLE_ASSIGNMENT_USER_NOT_FOUND}


@pytest.mark.imports
def test_contrib_redis_public_boundary_tracks_internal_surface() -> None:
    """The public Redis contrib package re-exports the dedicated internal surface."""
    assert redis_module.RedisAuthClientProtocol is redis_surface_module.RedisAuthClientProtocol
    assert redis_module.RedisAuthPreset is redis_surface_module.RedisAuthPreset
    assert redis_module.RedisAuthRateLimitConfigOptions is redis_surface_module.RedisAuthRateLimitConfigOptions
    assert redis_module.RedisAuthRateLimitTier is redis_surface_module.RedisAuthRateLimitTier
    assert redis_module.RedisTotpEnrollmentStore is redis_surface_module.RedisTotpEnrollmentStore
    assert redis_module.RedisTokenStrategy is redis_surface_module.RedisTokenStrategy
    assert redis_module.RedisTokenStrategyConfig is redis_surface_module.RedisTokenStrategyConfig
    assert redis_module.RedisUsedTotpCodeStore is redis_surface_module.RedisUsedTotpCodeStore
    assert redis_module.__all__ == redis_surface_module.__all__


def test_contrib_redis_preset_exposes_public_shared_client_protocol(async_fakeredis: AsyncFakeRedis) -> None:
    """The preset's public client annotation points at the stable contrib protocol."""
    preset_hints = get_type_hints(RedisAuthPreset, include_extras=True)

    assert preset_hints["redis"] is RedisAuthClientProtocol
    assert isinstance(async_fakeredis, RedisAuthClientProtocol)


def test_contrib_redis_preset_snapshots_group_rate_limit_tiers_as_read_only_mapping(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The preset stores group tiers as a read-only snapshot detached from caller-owned mappings."""
    source_tiers: dict[AuthRateLimitEndpointGroup, RedisAuthRateLimitTier] = {
        "refresh": RedisAuthRateLimitTier(
            max_attempts=REFRESH_MAX_ATTEMPTS,
            window_seconds=REFRESH_WINDOW_SECONDS,
        ),
    }

    preset = RedisAuthPreset(
        redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol),
        group_rate_limit_tiers=source_tiers,
    )
    source_tiers["totp"] = RedisAuthRateLimitTier(
        max_attempts=TOTP_MAX_ATTEMPTS,
        window_seconds=TOTP_WINDOW_SECONDS,
    )

    assert isinstance(preset.group_rate_limit_tiers, MappingProxyType)
    assert tuple(preset.group_rate_limit_tiers) == ("refresh",)
    with pytest.raises(TypeError, match="mappingproxy"):
        cast("Any", preset.group_rate_limit_tiers)["totp"] = RedisAuthRateLimitTier(
            max_attempts=TOTP_MAX_ATTEMPTS,
            window_seconds=TOTP_WINDOW_SECONDS,
        )


async def test_contrib_redis_preset_builds_shared_client_auth_components(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The contrib preset derives auth rate limiting plus the Redis-backed TOTP stores."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr("litestar_auth.ratelimit._helpers._load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth._totp_stores._load_used_totp_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth._totp_stores._load_enrollment_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth.authentication.strategy._jwt_denylist._load_redis_asyncio", load_optional_redis)
    redis_client = cast_fakeredis(async_fakeredis, RedisAuthClientProtocol)
    assert isinstance(redis_client, RedisAuthClientProtocol)
    preset = RedisAuthPreset(
        redis=redis_client,
        rate_limit_tier=RedisAuthRateLimitTier(
            max_attempts=SHARED_MAX_ATTEMPTS,
            window_seconds=SHARED_WINDOW_SECONDS,
        ),
        group_rate_limit_tiers={
            "refresh": RedisAuthRateLimitTier(
                max_attempts=REFRESH_MAX_ATTEMPTS,
                window_seconds=REFRESH_WINDOW_SECONDS,
                key_prefix="refresh:",
            ),
            "totp": RedisAuthRateLimitTier(
                max_attempts=TOTP_MAX_ATTEMPTS,
                window_seconds=TOTP_WINDOW_SECONDS,
                key_prefix="totp:",
            ),
        },
        totp_used_tokens_key_prefix="used:",
        totp_pending_jti_key_prefix="pending:",
        totp_enrollment_key_prefix="enroll:",
    )

    config = preset.build_rate_limit_config(
        options=RedisAuthRateLimitConfigOptions(
            disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS,
            identity_fields=("username", "email"),
            trusted_headers=("X-Real-IP",),
        ),
    )
    store = preset.build_totp_used_tokens_store()
    enrollment_store = preset.build_totp_enrollment_store()
    pending_store = preset.build_totp_pending_jti_store()

    assert config.login is not None
    assert isinstance(config.login.backend, ratelimit_module.RedisRateLimiter)
    assert config.login.backend.redis is redis_client
    assert config.login.backend.max_attempts == SHARED_MAX_ATTEMPTS
    assert config.login.backend.window_seconds == SHARED_WINDOW_SECONDS
    assert config.login.backend.key_prefix == ratelimit_module.DEFAULT_KEY_PREFIX
    assert config.login.identity_fields == ("username", "email")
    assert config.login.trusted_headers == ("X-Real-IP",)
    assert config.refresh is not None
    assert isinstance(config.refresh.backend, ratelimit_module.RedisRateLimiter)
    assert config.refresh.backend.redis is redis_client
    assert config.refresh.backend.max_attempts == REFRESH_MAX_ATTEMPTS
    assert config.refresh.backend.window_seconds == REFRESH_WINDOW_SECONDS
    assert config.refresh.backend.key_prefix == "refresh:"
    assert config.refresh.identity_fields == ("username", "email")
    assert config.refresh.trusted_headers == ("X-Real-IP",)
    assert config.totp_verify is not None
    assert isinstance(config.totp_verify.backend, ratelimit_module.RedisRateLimiter)
    assert config.totp_verify.backend.redis is redis_client
    assert config.totp_verify.backend.max_attempts == TOTP_MAX_ATTEMPTS
    assert config.totp_verify.backend.window_seconds == TOTP_WINDOW_SECONDS
    assert config.totp_verify.backend.key_prefix == "totp:"
    assert config.verify_token is None
    assert config.request_verify_token is None
    assert store._redis is redis_client
    assert enrollment_store._redis is redis_client
    assert pending_store.redis is redis_client
    assert enrollment_store._key("user-1").startswith("enroll:")
    assert pending_store.key_prefix == "pending:"
    assert (await store.mark_used("user-1", 7, 1.25)).stored is True
    await pending_store.deny("pending-jti", ttl_seconds=PENDING_JTI_TTL_SECONDS)
    assert await pending_store.is_denied("pending-jti") is True
    assert await async_fakeredis.get("used:user-1:7") == b"1"
    assert await async_fakeredis.get("pending:pending-jti") == b"1"
    assert 0 < await async_fakeredis.pttl("used:user-1:7") <= USED_TOTP_TTL_MS
    assert PENDING_JTI_TTL_FLOOR <= await async_fakeredis.ttl("pending:pending-jti") <= PENDING_JTI_TTL_SECONDS


def test_contrib_redis_preset_covers_optional_identity_and_proxy_header_branches(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The preset forwards either optional builder input independently."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr("litestar_auth.ratelimit._helpers._load_redis_asyncio", load_optional_redis)
    preset = RedisAuthPreset(redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol))

    config_with_headers = preset.build_rate_limit_config(
        options=RedisAuthRateLimitConfigOptions(trusted_headers=("X-Real-IP",)),
    )
    config_with_identity_fields = preset.build_rate_limit_config(
        options=RedisAuthRateLimitConfigOptions(identity_fields=("email",)),
    )

    assert config_with_headers.login is not None
    assert config_with_headers.login.identity_fields == ("identifier", "username", "email")
    assert config_with_headers.login.trusted_headers == ("X-Real-IP",)
    assert config_with_identity_fields.login is not None
    assert config_with_identity_fields.login.identity_fields == ("email",)
    assert config_with_identity_fields.login.trusted_headers == ("X-Forwarded-For",)


def test_contrib_redis_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib Redis alias preserves the strategy's optional dependency guard."""

    def fail_load() -> object:
        msg = "Install litestar-auth[redis] to use RedisTokenStrategy"
        raise ImportError(msg)

    monkeypatch.setattr("litestar_auth.authentication.strategy.redis._load_redis_asyncio", fail_load)

    redis_client_sentinel = cast("Any", object())
    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisTokenStrategy"):
        RedisTokenStrategy(
            config=RedisTokenStrategyConfig(redis=redis_client_sentinel, token_hash_secret=REDIS_TOKEN_HASH_SECRET),
        )


def test_contrib_redis_preset_preserves_rate_limit_lazy_dependency_error(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The contrib preset defers Redis rate-limit imports until config construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisRateLimiter"
        raise ImportError(msg)

    monkeypatch.setattr("litestar_auth.ratelimit._helpers._load_redis_asyncio", fail_load_redis)
    preset = RedisAuthPreset(redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol))

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisRateLimiter"):
        preset.build_rate_limit_config()


def test_contrib_redis_preset_preserves_totp_lazy_dependency_error(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The contrib preset defers TOTP Redis imports until replay-store construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisUsedTotpCodeStore"
        raise ImportError(msg)

    monkeypatch.setattr("litestar_auth._totp_stores._load_used_totp_redis_asyncio", fail_load_redis)
    preset = RedisAuthPreset(redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol))

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisUsedTotpCodeStore"):
        preset.build_totp_used_tokens_store()


def test_contrib_redis_preset_preserves_pending_jti_lazy_dependency_error(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The contrib preset defers pending-token denylist imports until store construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisJWTDenylistStore"
        raise ImportError(msg)

    monkeypatch.setattr("litestar_auth.authentication.strategy._jwt_denylist._load_redis_asyncio", fail_load_redis)
    preset = RedisAuthPreset(redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol))

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisJWTDenylistStore"):
        preset.build_totp_pending_jti_store()


def test_contrib_redis_preset_preserves_enrollment_lazy_dependency_error(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The contrib preset defers pending-enrollment Redis imports until store construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisTotpEnrollmentStore"
        raise ImportError(msg)

    monkeypatch.setattr("litestar_auth._totp_stores._load_enrollment_redis_asyncio", fail_load_redis)
    preset = RedisAuthPreset(redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol))

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisTotpEnrollmentStore"):
        preset.build_totp_enrollment_store()


def test_oauth_package_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The canonical OAuth package preserves the router's optional dependency guard."""

    def fail_import(module_name: str) -> None:
        message = f"No module named {module_name!r}"
        raise ModuleNotFoundError(
            message,
            name="httpx_oauth.clients.github",
        )

    monkeypatch.setattr("litestar_auth.oauth.router.import_module", fail_import)
    backend = AuthenticationBackend[ExampleUser, str](
        name="oauth",
        transport=BearerTransport(),
        strategy=ExampleStrategy(),
    )
    user_manager = ExampleUserManager()

    with pytest.raises(ImportError, match=r"Install litestar-auth\[oauth\] to use OAuth controllers\."):
        create_provider_oauth_controller(
            provider_name="github",
            backend=backend,
            user_manager=user_manager,
            oauth_client_class="httpx_oauth.clients.github.GitHubOAuth2",
            redirect_base_url="https://app.example/auth/oauth",
            oauth_flow_cookie_secret="oauth-flow-cookie-secret-1234567890",
        )
