"""OpenAPI regression tests for controller request-body contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

import pytest
from litestar import Litestar

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests._helpers import ExampleUser
from tests.integration.conftest import DummySessionMaker, InMemoryUserDatabase
from tests.integration.test_controller_auth import build_app as build_auth_app
from tests.integration.test_controller_register import build_app as build_register_app
from tests.integration.test_controller_reset import build_app as build_reset_app
from tests.integration.test_controller_totp import build_app as build_totp_app
from tests.integration.test_controller_users import build_app as build_users_app
from tests.integration.test_controller_verify import build_app as build_verify_app
from tests.integration.test_orchestrator import InMemoryRefreshTokenStrategy, PluginUserManager

pytestmark = [pytest.mark.integration]
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
TOTP_VERIFICATION_CODE_PATTERN = r"^(?:\d{6}|[0-9a-f]{28})$"
ARRAY_TYPE = "array"
BOOLEAN_TYPE = "boolean"
STRING_TYPE = "string"


@dataclass(frozen=True, slots=True)
class PropertyContract:
    """Stable OpenAPI details exposed for a single request-body field."""

    min_length: int | None = None
    max_length: int | None = None
    pattern: str | None = None


@dataclass(frozen=True, slots=True)
class ComponentContract:
    """Stable request-body schema details that should remain visible in OpenAPI."""

    required: frozenset[str]
    properties: dict[str, PropertyContract]


COMPONENT_CONTRACTS = {
    "ChangePasswordRequest": ComponentContract(
        required=frozenset({"current_password", "new_password"}),
        properties={
            "current_password": PropertyContract(min_length=12, max_length=128),
            "new_password": PropertyContract(min_length=12, max_length=128),
        },
    ),
    "ForgotPassword": ComponentContract(
        required=frozenset({"email"}),
        properties={"email": PropertyContract(max_length=320, pattern=EMAIL_PATTERN)},
    ),
    "LoginCredentials": ComponentContract(
        required=frozenset({"identifier", "password"}),
        properties={
            "identifier": PropertyContract(min_length=1, max_length=320),
            "password": PropertyContract(min_length=1, max_length=128),
        },
    ),
    "RefreshTokenRequest": ComponentContract(
        required=frozenset({"refresh_token"}),
        properties={"refresh_token": PropertyContract(min_length=1, max_length=512)},
    ),
    "RequestVerifyToken": ComponentContract(
        required=frozenset({"email"}),
        properties={"email": PropertyContract(max_length=320, pattern=EMAIL_PATTERN)},
    ),
    "ResetPassword": ComponentContract(
        required=frozenset({"password", "token"}),
        properties={
            "password": PropertyContract(min_length=1, max_length=128),
            "token": PropertyContract(min_length=1, max_length=2048),
        },
    ),
    "TotpConfirmEnableRequest": ComponentContract(
        required=frozenset({"code", "enrollment_token"}),
        properties={
            "code": PropertyContract(min_length=6, max_length=6),
            "enrollment_token": PropertyContract(min_length=1, max_length=2048),
        },
    ),
    "TotpDisableRequest": ComponentContract(
        required=frozenset({"code"}),
        properties={"code": PropertyContract(min_length=6, max_length=28, pattern=TOTP_VERIFICATION_CODE_PATTERN)},
    ),
    "TotpEnableRequest": ComponentContract(
        required=frozenset({"password"}),
        properties={"password": PropertyContract(min_length=1, max_length=128)},
    ),
    "TotpRegenerateRecoveryCodesRequest": ComponentContract(
        required=frozenset({"current_password"}),
        properties={"current_password": PropertyContract(min_length=1, max_length=128)},
    ),
    "TotpVerifyRequest": ComponentContract(
        required=frozenset({"code", "pending_token"}),
        properties={
            "code": PropertyContract(min_length=6, max_length=28, pattern=TOTP_VERIFICATION_CODE_PATTERN),
            "pending_token": PropertyContract(min_length=1, max_length=2048),
        },
    ),
    "UserCreate": ComponentContract(
        required=frozenset({"email", "password"}),
        properties={
            "email": PropertyContract(max_length=320, pattern=EMAIL_PATTERN),
            "password": PropertyContract(min_length=12, max_length=128),
        },
    ),
    "VerifyToken": ComponentContract(
        required=frozenset({"token"}),
        properties={"token": PropertyContract(min_length=1, max_length=2048)},
    ),
}


def _build_plugin_openapi_app() -> Litestar:
    """Build a plugin-mounted app using the consumer-reported ``/auth/jwt`` prefix.

    Returns:
        Litestar app exposing plugin-managed auth routes under ``/auth/jwt``.
    """
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryRefreshTokenStrategy(token_prefix="openapi")),
            ),
        ],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=PasswordHelper(),
        ),
        auth_path="/auth/jwt",
        enable_refresh=True,
        include_users=False,
        include_verify=True,
    )
    return Litestar(plugins=[LitestarAuth(config)])


def _request_body_ref(app: Litestar, *, path: str, method_name: str) -> str | None:
    """Return the OpenAPI request-body schema ref for an operation, if any."""
    operation = getattr(cast("Any", app.openapi_schema.paths)[path], method_name)
    request_body = operation.request_body
    if request_body is None:
        return None
    media_type = next(iter(request_body.content.values()))
    return media_type.schema.ref


def _response_body_ref(app: Litestar, *, path: str, method_name: str, status_code: str) -> str | None:
    """Return the OpenAPI response-body schema ref for an operation, if any."""
    operation = getattr(cast("Any", app.openapi_schema.paths)[path], method_name)
    response = operation.responses[status_code]
    if response.content is None:
        return None
    media_type = next(iter(response.content.values()))
    return media_type.schema.ref


def _assert_request_body_component_ref(
    app: Litestar,
    *,
    path: str,
    method_name: str,
    schema_ref: str | None,
) -> None:
    """Assert the request body uses the expected schema ref and that the component exists."""
    assert _request_body_ref(app, path=path, method_name=method_name) == schema_ref
    if schema_ref is None:
        return
    component_name = schema_ref.removeprefix("#/components/schemas/")
    schemas = cast("Any", app.openapi_schema.components.schemas)
    assert component_name in schemas


def _assert_component_contract(
    app: Litestar,
    *,
    component_name: str,
) -> None:
    """Assert a component exposes the stable field names and validation limits we document."""
    schema = cast("Any", app.openapi_schema.components.schemas)[component_name]
    contract = COMPONENT_CONTRACTS[component_name]
    properties = schema.properties or {}

    assert set(schema.required or []) == contract.required
    assert set(properties) == set(contract.properties)
    for property_name, expected in contract.properties.items():
        property_schema = properties[property_name]

        assert getattr(property_schema.type, "value", property_schema.type) == STRING_TYPE
        assert property_schema.min_length == expected.min_length
        assert property_schema.max_length == expected.max_length
        assert property_schema.pattern == expected.pattern


def _assert_recovery_codes_property(schema: object) -> None:
    """Assert an OpenAPI schema exposes the documented recovery-code array."""
    properties = cast("Any", schema).properties or {}
    recovery_codes = properties["recovery_codes"]

    assert getattr(recovery_codes.type, "value", recovery_codes.type) == ARRAY_TYPE
    assert recovery_codes.items is not None
    assert getattr(recovery_codes.items.type, "value", recovery_codes.items.type) == STRING_TYPE


def _assert_request_body_component_contract(
    app: Litestar,
    *,
    path: str,
    method_name: str,
    schema_ref: str | None,
) -> None:
    """Assert both the request-body ref and the referenced component contract."""
    _assert_request_body_component_ref(app, path=path, method_name=method_name, schema_ref=schema_ref)
    if schema_ref is None:
        return
    _assert_component_contract(
        app,
        component_name=schema_ref.removeprefix("#/components/schemas/"),
    )


@pytest.fixture
def plugin_app() -> Litestar:
    """Provide the plugin-mounted app used to lock `/auth/jwt/*` schema paths.

    Returns:
        Litestar app exposing the plugin-mounted auth schema.
    """
    return _build_plugin_openapi_app()


@pytest.mark.parametrize(
    ("path", "schema_ref"),
    [
        ("/auth/jwt/login", "#/components/schemas/LoginCredentials"),
        ("/auth/jwt/register", "#/components/schemas/UserCreate"),
        ("/auth/jwt/request-verify-token", "#/components/schemas/RequestVerifyToken"),
        ("/auth/jwt/verify", "#/components/schemas/VerifyToken"),
        ("/auth/jwt/forgot-password", "#/components/schemas/ForgotPassword"),
        ("/auth/jwt/reset-password", "#/components/schemas/ResetPassword"),
        ("/auth/jwt/refresh", "#/components/schemas/RefreshTokenRequest"),
    ],
)
def test_plugin_mounted_auth_routes_publish_expected_request_bodies_and_component_shapes(
    plugin_app: Litestar,
    path: str,
    schema_ref: str,
) -> None:
    """Plugin-mounted auth routes retain the documented `/auth/jwt/*` request contracts."""
    paths = cast("Any", plugin_app.openapi_schema.paths)

    assert "/auth/login" not in paths
    assert path in paths
    _assert_request_body_component_contract(plugin_app, path=path, method_name="post", schema_ref=schema_ref)


@pytest.mark.parametrize(
    ("path", "schema_ref"),
    [
        ("/auth/login", "#/components/schemas/LoginCredentials"),
        ("/auth/refresh", "#/components/schemas/RefreshTokenRequest"),
    ],
)
def test_direct_auth_routes_publish_expected_request_bodies_and_component_shapes(
    path: str,
    schema_ref: str,
) -> None:
    """Direct auth-controller mounts keep the built-in login and refresh request contracts."""
    app, *_ = build_auth_app(enable_refresh=True)

    _assert_request_body_component_contract(app, path=path, method_name="post", schema_ref=schema_ref)


def test_direct_register_route_publishes_expected_request_body_component_shape() -> None:
    """Direct register-controller mounts keep the built-in registration request contract."""
    app, *_ = build_register_app()

    _assert_request_body_component_contract(
        app,
        path="/auth/register",
        method_name="post",
        schema_ref="#/components/schemas/UserCreate",
    )


@pytest.mark.parametrize(
    ("path", "schema_ref"),
    [
        ("/auth/forgot-password", "#/components/schemas/ForgotPassword"),
        ("/auth/reset-password", "#/components/schemas/ResetPassword"),
    ],
)
def test_direct_reset_routes_publish_expected_request_bodies_and_component_shapes(
    path: str,
    schema_ref: str,
) -> None:
    """Direct reset-controller mounts keep the email and token request contracts."""
    app, *_ = build_reset_app()

    _assert_request_body_component_contract(app, path=path, method_name="post", schema_ref=schema_ref)


@pytest.mark.parametrize(
    ("path", "schema_ref"),
    [
        ("/auth/request-verify-token", "#/components/schemas/RequestVerifyToken"),
        ("/auth/verify", "#/components/schemas/VerifyToken"),
    ],
)
def test_direct_verify_routes_publish_expected_request_bodies_and_component_shapes(
    path: str,
    schema_ref: str,
) -> None:
    """Direct verify-controller mounts keep the email and token request contracts."""
    app, *_ = build_verify_app()

    _assert_request_body_component_contract(app, path=path, method_name="post", schema_ref=schema_ref)


@pytest.mark.parametrize(
    ("path", "schema_ref"),
    [
        ("/users/me", "#/components/schemas/UserUpdate"),
        ("/users/{user_id}", "#/components/schemas/AdminUserUpdate"),
    ],
)
def test_direct_users_patch_routes_publish_expected_request_bodies(path: str, schema_ref: str) -> None:
    """Direct users-controller patch routes retain their request-body contract."""
    app, *_ = build_users_app()

    _assert_request_body_component_ref(
        app,
        path=path,
        method_name="patch",
        schema_ref=schema_ref,
    )


def test_direct_users_change_password_route_publishes_expected_request_body_component_shape() -> None:
    """Direct users-controller password rotation publishes the documented request contract."""
    app, *_ = build_users_app()

    _assert_request_body_component_contract(
        app,
        path="/users/me/change-password",
        method_name="post",
        schema_ref="#/components/schemas/ChangePasswordRequest",
    )


def test_direct_totp_routes_publish_expected_request_bodies_when_step_up_is_enabled() -> None:
    """Direct TOTP routes retain the documented request bodies when step-up is required."""
    app, *_ = build_totp_app(totp_enable_requires_password=True)

    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/enable",
        method_name="post",
        schema_ref="#/components/schemas/TotpEnableRequest",
    )
    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/verify",
        method_name="post",
        schema_ref="#/components/schemas/TotpVerifyRequest",
    )
    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/enable/confirm",
        method_name="post",
        schema_ref="#/components/schemas/TotpConfirmEnableRequest",
    )
    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/disable",
        method_name="post",
        schema_ref="#/components/schemas/TotpDisableRequest",
    )
    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/recovery-codes/regenerate",
        method_name="post",
        schema_ref="#/components/schemas/TotpRegenerateRecoveryCodesRequest",
    )


def test_direct_totp_routes_publish_recovery_code_response_components() -> None:
    """Direct TOTP routes document the recovery-code response shapes in OpenAPI."""
    app, *_ = build_totp_app(totp_enable_requires_password=True)
    schemas = cast("Any", app.openapi_schema.components.schemas)
    confirm_response_schema = schemas["TotpConfirmEnableResponse"]
    recovery_codes_response_schema = schemas["TotpRecoveryCodesResponse"]
    confirm_properties = confirm_response_schema.properties or {}

    assert (
        _response_body_ref(app, path="/auth/2fa/enable/confirm", method_name="post", status_code="201")
        == "#/components/schemas/TotpConfirmEnableResponse"
    )
    assert (
        _response_body_ref(app, path="/auth/2fa/recovery-codes/regenerate", method_name="post", status_code="201")
        == "#/components/schemas/TotpRecoveryCodesResponse"
    )
    assert set(confirm_response_schema.required or []) == {"enabled", "recovery_codes"}
    assert getattr(confirm_properties["enabled"].type, "value", confirm_properties["enabled"].type) == BOOLEAN_TYPE
    _assert_recovery_codes_property(confirm_response_schema)
    assert set(recovery_codes_response_schema.required or []) == {"recovery_codes"}
    _assert_recovery_codes_property(recovery_codes_response_schema)


def test_direct_totp_enable_omits_request_body_when_step_up_is_disabled() -> None:
    """Password-optional direct TOTP enable keeps the no-body contract while other TOTP payloads stay documented."""
    app, *_ = build_totp_app(totp_enable_requires_password=False)

    _assert_request_body_component_ref(app, path="/auth/2fa/enable", method_name="post", schema_ref=None)
    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/verify",
        method_name="post",
        schema_ref="#/components/schemas/TotpVerifyRequest",
    )
    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/enable/confirm",
        method_name="post",
        schema_ref="#/components/schemas/TotpConfirmEnableRequest",
    )
    _assert_request_body_component_contract(
        app,
        path="/auth/2fa/disable",
        method_name="post",
        schema_ref="#/components/schemas/TotpDisableRequest",
    )
    _assert_request_body_component_ref(
        app,
        path="/auth/2fa/recovery-codes/regenerate",
        method_name="post",
        schema_ref=None,
    )
