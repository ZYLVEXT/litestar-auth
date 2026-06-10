"""End-to-end coverage for API keys mounted through the internal extension path."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from litestar import Litestar

from litestar_auth._totp_primitive import _current_counter, _generate_totp_code
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers._utils import _is_litestar_auth_route_handler
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import ApiKeyConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.totp import generate_totp_secret
from tests.integration.conftest import ExampleUser, InMemoryTokenStrategy, InMemoryUserDatabase
from tests.integration.test_controller_api_keys import (
    API_KEY_HASH_SECRET,
    ApiKeyControllerManager,
    InMemoryApiKeyStore,
    _error_code,
    protected,
)
from tests.integration.test_orchestrator import DummySessionMaker

pytestmark = pytest.mark.integration

HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401


class StepUpTokenStrategy(InMemoryTokenStrategy):
    """In-memory bearer strategy that can persist TOTP step-up markers."""

    def __init__(self) -> None:
        """Initialize bearer-token and step-up marker storage."""
        super().__init__()
        self.stepup_session_ids: set[tuple[UUID, str]] = set()

    async def issue_totp_stepup(self, user: ExampleUser, session_id: str, *, ttl_seconds: int) -> None:
        """Store a recent TOTP verification marker for the test session."""
        self.stepup_session_ids.add((user.id, session_id))

    async def has_recent_totp_verification(self, user: ExampleUser, session_id: str) -> bool:
        """Return whether the test session has a TOTP verification marker."""
        return (user.id, session_id) in self.stepup_session_ids


def _build_app(
    *,
    captured_controllers: list[object] | None = None,
) -> tuple[Litestar, InMemoryApiKeyStore, StepUpTokenStrategy, ExampleUser, ExampleUser, str]:
    """Build a plugin app whose API-key routes come only from ``config.api_keys.enabled``.

    Returns:
        App, API-key store, bearer strategy, owner user, admin user, and owner's raw TOTP secret.
    """
    password_helper = PasswordHelper()
    owner_totp_secret = generate_totp_secret()
    owner = ExampleUser(
        id=uuid4(),
        email="owner@example.com",
        hashed_password=password_helper.hash("owner-password"),
        is_verified=True,
        roles=["read", "write"],
    )
    admin = ExampleUser(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=password_helper.hash("admin-password"),
        is_verified=True,
        roles=["admin"],
    )
    user_db = InMemoryUserDatabase([owner, admin])
    api_key_store = InMemoryApiKeyStore()
    strategy = StepUpTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    security = UserManagerSecurity[UUID](
        verification_token_secret="0123456789abcdef" * 4,
        reset_password_token_secret="fedcba9876543210" * 4,
        api_key_hash_secret=API_KEY_HASH_SECRET,
        totp_secret_key=Fernet.generate_key().decode(),
        id_parser=UUID,
        password_helper=password_helper,
    )
    owner.totp_secret = ApiKeyControllerManager(
        user_db,
        password_helper=password_helper,
        security=security,
    )._prepare_totp_secret_for_storage(owner_totp_secret)
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=ApiKeyControllerManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=security,
        superuser_role_name="admin",
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        api_keys=ApiKeyConfig(
            enabled=True,
            store_factory=lambda _session: api_key_store,
            allowed_scopes=("read", "write"),
            environment_marker="prod",
        ),
        unsafe_testing=True,
    )

    if captured_controllers is not None:

        def capture_controllers(controllers: list[object]) -> list[object]:
            captured_controllers.extend(controllers)
            return controllers

        config.controller_hook = cast("Any", capture_controllers)

    return (
        Litestar(route_handlers=[protected], plugins=[LitestarAuth(config)]),
        api_key_store,
        strategy,
        owner,
        admin,
        owner_totp_secret,
    )


async def _login(user: ExampleUser, strategy: InMemoryTokenStrategy) -> dict[str, str]:
    token = await strategy.write_token(user)
    return {"Authorization": f"Bearer {token}"}


async def test_api_key_extension_mounts_controllers_and_preserves_management_and_backend_flow(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """API keys configured by ``api_keys.enabled`` manage keys and still authenticate requests."""
    captured_controllers: list[object] = []
    app, store, strategy, owner, admin, owner_totp_secret = _build_app(captured_controllers=captured_controllers)
    paths = cast("Any", app.openapi_schema.paths)
    assert {"/api-keys", "/users/{user_id}/api-keys"}.issubset(paths)
    assert {getattr(controller, "path", "") for controller in captured_controllers} >= {"/api-keys", "/users"}
    assert all(
        _is_litestar_auth_route_handler(controller)
        for controller in captured_controllers
        if getattr(controller, "path", "") in {"/api-keys", "/users"}
    )

    async with async_test_client_factory(app) as test_client:
        owner_headers = await _login(owner, strategy)
        admin_headers = await _login(admin, strategy)

        missing_totp_response = await test_client.post(
            "/api-keys",
            headers=owner_headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        assert missing_totp_response.status_code == HTTP_FORBIDDEN
        assert _error_code(missing_totp_response) == ErrorCode.TOTP_STEPUP_REQUIRED
        assert store.rows == {}

        create_response = await test_client.post(
            "/api-keys",
            headers=owner_headers,
            json={
                "name": "CLI",
                "scopes": ["read"],
                "current_password": "owner-password",
                "totp_code": _generate_totp_code(owner_totp_secret, _current_counter()),
            },
        )
        assert create_response.status_code == HTTP_CREATED
        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key"]["key_id"]

        list_response = await test_client.get("/api-keys", headers=owner_headers)
        assert list_response.status_code == HTTP_OK
        assert list_response.json()["api_keys"][0]["key_id"] == key_id

        api_key_headers = {"Authorization": f"Bearer {raw_api_key}"}
        protected_response = await test_client.get("/protected", headers=api_key_headers)
        assert protected_response.status_code == HTTP_OK

        nested_create_response = await test_client.post(
            "/api-keys",
            headers=api_key_headers,
            json={"name": "Nested", "scopes": ["read"], "current_password": "owner-password"},
        )
        assert nested_create_response.status_code == HTTP_FORBIDDEN
        assert _error_code(nested_create_response) == ErrorCode.AUTHORIZATION_DENIED

        admin_create_response = await test_client.post(
            f"/users/{owner.id}/api-keys",
            headers=admin_headers,
            json={"name": "Admin", "scopes": ["write"]},
        )
        assert admin_create_response.status_code == HTTP_CREATED
        admin_key_id = admin_create_response.json()["key"]["key_id"]

        non_superuser_admin_response = await test_client.get(f"/users/{admin.id}/api-keys", headers=owner_headers)
        assert non_superuser_admin_response.status_code == HTTP_FORBIDDEN

        admin_list_response = await test_client.get(f"/users/{owner.id}/api-keys", headers=admin_headers)
        assert admin_list_response.status_code == HTTP_OK
        assert {row["key_id"] for row in admin_list_response.json()["api_keys"]} == {key_id, admin_key_id}

        missing_revoke_stepup_response = await test_client.delete(f"/api-keys/{key_id}", headers=owner_headers)
        assert missing_revoke_stepup_response.status_code == HTTP_FORBIDDEN
        assert _error_code(missing_revoke_stepup_response) == ErrorCode.TOTP_STEPUP_REQUIRED

        owner_session_id = owner_headers["Authorization"].removeprefix("Bearer ")
        await strategy.issue_totp_stepup(owner, owner_session_id, ttl_seconds=300)
        revoke_response = await test_client.delete(f"/api-keys/{key_id}", headers=owner_headers)
        assert revoke_response.status_code == HTTP_OK
        revoked_response = await test_client.get("/protected", headers=api_key_headers)
        assert revoked_response.status_code == HTTP_UNAUTHORIZED
        assert _error_code(revoked_response) == ErrorCode.API_KEY_REVOKED
