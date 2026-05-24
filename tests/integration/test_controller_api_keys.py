"""Integration tests for generated API-key controllers."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Any, cast, override
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from litestar import Litestar, get
from litestar.exceptions import ClientException
from litestar.middleware import DefineMiddleware
from litestar.openapi.config import OpenAPIConfig

from litestar_auth._plugin.dependencies import client_exception_handler
from litestar_auth._secrets_at_rest import FernetKeyring
from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.strategy._api_key_format import parse_api_key
from litestar_auth.authentication.strategy._api_key_nonce_store import InMemoryApiKeyNonceStore
from litestar_auth.authentication.strategy.api_key import ApiKeyStrategy
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport._api_key_signing import (
    API_KEY_HMAC_DATE_HEADER,
    API_KEY_HMAC_NONCE_HEADER,
    API_KEY_HMAC_SCHEME,
    sign_canonical_request,
)
from litestar_auth.authentication.transport.api_key import ApiKeyTransport
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers import ApiKeysControllerConfig, create_api_keys_controllers, create_auth_controller
from litestar_auth.db import ApiKeyData, BaseApiKeyStore
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import has_scope, is_authenticated, requires_api_key
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import ApiKeyConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter
from litestar_auth.totp import _current_counter, _generate_totp_code, generate_totp_secret
from tests._helpers import auth_middleware_get_request_session, litestar_app_with_user_manager
from tests.integration.conftest import DummySessionMaker, ExampleUser, InMemoryTokenStrategy, InMemoryUserDatabase

pytestmark = pytest.mark.integration

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_UNAUTHORIZED = 401
HTTP_REQUEST_ENTITY_TOO_LARGE = 413
HTTP_TOO_MANY_REQUESTS = 429

API_KEY_HASH_SECRET = "api-key-hash-secret-0123456789abcdef"
JWT_TEST_SECRET = "jwt-test-secret-0123456789abcdef0123456789abcdef"


class InMemoryApiKeyRow:
    """Mutable API-key row for controller tests."""

    def __init__(self, data: ApiKeyData[UUID]) -> None:
        """Copy persisted API-key data into a mutable row object."""
        self.key_id = data.key_id
        self.user_id = data.user_id
        self.hashed_secret = data.hashed_secret
        self.encrypted_secret = data.encrypted_secret
        self.name = data.name
        self.scopes = list(data.scopes)
        self.prefix_env = data.prefix_env
        self.signing_required = data.signing_required
        self.expires_at = data.expires_at
        self.last_used_at: datetime | None = None
        self.created_at = datetime.now(tz=UTC)
        self.revoked_at: datetime | None = None
        self.created_via = data.created_via
        self.client_metadata = data.client_metadata


class InMemoryApiKeyStore(BaseApiKeyStore[InMemoryApiKeyRow, UUID]):
    """In-memory API-key store with active-row filtering."""

    def __init__(self) -> None:
        """Initialize empty keyed storage."""
        self.rows: dict[str, InMemoryApiKeyRow] = {}
        self._create_lock = asyncio.Lock()

    @override
    async def create(self, data: ApiKeyData[UUID]) -> InMemoryApiKeyRow:
        row = InMemoryApiKeyRow(data)
        self.rows[row.key_id] = row
        return row

    @override
    async def create_for_user_with_limit(
        self,
        data: ApiKeyData[UUID],
        *,
        max_keys_per_user: int,
    ) -> InMemoryApiKeyRow | None:
        async with self._create_lock:
            if len(await self.list_for_user(data.user_id)) >= max_keys_per_user:
                return None
            return await self.create(data)

    @override
    async def get_by_key_id(self, key_id: str, *, include_inactive: bool = False) -> InMemoryApiKeyRow | None:
        row = self.rows.get(key_id)
        if row is None:
            return None
        if include_inactive or _api_key_is_active(row):
            return row
        return None

    @override
    async def list_for_user(self, user_id: UUID, *, include_inactive: bool = False) -> list[InMemoryApiKeyRow]:
        return [
            row
            for row in self.rows.values()
            if row.user_id == user_id and (include_inactive or _api_key_is_active(row))
        ]

    @override
    async def delete_for_user(self, user_id: UUID) -> int:
        deleted_keys = [key_id for key_id, row in self.rows.items() if row.user_id == user_id]
        for key_id in deleted_keys:
            del self.rows[key_id]
        return len(deleted_keys)

    @override
    async def revoke(self, key_id: str, *, revoked_at: datetime) -> InMemoryApiKeyRow | None:
        row = self.rows.get(key_id)
        if row is None:
            return None
        if row.revoked_at is None:
            row.revoked_at = revoked_at
        return row

    @override
    async def update(
        self,
        key_id: str,
        *,
        name: str | None = None,
        scopes: list[str] | None = None,
    ) -> InMemoryApiKeyRow | None:
        row = await self.get_by_key_id(key_id)
        if row is None:
            return None
        if name is not None:
            row.name = name
        if scopes is not None:
            row.scopes = scopes
        return row

    @override
    async def update_last_used_at(self, key_id: str, *, last_used_at: datetime) -> InMemoryApiKeyRow | None:
        row = await self.get_by_key_id(key_id)
        if row is None:
            return None
        row.last_used_at = last_used_at
        return row


class ApiKeyControllerManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager exposing API-key operations to the generated controller."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return users ordered by insertion."""
        return await self.user_db.list_users(offset=offset, limit=limit)


def _api_key_is_active(row: InMemoryApiKeyRow) -> bool:
    if row.revoked_at is not None:
        return False
    return row.expires_at is None or row.expires_at > datetime.now(tz=UTC)


def _error_code(response: Any) -> object:  # noqa: ANN401
    body = response.json()
    extra = body.get("extra")
    if isinstance(extra, dict):
        return extra.get("code")
    return body.get("code")


@get("/protected", guards=[is_authenticated], sync_to_thread=False)
def protected() -> dict[str, bool]:
    """Return a protected response."""
    return {"ok": True}


@get("/scoped-read", guards=[requires_api_key, has_scope("read")], sync_to_thread=False)
def scoped_read() -> dict[str, bool]:
    """Return a scope-protected response."""
    return {"ok": True}


def build_app(  # noqa: PLR0913
    *,
    max_keys_per_user: int = 5,
    allowed_scopes: tuple[str, ...] = ("read", "write"),
    owner_roles: list[str] | None = None,
    rate_limit_config: AuthRateLimitConfig | None = None,
    signing_keyring: FernetKeyring | None = None,
    signing_nonce_store: InMemoryApiKeyNonceStore | None = None,
    signed_body_max_bytes: int = 1024 * 1024,
    require_step_up_on_create: bool = True,
    owner_totp_secret: str | None = None,
) -> tuple[Any, InMemoryApiKeyStore, InMemoryTokenStrategy, ExampleUser, ExampleUser]:
    """Create an app with auth plus API-key controllers.

    Returns:
        App, API-key store, bearer strategy, owner user, and another user.
    """
    password_helper = PasswordHelper()
    owner = ExampleUser(
        id=uuid4(),
        email="owner@example.com",
        hashed_password=password_helper.hash("owner-password"),
        is_verified=True,
        roles=["read", "write"] if owner_roles is None else owner_roles,
        totp_secret=owner_totp_secret,
    )
    other = ExampleUser(
        id=uuid4(),
        email="other@example.com",
        hashed_password=password_helper.hash("other-password"),
        is_verified=True,
        roles=["superuser"],
    )
    user_db = InMemoryUserDatabase([owner, other])
    api_key_store = InMemoryApiKeyStore()
    bearer_strategy = InMemoryTokenStrategy()
    bearer_backend = AuthenticationBackend[ExampleUser, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast("Any", bearer_strategy),
    )
    jwt_strategy = JWTStrategy[ExampleUser, UUID](
        secret=JWT_TEST_SECRET,
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    )
    jwt_backend = AuthenticationBackend[ExampleUser, UUID](
        name="jwt",
        transport=BearerTransport(),
        strategy=cast("Any", jwt_strategy),
    )
    cookie_backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie",
        transport=CookieTransport(cookie_name="litestar_auth_test", secure=False),
        strategy=cast("Any", bearer_strategy),
    )
    api_key_backend = AuthenticationBackend[ExampleUser, UUID](
        name="api_key",
        transport=ApiKeyTransport(),
        strategy=ApiKeyStrategy[ExampleUser, UUID](
            api_key_store=api_key_store,
            api_key_hash_secret=API_KEY_HASH_SECRET,
            prefix_env="prod",
            nonce_store=signing_nonce_store,
            secret_encryption_keyring=signing_keyring,
            unsafe_testing=True,
        ),
    )
    manager = ApiKeyControllerManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            api_key_hash_secret=API_KEY_HASH_SECRET,
            totp_secret_key=Fernet.generate_key().decode(),
        ),
        backends=(bearer_backend, api_key_backend),
        api_key_store=api_key_store,
        api_key_config=ApiKeyConfig(
            enabled=True,
            max_keys_per_user=max_keys_per_user,
            allowed_scopes=allowed_scopes,
            environment_marker="prod",
            signing_enabled=signing_keyring is not None,
            nonce_store=signing_nonce_store,
            secret_encryption_keyring=None if signing_keyring is None else cast("Any", signing_keyring),
        ),
    )
    if owner_totp_secret is not None:
        owner.totp_secret = manager._prepare_totp_secret_for_storage(owner_totp_secret)
    auth_controller = create_auth_controller(backend=bearer_backend)
    route_handlers: list[object] = [
        auth_controller,
        *create_api_keys_controllers(
            id_parser=UUID,
            rate_limit_config=rate_limit_config,
            require_step_up_on_create=require_step_up_on_create,
            signing_enabled=signing_keyring is not None,
        ),
        protected,
        scoped_read,
    ]
    for route_handler in route_handlers:
        route_handler_dict = getattr(route_handler, "__dict__", {})
        existing = dict(route_handler_dict.get("exception_handlers") or {})
        existing.setdefault(Exception, cast("Any", None))
        existing.pop(Exception, None)
        existing.setdefault(ClientException, client_exception_handler)
        cast("Any", route_handler).exception_handlers = existing

    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator(
            [bearer_backend, jwt_backend, cookie_backend, api_key_backend],
            manager,
        ),
        api_key_use_rate_limit=None if rate_limit_config is None else rate_limit_config.api_key_use,
        api_key_backend_present=True,
        api_key_signed_body_max_bytes=signed_body_max_bytes,
    )
    app = litestar_app_with_user_manager(manager, *route_handlers, middleware=[middleware])
    cast("Any", app.state).test_user_db = user_db
    return app, api_key_store, bearer_strategy, owner, other


async def _login(_client: Any, user: ExampleUser, strategy: InMemoryTokenStrategy) -> dict[str, str]:  # noqa: ANN401
    token = await strategy.write_token(user)
    return {"Authorization": f"Bearer {token}"}


async def _cookie_login(user: ExampleUser, strategy: InMemoryTokenStrategy) -> dict[str, str]:
    token = await strategy.write_token(user)
    return {"Cookie": f"litestar_auth_test={token}"}


async def _jwt_login(user: ExampleUser) -> dict[str, str]:
    token = await JWTStrategy[ExampleUser, UUID](
        secret=JWT_TEST_SECRET,
        subject_decoder=UUID,
        allow_inmemory_denylist=True,
    ).write_token(user)
    return {"Authorization": f"Bearer {token}"}


def _hmac_headers(
    *,
    raw_api_key: str,
    path: str,
    body: bytes = b"",
    nonce: str = "nonce-1",
    sign_host: bool = True,
) -> dict[str, str]:
    """Return LSA1-HMAC-SHA256 headers for an integration request."""
    parsed = parse_api_key(raw_api_key, expected_prefix_env="prod")
    assert parsed is not None
    request_date = datetime.now(tz=UTC).isoformat()
    body_digest = hashlib.sha256(body).hexdigest()
    host = "example.test"
    signed_header_names = ["x-auth-date", "x-auth-nonce", "x-auth-content-sha256"]
    canonical_header_lines = [
        f"x-auth-date:{request_date}",
        f"x-auth-nonce:{nonce}",
        f"x-auth-content-sha256:{body_digest}",
    ]
    if sign_host:
        signed_header_names.insert(0, "host")
        canonical_header_lines.insert(0, f"host:{host}")
    signed_headers = ";".join(signed_header_names)
    canonical_request = "\n".join(
        (
            "GET",
            path,
            "",
            "\n".join(canonical_header_lines),
            signed_headers,
            body_digest,
        ),
    )
    signature = sign_canonical_request(secret=parsed.secret, canonical_request=canonical_request)
    return {
        "Host": host,
        API_KEY_HMAC_DATE_HEADER: request_date,
        API_KEY_HMAC_NONCE_HEADER: nonce,
        "X-Auth-Content-SHA256": body_digest,
        "Authorization": (
            f"{API_KEY_HMAC_SCHEME} Credential={parsed.key_id}, SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


async def test_create_returns_raw_secret_once_and_get_never_exposes_it(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """POST returns the raw API key once; password-session GETs return metadata only."""
    app, _store, strategy, owner, _other = build_app()
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)
        response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        assert response.status_code == HTTP_CREATED
        body = response.json()
        assert body["api_key"].startswith("ak_prod_")
        key_id = body["key"]["key_id"]

        get_response = await test_client.get(f"/api-keys/{key_id}", headers=headers)
        assert get_response.status_code == HTTP_OK
        assert "api_key" not in get_response.json()
        assert body["api_key"] not in get_response.text
        list_response = await test_client.get("/api-keys", headers=headers)
        assert list_response.status_code == HTTP_OK
        assert list_response.json()["api_keys"][0]["key_id"] == key_id

        cookie_headers = await _cookie_login(owner, strategy)
        cookie_get_response = await test_client.get(f"/api-keys/{key_id}", headers=cookie_headers)
        cookie_list_response = await test_client.get("/api-keys", headers=cookie_headers)

        assert cookie_get_response.status_code == HTTP_OK
        assert cookie_get_response.json() == get_response.json()
        assert cookie_list_response.status_code == HTTP_OK
        assert cookie_list_response.json() == list_response.json()

        jwt_headers = await _jwt_login(owner)
        jwt_get_response = await test_client.get(f"/api-keys/{key_id}", headers=jwt_headers)
        jwt_list_response = await test_client.get("/api-keys", headers=jwt_headers)

        assert jwt_get_response.status_code == HTTP_OK
        assert jwt_get_response.json() == get_response.json()
        assert jwt_list_response.status_code == HTTP_OK
        assert jwt_list_response.json() == list_response.json()


async def test_self_routes_do_not_expose_foreign_keys(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """A user cannot read another user's API-key metadata by key id."""
    app, _store, strategy, owner, other = build_app()
    async with async_test_client_factory(app) as test_client:
        other_headers = await _login(test_client, other, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=other_headers,
            json={"name": "Other", "scopes": ["read"], "current_password": "other-password"},
        )
        key_id = create_response.json()["key"]["key_id"]
        owner_headers = await _login(test_client, owner, strategy)

        response = await test_client.get(f"/api-keys/{key_id}", headers=owner_headers)

        assert response.status_code == HTTP_NOT_FOUND
        assert _error_code(response) == ErrorCode.API_KEY_INVALID


async def test_create_enforces_current_password_scope_and_limit(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """Create fails closed for bad step-up credentials, denied scopes, and max-key limit."""
    app, _store, strategy, owner, _other = build_app(max_keys_per_user=1, allowed_scopes=("read",))
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)

        bad_password = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "Bad", "scopes": ["read"], "current_password": "wrong-password"},
        )
        assert bad_password.status_code == HTTP_BAD_REQUEST
        assert _error_code(bad_password) == ErrorCode.LOGIN_BAD_CREDENTIALS

        denied_scope = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "Denied", "scopes": ["write"], "current_password": "owner-password"},
        )
        assert denied_scope.status_code == HTTP_BAD_REQUEST
        assert _error_code(denied_scope) == ErrorCode.API_KEY_SCOPE_DENIED

        first = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "First", "scopes": ["read"], "current_password": "owner-password"},
        )
        assert first.status_code == HTTP_CREATED
        limit = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "Second", "scopes": ["read"], "current_password": "owner-password"},
        )
        assert limit.status_code == HTTP_BAD_REQUEST
        assert _error_code(limit) == ErrorCode.API_KEY_LIMIT_REACHED


async def test_create_rejects_signing_required_when_signing_is_not_configured(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Signing-required create requests fail with a structured 400 unless signing support is configured."""
    app, _store, strategy, owner, _other = build_app()
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)

        response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={
                "name": "Signed",
                "scopes": ["read"],
                "current_password": "owner-password",
                "signing_required": True,
            },
        )

    assert response.status_code == HTTP_BAD_REQUEST
    assert _error_code(response) == ErrorCode.REQUEST_BODY_INVALID


async def test_create_current_password_requirement_follows_controller_config(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Self-service create requires current_password by default but can be explicitly relaxed."""
    required_app, _required_store, required_strategy, required_owner, _other = build_app()
    relaxed_app, _relaxed_store, relaxed_strategy, relaxed_owner, _other = build_app(require_step_up_on_create=False)

    async with async_test_client_factory(required_app) as test_client:
        required_headers = await _login(test_client, required_owner, required_strategy)
        required_response = await test_client.post(
            "/api-keys",
            headers=required_headers,
            json={"name": "Missing step-up", "scopes": ["read"]},
        )

    async with async_test_client_factory(relaxed_app) as test_client:
        relaxed_headers = await _login(test_client, relaxed_owner, relaxed_strategy)
        relaxed_response = await test_client.post(
            "/api-keys",
            headers=relaxed_headers,
            json={"name": "No step-up", "scopes": ["read"]},
        )

    assert required_response.status_code == HTTP_BAD_REQUEST
    assert _error_code(required_response) == ErrorCode.REQUEST_BODY_INVALID
    assert relaxed_response.status_code == HTTP_CREATED


async def test_create_requires_totp_stepup_for_enrolled_user(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """API-key creation fails before persistence when an enrolled user lacks TOTP step-up."""
    secret = generate_totp_secret()
    app, store, strategy, owner, _other = build_app(owner_totp_secret=secret)
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)

        response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )

    assert response.status_code == HTTP_FORBIDDEN
    assert _error_code(response) == ErrorCode.TOTP_STEPUP_REQUIRED
    assert store.rows == {}


async def test_create_accepts_inline_totp_code_for_enrolled_user(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """A valid inline TOTP code satisfies the API-key create step-up gate."""
    secret = generate_totp_secret()
    app, _store, strategy, owner, _other = build_app(owner_totp_secret=secret)
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)

        response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={
                "name": "CLI",
                "scopes": ["read"],
                "current_password": "owner-password",
                "totp_code": _generate_totp_code(secret, _current_counter()),
            },
        )

    assert response.status_code == HTTP_CREATED


async def test_api_key_authenticates_then_revoke_blocks_future_use(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """A created API key authenticates protected routes until revoked."""
    app, _store, strategy, owner, _other = build_app()
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key"]["key_id"]
        api_key_headers = {"Authorization": f"Bearer {raw_api_key}"}

        protected_response = await test_client.get("/protected", headers=api_key_headers)
        assert protected_response.status_code == HTTP_OK

        revoke_response = await test_client.delete(f"/api-keys/{key_id}", headers=bearer_headers)
        assert revoke_response.status_code == HTTP_OK
        rejected_response = await test_client.get("/protected", headers=api_key_headers)
        assert rejected_response.status_code == HTTP_UNAUTHORIZED
        assert _error_code(rejected_response) == ErrorCode.API_KEY_REVOKED


async def test_successful_api_key_use_updates_last_used_without_consuming_invalid_attempt_bucket(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Successful API-key authentication records use without consuming the invalid-attempt bucket."""
    backend = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    rate_limit_config = AuthRateLimitConfig(
        api_key_use=EndpointRateLimit(backend=backend, scope="api_key_id", namespace="api-key-use"),
    )
    app, store, strategy, owner, _other = build_app(rate_limit_config=rate_limit_config)
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key"]["key_id"]

        first_use = await test_client.get("/protected", headers={"Authorization": f"Bearer {raw_api_key}"})
        second_use = await test_client.get("/protected", headers={"Authorization": f"Bearer {raw_api_key}"})

        assert first_use.status_code == HTTP_OK
        assert store.rows[key_id].last_used_at is not None
        assert second_use.status_code == HTTP_OK


async def test_unknown_api_key_ids_do_not_consume_use_rate_limit_budget(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Malformed and unknown API-key credentials are classified without rate-limit accounting."""
    backend = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    rate_limit_config = AuthRateLimitConfig(
        api_key_use=EndpointRateLimit(backend=backend, scope="api_key_id", namespace="api-key-use"),
    )
    app, _store, _strategy, _owner, _other = build_app(rate_limit_config=rate_limit_config)

    async with async_test_client_factory(app) as test_client:
        responses = [
            await test_client.get("/protected", headers={"Authorization": "Bearer ak_badformat"}),
            await test_client.get("/protected", headers={"Authorization": "Bearer ak_prod_missing.secret"}),
            await test_client.get("/protected", headers={"Authorization": "Bearer ak_prod_other.secret"}),
        ]

    assert [response.status_code for response in responses] == [HTTP_UNAUTHORIZED, HTTP_UNAUTHORIZED, HTTP_UNAUTHORIZED]
    assert [_error_code(response) for response in responses] == [
        ErrorCode.API_KEY_INVALID,
        ErrorCode.API_KEY_INVALID,
        ErrorCode.API_KEY_INVALID,
    ]
    assert backend._windows == {}


async def test_expired_api_key_use_still_consumes_rate_limit_budget(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Resolved unusable API keys still consume the API-key-use limiter."""
    backend = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    rate_limit_config = AuthRateLimitConfig(
        api_key_use=EndpointRateLimit(backend=backend, scope="api_key_id", namespace="api-key-use"),
    )
    app, _store, strategy, owner, _other = build_app(rate_limit_config=rate_limit_config)

    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        expired_create = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={
                "name": "Expired",
                "scopes": ["read"],
                "current_password": "owner-password",
                "expires_at": "2020-01-01T00:00:00Z",
            },
        )
        expired_key = expired_create.json()["api_key"]

        first_expired = await test_client.get("/protected", headers={"X-API-Key": expired_key})
        second_expired = await test_client.get("/protected", headers={"X-API-Key": expired_key})

    assert first_expired.status_code == HTTP_UNAUTHORIZED
    assert _error_code(first_expired) == ErrorCode.API_KEY_EXPIRED
    assert second_expired.status_code == HTTP_TOO_MANY_REQUESTS
    assert second_expired.headers["Retry-After"].isdigit()


async def test_signing_required_api_key_authenticates_signed_request_and_rejects_bearer(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Signing-required keys authenticate only through signed requests."""
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    app, store, strategy, owner, _other = build_app(
        signing_keyring=keyring,
        signing_nonce_store=InMemoryApiKeyNonceStore(),
    )
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={
                "name": "CLI",
                "scopes": ["read"],
                "current_password": "owner-password",
                "signing_required": True,
            },
        )
        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key"]["key_id"]

        bearer_response = await test_client.get("/protected", headers={"Authorization": f"Bearer {raw_api_key}"})
        signed_response = await test_client.get(
            "/protected",
            headers=_hmac_headers(raw_api_key=raw_api_key, path="/protected"),
        )

        assert store.rows[key_id].signing_required is True
        assert store.rows[key_id].encrypted_secret is not None
        assert bearer_response.status_code == HTTP_UNAUTHORIZED
        assert _error_code(bearer_response) == ErrorCode.API_KEY_SIGNATURE_INVALID
        assert signed_response.status_code == HTTP_OK


async def test_orphaned_signing_required_api_key_reports_invalid_without_consuming_nonce(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Signing keys whose owner disappeared remain generic invalid failures without burning nonces."""
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    app, _store, strategy, owner, _other = build_app(
        signing_keyring=keyring,
        signing_nonce_store=InMemoryApiKeyNonceStore(),
    )
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={
                "name": "CLI",
                "scopes": ["read"],
                "current_password": "owner-password",
                "signing_required": True,
            },
        )
        raw_api_key = create_response.json()["api_key"]
        await cast("InMemoryUserDatabase[ExampleUser]", app.state.test_user_db).delete(owner.id)
        headers = _hmac_headers(
            raw_api_key=raw_api_key,
            path="/protected",
            nonce="orphaned-user",
        )

        first_response = await test_client.get("/protected", headers=headers)
        retry_response = await test_client.get("/protected", headers=headers)

    assert first_response.status_code == HTTP_UNAUTHORIZED
    assert _error_code(first_response) == ErrorCode.API_KEY_SIGNATURE_INVALID
    assert retry_response.status_code == HTTP_UNAUTHORIZED
    assert _error_code(retry_response) == ErrorCode.API_KEY_SIGNATURE_INVALID


async def test_signed_request_omitting_host_signed_header_is_invalid(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Signed requests must commit the request Host header in SignedHeaders."""
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    app, _store, strategy, owner, _other = build_app(
        signing_keyring=keyring,
        signing_nonce_store=InMemoryApiKeyNonceStore(),
    )
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={
                "name": "CLI",
                "scopes": ["read"],
                "current_password": "owner-password",
                "signing_required": True,
            },
        )
        raw_api_key = create_response.json()["api_key"]

        response = await test_client.get(
            "/protected",
            headers=_hmac_headers(raw_api_key=raw_api_key, path="/protected", sign_host=False),
        )

    assert response.status_code == HTTP_UNAUTHORIZED
    assert _error_code(response) == ErrorCode.API_KEY_SIGNATURE_INVALID


async def test_signed_request_rejects_body_over_configured_limit(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """Signed requests fail before authentication when the raw body exceeds the configured cap."""
    keyring = FernetKeyring(active_key_id="current", keys={"current": Fernet.generate_key().decode()})
    app, _store, strategy, owner, _other = build_app(
        signing_keyring=keyring,
        signing_nonce_store=InMemoryApiKeyNonceStore(),
        signed_body_max_bytes=5,
    )
    oversized_body = b"123456"

    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={
                "name": "CLI",
                "scopes": ["read"],
                "current_password": "owner-password",
                "signing_required": True,
            },
        )
        raw_api_key = create_response.json()["api_key"]

        response = await test_client.request(
            "GET",
            "/protected",
            headers=_hmac_headers(raw_api_key=raw_api_key, path="/protected", body=oversized_body),
            content=oversized_body,
        )

    assert response.status_code == HTTP_REQUEST_ENTITY_TOO_LARGE
    assert _error_code(response) == ErrorCode.REQUEST_BODY_INVALID


async def test_api_key_scope_guard_allows_matching_scope_and_rejects_missing_scope(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """A scoped API-key route accepts matching key scopes and rejects missing scopes."""
    app, _store, strategy, owner, _other = build_app()
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        read_key_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "Read", "scopes": ["read"], "current_password": "owner-password"},
        )
        write_key_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "Write", "scopes": ["write"], "current_password": "owner-password"},
        )

        allowed_response = await test_client.get(
            "/scoped-read",
            headers={"Authorization": f"Bearer {read_key_response.json()['api_key']}"},
        )
        denied_response = await test_client.get(
            "/scoped-read",
            headers={"Authorization": f"Bearer {write_key_response.json()['api_key']}"},
        )

    assert allowed_response.status_code == HTTP_OK
    assert denied_response.status_code == HTTP_FORBIDDEN
    assert _error_code(denied_response) == ErrorCode.API_KEY_SCOPE_DENIED


async def test_api_key_scope_guard_reflects_user_role_revocation_immediately(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Current user roles downscope API keys without revoking the key row."""
    app, store, strategy, owner, _other = build_app()
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "Read", "scopes": ["read"], "current_password": "owner-password"},
        )
        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key"]["key_id"]

        allowed_response = await test_client.get("/scoped-read", headers={"Authorization": f"Bearer {raw_api_key}"})
        owner.roles = []
        denied_response = await test_client.get("/scoped-read", headers={"Authorization": f"Bearer {raw_api_key}"})

    assert allowed_response.status_code == HTTP_OK
    assert denied_response.status_code == HTTP_FORBIDDEN
    assert _error_code(denied_response) == ErrorCode.API_KEY_SCOPE_DENIED
    assert store.rows[key_id].revoked_at is None


async def test_password_session_boundary_rejects_api_key_mutations(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """API-key callers cannot create, update, or revoke API keys through self-service routes."""
    app, _store, strategy, owner, _other = build_app()
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "Read", "scopes": ["read"], "current_password": "owner-password"},
        )
        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key"]["key_id"]
        api_key_headers = {"Authorization": f"Bearer {raw_api_key}"}

        create_with_api_key = await test_client.post(
            "/api-keys",
            headers=api_key_headers,
            json={"name": "Nested", "scopes": ["read"], "current_password": "owner-password"},
        )
        update_with_api_key = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=api_key_headers,
            json={"name": "Renamed", "current_password": "owner-password"},
        )
        revoke_with_api_key = await test_client.delete(f"/api-keys/{key_id}", headers=api_key_headers)

    assert create_with_api_key.status_code == HTTP_FORBIDDEN
    assert update_with_api_key.status_code == HTTP_FORBIDDEN
    assert revoke_with_api_key.status_code == HTTP_FORBIDDEN
    assert _error_code(create_with_api_key) == ErrorCode.AUTHORIZATION_DENIED


async def test_password_session_boundary_rejects_api_key_reads(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """API-key callers cannot list or inspect self-service API-key metadata."""
    app, _store, strategy, owner, _other = build_app()
    async with async_test_client_factory(app) as test_client:
        bearer_headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "Read", "scopes": ["read"], "current_password": "owner-password"},
        )
        raw_api_key = create_response.json()["api_key"]
        key_id = create_response.json()["key"]["key_id"]
        api_key_headers = {"Authorization": f"Bearer {raw_api_key}"}

        list_with_api_key = await test_client.get("/api-keys", headers=api_key_headers)
        get_with_api_key = await test_client.get(f"/api-keys/{key_id}", headers=api_key_headers)

    assert list_with_api_key.status_code == HTTP_FORBIDDEN
    assert get_with_api_key.status_code == HTTP_FORBIDDEN
    assert _error_code(list_with_api_key) == ErrorCode.AUTHORIZATION_DENIED
    assert _error_code(get_with_api_key) == ErrorCode.AUTHORIZATION_DENIED


async def test_admin_api_key_routes_reject_api_key_authenticated_superuser(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Admin API-key inventory routes require a password session even for superusers."""
    app, _store, strategy, owner, admin = build_app()
    async with async_test_client_factory(app) as test_client:
        admin_headers = await _login(test_client, admin, strategy)
        admin_key_response = await test_client.post(
            "/api-keys",
            headers=admin_headers,
            json={"name": "Admin automation", "scopes": ["read"], "current_password": "other-password"},
        )
        admin_api_key_headers = {"Authorization": f"Bearer {admin_key_response.json()['api_key']}"}

        target_key_response = await test_client.post(
            f"/users/{owner.id}/api-keys",
            headers=admin_headers,
            json={"name": "Target", "scopes": ["read"]},
        )
        target_key_id = target_key_response.json()["key"]["key_id"]

        create_with_api_key = await test_client.post(
            f"/users/{owner.id}/api-keys",
            headers=admin_api_key_headers,
            json={"name": "Denied", "scopes": ["read"]},
        )
        list_with_api_key = await test_client.get(f"/users/{owner.id}/api-keys", headers=admin_api_key_headers)
        revoke_with_api_key = await test_client.delete(
            f"/users/{owner.id}/api-keys/{target_key_id}",
            headers=admin_api_key_headers,
        )

    assert create_with_api_key.status_code == HTTP_FORBIDDEN
    assert list_with_api_key.status_code == HTTP_FORBIDDEN
    assert revoke_with_api_key.status_code == HTTP_FORBIDDEN
    assert _error_code(create_with_api_key) == ErrorCode.AUTHORIZATION_DENIED
    assert _error_code(list_with_api_key) == ErrorCode.AUTHORIZATION_DENIED
    assert _error_code(revoke_with_api_key) == ErrorCode.AUTHORIZATION_DENIED


async def test_admin_api_key_routes_allow_password_session_superuser(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Password-session superusers can still mint, list, and revoke user API keys."""
    app, _store, strategy, owner, admin = build_app()
    async with async_test_client_factory(app) as test_client:
        admin_headers = await _login(test_client, admin, strategy)
        create_response = await test_client.post(
            f"/users/{owner.id}/api-keys",
            headers=admin_headers,
            json={"name": "Admin", "scopes": ["read"]},
        )
        key_id = create_response.json()["key"]["key_id"]

        list_response = await test_client.get(f"/users/{owner.id}/api-keys", headers=admin_headers)
        revoke_response = await test_client.delete(f"/users/{owner.id}/api-keys/{key_id}", headers=admin_headers)

    assert create_response.status_code == HTTP_CREATED
    assert set(create_response.json()) == {"api_key", "key"}
    assert list_response.status_code == HTTP_OK
    assert list_response.json()["api_keys"][0]["key_id"] == key_id
    assert revoke_response.status_code == HTTP_OK
    assert revoke_response.json()["key_id"] == key_id


async def test_api_key_authentication_failures_are_structured(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """Invalid, missing, expired, and bad-secret API-key credentials return stable codes."""
    backend = InMemoryRateLimiter(max_attempts=3, window_seconds=60)
    rate_limit_config = AuthRateLimitConfig(
        api_key_use=EndpointRateLimit(backend=backend, scope="api_key_id", namespace="api-key-use"),
    )
    app, _store, strategy, owner, _other = build_app(rate_limit_config=rate_limit_config)
    async with async_test_client_factory(app) as test_client:
        malformed = await test_client.get("/protected", headers={"Authorization": "Bearer ak_badformat"})
        assert malformed.status_code == HTTP_UNAUTHORIZED
        assert _error_code(malformed) == ErrorCode.API_KEY_INVALID

        unknown = await test_client.get("/protected", headers={"Authorization": "Bearer ak_prod_missing.secret"})
        assert unknown.status_code == HTTP_UNAUTHORIZED
        assert _error_code(unknown) == ErrorCode.API_KEY_INVALID

        bearer_headers = await _login(test_client, owner, strategy)
        expired_create = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={
                "name": "Expired",
                "scopes": ["read"],
                "current_password": "owner-password",
                "expires_at": "2020-01-01T00:00:00Z",
            },
        )
        expired_key = expired_create.json()["api_key"]
        expired = await test_client.get("/protected", headers={"X-API-Key": expired_key})
        assert expired.status_code == HTTP_UNAUTHORIZED
        assert _error_code(expired) == ErrorCode.API_KEY_EXPIRED

        active_create = await test_client.post(
            "/api-keys",
            headers=bearer_headers,
            json={"name": "Active", "scopes": ["read"], "current_password": "owner-password"},
        )
        raw_api_key = active_create.json()["api_key"]
        prefix, _secret = raw_api_key.split(".", maxsplit=1)
        bad_secret = await test_client.get("/protected", headers={"Authorization": f"Bearer {prefix}.wrong"})
        assert bad_secret.status_code == HTTP_UNAUTHORIZED
        assert _error_code(bad_secret) == ErrorCode.API_KEY_INVALID

        wrong_scheme = await test_client.get("/protected", headers={"Authorization": "Basic not-api-key"})
        assert wrong_scheme.status_code == HTTP_UNAUTHORIZED


async def test_update_and_admin_routes_pin_user_scope(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """Self update and admin nested routes operate on the intended user only."""
    app, _store, strategy, owner, admin = build_app()
    async with async_test_client_factory(app) as test_client:
        owner_headers = await _login(test_client, owner, strategy)
        admin_headers = await _login(test_client, admin, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=owner_headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        key_id = create_response.json()["key"]["key_id"]

        update_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=owner_headers,
            json={"name": "Renamed", "scopes": ["write"], "current_password": "owner-password"},
        )
        assert update_response.status_code == HTTP_OK
        assert update_response.json()["name"] == "Renamed"
        assert update_response.json()["scopes"] == ["write"]

        admin_list = await test_client.get(f"/users/{owner.id}/api-keys", headers=admin_headers)
        assert admin_list.status_code == HTTP_OK
        assert admin_list.json()["api_keys"][0]["key_id"] == key_id

        admin_revoke = await test_client.delete(f"/users/{owner.id}/api-keys/{key_id}", headers=admin_headers)
        assert admin_revoke.status_code == HTTP_OK
        missing_update = await test_client.patch(
            "/api-keys/missing",
            headers=owner_headers,
            json={"name": "Missing", "current_password": "owner-password"},
        )
        assert missing_update.status_code == HTTP_NOT_FOUND
        missing_revoke = await test_client.delete("/api-keys/missing", headers=owner_headers)
        assert missing_revoke.status_code == HTTP_NOT_FOUND
        missing_user = await test_client.get(f"/users/{uuid4()}/api-keys", headers=admin_headers)
        assert missing_user.status_code == HTTP_NOT_FOUND
        malformed_user = await test_client.get("/users/not-a-uuid/api-keys", headers=admin_headers)
        assert malformed_user.status_code == HTTP_NOT_FOUND


async def test_admin_create_and_delete_missing_key(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """Admin create uses the path user id and missing deletes keep the API-key invalid code."""
    app, _store, strategy, owner, admin = build_app()
    async with async_test_client_factory(app) as test_client:
        admin_headers = await _login(test_client, admin, strategy)
        create_response = await test_client.post(
            f"/users/{owner.id}/api-keys",
            headers=admin_headers,
            json={"name": "Admin", "scopes": ["read"]},
        )
        assert create_response.status_code == HTTP_CREATED
        assert create_response.json()["key"]["key_id"]

        missing_delete = await test_client.delete(f"/users/{owner.id}/api-keys/missing", headers=admin_headers)
        assert missing_delete.status_code == HTTP_NOT_FOUND
        assert _error_code(missing_delete) == ErrorCode.API_KEY_INVALID


async def test_create_rate_limit_slot_is_used(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """The api_key_create limiter is checked before create and reset after success."""
    backend = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    rate_limit_config = AuthRateLimitConfig(
        api_key_create=EndpointRateLimit(backend=backend, scope="ip", namespace="api-key-create"),
    )
    app, _store, strategy, owner, _admin = build_app(rate_limit_config=rate_limit_config)
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)
        success_response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "Good", "scopes": ["read"], "current_password": "owner-password"},
        )
        assert success_response.status_code == HTTP_CREATED
        bad_response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "Bad", "scopes": ["read"], "current_password": "wrong-password"},
        )
        assert bad_response.status_code == HTTP_BAD_REQUEST
        limited_response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "Bad", "scopes": ["read"], "current_password": "wrong-password"},
        )
        assert limited_response.status_code == HTTP_TOO_MANY_REQUESTS


async def test_update_rate_limit_slot_blocks_repeated_bad_passwords(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """The update limiter counts failed password checks and blocks once exhausted."""
    backend = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    rate_limit_config = AuthRateLimitConfig(
        api_key_update=EndpointRateLimit(backend=backend, scope="ip", namespace="api-key-update"),
    )
    app, _store, strategy, owner, _admin = build_app(rate_limit_config=rate_limit_config)
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        key_id = create_response.json()["key"]["key_id"]

        bad_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=headers,
            json={"name": "Denied", "current_password": "wrong-password"},
        )
        limited_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=headers,
            json={"name": "Denied", "current_password": "wrong-password"},
        )

        assert bad_response.status_code == HTTP_BAD_REQUEST
        assert _error_code(bad_response) == ErrorCode.LOGIN_BAD_CREDENTIALS
        assert limited_response.status_code == HTTP_TOO_MANY_REQUESTS
        assert limited_response.headers["Retry-After"].isdigit()


async def test_successful_update_resets_update_rate_limit_counter(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """A successful API-key update clears the failed update counter for the request key."""
    backend = InMemoryRateLimiter(max_attempts=2, window_seconds=60)
    rate_limit_config = AuthRateLimitConfig(
        api_key_update=EndpointRateLimit(backend=backend, scope="ip", namespace="api-key-update"),
    )
    app, _store, strategy, owner, _admin = build_app(rate_limit_config=rate_limit_config)
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        key_id = create_response.json()["key"]["key_id"]

        first_bad_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=headers,
            json={"name": "Denied", "current_password": "wrong-password"},
        )
        success_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=headers,
            json={"name": "Renamed", "current_password": "owner-password"},
        )
        second_bad_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=headers,
            json={"name": "Denied", "current_password": "wrong-password"},
        )
        third_bad_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=headers,
            json={"name": "Denied", "current_password": "wrong-password"},
        )
        limited_response = await test_client.patch(
            f"/api-keys/{key_id}",
            headers=headers,
            json={"name": "Denied", "current_password": "wrong-password"},
        )

        assert first_bad_response.status_code == HTTP_BAD_REQUEST
        assert success_response.status_code == HTTP_OK
        assert second_bad_response.status_code == HTTP_BAD_REQUEST
        assert third_bad_response.status_code == HTTP_BAD_REQUEST
        assert limited_response.status_code == HTTP_TOO_MANY_REQUESTS


async def test_update_without_rate_limit_config_preserves_unthrottled_baseline(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Leaving AuthRateLimitConfig.api_key_update unset preserves pre-change PATCH behavior."""
    app, _store, strategy, owner, _admin = build_app(rate_limit_config=AuthRateLimitConfig())
    async with async_test_client_factory(app) as test_client:
        headers = await _login(test_client, owner, strategy)
        create_response = await test_client.post(
            "/api-keys",
            headers=headers,
            json={"name": "CLI", "scopes": ["read"], "current_password": "owner-password"},
        )
        key_id = create_response.json()["key"]["key_id"]

        responses = [
            await test_client.patch(
                f"/api-keys/{key_id}",
                headers=headers,
                json={"name": "Denied", "current_password": "wrong-password"},
            )
            for _ in range(3)
        ]

        assert [response.status_code for response in responses] == [
            HTTP_BAD_REQUEST,
            HTTP_BAD_REQUEST,
            HTTP_BAD_REQUEST,
        ]
        assert [_error_code(response) for response in responses] == [ErrorCode.LOGIN_BAD_CREDENTIALS] * 3


def test_api_key_controller_factory_supports_config_and_rejects_mixed_options() -> None:
    """The controller factory supports config objects and rejects ambiguous calls."""
    config = ApiKeysControllerConfig[UUID](
        id_parser=UUID,
        path="/keys",
        users_path="/accounts",
    )
    controllers = create_api_keys_controllers(config=config)

    assert [controller.path for controller in controllers] == ["/keys", "/accounts"]
    with pytest.raises(ValueError, match="either ApiKeysControllerConfig"):
        create_api_keys_controllers(config=config, path="/other")


def test_plugin_mounts_api_key_controllers_and_openapi_scheme_when_enabled() -> None:
    """The plugin mounts API-key controllers and advertises apiKeyAuth only when enabled."""
    user_db = InMemoryUserDatabase([])
    api_key_store = InMemoryApiKeyStore()
    config = LitestarAuthConfig[ExampleUser, UUID](
        api_keys=ApiKeyConfig(
            enabled=True,
            store_factory=lambda _session: api_key_store,
            allowed_scopes=("read",),
        ),
        user_model=ExampleUser,
        user_manager_class=ApiKeyControllerManager,
        user_db_factory=lambda _session: user_db,
        session_maker=cast("Any", DummySessionMaker()),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        users_path="/accounts",
    )
    app = Litestar(
        plugins=[LitestarAuth(config)],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )

    paths = cast("Any", app.openapi_schema.paths)
    schemes = cast("Any", app.openapi_schema.components.security_schemes)

    assert "/api-keys" in paths
    assert "/accounts/{user_id}/api-keys" in paths
    assert "/users/{user_id}/api-keys" not in paths
    assert "/auth/api_key/login" not in paths
    assert "/auth/api_key/logout" not in paths
    assert "apiKeyAuth" in schemes
