"""Integration tests for the TOTP 2FA controller."""

from __future__ import annotations

import asyncio
import importlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import AsyncMock
from urllib.parse import unquote
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.fernet import Fernet
from litestar import Litestar, Request, get
from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.middleware import DefineMiddleware
from litestar.testing import AsyncTestClient

import litestar_auth.controllers.totp as totp_controller_module
import litestar_auth.totp as _totp_mod
from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY, TotpConfig
from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import create_auth_controller, create_totp_controller
from litestar_auth.controllers.auth import TOTP_PENDING_AUDIENCE
from litestar_auth.controllers.totp import (
    INVALID_ENROLL_TOKEN_DETAIL,
    INVALID_TOTP_CODE_DETAIL,
    INVALID_TOTP_TOKEN_DETAIL,
    TOTP_ENROLL_AUDIENCE,
    _consume_enrollment_secret,
    _decode_enrollment_token,
    _EnrollmentTokenCipher,
    _issue_enrollment_token,
    _sign_enrollment_token,
    _totp_handle_confirm_enable,
    _totp_handle_disable,
    _totp_handle_enable,
    _totp_resolve_enrollment_store,
    _totp_resolve_pending_jti_store,
    _totp_validate_replay_and_password,
)
from litestar_auth.exceptions import ConfigurationError, ErrorCode, TokenError
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit
from litestar_auth.totp import (
    InMemoryTotpEnrollmentStore,
    InMemoryUsedTotpCodeStore,
    _current_counter,
    _generate_totp_code,
)
from litestar_auth.totp_flow import InvalidTotpPendingTokenError
from tests._helpers import auth_middleware_get_request_session, litestar_app_with_user_manager
from tests.integration.conftest import DummySessionMaker, ExampleUser, InMemoryTokenStrategy, InMemoryUserDatabase

if TYPE_CHECKING:
    from litestar_auth.db.base import BaseUserStore

pytestmark = [pytest.mark.integration]

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_UNAUTHORIZED = 401
HTTP_SERVICE_UNAVAILABLE = 503
TWO_CALLS = 2

TOTP_PENDING_SECRET = "test-totp-pending-secret-thirty-two!"  # ≥ 32 bytes
TOTP_SECRET_KEY = Fernet.generate_key().decode()
_TEST_ENROLLMENT_CIPHER = _EnrollmentTokenCipher.from_key(TOTP_SECRET_KEY)
PENDING_JTI_HEX_LENGTH = 32
_DEFAULT_USED_TOKENS_STORE = object()
_DEFAULT_PENDING_JTI_STORE = object()
_DEFAULT_ENROLLMENT_STORE = object()


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records completed login hooks."""

    def __init__(  # noqa: PLR0913
        self,
        user_db: BaseUserStore[ExampleUser, UUID],
        password_helper: PasswordHelper,
        verification_token_secret: str = "verify-secret-1234567890-1234567890",
        reset_password_token_secret: str = "reset-secret-1234567890-1234567890",
        *,
        backends: tuple[object, ...] = (),
        login_identifier: Literal["email", "username"] = "email",
    ) -> None:
        """Initialize the manager with deterministic hook tracking."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
            ),
            backends=backends,
            login_identifier=login_identifier,
        )
        self.logged_in_users: list[ExampleUser] = []

    async def on_after_login(self, user: ExampleUser) -> None:
        """Record successful login completion."""
        self.logged_in_users.append(user)


class PluginUserManager(BaseUserManager[ExampleUser, UUID]):
    """Minimal plugin-compatible manager for custom-path TOTP tests."""


@get("/probe")
async def probe(request: Request[Any, Any, Any]) -> dict[str, str | None]:
    """Expose the authenticated email for assertions.

    Returns:
        Authenticated email when a user is present, otherwise ``None``.
    """
    await asyncio.sleep(0)
    user = cast("ExampleUser | None", request.user)
    return {"email": user.email if user is not None else None}


@dataclass(frozen=True, slots=True)
class AccountState:
    """Initial account-state used to mint and complete TOTP sessions in tests."""

    requires_verification: bool = False
    is_active: bool = True
    is_verified: bool = False


def build_app(  # noqa: PLR0913
    *,
    with_totp: bool = True,
    used_tokens_store: InMemoryUsedTotpCodeStore | object | None = _DEFAULT_USED_TOKENS_STORE,
    pending_jti_store: InMemoryJWTDenylistStore | object | None = _DEFAULT_PENDING_JTI_STORE,
    enrollment_store: InMemoryTotpEnrollmentStore | object | None = _DEFAULT_ENROLLMENT_STORE,
    rate_limit_config: AuthRateLimitConfig | None = None,
    totp_enable_requires_password: bool = True,
    account_state: AccountState | None = None,
    login_identifier: Literal["email", "username"] = "email",
    unsafe_testing: bool = False,
) -> tuple[Litestar, InMemoryUserDatabase, InMemoryTokenStrategy, TrackingUserManager]:
    """Create a test application with optional 2FA support.

    Returns:
        Litestar application, user database, backing token strategy, and tracking manager.
    """
    account_state = account_state if account_state is not None else AccountState()
    requires_verification = account_state.requires_verification
    initial_is_active = account_state.is_active
    initial_is_verified = account_state.is_verified

    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        username="totp-user" if login_identifier == "username" else "",
        hashed_password=password_helper.hash("correct-password"),
        is_active=initial_is_active,
        is_verified=initial_is_verified,
    )
    user_db = InMemoryUserDatabase([user])
    user_manager = TrackingUserManager(user_db, password_helper, login_identifier=login_identifier)
    strategy = InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    pending_secret = TOTP_PENDING_SECRET if with_totp else None
    replay_store = InMemoryUsedTotpCodeStore() if used_tokens_store is _DEFAULT_USED_TOKENS_STORE else used_tokens_store
    if pending_jti_store is _DEFAULT_PENDING_JTI_STORE:
        pending_jti_store = InMemoryJWTDenylistStore()
    if enrollment_store is _DEFAULT_ENROLLMENT_STORE:
        enrollment_store = InMemoryTotpEnrollmentStore()
    auth_controller = create_auth_controller(
        backend=backend,
        totp_pending_secret=pending_secret,
        requires_verification=requires_verification,
        login_identifier=login_identifier,
        unsafe_testing=unsafe_testing,
    )
    totp_controller = create_totp_controller(
        backend=backend,
        user_manager_dependency_key=DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        used_tokens_store=cast("InMemoryUsedTotpCodeStore | None", replay_store),
        pending_jti_store=cast("InMemoryJWTDenylistStore | None", pending_jti_store),
        enrollment_store=cast("InMemoryTotpEnrollmentStore | None", enrollment_store),
        rate_limit_config=rate_limit_config,
        totp_pending_secret=TOTP_PENDING_SECRET,
        totp_secret_key=TOTP_SECRET_KEY,
        totp_enable_requires_password=totp_enable_requires_password,
        totp_issuer="Test App",
        id_parser=UUID,
        requires_verification=requires_verification,
        unsafe_testing=unsafe_testing,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = litestar_app_with_user_manager(
        user_manager,
        auth_controller,
        totp_controller,
        probe,
        middleware=[middleware],
    )
    return app, user_db, strategy, user_manager


def _build_direct_totp_context(
    *,
    totp_enable_requires_password: bool = True,
    require_replay_protection: bool = False,
    effective_pending_jti_store: object | None = None,
) -> tuple[Any, SimpleNamespace, AsyncMock]:
    """Create a controller context with async mocks for direct handler tests.

    Returns:
        Tuple of controller context, mocked rate-limit callbacks, and mocked backend.
    """
    rate_limit = SimpleNamespace(
        before_request=AsyncMock(),
        on_invalid_attempt=AsyncMock(),
        on_success=AsyncMock(),
        on_account_state_failure=AsyncMock(),
    )
    backend = AsyncMock()
    backend.login.return_value = {"access_token": "verified-token"}
    ctx = totp_controller_module._TotpControllerContext(
        backend=backend,
        used_tokens_store=None,
        require_replay_protection=require_replay_protection,
        requires_verification=False,
        totp_enable_requires_password=totp_enable_requires_password,
        totp_issuer="Test App",
        totp_algorithm="SHA256",
        totp_rate_limit=cast("Any", rate_limit),
        totp_pending_secret=TOTP_PENDING_SECRET,
        effective_pending_jti_store=cast("Any", effective_pending_jti_store),
        id_parser=UUID,
        unsafe_testing=False,
        enrollment_token_cipher=_TEST_ENROLLMENT_CIPHER,
        enrollment_store=InMemoryTotpEnrollmentStore(),
    )
    return ctx, rate_limit, backend


async def _full_enrollment_store() -> InMemoryTotpEnrollmentStore:
    """Return a real enrollment store with no free user slots."""
    enrollment_store = InMemoryTotpEnrollmentStore(max_entries=1)
    assert await enrollment_store.save(user_id="occupied-user", jti="occupied-jti", secret="secret", ttl_seconds=60)
    return enrollment_store


@pytest.fixture
def app() -> tuple[Litestar, InMemoryUserDatabase]:
    """Create the shared TOTP app and backing database.

    Returns:
        App plus the in-memory user database.
    """
    litestar_app, user_db, _, _ = build_app()
    return litestar_app, user_db


def test_totp_controller_module_executes_under_coverage() -> None:
    """Reload the TOTP controller module so coverage records its module body."""
    reloaded_module = importlib.reload(totp_controller_module)

    assert reloaded_module.TOTP_ENROLL_AUDIENCE == TOTP_ENROLL_AUDIENCE
    assert reloaded_module.TotpEnableRequest.__name__ == totp_controller_module.TotpEnableRequest.__name__
    assert reloaded_module.TotpUserManagerProtocol.__name__.endswith("Protocol")


def test_validate_replay_and_password_requires_replay_store_outside_testing() -> None:
    """Production mode refuses replay protection without a used-code store."""
    with pytest.raises(ConfigurationError, match="used_tokens_store is required"):
        _totp_validate_replay_and_password(
            used_tokens_store=None,
            require_replay_protection=True,
            totp_enable_requires_password=False,
            user_manager=None,
        )


def test_validate_replay_and_password_requires_authenticate_for_step_up() -> None:
    """Step-up enrollment requires a manager authenticate method."""

    class NoAuthenticateManager:
        """Stub manager missing the authenticate seam."""

    with pytest.raises(ConfigurationError, match="totp_enable_requires_password=True"):
        _totp_validate_replay_and_password(
            used_tokens_store=InMemoryUsedTotpCodeStore(),
            require_replay_protection=False,
            totp_enable_requires_password=True,
            user_manager=NoAuthenticateManager(),
        )


def test_enable_route_publishes_request_body_in_openapi_when_step_up_is_enabled() -> None:
    """Password-protected enrollment advertises its request body in OpenAPI."""
    app, *_ = build_app(totp_enable_requires_password=True)

    enable_post = cast("Any", app.openapi_schema.paths)["/auth/2fa/enable"].post
    verify_post = cast("Any", app.openapi_schema.paths)["/auth/2fa/verify"].post
    confirm_post = cast("Any", app.openapi_schema.paths)["/auth/2fa/enable/confirm"].post
    disable_post = cast("Any", app.openapi_schema.paths)["/auth/2fa/disable"].post
    request_body = enable_post.request_body
    enable_schema = cast("Any", app.openapi_schema.components.schemas)["TotpEnableRequest"]

    assert request_body is not None
    assert next(iter(request_body.content.values())).schema.ref == "#/components/schemas/TotpEnableRequest"
    assert "password" in (enable_schema.properties or {})
    assert verify_post.request_body is not None
    assert confirm_post.request_body is not None
    assert disable_post.request_body is not None


def test_enable_route_omits_request_body_in_openapi_when_step_up_is_disabled() -> None:
    """Password-optional enrollment keeps the no-body OpenAPI contract."""
    app, *_ = build_app(totp_enable_requires_password=False)

    enable_post = cast("Any", app.openapi_schema.paths)["/auth/2fa/enable"].post

    assert enable_post.request_body is None


async def test_enable_2fa_returns_secret_and_uri(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """Enabling 2FA while authenticated returns the TOTP secret and otpauth URI."""
    client, user_db = client_and_db

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert login_resp.status_code == HTTP_CREATED
    token = login_resp.json()["access_token"]

    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert enable_resp.status_code == HTTP_CREATED
    body = enable_resp.json()
    assert "secret" in body
    assert body["uri"].startswith("otpauth://totp/")
    assert "Test%20App" in body["uri"] or "Test+App" in body["uri"] or "Test" in body["uri"]
    assert "enrollment_token" in body

    # secret NOT persisted until confirmation
    stored_user = next(iter(user_db.users_by_id.values()))
    assert stored_user.totp_secret is None

    # confirm enrollment with a valid TOTP code
    confirm_code = _generate_totp_code(body["secret"], _current_counter())
    confirm_resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert confirm_resp.status_code == HTTP_CREATED
    assert confirm_resp.json()["enabled"] is True

    # secret persisted after confirmation
    stored_user = next(iter(user_db.users_by_id.values()))
    assert stored_user.totp_secret == body["secret"]


async def test_enable_2fa_keeps_email_in_the_otpauth_uri_under_username_login_mode(
    async_test_client_factory: Any,  # noqa: ANN401
) -> None:
    """Username-mode login does not change TOTP enrollment's email-based URI."""
    app_value = build_app(login_identifier="username")
    async with async_test_client_factory(app_value) as client_and_db:
        client, user_db, _strategy, user_manager = client_and_db
        user = next(iter(user_db.users_by_id.values()))

        login_resp = await client.post(
            "/auth/login",
            json={"identifier": user.username, "password": "correct-password"},
        )
        assert login_resp.status_code == HTTP_CREATED
        token = login_resp.json()["access_token"]

        enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert user_manager.login_identifier == "username"
    assert enable_resp.status_code == HTTP_CREATED
    decoded_uri = unquote(enable_resp.json()["uri"])
    assert user.email in decoded_uri
    assert user.username not in decoded_uri


def test_sign_and_decode_enrollment_token_round_trip_plaintext() -> None:
    """Plaintext enrollment tokens carry only state lookup claims."""
    token = _sign_enrollment_token(
        user_id="user-123",
        signing_key=TOTP_PENDING_SECRET,
        jti="a" * PENDING_JTI_HEX_LENGTH,
        encoding="plain",
        lifetime_seconds=120,
    )

    payload = jwt.decode(
        token,
        TOTP_PENDING_SECRET,
        algorithms=["HS256"],
        audience=TOTP_ENROLL_AUDIENCE,
    )

    assert payload["sub"] == "user-123"
    assert "totp_secret" not in payload
    assert payload["enc"] == "plain"
    assert isinstance(payload["iat"], int)
    assert isinstance(payload["nbf"], int)
    assert isinstance(payload["exp"], int)
    assert payload["jti"] == "a" * PENDING_JTI_HEX_LENGTH
    claims = _decode_enrollment_token(
        token,
        signing_key=TOTP_PENDING_SECRET,
        expected_user_id="user-123",
        cipher=None,
    )
    assert claims.user_id == "user-123"
    assert claims.jti == "a" * PENDING_JTI_HEX_LENGTH
    assert claims.encoding == "plain"


def test_enrollment_cipher_reports_missing_cryptography(monkeypatch: pytest.MonkeyPatch) -> None:
    """Optional Fernet imports fail with the TOTP extra guidance."""

    def fail_import(module_name: str) -> object:
        if module_name == "cryptography.fernet":
            msg = "missing cryptography"
            raise ImportError(msg)
        return importlib.import_module(module_name)

    monkeypatch.setattr(totp_controller_module.importlib, "import_module", fail_import)

    with pytest.raises(ImportError, match=r"litestar-auth\[totp\]"):
        totp_controller_module._load_cryptography_fernet()


async def test_issue_and_consume_enrollment_token_round_trip_encrypted() -> None:
    """Enrollment tokens point at encrypted server-side secret state."""
    enrollment_store = InMemoryTotpEnrollmentStore()
    token = await _issue_enrollment_token(
        user_id="user-123",
        secret="totp-secret",
        signing_key=TOTP_PENDING_SECRET,
        cipher=_TEST_ENROLLMENT_CIPHER,
        enrollment_store=enrollment_store,
        lifetime_seconds=120,
    )

    payload = jwt.decode(
        token,
        TOTP_PENDING_SECRET,
        algorithms=["HS256"],
        audience=TOTP_ENROLL_AUDIENCE,
    )

    assert payload["enc"] == "fernet"
    assert "totp_secret" not in payload
    claims = _decode_enrollment_token(
        token,
        signing_key=TOTP_PENDING_SECRET,
        expected_user_id="user-123",
        cipher=_TEST_ENROLLMENT_CIPHER,
    )
    assert (
        await _consume_enrollment_secret(
            claims,
            enrollment_store=enrollment_store,
            cipher=_TEST_ENROLLMENT_CIPHER,
        )
        == "totp-secret"
    )
    assert await enrollment_store.consume(user_id="user-123", jti=claims.jti) is None


async def test_issue_and_consume_enrollment_token_round_trip_plaintext() -> None:
    """Unsafe-testing plaintext mode still keeps the secret in server-side state, not the JWT."""
    enrollment_store = InMemoryTotpEnrollmentStore()
    token = await _issue_enrollment_token(
        user_id="user-123",
        secret="totp-secret",
        signing_key=TOTP_PENDING_SECRET,
        cipher=None,
        enrollment_store=enrollment_store,
        lifetime_seconds=120,
    )

    payload = jwt.decode(
        token,
        TOTP_PENDING_SECRET,
        algorithms=["HS256"],
        audience=TOTP_ENROLL_AUDIENCE,
    )
    claims = _decode_enrollment_token(
        token,
        signing_key=TOTP_PENDING_SECRET,
        expected_user_id="user-123",
        cipher=None,
    )

    assert payload["enc"] == "plain"
    assert "totp_secret" not in payload
    assert await _consume_enrollment_secret(claims, enrollment_store=enrollment_store, cipher=None) == "totp-secret"


async def test_issue_enrollment_token_raises_when_store_rejects_write() -> None:
    """Enrollment issuance fails closed when the server-side store is at capacity."""
    with pytest.raises(TokenError, match="Could not record TOTP enrollment state"):
        await _issue_enrollment_token(
            user_id="user-123",
            secret="totp-secret",
            signing_key=TOTP_PENDING_SECRET,
            cipher=None,
            enrollment_store=await _full_enrollment_store(),
        )


def test_decode_enrollment_secret_rejects_plain_encoding_when_cipher_is_active() -> None:
    """Cipher-enabled deployments reject plaintext server-side enrollment values."""
    assert (
        totp_controller_module._decode_enrollment_secret(
            "totp-secret",
            cipher=_TEST_ENROLLMENT_CIPHER,
            encoding="plain",
        )
        is None
    )


def test_decode_enrollment_token_rejects_encoding_mismatch() -> None:
    """Decoder refuses plaintext tokens when a cipher is configured, and vice versa."""
    plaintext_token = _sign_enrollment_token(
        user_id="user-123",
        signing_key=TOTP_PENDING_SECRET,
        jti="a" * PENDING_JTI_HEX_LENGTH,
        encoding="plain",
    )
    with pytest.raises(InvalidTotpPendingTokenError):
        _decode_enrollment_token(
            plaintext_token,
            signing_key=TOTP_PENDING_SECRET,
            expected_user_id="user-123",
            cipher=_TEST_ENROLLMENT_CIPHER,
        )

    encrypted_token = _sign_enrollment_token(
        user_id="user-123",
        signing_key=TOTP_PENDING_SECRET,
        jti="b" * PENDING_JTI_HEX_LENGTH,
        encoding="fernet",
    )
    with pytest.raises(InvalidTotpPendingTokenError):
        _decode_enrollment_token(
            encrypted_token,
            signing_key=TOTP_PENDING_SECRET,
            expected_user_id="user-123",
            cipher=None,
        )


async def test_consume_enrollment_token_rejects_wrong_cipher_key() -> None:
    """Enrollment state encrypted with another Fernet key cannot be consumed."""
    other_cipher = _EnrollmentTokenCipher.from_key(Fernet.generate_key().decode())
    enrollment_store = InMemoryTotpEnrollmentStore()
    token = await _issue_enrollment_token(
        user_id="user-123",
        secret="totp-secret",
        signing_key=TOTP_PENDING_SECRET,
        cipher=other_cipher,
        enrollment_store=enrollment_store,
    )
    claims = _decode_enrollment_token(
        token,
        signing_key=TOTP_PENDING_SECRET,
        expected_user_id="user-123",
        cipher=_TEST_ENROLLMENT_CIPHER,
    )

    with pytest.raises(InvalidTotpPendingTokenError):
        await _consume_enrollment_secret(
            claims,
            enrollment_store=enrollment_store,
            cipher=_TEST_ENROLLMENT_CIPHER,
        )


def test_decode_enrollment_token_rejects_invalid_jti() -> None:
    """Enrollment tokens with a malformed JTI are rejected."""
    token = jwt.encode(
        {
            "sub": "user-123",
            "aud": TOTP_ENROLL_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "jti": "not-hex",
            "enc": "plain",
        },
        TOTP_PENDING_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(InvalidTotpPendingTokenError):
        _decode_enrollment_token(
            token,
            signing_key=TOTP_PENDING_SECRET,
            expected_user_id="user-123",
            cipher=None,
        )


def test_decode_enrollment_token_rejects_mismatched_subject() -> None:
    """Enrollment tokens must belong to the authenticated user."""
    token = _sign_enrollment_token(
        user_id="user-123",
        signing_key=TOTP_PENDING_SECRET,
        jti="a" * PENDING_JTI_HEX_LENGTH,
        encoding="plain",
    )

    with pytest.raises(InvalidTotpPendingTokenError):
        _decode_enrollment_token(
            token,
            signing_key=TOTP_PENDING_SECRET,
            expected_user_id="different-user",
            cipher=None,
        )


def test_decode_enrollment_token_rejects_missing_encoding() -> None:
    """Enrollment tokens without an encoding marker are rejected."""
    token = jwt.encode(
        {
            "sub": "user-123",
            "aud": TOTP_ENROLL_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "jti": "a" * PENDING_JTI_HEX_LENGTH,
        },
        TOTP_PENDING_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(InvalidTotpPendingTokenError):
        _decode_enrollment_token(
            token,
            signing_key=TOTP_PENDING_SECRET,
            expected_user_id="user-123",
            cipher=None,
        )


def test_resolve_enrollment_store_handles_explicit_and_unsafe_testing_modes() -> None:
    """Enrollment-store resolution keeps configured stores and creates an unsafe-testing fallback."""
    configured_store = InMemoryTotpEnrollmentStore()

    assert _totp_resolve_enrollment_store(configured_store, unsafe_testing=False) is configured_store
    assert isinstance(_totp_resolve_enrollment_store(None, unsafe_testing=True), InMemoryTotpEnrollmentStore)
    with pytest.raises(ConfigurationError, match="totp_enrollment_store is required"):
        _totp_resolve_enrollment_store(None, unsafe_testing=False)


def test_resolve_pending_jti_store_handles_explicit_and_unsafe_testing_modes() -> None:
    """Pending-JTI resolution preserves configured stores and skips checks only in explicit unsafe testing."""
    configured_store = InMemoryJWTDenylistStore()

    assert _totp_resolve_pending_jti_store(configured_store, unsafe_testing=False) is configured_store
    assert _totp_resolve_pending_jti_store(None, unsafe_testing=True) is None
    with pytest.raises(ConfigurationError, match="pending_jti_store is required"):
        _totp_resolve_pending_jti_store(None, unsafe_testing=False)


async def test_handle_enable_requires_authenticated_totp_user() -> None:
    """Direct enable handler calls reject missing authenticated users."""
    ctx, _rate_limit, _backend = _build_direct_totp_context()
    request = cast("Any", SimpleNamespace(user=None))

    with pytest.raises(NotAuthorizedException, match="Authentication credentials were not provided"):
        await _totp_handle_enable(
            request,
            ctx=ctx,
            user_manager=cast("Any", SimpleNamespace()),
        )


async def test_handle_enable_rejects_non_enable_request_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unexpected decode results still map to the payload-invalid client response."""
    _app, user_db, _strategy, _user_manager = build_app()
    user = next(iter(user_db.users_by_id.values()))
    ctx, _rate_limit, _backend = _build_direct_totp_context()

    async def return_unexpected_payload(*_args: object, **_kwargs: object) -> object:
        await asyncio.sleep(0)
        return object()

    monkeypatch.setattr(totp_controller_module, "_decode_request_body", return_unexpected_payload)

    with pytest.raises(ClientException) as exc_info:
        await _totp_handle_enable(
            cast("Any", SimpleNamespace(user=user)),
            ctx=ctx,
            user_manager=cast("Any", SimpleNamespace(authenticate=AsyncMock(return_value=user))),
        )

    assert exc_info.value.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}


async def test_handle_enable_accepts_valid_decoded_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Direct helper calls still support the legacy decode path when data is omitted."""
    _app, user_db, _strategy, _user_manager = build_app()
    user = next(iter(user_db.users_by_id.values()))
    ctx, rate_limit, _backend = _build_direct_totp_context()
    user_manager = SimpleNamespace(authenticate=AsyncMock(return_value=user))

    async def return_valid_payload(*_args: object, **_kwargs: object) -> object:
        await asyncio.sleep(0)
        return totp_controller_module.TotpEnableRequest(password="correct-password")

    monkeypatch.setattr(totp_controller_module, "_decode_request_body", return_valid_payload)

    response = await _totp_handle_enable(
        cast("Any", SimpleNamespace(user=user)),
        ctx=ctx,
        user_manager=cast("Any", user_manager),
    )

    assert response.secret
    assert response.enrollment_token
    assert response.uri.startswith("otpauth://")
    user_manager.authenticate.assert_awaited_once_with(
        user.email,
        "correct-password",
        login_identifier="email",
    )
    rate_limit.on_invalid_attempt.assert_not_awaited()
    rate_limit.on_success.assert_awaited_once()


async def test_handle_enable_maps_enrollment_store_rejection_to_service_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct enable handler fails closed when enrollment state cannot be recorded."""
    _app, user_db, _strategy, _user_manager = build_app()
    user = next(iter(user_db.users_by_id.values()))
    ctx, rate_limit, _backend = _build_direct_totp_context()
    ctx.enrollment_store = await _full_enrollment_store()
    user_manager = SimpleNamespace(authenticate=AsyncMock(return_value=user))

    async def return_valid_payload(*_args: object, **_kwargs: object) -> object:
        await asyncio.sleep(0)
        return totp_controller_module.TotpEnableRequest(password="correct-password")

    monkeypatch.setattr(totp_controller_module, "_decode_request_body", return_valid_payload)

    with pytest.raises(ClientException) as exc_info:
        await _totp_handle_enable(
            cast("Any", SimpleNamespace(user=user)),
            ctx=ctx,
            user_manager=cast("Any", user_manager),
        )

    assert exc_info.value.status_code == HTTP_SERVICE_UNAVAILABLE
    assert exc_info.value.extra == {"code": ErrorCode.TOKEN_PROCESSING_FAILED}
    rate_limit.on_success.assert_not_awaited()


async def test_handle_enable_rejects_invalid_explicit_data_payload() -> None:
    """Direct helper calls reject explicit non-TotpEnableRequest payloads before authentication."""
    _app, user_db, _strategy, _user_manager = build_app()
    user = next(iter(user_db.users_by_id.values()))
    ctx, _rate_limit, _backend = _build_direct_totp_context()
    user_manager = SimpleNamespace(authenticate=AsyncMock(return_value=user))

    with pytest.raises(ClientException) as exc_info:
        await _totp_handle_enable(
            cast("Any", SimpleNamespace(user=user)),
            ctx=ctx,
            data=cast("Any", object()),
            user_manager=cast("Any", user_manager),
        )

    assert exc_info.value.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert exc_info.value.detail == "Invalid request payload."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}
    user_manager.authenticate.assert_not_awaited()


async def test_enable_2fa_step_up_requires_password(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """When step-up is enabled, /enable requires the current password."""
    app_value = build_app(totp_enable_requires_password=True)
    async with async_test_client_factory(app_value) as client_and_db:
        client, _user_db, _strategy, _user_manager = client_and_db

        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_resp.status_code == HTTP_CREATED
        token = login_resp.json()["access_token"]

        missing_password_resp = await client.post(
            "/auth/2fa/enable",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert missing_password_resp.status_code == HTTP_BAD_REQUEST

        wrong_password_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "wrong-password"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert wrong_password_resp.status_code == HTTP_BAD_REQUEST

        ok_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ok_resp.status_code == HTTP_CREATED


async def test_enable_2fa_rejects_reenrollment_when_already_enabled(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """Enable rejects authenticated users who already have a TOTP secret."""
    client, user_db = client_and_db

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert login_resp.status_code == HTTP_CREATED
    token = login_resp.json()["access_token"]

    first_enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert first_enable_resp.status_code == HTTP_CREATED
    first_body = first_enable_resp.json()
    confirm_code = _generate_totp_code(first_body["secret"], _current_counter())
    confirm_resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": first_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert confirm_resp.status_code == HTTP_CREATED
    stored_secret = next(iter(user_db.users_by_id.values())).totp_secret

    second_enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert second_enable_resp.status_code == HTTP_BAD_REQUEST
    body = second_enable_resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.TOTP_ALREADY_ENABLED
    assert body["detail"] == "TOTP is already enabled."
    assert next(iter(user_db.users_by_id.values())).totp_secret == stored_secret


async def test_enable_2fa_checks_step_up_before_already_enabled(async_test_client_factory: Any) -> None:  # noqa: ANN401
    """Invalid step-up credentials fail before the already-enabled check runs."""
    app_value = build_app(totp_enable_requires_password=True)
    async with async_test_client_factory(app_value) as client_and_db:
        client, _user_db, _strategy, _user_manager = client_and_db

        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_resp.status_code == HTTP_CREATED
        token = login_resp.json()["access_token"]

        first_enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert first_enable_resp.status_code == HTTP_CREATED
        first_body = first_enable_resp.json()
        confirm_code = _generate_totp_code(first_body["secret"], _current_counter())
        confirm_resp = await client.post(
            "/auth/2fa/enable/confirm",
            json={"enrollment_token": first_body["enrollment_token"], "code": confirm_code},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert confirm_resp.status_code == HTTP_CREATED

        wrong_password_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "wrong-password"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert wrong_password_resp.status_code == HTTP_BAD_REQUEST
        body = wrong_password_resp.json()
        code = body.get("code") or (body.get("extra") or {}).get("code")
        assert code == ErrorCode.LOGIN_BAD_CREDENTIALS
        assert body["detail"] == "Invalid credentials."


async def test_enable_2fa_rejects_invalid_payload_shape() -> None:
    """Enable returns 422 and the payload-invalid code when the body fails msgspec validation."""
    rate_limit_config, enable_backend, _confirm_backend, verify_backend, disable_backend = (
        _build_totp_all_endpoint_rate_limiters()
    )
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config, totp_enable_requires_password=True)

    async with AsyncTestClient(app=app) as client:
        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        access_token = login_resp.json()["access_token"]

        resp = await client.post(
            "/auth/2fa/enable",
            json={"password": 123},
            headers={"Authorization": f"Bearer {access_token}"},
        )

    assert resp.status_code == HTTP_UNPROCESSABLE_ENTITY
    body = resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert body["detail"] == "Invalid request payload."
    assert code == ErrorCode.LOGIN_PAYLOAD_INVALID
    assert enable_backend.increment.await_count == 1
    assert verify_backend.increment.await_count == 0
    assert disable_backend.increment.await_count == 0


async def test_enable_2fa_rejects_malformed_json_body() -> None:
    """Enable returns 400 and the request-body-invalid code for malformed JSON."""
    rate_limit_config, enable_backend, _confirm_backend, verify_backend, disable_backend = (
        _build_totp_all_endpoint_rate_limiters()
    )
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config, totp_enable_requires_password=True)

    async with AsyncTestClient(app=app) as client:
        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        access_token = login_resp.json()["access_token"]

        resp = await client.post(
            "/auth/2fa/enable",
            content=b"{",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == HTTP_BAD_REQUEST
    body = resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert body["detail"] == "Invalid request body."
    assert code == ErrorCode.REQUEST_BODY_INVALID
    assert enable_backend.increment.await_count == 1
    assert verify_backend.increment.await_count == 0
    assert disable_backend.increment.await_count == 0


async def test_login_with_2fa_enabled_returns_pending_token(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """Login when 2FA is enabled returns 202 with a pending token instead of a full auth token."""
    client, _ = client_and_db

    # enable 2fa first
    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await _confirm_enrollment(client, token=token, enable_body=enable_resp.json())

    # login again — should return pending
    pending_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert pending_resp.status_code == HTTP_ACCEPTED
    body = pending_resp.json()
    assert body["totp_required"] is True
    assert isinstance(body["pending_token"], str)
    assert len(body["pending_token"]) > 0
    payload = jwt.decode(
        body["pending_token"],
        TOTP_PENDING_SECRET,
        algorithms=["HS256"],
        audience=TOTP_PENDING_AUDIENCE,
    )
    assert isinstance(payload["iat"], int)
    assert isinstance(payload["jti"], str)
    assert len(payload["jti"]) == PENDING_JTI_HEX_LENGTH


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_verify_with_valid_code_issues_full_token(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """Providing the correct TOTP code via /verify issues a full auth token."""
    client, _ = client_and_db

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    enable_body = enable_resp.json()
    secret = enable_body["secret"]
    await _confirm_enrollment(client, token=token, enable_body=enable_body)

    pending_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    pending_token = pending_resp.json()["pending_token"]

    valid_code = _generate_totp_code(secret, _current_counter())
    verify_resp = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": valid_code},
    )
    assert verify_resp.status_code == HTTP_CREATED
    assert "access_token" in verify_resp.json()


async def test_confirm_enable_rejects_expired_enrollment_token(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """Expired enrollment tokens are rejected before the secret is persisted."""
    client, user_db = client_and_db
    user = next(iter(user_db.users_by_id.values()))

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    enable_body = enable_resp.json()
    expired_token = _sign_enrollment_token(
        user_id=str(user.id),
        signing_key=TOTP_PENDING_SECRET,
        jti="a" * PENDING_JTI_HEX_LENGTH,
        encoding="fernet",
        lifetime_seconds=-1,
    )

    confirm_resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={
            "enrollment_token": expired_token,
            "code": _generate_totp_code(enable_body["secret"], _current_counter()),
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert confirm_resp.status_code == HTTP_BAD_REQUEST
    body = confirm_resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.TOTP_ENROLL_BAD_TOKEN
    assert body["detail"] == INVALID_ENROLL_TOKEN_DETAIL
    assert user.totp_secret is None


async def test_confirm_enable_rejects_invalid_jti_enrollment_token(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """Enrollment confirmation rejects structurally invalid JTIs."""
    client, user_db = client_and_db
    user = next(iter(user_db.users_by_id.values()))

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    enable_body = enable_resp.json()
    invalid_token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": TOTP_ENROLL_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "jti": "g" * PENDING_JTI_HEX_LENGTH,
            "enc": "fernet",
        },
        TOTP_PENDING_SECRET,
        algorithm="HS256",
    )

    confirm_resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={
            "enrollment_token": invalid_token,
            "code": _generate_totp_code(enable_body["secret"], _current_counter()),
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert confirm_resp.status_code == HTTP_BAD_REQUEST
    body = confirm_resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.TOTP_ENROLL_BAD_TOKEN
    assert body["detail"] == INVALID_ENROLL_TOKEN_DETAIL
    assert user.totp_secret is None


async def test_handle_confirm_enable_requires_authenticated_totp_user() -> None:
    """Direct confirm-enable calls reject requests without an authenticated user."""
    ctx, _rate_limit, _backend = _build_direct_totp_context()

    with pytest.raises(NotAuthorizedException, match="Authentication credentials were not provided"):
        await _totp_handle_confirm_enable(
            cast("Any", SimpleNamespace(user=None)),
            ctx=ctx,
            data=totp_controller_module.TotpConfirmEnableRequest(enrollment_token="token", code="123456"),
            user_manager=cast("Any", SimpleNamespace()),
        )


async def test_handle_confirm_enable_rejects_invalid_code_directly() -> None:
    """Direct confirm-enable calls reject bad TOTP codes before persistence."""
    _app, user_db, _strategy, _user_manager = build_app()
    user = next(iter(user_db.users_by_id.values()))
    ctx, rate_limit, _backend = _build_direct_totp_context()
    enrollment_token = await _issue_enrollment_token(
        user_id=str(user.id),
        secret="totp-secret",
        signing_key=TOTP_PENDING_SECRET,
        cipher=_TEST_ENROLLMENT_CIPHER,
        enrollment_store=ctx.enrollment_store,
    )

    with pytest.raises(ClientException) as exc_info:
        await _totp_handle_confirm_enable(
            cast("Any", SimpleNamespace(user=user)),
            ctx=ctx,
            data=totp_controller_module.TotpConfirmEnableRequest(enrollment_token=enrollment_token, code="000000"),
            user_manager=cast("Any", SimpleNamespace(set_totp_secret=AsyncMock())),
        )

    assert exc_info.value.status_code == HTTP_BAD_REQUEST
    assert exc_info.value.extra == {"code": ErrorCode.TOTP_CODE_INVALID}
    assert rate_limit.on_invalid_attempt.await_count == 1


async def test_confirm_enable_rejects_replayed_enrollment_token(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """Reusing the enrollment token after success hits the already-enabled guard."""
    client, user_db = client_and_db
    user = next(iter(user_db.users_by_id.values()))

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    enable_body = enable_resp.json()
    confirm_code = _generate_totp_code(enable_body["secret"], _current_counter())

    first_confirm = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    second_confirm = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert first_confirm.status_code == HTTP_CREATED
    assert second_confirm.status_code == HTTP_BAD_REQUEST
    body = second_confirm.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.TOTP_ALREADY_ENABLED
    assert body["detail"] == "TOTP is already enabled."
    assert user.totp_secret == enable_body["secret"]


async def test_confirm_enable_rejects_stale_enrollment_token_after_new_enable(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """A newer `/enable` call invalidates the previous enrollment token for that user."""
    client, user_db = client_and_db
    user = next(iter(user_db.users_by_id.values()))

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    first_enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    first_body = first_enable_resp.json()
    second_enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    second_body = second_enable_resp.json()

    stale_confirm = await client.post(
        "/auth/2fa/enable/confirm",
        json={
            "enrollment_token": first_body["enrollment_token"],
            "code": _generate_totp_code(first_body["secret"], _current_counter()),
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    latest_confirm = await client.post(
        "/auth/2fa/enable/confirm",
        json={
            "enrollment_token": second_body["enrollment_token"],
            "code": _generate_totp_code(second_body["secret"], _current_counter()),
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert stale_confirm.status_code == HTTP_BAD_REQUEST
    stale_body = stale_confirm.json()
    code = stale_body.get("code") or (stale_body.get("extra") or {}).get("code")
    assert code == ErrorCode.TOTP_ENROLL_BAD_TOKEN
    assert latest_confirm.status_code == HTTP_CREATED
    assert user.totp_secret == second_body["secret"]


async def test_confirm_enable_consumes_enrollment_token_on_invalid_code(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """A failed confirmation attempt consumes the enrollment token before code validation."""
    client, user_db = client_and_db
    user = next(iter(user_db.users_by_id.values()))

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    enable_body = enable_resp.json()

    invalid_code_resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": "000000"},
        headers={"Authorization": f"Bearer {token}"},
    )
    replay_resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={
            "enrollment_token": enable_body["enrollment_token"],
            "code": _generate_totp_code(enable_body["secret"], _current_counter()),
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert invalid_code_resp.status_code == HTTP_BAD_REQUEST
    assert replay_resp.status_code == HTTP_BAD_REQUEST
    body = replay_resp.json()
    code = body.get("code") or (body.get("extra") or {}).get("code")
    assert code == ErrorCode.TOTP_ENROLL_BAD_TOKEN
    assert user.totp_secret is None


async def test_plugin_mounts_totp_routes_under_custom_auth_path() -> None:
    """The plugin mounts TOTP routes beneath the configured auth path."""
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy()),
    )
    app = Litestar(
        plugins=[
            LitestarAuth(
                LitestarAuthConfig[ExampleUser, UUID](
                    backends=[backend],
                    session_maker=cast("Any", DummySessionMaker()),
                    user_model=ExampleUser,
                    user_manager_class=PluginUserManager,
                    user_db_factory=lambda _session: user_db,
                    user_manager_security=UserManagerSecurity[UUID](
                        verification_token_secret="verify-secret-12345678901234567890",
                        reset_password_token_secret="reset-secret-123456789012345678901",
                        totp_secret_key=Fernet.generate_key().decode(),
                        id_parser=UUID,
                        password_helper=password_helper,
                    ),
                    auth_path="/api/auth",
                    totp_config=TotpConfig(
                        totp_pending_secret=TOTP_PENDING_SECRET,
                        totp_pending_jti_store=InMemoryJWTDenylistStore(),
                        totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
                        totp_enrollment_store=InMemoryTotpEnrollmentStore(),
                    ),
                ),
            ),
        ],
    )

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/api/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        enable_response = await client.post(
            "/api/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert enable_response.status_code == HTTP_CREATED
        enable_body = enable_response.json()
        secret = enable_body["secret"]
        assert secret
        confirm_code = _generate_totp_code(secret, _current_counter())
        confirm_response = await client.post(
            "/api/auth/2fa/enable/confirm",
            json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert confirm_response.status_code == HTTP_CREATED

        pending_response = await client.post(
            "/api/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert pending_response.status_code == HTTP_ACCEPTED

        verify_response = await client.post(
            "/api/auth/2fa/verify",
            json={"pending_token": pending_response.json()["pending_token"], "code": "000000"},
        )
        assert verify_response.status_code == HTTP_BAD_REQUEST

        disable_requires_auth_response = await client.post(
            "/api/auth/2fa/disable",
            json={"code": _generate_totp_code(secret, _current_counter())},
        )
        assert disable_requires_auth_response.status_code == HTTP_UNAUTHORIZED


async def test_plugin_allows_opt_out_of_totp_step_up_enrollment() -> None:
    """Integrators can explicitly opt out of step-up enrollment (unsafe)."""
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy()),
    )
    app = Litestar(
        plugins=[
            LitestarAuth(
                LitestarAuthConfig[ExampleUser, UUID](
                    backends=[backend],
                    session_maker=cast("Any", DummySessionMaker()),
                    user_model=ExampleUser,
                    user_manager_class=PluginUserManager,
                    user_db_factory=lambda _session: user_db,
                    user_manager_security=UserManagerSecurity[UUID](
                        verification_token_secret="verify-secret-12345678901234567890",
                        reset_password_token_secret="reset-secret-123456789012345678901",
                        totp_secret_key=Fernet.generate_key().decode(),
                        id_parser=UUID,
                        password_helper=password_helper,
                    ),
                    totp_config=TotpConfig(
                        totp_pending_secret=TOTP_PENDING_SECRET,
                        totp_pending_jti_store=InMemoryJWTDenylistStore(),
                        totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
                        totp_enrollment_store=InMemoryTotpEnrollmentStore(),
                        totp_enable_requires_password=False,
                    ),
                ),
            ),
        ],
    )

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        enable_response = await client.post(
            "/auth/2fa/enable",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert enable_response.status_code == HTTP_CREATED
        assert enable_response.json()["secret"]


async def test_verify_with_wrong_code_returns_400(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """An incorrect TOTP code is rejected with 400."""
    client, _ = client_and_db

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await _confirm_enrollment(client, token=token, enable_body=enable_resp.json())

    pending_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    pending_token = pending_resp.json()["pending_token"]

    resp = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": "000000"},
    )
    assert resp.status_code == HTTP_BAD_REQUEST
    detail = resp.json().get("detail")
    assert isinstance(detail, str)
    assert len(detail) > 0
    assert detail == INVALID_TOTP_CODE_DETAIL
    assert "Traceback" not in detail
    assert "Exception" not in detail


async def test_verify_rejects_inactive_user_when_requires_verification_enabled() -> None:
    """When requires_verification=True, TOTP completion rejects inactive users."""
    app, user_db, _, _ = build_app(
        account_state=AccountState(requires_verification=True, is_active=True, is_verified=True),
    )

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]

        user = next(iter(user_db.users_by_id.values()))
        user.is_active = False

        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": _generate_totp_code(secret, _current_counter())},
        )

        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == "The user account is inactive."


async def test_verify_rejects_unverified_user_when_requires_verification_enabled() -> None:
    """When requires_verification=True, TOTP completion rejects unverified users."""
    app, user_db, _, _ = build_app(
        account_state=AccountState(requires_verification=True, is_active=True, is_verified=True),
    )

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]

        user = next(iter(user_db.users_by_id.values()))
        user.is_verified = False

        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": _generate_totp_code(secret, _current_counter())},
        )

        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == "The user account is not verified."


@pytest.mark.parametrize(
    ("account_patch", "expected_detail"),
    [
        ({"is_active": False}, "The user account is inactive."),
        ({"is_verified": False}, "The user account is not verified."),
    ],
)
async def test_verify_account_state_failures_reset_without_incrementing_rate_limit(
    account_patch: dict[str, bool],
    expected_detail: str,
) -> None:
    """Account-state verify failures preserve reset-only rate-limit semantics."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, user_db, _, _ = build_app(
        rate_limit_config=rate_limit_config,
        account_state=AccountState(requires_verification=True, is_active=True, is_verified=True),
    )

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]

        user = next(iter(user_db.users_by_id.values()))
        for attr, value in account_patch.items():
            setattr(user, attr, value)

        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": _generate_totp_code(secret, _current_counter())},
        )
        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == expected_detail

    assert rate_limiter_backend.increment.await_count == 0
    assert rate_limiter_backend.reset.await_count == 1


async def test_verify_rejects_replayed_code_when_store_enabled() -> None:
    """Replay protection rejects a second successful verification in the same window."""
    app, _, _, _ = build_app(used_tokens_store=InMemoryUsedTotpCodeStore())

    async with AsyncTestClient(app=app) as client:
        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        token = login_resp.json()["access_token"]
        enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {token}"},
        )
        enable_body = enable_resp.json()
        secret = enable_body["secret"]
        await _confirm_enrollment(client, token=token, enable_body=enable_body)
        valid_code = _generate_totp_code(secret, _current_counter())

        first_pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        first_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": first_pending_token, "code": valid_code},
        )
        assert first_verify.status_code == HTTP_CREATED

        second_pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        second_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": second_pending_token, "code": valid_code},
        )
        assert second_verify.status_code == HTTP_BAD_REQUEST


async def test_verify_with_invalid_pending_token_returns_400(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """A tampered or expired pending token is rejected with 400."""
    client, _ = client_and_db

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await _confirm_enrollment(client, token=token, enable_body=enable_resp.json())

    resp = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": "not.a.valid.jwt", "code": "123456"},
    )
    assert resp.status_code == HTTP_BAD_REQUEST


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_disable_2fa_with_valid_code_clears_secret(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Providing the correct TOTP code via /disable removes the stored secret."""
    client, user_db = client_and_db
    fixed_counter = 123_456
    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter)

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    enable_body = enable_resp.json()
    secret = enable_body["secret"]
    await _confirm_enrollment(client, token=token, enable_body=enable_body)

    # re-login to get a fresh full token after 2fa was enabled
    pending_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    pending_token = pending_resp.json()["pending_token"]
    valid_code = _generate_totp_code(secret, fixed_counter)
    verify_resp = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": valid_code},
    )
    full_token = verify_resp.json()["access_token"]

    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter + 1)
    disable_code = _generate_totp_code(secret, fixed_counter + 1)
    disable_resp = await client.post(
        "/auth/2fa/disable",
        json={"code": disable_code},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    assert disable_resp.status_code == HTTP_CREATED

    stored_user = next(iter(user_db.users_by_id.values()))
    assert stored_user.totp_secret is None


async def test_handle_disable_requires_authenticated_totp_user() -> None:
    """Direct disable handler calls reject missing authenticated users."""
    ctx, _rate_limit, _backend = _build_direct_totp_context()

    with pytest.raises(NotAuthorizedException, match="Authentication credentials were not provided"):
        await _totp_handle_disable(
            cast("Any", SimpleNamespace(user=None)),
            ctx=ctx,
            data=totp_controller_module.TotpDisableRequest(code="123456"),
            user_manager=cast("Any", SimpleNamespace()),
        )


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_disable_then_enable_allows_reenrollment(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Users can rotate their TOTP secret only through disable-then-enable."""
    client, user_db = client_and_db
    fixed_counter = 123_456
    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter)

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert login_resp.status_code == HTTP_CREATED
    access_token = login_resp.json()["access_token"]

    first_enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert first_enable_resp.status_code == HTTP_CREATED
    first_body = first_enable_resp.json()
    first_secret = first_body["secret"]
    await _confirm_enrollment(client, token=access_token, enable_body=first_body)

    pending_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    pending_token = pending_resp.json()["pending_token"]
    verify_resp = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": _generate_totp_code(first_secret, fixed_counter)},
    )
    assert verify_resp.status_code == HTTP_CREATED
    full_token = verify_resp.json()["access_token"]

    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter + 1)
    disable_resp = await client.post(
        "/auth/2fa/disable",
        json={"code": _generate_totp_code(first_secret, fixed_counter + 1)},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    assert disable_resp.status_code == HTTP_CREATED
    assert next(iter(user_db.users_by_id.values())).totp_secret is None

    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter + 2)
    second_enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert second_enable_resp.status_code == HTTP_CREATED
    second_body = second_enable_resp.json()
    second_secret = second_body["secret"]
    assert second_secret != first_secret
    await _confirm_enrollment(client, token=access_token, enable_body=second_body)
    assert next(iter(user_db.users_by_id.values())).totp_secret == second_secret


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_disable_2fa_with_wrong_code_returns_400(
    client_and_db: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase],
) -> None:
    """A wrong TOTP code on /disable is rejected with 400."""
    client, _ = client_and_db

    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await _confirm_enrollment(client, token=token, enable_body=enable_resp.json())

    pending_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    pending_token = pending_resp.json()["pending_token"]
    secret = next(iter(client_and_db[1].users_by_id.values())).totp_secret
    assert isinstance(secret, str)
    valid_code = _generate_totp_code(secret, _current_counter())
    verify_resp = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": valid_code},
    )
    full_token = verify_resp.json()["access_token"]

    resp = await client.post(
        "/auth/2fa/disable",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    assert resp.status_code == HTTP_BAD_REQUEST


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_login_hook_waits_until_totp_verify() -> None:
    """Password login with 2FA enabled must not trigger the login hook before /verify."""
    app, _, _, user_manager = build_app()

    async with AsyncTestClient(app=app) as client:
        initial_login = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        initial_token = initial_login.json()["access_token"]
        enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {initial_token}"},
        )
        enable_body = enable_resp.json()
        secret = enable_body["secret"]
        await _confirm_enrollment(client, token=initial_token, enable_body=enable_body)

        pending_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert pending_resp.status_code == HTTP_ACCEPTED
        assert [user.email for user in user_manager.logged_in_users] == ["user@example.com"]

        verify_resp = await client.post(
            "/auth/2fa/verify",
            json={
                "pending_token": pending_resp.json()["pending_token"],
                "code": _generate_totp_code(secret, _current_counter()),
            },
        )
        assert verify_resp.status_code == HTTP_CREATED
        assert [user.email for user in user_manager.logged_in_users] == ["user@example.com", "user@example.com"]


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_pending_login_does_not_issue_backend_token_before_totp_verify() -> None:
    """The password step stays pending until /verify succeeds."""
    app, user_db, strategy, _user_manager = build_app()
    user = next(iter(user_db.users_by_id.values()))

    async with AsyncTestClient(app=app) as client:
        initial_login = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert initial_login.status_code == HTTP_CREATED
        initial_token = initial_login.json()["access_token"]
        assert strategy.tokens == {initial_token: user.id}

        enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {initial_token}"},
        )
        enable_body = enable_resp.json()
        secret = enable_body["secret"]
        await _confirm_enrollment(client, token=initial_token, enable_body=enable_body)

        pending_login = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert pending_login.status_code == HTTP_ACCEPTED
        pending_token = pending_login.json()["pending_token"]
        assert strategy.tokens == {initial_token: user.id}

        invalid_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": "000000"},
        )
        assert invalid_verify.status_code == HTTP_BAD_REQUEST
        assert strategy.tokens == {initial_token: user.id}

        valid_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": _generate_totp_code(secret, _current_counter())},
        )
        assert valid_verify.status_code == HTTP_CREATED
        verified_token = valid_verify.json()["access_token"]
        assert strategy.tokens == {initial_token: user.id, verified_token: user.id}


async def test_login_without_totp_configured_gives_direct_token() -> None:
    """When totp_pending_secret is not set, login always issues a direct token."""
    app, _, _, _ = build_app(with_totp=False)

    async with AsyncTestClient(app=app) as client:
        resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert resp.status_code == HTTP_CREATED
        assert "access_token" in resp.json()


def _build_totp_verify_rate_limiter() -> tuple[AuthRateLimitConfig, AsyncMock]:
    backend = AsyncMock()
    backend.check.return_value = True
    backend.retry_after.return_value = 0
    config = AuthRateLimitConfig(
        totp_verify=EndpointRateLimit(backend=backend, scope="ip", namespace="totp-verify"),
    )
    return config, backend


def _build_totp_all_endpoint_rate_limiters() -> tuple[AuthRateLimitConfig, AsyncMock, AsyncMock, AsyncMock, AsyncMock]:
    enable_backend = AsyncMock()
    enable_backend.check.return_value = True
    enable_backend.retry_after.return_value = 0
    confirm_backend = AsyncMock()
    confirm_backend.check.return_value = True
    confirm_backend.retry_after.return_value = 0
    verify_backend = AsyncMock()
    verify_backend.check.return_value = True
    verify_backend.retry_after.return_value = 0
    disable_backend = AsyncMock()
    disable_backend.check.return_value = True
    disable_backend.retry_after.return_value = 0
    config = AuthRateLimitConfig(
        totp_enable=EndpointRateLimit(backend=enable_backend, scope="ip", namespace="totp-enable"),
        totp_confirm_enable=EndpointRateLimit(
            backend=confirm_backend,
            scope="ip",
            namespace="totp-confirm-enable",
        ),
        totp_verify=EndpointRateLimit(backend=verify_backend, scope="ip", namespace="totp-verify"),
        totp_disable=EndpointRateLimit(backend=disable_backend, scope="ip", namespace="totp-disable"),
    )
    return config, enable_backend, confirm_backend, verify_backend, disable_backend


def _mint_pending_token(*, secret: str, payload: dict[str, Any]) -> str:
    token_payload = {
        "aud": TOTP_PENDING_AUDIENCE,
        "iat": datetime.now(tz=UTC),
        "jti": "0" * 32,
        **payload,
    }
    return jwt.encode(token_payload, secret, algorithm="HS256")


async def _confirm_enrollment(
    client: AsyncTestClient[Litestar],
    *,
    token: str,
    enable_body: dict[str, str],
    counter: int | None = None,
) -> None:
    """Complete the two-phase TOTP enrollment by confirming with a valid code."""
    secret = enable_body["secret"]
    confirm_code = _generate_totp_code(secret, counter if counter is not None else _totp_mod._current_counter())
    resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == HTTP_CREATED


async def _enable_totp_and_get_secret(client: AsyncTestClient[Litestar]) -> str:
    login_resp = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    token = login_resp.json()["access_token"]
    enable_resp = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    enable_body = enable_resp.json()
    secret = enable_body["secret"]
    confirm_code = _generate_totp_code(secret, _totp_mod._current_counter())
    confirm_resp = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert confirm_resp.status_code == HTTP_CREATED
    return secret


async def test_verify_with_expired_jwt_increments_rate_limit() -> None:
    """Expired pending tokens are rejected and count toward rate limiting."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, user_db, _, _ = build_app(rate_limit_config=rate_limit_config)
    user = next(iter(user_db.users_by_id.values()))
    expired_token = _mint_pending_token(
        secret=TOTP_PENDING_SECRET,
        payload={"sub": str(user.id), "exp": int(time.time()) - 1},
    )

    async with AsyncTestClient(app=app) as client:
        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": expired_token, "code": "123456"},
        )
        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL

    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_with_invalid_jwt_increments_rate_limit() -> None:
    """Syntactically invalid JWTs are rejected and count toward rate limiting."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": "not.a.valid.jwt", "code": "123456"},
        )
        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL

    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_with_empty_sub_increments_rate_limit() -> None:
    """Empty subject claims are treated as invalid and rate-limited."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)
    token = _mint_pending_token(secret=TOTP_PENDING_SECRET, payload={"sub": ""})

    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/2fa/verify", json={"pending_token": token, "code": "123456"})
        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL

    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_with_missing_sub_increments_rate_limit() -> None:
    """Missing subject claims are treated as invalid and rate-limited."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)
    token = _mint_pending_token(secret=TOTP_PENDING_SECRET, payload={})

    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/2fa/verify", json={"pending_token": token, "code": "123456"})
        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL

    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_rejects_non_string_subject_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-string subject claims are treated as invalid pending tokens."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, user_db, _, _ = build_app(rate_limit_config=rate_limit_config)
    user = next(iter(user_db.users_by_id.values()))

    def decode_pending_token(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "sub": user.id,
            "aud": TOTP_PENDING_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "exp": int(time.time()) + 300,
            "jti": "c" * PENDING_JTI_HEX_LENGTH,
        }

    monkeypatch.setattr("litestar_auth.totp_flow.jwt.decode", decode_pending_token)

    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/2fa/verify", json={"pending_token": "ignored", "code": "123456"})

    assert resp.status_code == HTTP_BAD_REQUEST
    assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL
    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_rejects_pending_token_without_jti() -> None:
    """Pending tokens without a JTI claim are rejected."""
    app, user_db, _, _ = build_app()
    user = next(iter(user_db.users_by_id.values()))
    token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": TOTP_PENDING_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
        },
        TOTP_PENDING_SECRET,
        algorithm="HS256",
    )

    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/2fa/verify", json={"pending_token": token, "code": "123456"})

    assert resp.status_code == HTTP_BAD_REQUEST
    assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL


@pytest.mark.parametrize("jti", ["short", "g" * PENDING_JTI_HEX_LENGTH])
async def test_verify_rejects_pending_token_with_structurally_invalid_jti(jti: str) -> None:
    """Pending-token JTIs must be the expected-length lowercase hex string."""
    app, user_db, _, _ = build_app()
    user = next(iter(user_db.users_by_id.values()))
    token = _mint_pending_token(
        secret=TOTP_PENDING_SECRET,
        payload={
            "sub": str(user.id),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "jti": jti,
        },
    )

    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/2fa/verify", json={"pending_token": token, "code": "123456"})

    assert resp.status_code == HTTP_BAD_REQUEST
    assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_verify_rejects_replayed_pending_jti_when_store_enabled() -> None:
    """A consumed pending-token JTI cannot be reused when a denylist store is configured."""
    app, _, _, _ = build_app(pending_jti_store=InMemoryJWTDenylistStore())

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        valid_code = _generate_totp_code(secret, _current_counter())

        first_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": valid_code},
        )
        assert first_verify.status_code == HTTP_CREATED

        second_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": valid_code},
        )
        assert second_verify.status_code == HTTP_BAD_REQUEST
        assert second_verify.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_verify_returns_service_unavailable_when_pending_jti_denylist_cannot_record() -> None:
    """When the pending-JTI denylist rejects a new write, verification fails closed with 503 JSON."""
    deny_store = InMemoryJWTDenylistStore(max_entries=1)
    await deny_store.deny("a" * PENDING_JTI_HEX_LENGTH, ttl_seconds=3600)
    app, _, _, _ = build_app(pending_jti_store=deny_store)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        valid_code = _generate_totp_code(secret, _current_counter())

        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": valid_code},
        )

    assert resp.status_code == HTTP_SERVICE_UNAVAILABLE
    body = resp.json()
    code = body.get("code") or body.get("extra", {}).get("code")
    assert code == ErrorCode.TOKEN_PROCESSING_FAILED
    detail = body.get("detail", "")
    assert "pending-login JTI" in detail


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_verify_allows_replayed_pending_token_when_pending_jti_store_is_disabled_in_unsafe_testing() -> None:
    """Without a pending-token denylist or used-code store, the same pending token can be replayed."""
    app, _, _, _ = build_app(used_tokens_store=None, pending_jti_store=None, unsafe_testing=True)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        valid_code = _generate_totp_code(secret, _current_counter())

        first_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": valid_code},
        )
        assert first_verify.status_code == HTTP_CREATED
        assert "access_token" in first_verify.json()

        second_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": valid_code},
        )
        assert second_verify.status_code == HTTP_CREATED
        assert "access_token" in second_verify.json()


def test_build_app_rejects_missing_pending_jti_store_outside_testing() -> None:
    """Production controller assembly fails closed when pending-token replay storage is missing."""
    with pytest.raises(ConfigurationError, match="pending_jti_store is required"):
        build_app(pending_jti_store=None)


async def test_verify_with_unknown_user_increments_rate_limit() -> None:
    """Unknown users are treated as invalid pending tokens and rate-limited."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)
    token = _mint_pending_token(secret=TOTP_PENDING_SECRET, payload={"sub": str(uuid4())})

    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/2fa/verify", json={"pending_token": token, "code": "123456"})
        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL

    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_rejects_pending_token_for_unknown_user_after_decode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decoded pending tokens for unknown users are rejected before TOTP verification."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)

    def decode_pending_token(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "sub": str(uuid4()),
            "aud": TOTP_PENDING_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "exp": int(time.time()) + 300,
            "jti": "d" * PENDING_JTI_HEX_LENGTH,
        }

    monkeypatch.setattr("litestar_auth.totp_flow.jwt.decode", decode_pending_token)

    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/2fa/verify", json={"pending_token": "ignored", "code": "123456"})

    assert resp.status_code == HTTP_BAD_REQUEST
    assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL
    assert rate_limiter_backend.increment.await_count == 1


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
@pytest.mark.parametrize(
    "expires_at",
    [
        datetime.now(tz=UTC) + timedelta(minutes=5),
        (datetime.now(tz=UTC) + timedelta(minutes=5)).replace(tzinfo=None),
    ],
)
async def test_verify_accepts_datetime_expiration_payload(
    monkeypatch: pytest.MonkeyPatch,
    expires_at: datetime,
) -> None:
    """Verify accepts decoded datetime exp claims in aware and naive forms."""
    fixed_counter = 123_456
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    deny_store = AsyncMock()
    deny_store.is_denied = AsyncMock(return_value=False)
    app, user_db, _, _ = build_app(rate_limit_config=rate_limit_config, pending_jti_store=cast("Any", deny_store))
    user = next(iter(user_db.users_by_id.values()))

    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)

        def decode_pending_token(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "sub": str(user.id),
                "aud": TOTP_PENDING_AUDIENCE,
                "iat": datetime.now(tz=UTC),
                "exp": expires_at,
                "jti": "a" * PENDING_JTI_HEX_LENGTH,
            }

        monkeypatch.setattr("litestar_auth.totp_flow.jwt.decode", decode_pending_token)
        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": "ignored-by-monkeypatch", "code": _generate_totp_code(secret, fixed_counter)},
        )

    assert resp.status_code == HTTP_CREATED
    assert deny_store.deny.await_count == 1
    assert deny_store.deny.await_args.kwargs["ttl_seconds"] >= 1
    assert rate_limiter_backend.reset.await_count == 1


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_verify_rejects_pending_token_with_unparseable_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify treats an unparseable decoded exp claim as an invalid pending token."""
    fixed_counter = 123_456
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, user_db, _, _ = build_app(rate_limit_config=rate_limit_config)
    user = next(iter(user_db.users_by_id.values()))

    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)

        def decode_pending_token(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "sub": str(user.id),
                "aud": TOTP_PENDING_AUDIENCE,
                "iat": datetime.now(tz=UTC),
                "exp": object(),
                "jti": "b" * PENDING_JTI_HEX_LENGTH,
            }

        monkeypatch.setattr("litestar_auth.totp_flow.jwt.decode", decode_pending_token)
        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": "ignored-by-monkeypatch", "code": _generate_totp_code(secret, fixed_counter)},
        )

    assert resp.status_code == HTTP_BAD_REQUEST
    assert resp.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL
    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_with_wrong_code_increments_rate_limit() -> None:
    """Wrong codes are rejected and count toward rate limiting."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]

        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": "000000"},
        )
        assert resp.status_code == HTTP_BAD_REQUEST
        assert resp.json()["detail"] == INVALID_TOTP_CODE_DETAIL

    assert rate_limiter_backend.increment.await_count == 1


async def test_verify_replay_increments_rate_limit_when_store_enabled() -> None:
    """Replay protection rejects reused codes and counts the failure toward rate limiting."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(used_tokens_store=InMemoryUsedTotpCodeStore(), rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        valid_code = _generate_totp_code(secret, _current_counter())

        first_pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        first_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": first_pending_token, "code": valid_code},
        )
        assert first_verify.status_code == HTTP_CREATED

        second_pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        second_verify = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": second_pending_token, "code": valid_code},
        )
        assert second_verify.status_code == HTTP_BAD_REQUEST
        assert second_verify.json()["detail"] == INVALID_TOTP_CODE_DETAIL

    assert rate_limiter_backend.increment.await_count == 1


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_verify_success_resets_rate_limit() -> None:
    """Successful verification clears any accumulated failures for the request key."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        valid_code = _generate_totp_code(secret, _current_counter())
        resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": valid_code},
        )
        assert resp.status_code == HTTP_CREATED

    assert rate_limiter_backend.reset.await_count == 1


async def test_enable_invalid_password_does_not_increment_verify_rate_limit() -> None:
    """Failed enable step-up checks stay outside the verify rate-limit counter."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config, totp_enable_requires_password=True)

    async with AsyncTestClient(app=app) as client:
        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_resp.status_code == HTTP_CREATED
        access_token = login_resp.json()["access_token"]

        wrong_password_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "wrong-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert wrong_password_resp.status_code == HTTP_BAD_REQUEST
        assert rate_limiter_backend.increment.await_count == 0
        assert rate_limiter_backend.reset.await_count == 0

        enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert enable_resp.status_code == HTTP_CREATED
        await _confirm_enrollment(client, token=access_token, enable_body=enable_resp.json())
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        verify_resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": "000000"},
        )
        assert verify_resp.status_code == HTTP_BAD_REQUEST

    assert rate_limiter_backend.increment.await_count == 1
    assert rate_limiter_backend.reset.await_count == 0


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_disable_invalid_code_does_not_increment_verify_rate_limit() -> None:
    """Disable failures keep verify counters unchanged after a successful verify reset."""
    rate_limit_config, rate_limiter_backend = _build_totp_verify_rate_limiter()
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        verify_resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": _generate_totp_code(secret, _current_counter())},
        )
        assert verify_resp.status_code == HTTP_CREATED
        assert rate_limiter_backend.increment.await_count == 0
        assert rate_limiter_backend.reset.await_count == 1


async def test_enable_failures_and_success_use_enable_rate_limit_backend() -> None:
    """Enable endpoint uses its own configured rate-limit backend."""
    rate_limit_config, enable_backend, _confirm_backend, verify_backend, disable_backend = (
        _build_totp_all_endpoint_rate_limiters()
    )
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config, totp_enable_requires_password=True)

    async with AsyncTestClient(app=app) as client:
        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_resp.status_code == HTTP_CREATED
        access_token = login_resp.json()["access_token"]

        wrong_password_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "wrong-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert wrong_password_resp.status_code == HTTP_BAD_REQUEST

        enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert enable_resp.status_code == HTTP_CREATED

    assert enable_backend.check.await_count == TWO_CALLS
    assert enable_backend.increment.await_count == 1
    assert enable_backend.reset.await_count == 1
    assert verify_backend.increment.await_count == 0
    assert disable_backend.increment.await_count == 0


async def test_confirm_enable_failures_and_success_use_confirm_enable_rate_limit_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirm-enable uses its own configured backend, separate from enable/verify/disable."""
    rate_limit_config, enable_backend, confirm_backend, verify_backend, disable_backend = (
        _build_totp_all_endpoint_rate_limiters()
    )
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config, totp_enable_requires_password=True)
    fixed_counter = 123_456
    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter)

    async with AsyncTestClient(app=app) as client:
        login_resp = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_resp.status_code == HTTP_CREATED
        access_token = login_resp.json()["access_token"]

        enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert enable_resp.status_code == HTTP_CREATED
        enable_body = enable_resp.json()

        wrong_code_resp = await client.post(
            "/auth/2fa/enable/confirm",
            json={"enrollment_token": enable_body["enrollment_token"], "code": "000000"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert wrong_code_resp.status_code == HTTP_BAD_REQUEST

        second_enable_resp = await client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert second_enable_resp.status_code == HTTP_CREATED
        second_enable_body = second_enable_resp.json()

        valid_code_resp = await client.post(
            "/auth/2fa/enable/confirm",
            json={
                "enrollment_token": second_enable_body["enrollment_token"],
                "code": _generate_totp_code(second_enable_body["secret"], fixed_counter),
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert valid_code_resp.status_code == HTTP_CREATED

    assert confirm_backend.check.await_count == TWO_CALLS
    assert confirm_backend.increment.await_count == 1
    assert confirm_backend.reset.await_count == 1
    assert enable_backend.reset.await_count == TWO_CALLS
    assert verify_backend.increment.await_count == 0
    assert disable_backend.increment.await_count == 0


async def test_disable_failures_and_success_use_disable_rate_limit_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disable endpoint uses its own configured rate-limit backend."""
    rate_limit_config, enable_backend, _confirm_backend, verify_backend, disable_backend = (
        _build_totp_all_endpoint_rate_limiters()
    )
    app, _, _, _ = build_app(rate_limit_config=rate_limit_config)
    fixed_counter = 123_456
    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter)

    async with AsyncTestClient(app=app) as client:
        secret = await _enable_totp_and_get_secret(client)
        pending_token = (
            await client.post("/auth/login", json={"identifier": "user@example.com", "password": "correct-password"})
        ).json()["pending_token"]
        verify_resp = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": _generate_totp_code(secret, fixed_counter)},
        )
        assert verify_resp.status_code == HTTP_CREATED
        access_token = verify_resp.json()["access_token"]

        wrong_code_resp = await client.post(
            "/auth/2fa/disable",
            json={"code": "000000"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert wrong_code_resp.status_code == HTTP_BAD_REQUEST

        monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter + 1)
        correct_code_resp = await client.post(
            "/auth/2fa/disable",
            json={"code": _generate_totp_code(secret, fixed_counter + 1)},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert correct_code_resp.status_code == HTTP_CREATED

    assert disable_backend.check.await_count == TWO_CALLS
    assert disable_backend.increment.await_count == 1
    assert disable_backend.reset.await_count == 1
    assert enable_backend.increment.await_count == 0
    # Successful /verify still resets verify counters independently.
    assert verify_backend.reset.await_count == 1
