"""Tests for the base user manager."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import warnings
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import ANY, AsyncMock, Mock, patch
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.fernet import Fernet

import litestar_auth._concurrency as concurrency_module
import litestar_auth._manager.account_tokens as account_tokens_module
import litestar_auth._manager.totp_facade as totp_facade_module
import litestar_auth._optional_deps as optional_deps_module
import litestar_auth.manager as manager_module
from litestar_auth._manager._coercions import _account_state_user, _as_dict, _managed_user, _require_str
from litestar_auth._manager.construction import resolve_oauth_account_store
from litestar_auth._manager.security import _SecretValue
from litestar_auth._manager.user_lifecycle import PRIVILEGED_FIELDS
from litestar_auth._manager.user_policy import UserPolicy
from litestar_auth.authentication.strategy.base import TokenInvalidationCapable
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.config import require_password_length
from litestar_auth.exceptions import (
    AuthorizationError,
    ConfigurationError,
    InactiveUserError,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    UnverifiedUserError,
    UserAlreadyExistsError,
    UserNotExistsError,
)
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import AdminUserUpdate, UserCreate, UserUpdate
from litestar_auth.totp import SecurityWarning
from tests._helpers import ExampleUser, make_run_sync_spy

RESET_PASSWORD_TOKEN_AUDIENCE = manager_module.RESET_PASSWORD_TOKEN_AUDIENCE
BaseUserManager = manager_module.BaseUserManager
BaseUserManagerConfig = manager_module.BaseUserManagerConfig
FernetKeyringConfig = manager_module.FernetKeyringConfig
UserManagerSecurity = manager_module.UserManagerSecurity
manager_logger = manager_module.logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth._manager.api_key_config import ApiKeyConfigProtocol
    from litestar_auth._manager.hooks import ManagerHookEvent
    from litestar_auth.db import OAuthAccountData

JTI_HEX_LENGTH = 32
# ``secrets.token_hex(32)`` is 64 lowercase hex characters.
EXPECTED_TOKEN_HEX_32_LEN = 64
EXPECTED_SECRET_FALLBACK_WARNINGS = 2
LOGIN_IDENTIFIER_TELEMETRY_SECRET = "login-telemetry-secret-1234567890"

pytestmark = pytest.mark.unit


def _assert_account_token_service_dependencies(
    account_tokens: Mock,
    manager: BaseUserManager[Any, Any],
    token_security_service: object,
) -> None:
    """Assert account-token service dependencies are wired through the grouped contract."""
    account_tokens.assert_called_once_with(manager, dependencies=ANY)
    dependencies = account_tokens.call_args.kwargs["dependencies"]
    assert dependencies.audiences == manager_module.AccountTokenAudiences(
        verify=manager_module.VERIFY_TOKEN_AUDIENCE,
        reset_password=RESET_PASSWORD_TOKEN_AUDIENCE,
        organization_invitation=manager_module.ORGANIZATION_INVITATION_TOKEN_AUDIENCE,
    )
    assert dependencies.hook_bus is manager.hook_bus
    assert dependencies.token_security is token_security_service
    assert dependencies.logger is manager_logger
    assert dependencies.policy is manager.policy


@dataclass(frozen=True, slots=True)
class _AccountTokenSettings:
    verification_secret: str
    reset_secret: str
    organization_invitation_secret: str
    verification_lifetime: object
    reset_lifetime: object
    organization_invitation_lifetime: object


def _assert_manager_account_token_settings(
    manager: BaseUserManager[Any, Any],
    expected: _AccountTokenSettings,
) -> None:
    """Assert manager account-token secrets and lifetimes are assigned consistently."""
    organization_invitation_secret = manager.organization_invitation_token_secret
    assert organization_invitation_secret is not None
    assert manager.verification_token_secret.get_secret_value() == expected.verification_secret
    assert manager.reset_password_token_secret.get_secret_value() == expected.reset_secret
    assert organization_invitation_secret.get_secret_value() == expected.organization_invitation_secret
    assert manager.account_token_secrets.verification_token_secret is manager.verification_token_secret
    assert manager.account_token_secrets.reset_password_token_secret is manager.reset_password_token_secret
    assert manager.account_token_secrets.organization_invitation_token_secret is organization_invitation_secret
    assert manager.verification_token_lifetime == expected.verification_lifetime
    assert manager.reset_password_token_lifetime == expected.reset_lifetime
    assert manager.organization_invitation_token_lifetime == expected.organization_invitation_lifetime


def _as_any(value: object) -> Any:  # noqa: ANN401
    """Return a value through the test-only dynamic type boundary."""
    return cast("Any", value)


def _fernet_key() -> str:
    """Return a valid Fernet key for manager keyring tests."""
    return Fernet.generate_key().decode()


def test_manager_does_not_reexport_lifecycle_constants() -> None:
    """Lifecycle field allowlists live in the lifecycle service module."""
    assert not hasattr(manager_module, "SAFE_FIELDS")
    assert not hasattr(manager_module, "_PRIVILEGED_FIELDS")


def test_privileged_fields_cover_only_live_privileged_state() -> None:
    """Manager privilege checks use the current role and account-state surface."""
    assert frozenset({"is_active", "is_verified", "roles"}) == PRIVILEGED_FIELDS


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records hook invocations for assertions."""

    def __init__(  # noqa: PLR0913
        self,
        user_db: AsyncMock,
        password_helper: PasswordHelper,
        *,
        password_validator: Callable[[str], None] | None = None,
        reset_verification_on_email_change: bool = True,
        backends: tuple[object, ...] = (),
        login_identifier: Literal["email", "username"] = "email",
        login_identifier_telemetry_secret: str | None = LOGIN_IDENTIFIER_TELEMETRY_SECRET,
        api_key_store: object | None = None,
        api_key_config: ApiKeyConfigProtocol | None = None,
        api_key_hash_secret: str | None = None,
        creatable_fields: frozenset[str] = frozenset({"email", "password"}),
        updatable_fields: frozenset[str] = frozenset({"email", "password"}),
        account_token_denylist_store: object | None = None,
    ) -> None:
        """Initialize the tracking manager with predictable secrets."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret="fedcba9876543210" * 4,
                organization_invitation_token_secret="c4b7e9a13f6d8c2059ab7e3041f8d6e2" * 2,
                login_identifier_telemetry_secret=login_identifier_telemetry_secret,
                api_key_hash_secret=api_key_hash_secret,
                id_parser=UUID,
            ),
            api_key_store=cast("Any", api_key_store),
            api_key_config=api_key_config,
            password_validator=password_validator,
            reset_verification_on_email_change=reset_verification_on_email_change,
            backends=backends,
            login_identifier=login_identifier,
            creatable_fields=creatable_fields,
            updatable_fields=updatable_fields,
            account_token_denylist_store=cast("Any", account_token_denylist_store),
        )
        self.registered_users: list[ExampleUser] = []
        self.registration_events: list[tuple[ExampleUser, str]] = []
        self.duplicate_registration_users: list[ExampleUser] = []
        self.logged_in_users: list[ExampleUser] = []
        self.verified_users: list[ExampleUser] = []
        self.request_verify_events: list[tuple[ExampleUser | None, str | None]] = []
        self.forgot_password_events: list[tuple[ExampleUser | None, str | None]] = []
        self.reset_users: list[ExampleUser] = []
        self.after_update_events: list[tuple[ExampleUser, dict]] = []
        self.before_delete_users: list[ExampleUser] = []
        self.deleted_users: list[ExampleUser] = []
        self.created_api_key_events: list[tuple[ExampleUser, object]] = []
        self.revoked_api_key_events: list[tuple[ExampleUser, object]] = []
        self.used_api_key_events: list[object] = []

    async def on_after_register(self, user: ExampleUser, token: str) -> None:
        """Record a successful registration."""
        self.registered_users.append(user)
        self.registration_events.append((user, token))

    async def on_after_register_duplicate(self, user: ExampleUser) -> None:
        """Record a duplicate registration attempt."""
        self.duplicate_registration_users.append(user)

    async def on_after_login(self, user: ExampleUser) -> None:
        """Record a successful login."""
        self.logged_in_users.append(user)

    async def on_after_verify(self, user: ExampleUser) -> None:
        """Record a successful verification."""
        self.verified_users.append(user)

    async def on_after_request_verify_token(self, user: ExampleUser | None, token: str | None) -> None:
        """Record a verification-token request."""
        self.request_verify_events.append((user, token))

    async def on_after_forgot_password(self, user: ExampleUser | None, token: str | None) -> None:
        """Record a forgot-password request."""
        self.forgot_password_events.append((user, token))

    async def on_after_reset_password(self, user: ExampleUser) -> None:
        """Record a completed password reset."""
        self.reset_users.append(user)

    async def on_after_update(self, user: ExampleUser, update_dict: dict) -> None:
        """Record an update with the applied payload."""
        self.after_update_events.append((user, update_dict))

    async def on_before_delete(self, user: ExampleUser) -> None:
        """Record that delete is about to run (before DB delete)."""
        self.before_delete_users.append(user)

    async def on_after_delete(self, user: ExampleUser) -> None:
        """Record a completed hard delete."""
        self.deleted_users.append(user)

    async def on_after_api_key_created(self, user: ExampleUser, api_key: object) -> None:
        """Record an API-key creation."""
        self.created_api_key_events.append((user, api_key))

    async def on_after_api_key_revoked(self, user: ExampleUser, api_key: object) -> None:
        """Record an API-key revocation."""
        self.revoked_api_key_events.append((user, api_key))

    async def on_after_api_key_used(self, api_key: object) -> None:
        """Record an API-key use write."""
        self.used_api_key_events.append(api_key)


class _StepUpStrategy:
    """Fake server-side step-up strategy with an injectable monotonic clock."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._markers: dict[tuple[object, str], float] = {}

    async def issue_totp_stepup(self, user: ExampleUser, session_id: str, *, ttl_seconds: int) -> None:
        """Record a marker expiry from the fake clock."""
        if ttl_seconds <= 0:
            self._markers.pop((user.id, session_id), None)
            return
        self._markers[user.id, session_id] = self._clock() + ttl_seconds

    async def has_recent_totp_verification(self, user: ExampleUser, session_id: str) -> bool:
        """Return whether the marker has not expired under the fake clock."""
        return self._markers.get((user.id, session_id), 0) > self._clock()


@dataclass(slots=True)
class _StepUpBackend:
    """Backend wrapper exposing the fake strategy via the normal manager seam."""

    strategy: _StepUpStrategy


def _build_user(
    password_helper: PasswordHelper,
    *,
    email: str = "user@example.com",
    username: str = "",
) -> ExampleUser:
    """Return a test user with a hashed password."""
    return ExampleUser(
        id=uuid4(),
        email=email,
        username=username,
        hashed_password=password_helper.hash("test-password"),
    )


async def test_create_hashes_password_and_calls_register_hook() -> None:
    """Creating a user hashes the password before hitting the database."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    created_user = _build_user(password_helper)
    verified_user = replace(created_user, is_verified=True)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user
    user_db.get.return_value = created_user
    user_db.update.return_value = verified_user

    result = await manager.create(UserCreate(email=created_user.email, password="test-password"))

    assert result is created_user
    user_db.get_by_email.assert_awaited_once_with(created_user.email)
    user_db.create.assert_awaited_once()
    create_payload = user_db.create.await_args.args[0]
    assert create_payload["email"] == created_user.email
    assert "password" not in create_payload
    assert create_payload["hashed_password"] != "test-password"
    assert password_helper.verify("test-password", create_payload["hashed_password"]) is True
    assert manager.registered_users == [created_user]
    assert len(manager.registration_events) == 1
    event_user, token = manager.registration_events[0]
    assert event_user is created_user
    assert await manager.verify(token) is verified_user


async def test_create_logs_register_event(caplog: pytest.LogCaptureFixture) -> None:
    """Creating a user logs the registration event with the user identifier only."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    created_user = _build_user(password_helper)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    with caplog.at_level(logging.INFO, logger=manager_logger.name):
        result = await manager.create(UserCreate(email=created_user.email, password="test-password"))

    assert result is created_user
    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["register"]
    assert getattr(caplog.records[0], "user_id", None) == str(created_user.id)
    assert "password" not in caplog.records[0].getMessage().lower()


async def test_hook_bus_subscriber_records_service_dispatched_events_without_subclassing() -> None:
    """Subscribers can observe service lifecycle events without manager subclass hooks."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
    )
    created_user = _build_user(password_helper)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user
    events: list[ManagerHookEvent] = []

    async def record(event: ManagerHookEvent) -> None:
        await asyncio.sleep(0)
        events.append(event)

    unsubscribe = manager.hook_bus.subscribe(record)
    result = await manager.create(UserCreate(email=created_user.email, password="test-password"))
    unsubscribe()

    assert result is created_user
    assert len(events) == 1
    event = events[0]
    assert event.name == "after_register"
    event_user, token = event.args
    assert event_user is created_user
    assert isinstance(token, str)


async def test_create_register_hook_token_is_valid_for_verify_flow() -> None:
    """The post-register hook receives a verification token that can be consumed later."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    created_user = _build_user(password_helper)
    verified_user = replace(created_user, is_verified=True)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user
    user_db.get.return_value = created_user
    user_db.update.return_value = verified_user

    await manager.create(UserCreate(email=created_user.email, password="test-password"))

    assert len(manager.registration_events) == 1
    _, token = manager.registration_events[0]
    result = await manager.verify(token)

    assert result is verified_user
    assert manager.verified_users == [verified_user]

    payload = jwt.decode(
        token,
        manager.verification_token_secret.get_secret_value(),
        algorithms=["HS256"],
        audience=manager_module.VERIFY_TOKEN_AUDIENCE,
    )
    assert isinstance(payload.get("jti"), str)
    assert len(payload["jti"]) == JTI_HEX_LENGTH
    int(payload["jti"], 16)


async def test_create_rejects_duplicate_email() -> None:
    """Creating a duplicate email raises a user-exists error."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user_db.get_by_email.return_value = _build_user(password_helper)

    with pytest.raises(UserAlreadyExistsError):
        await manager.create(UserCreate(email="duplicate@example.com", password="test-password"))


def test_normalize_email_strips_lowercases_and_validates() -> None:
    """Email normalization strips, lowercases, and rejects invalid inputs."""
    assert UserPolicy.normalize_email("  User@Example.COM  ") == "user@example.com"

    with pytest.raises(ValueError, match="Invalid email address"):
        UserPolicy.normalize_email("not-an-email")


def test_normalize_username_lookup_strips_and_lowercases() -> None:
    """Username lookup normalization delegates to the canonical policy helper."""
    assert UserPolicy.normalize_username_lookup("  UserName  ") == "username"


def test_manager_init_requires_explicit_secrets_outside_testing() -> None:
    """Missing secrets should fail fast outside explicit unsafe testing."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.raises(ConfigurationError, match=r'python -c "import secrets; print\(secrets\.token_hex\(32\)\)"'):
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](),
        )


def test_user_manager_security_masks_secret_repr() -> None:
    """The typed security contract must not leak secrets in repr/str output."""
    security = UserManagerSecurity[UUID](
        verification_token_secret="0123456789abcdef" * 4,
        reset_password_token_secret="fedcba9876543210" * 4,
        login_identifier_telemetry_secret=LOGIN_IDENTIFIER_TELEMETRY_SECRET,
        totp_secret_key="89abcdef01234567" * 4,
        id_parser=UUID,
    )

    rendered = repr(security)

    assert "0123456789abcdef" * 4 not in rendered
    assert "fedcba9876543210" * 4 not in rendered
    assert LOGIN_IDENTIFIER_TELEMETRY_SECRET not in rendered
    assert "0123456789abcdef" * 4 not in rendered
    assert "**********" in rendered
    assert "UUID" in rendered
    assert str(security) == rendered


def test_user_manager_security_masks_totp_keyring_repr() -> None:
    """TOTP keyring material stays out of the manager security repr surface."""
    current_key = _fernet_key()
    old_key = _fernet_key()
    security = UserManagerSecurity[UUID](
        verification_token_secret="0123456789abcdef" * 4,
        reset_password_token_secret="fedcba9876543210" * 4,
        totp_secret_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": current_key, "old": old_key}),
        id_parser=UUID,
    )

    rendered = repr(security)

    assert current_key not in rendered
    assert old_key not in rendered
    assert "totp_secret_keyring=FernetKeyringConfig" in rendered
    assert "'current': '***'" in rendered


def test_manager_init_accepts_typed_security_contract() -> None:
    """The public security dataclass wires manager secrets and id parsing in one bundle."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    security = UserManagerSecurity[UUID](
        verification_token_secret="0123456789abcdef" * 4,
        reset_password_token_secret="fedcba9876543210" * 4,
        login_identifier_telemetry_secret=LOGIN_IDENTIFIER_TELEMETRY_SECRET,
        totp_secret_key="89abcdef01234567" * 4,
        id_parser=UUID,
    )

    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=security,
    )

    assert manager.verification_token_secret.get_secret_value() == security.verification_token_secret
    assert manager.reset_password_token_secret.get_secret_value() == security.reset_password_token_secret
    assert manager.login_identifier_telemetry_secret is not None
    assert manager.login_identifier_telemetry_secret.get_secret_value() == security.login_identifier_telemetry_secret
    assert manager.totp_secret_key == security.totp_secret_key
    assert manager.id_parser is UUID


def test_manager_init_accepts_config_object() -> None:
    """BaseUserManager can receive its constructor settings as one typed config."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    security = UserManagerSecurity[UUID](
        verification_token_secret="0123456789abcdef" * 4,
        reset_password_token_secret="fedcba9876543210" * 4,
        login_identifier_telemetry_secret=LOGIN_IDENTIFIER_TELEMETRY_SECRET,
        id_parser=UUID,
    )

    manager = BaseUserManager(
        config=BaseUserManagerConfig(
            user_db=user_db,
            password_helper=password_helper,
            security=security,
            login_identifier="username",
        ),
    )

    assert manager.user_db is user_db
    assert manager.password_helper is password_helper
    assert manager.login_identifier == "username"
    assert manager.id_parser is UUID


async def test_totp_stepup_marker_uses_backend_storage_and_ttl() -> None:
    """The manager facade delegates TOTP step-up state to backend storage."""
    now = 10.0

    def clock() -> float:
        return now

    user_db = AsyncMock()
    password_helper = PasswordHelper()
    strategy = _StepUpStrategy(clock)
    manager = TrackingUserManager(user_db, password_helper, backends=(_StepUpBackend(strategy),))
    user = _build_user(password_helper)

    await manager.issue_totp_stepup_verification(user, "session-1", ttl_seconds=5)

    assert await manager.has_recent_totp_verification(user, "session-1") is True
    now = 15.1
    assert await manager.has_recent_totp_verification(user, "session-1") is False


async def test_totp_stepup_marker_is_absent_without_capable_backend() -> None:
    """Managers without a capable backend do not create in-memory step-up state."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    await manager.issue_totp_stepup_verification(user, "session-1", ttl_seconds=5)

    assert await manager.has_recent_totp_verification(user, "session-1") is False


def test_manager_init_rejects_config_combined_with_user_db_or_options() -> None:
    """BaseUserManager accepts either a config object or the keyword constructor surface."""
    user_db = AsyncMock()
    config = BaseUserManagerConfig(
        user_db=user_db,
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
        ),
    )

    loose_ctor = _as_any(BaseUserManager)

    with pytest.raises(ValueError, match="BaseUserManagerConfig or user_db plus keyword options"):
        loose_ctor(user_db, config=config)

    with pytest.raises(ValueError, match="BaseUserManagerConfig or user_db plus keyword options"):
        loose_ctor(config=config, password_helper=PasswordHelper())


def test_manager_init_requires_user_db_or_config() -> None:
    """BaseUserManager fails loudly when no persistence boundary is provided."""
    loose_ctor = _as_any(BaseUserManager)

    with pytest.raises(TypeError, match="requires user_db or config"):
        loose_ctor()


def test_user_manager_security_rejects_ambiguous_totp_key_inputs() -> None:
    """TOTP encryption config accepts either a single key or a keyring, not both."""
    keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key()})

    with pytest.raises(ConfigurationError, match="totp_secret_key or totp_secret_keyring"):
        UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            totp_secret_key=_fernet_key(),
            totp_secret_keyring=keyring,
        )


def test_manager_init_accepts_totp_keyring_contract() -> None:
    """Direct manager construction can wire a versioned Fernet keyring for TOTP storage."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key(), "old": _fernet_key()})
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            totp_secret_keyring=keyring,
            id_parser=UUID,
        ),
    )

    assert manager.totp_secret_key is None
    assert manager.totp_secret_keyring is keyring
    stored = manager._prepare_totp_secret_for_storage("plain-secret")
    assert stored is not None
    assert stored.startswith("fernet:v1:current:")


def test_manager_init_stores_normalized_superuser_role_name() -> None:
    """The manager exposes the normalized superuser role name used by guards."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    security = UserManagerSecurity[UUID](
        verification_token_secret="0123456789abcdef" * 4,
        reset_password_token_secret="fedcba9876543210" * 4,
    )

    default_manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=security,
    )
    custom_manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=security,
        superuser_role_name=" Admin ",
    )

    assert default_manager.superuser_role_name == "superuser"
    assert custom_manager.superuser_role_name == "admin"


def test_manager_init_rejects_legacy_secret_keyword_arguments() -> None:
    """Standalone verify/reset secret kwargs are not accepted; use ``security=`` only."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    loose_ctor = cast("Callable[..., Any]", BaseUserManager)
    with pytest.raises(TypeError, match="unexpected keyword argument 'verification_token_secret'"):
        loose_ctor(
            user_db,
            password_helper=password_helper,
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
        )


def test_manager_init_rejects_legacy_totp_and_id_parser_keyword_arguments() -> None:
    """``totp_secret_key`` / ``id_parser`` must be passed via ``security=``, not as standalone kwargs."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    loose_ctor = cast("Callable[..., Any]", BaseUserManager)
    with pytest.raises(TypeError, match="unexpected keyword argument 'totp_secret_key'"):
        loose_ctor(
            user_db,
            password_helper=password_helper,
            totp_secret_key="0123456789abcdef" * 4,
            unsafe_testing=True,
        )
    with pytest.raises(TypeError, match="unexpected keyword argument 'id_parser'"):
        loose_ctor(
            user_db,
            password_helper=password_helper,
            id_parser=UUID,
            unsafe_testing=True,
        )


def test_manager_init_no_deprecation_when_only_unsafe_testing_with_default_secret_nones() -> None:
    """Omitted secrets with ``unsafe_testing=True`` use generated fallbacks without deprecation noise."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](),
            unsafe_testing=True,
        )

    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]
    unsafe_testing_warns = [w for w in caught if issubclass(w.category, UserWarning)]
    assert len(unsafe_testing_warns) == EXPECTED_SECRET_FALLBACK_WARNINGS


def test_manager_init_rejects_reused_typed_secret_roles_in_production() -> None:
    """Direct manager construction fails closed when roles reuse one value."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    shared_secret = "shared-manager-secret-role-1234567890"

    with pytest.raises(ConfigurationError, match="Distinct secrets/keys") as exc_info:
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret=shared_secret,
                reset_password_token_secret=shared_secret,
                totp_secret_key=shared_secret,
            ),
        )

    message = str(exc_info.value)
    assert "verification_token_secret" in message
    assert "reset_password_token_secret" in message
    assert "totp_secret_key" in message
    assert manager_module.VERIFY_TOKEN_AUDIENCE in message
    assert RESET_PASSWORD_TOKEN_AUDIENCE in message
    assert "no JWT audience" in message
    assert shared_secret not in message


def test_manager_init_rejects_reused_login_telemetry_secret_in_production() -> None:
    """Failed-login telemetry must not share signing or encryption secret material."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    shared_secret = "shared-manager-secret-role-1234567890"

    with pytest.raises(ConfigurationError, match="Distinct secrets/keys") as exc_info:
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret=shared_secret,
                login_identifier_telemetry_secret=shared_secret,
            ),
        )

    message = str(exc_info.value)
    assert "reset_password_token_secret" in message
    assert "login_identifier_telemetry_secret" in message
    assert shared_secret not in message


def test_manager_init_rejects_reused_organization_invitation_secret_in_production() -> None:
    """Organization invitation tokens must use secret material distinct from account-token roles."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    shared_secret = "shared-manager-secret-role-1234567890"

    with pytest.raises(ConfigurationError, match="Distinct secrets/keys") as exc_info:
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret=shared_secret,
                organization_invitation_token_secret=shared_secret,
            ),
        )

    message = str(exc_info.value)
    assert "reset_password_token_secret" in message
    assert "organization_invitation_token_secret" in message
    assert manager_module.ORGANIZATION_INVITATION_TOKEN_AUDIENCE in message
    assert shared_secret not in message


def test_manager_init_rejects_short_login_telemetry_secret_in_production() -> None:
    """Configured failed-login telemetry secrets must meet the normal secret-length floor."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.raises(ConfigurationError, match="login_identifier_telemetry_secret"):
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret="fedcba9876543210" * 4,
                login_identifier_telemetry_secret="short",
            ),
        )


def test_manager_init_rejects_short_api_key_hash_secret_in_production() -> None:
    """Configured API-key hash secrets must meet the normal secret-length floor."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.raises(ConfigurationError, match="api_key_hash_secret"):
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret="fedcba9876543210" * 4,
                api_key_hash_secret="short",
            ),
        )


def test_manager_init_rejects_reused_totp_keyring_secret_roles_in_production() -> None:
    """Direct manager distinct-role validation checks every configured TOTP keyring value."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    shared_secret = _fernet_key()

    with pytest.raises(ConfigurationError, match="Distinct secrets/keys") as exc_info:
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret=shared_secret,
                reset_password_token_secret="fedcba9876543210" * 4,
                totp_secret_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": shared_secret}),
            ),
        )

    message = str(exc_info.value)
    assert "verification_token_secret" in message
    assert "totp_secret_key" in message
    assert shared_secret not in message


def test_manager_init_allows_reused_secret_roles_under_explicit_unsafe_testing() -> None:
    """Explicit unsafe testing is the only bypass for reused manager-owned secret material."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    shared_secret = "shared-manager-secret-role-1234567890"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        manager = BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret=shared_secret,
                reset_password_token_secret=shared_secret,
                totp_secret_key=shared_secret,
            ),
            unsafe_testing=True,
        )

    assert not [warning for warning in caught if issubclass(warning.category, SecurityWarning)]
    assert manager.verification_token_secret.get_secret_value() == shared_secret
    assert manager.reset_password_token_secret.get_secret_value() == shared_secret
    assert manager.totp_secret_key == shared_secret


def test_manager_init_rejects_mixed_typed_security_and_legacy_secret_kwargs() -> None:
    """Surplus legacy keyword arguments are rejected at the Python level."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    loose_ctor = cast("Callable[..., Any]", BaseUserManager)

    with pytest.raises(TypeError, match="unexpected keyword argument 'verification_token_secret'"):
        loose_ctor(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret="fedcba9876543210" * 4,
            ),
            verification_token_secret="89abcdef01234567" * 4,
        )


def test_manager_init_security_contract_allows_unsafe_testing_fallback() -> None:
    """Explicit unsafe testing still works when callers use the typed security bundle."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.warns(UserWarning, match=r"unsafe_testing=True") as warnings:
        manager = BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](),
            unsafe_testing=True,
        )

    assert len(warnings) == EXPECTED_SECRET_FALLBACK_WARNINGS
    assert manager.verification_token_secret
    assert manager.reset_password_token_secret


def test_manager_init_allows_insecure_fallback_under_explicit_unsafe_testing() -> None:
    """Missing secrets are allowed only when ``unsafe_testing=True`` is set."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.warns(UserWarning, match=r"unsafe_testing=True") as warnings:
        manager = BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](),
            unsafe_testing=True,
        )

    assert len(warnings) == EXPECTED_SECRET_FALLBACK_WARNINGS
    assert manager.verification_token_secret
    assert manager.reset_password_token_secret


def test_manager_init_unsafe_testing_fallback_warning_points_to_caller() -> None:
    """Unsafe-testing fallback warnings should point at the manager instantiation site."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        current_frame = inspect.currentframe()
        assert current_frame is not None
        instantiation_line = current_frame.f_lineno + 1
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](),
            unsafe_testing=True,
        )

    assert len(caught) == EXPECTED_SECRET_FALLBACK_WARNINGS
    assert {warning.filename for warning in caught} == {__file__}
    assert {warning.lineno for warning in caught} == {instantiation_line}


def test_manager_unsafe_testing_generates_distinct_hex_secrets_when_omitted() -> None:
    """Under unsafe testing, omitted secrets resolve to unique ``secrets.token_hex(32)`` values."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.warns(UserWarning, match=r"unsafe_testing=True"):
        first = BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](),
            unsafe_testing=True,
        )
    with pytest.warns(UserWarning, match=r"unsafe_testing=True"):
        second = BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](),
            unsafe_testing=True,
        )

    for mgr in (first, second):
        for secret in (
            mgr.verification_token_secret.get_secret_value(),
            mgr.reset_password_token_secret.get_secret_value(),
        ):
            assert len(secret) == EXPECTED_TOKEN_HEX_32_LEN
            assert all(c in "0123456789abcdef" for c in secret)

    assert first.verification_token_secret.get_secret_value() != second.verification_token_secret.get_secret_value()


def test_secret_value_masks_repr_and_str() -> None:
    """Secret wrapper should never expose the underlying value in text output."""
    secret = _SecretValue("0123456789abcdef" * 4)

    assert secret.get_secret_value() == "0123456789abcdef" * 4
    assert str(secret) == "**********"
    assert repr(secret) == "_SecretValue('**********')"
    assert "0123456789abcdef" * 4 not in repr(secret)


def test_manager_repr_does_not_expose_token_secrets() -> None:
    """Manager text representations must not leak configured token secrets."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
        ),
    )

    assert "0123456789abcdef" * 4 not in repr(manager)
    assert "fedcba9876543210" * 4 not in repr(manager)
    assert "0123456789abcdef" * 4 not in str(manager)
    assert "fedcba9876543210" * 4 not in str(manager)


def test_manager_init_requires_reset_password_secret_when_verification_secret_present() -> None:
    """Missing reset password secret should fail fast when verify secret is provided."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.raises(ConfigurationError, match="reset_password_token_secret not provided"):
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret=None,
            ),
        )


def test_resolve_oauth_account_store_returns_matching_protocol_instance() -> None:
    """OAuth store resolution returns the store only when the structural protocol matches."""

    class DummyOAuthAccountStore:
        async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> ExampleUser | None:
            return None

        async def upsert_oauth_account(
            self,
            user: ExampleUser,
            *,
            account: OAuthAccountData,
        ) -> None:
            pass

    store = DummyOAuthAccountStore()

    assert resolve_oauth_account_store(store) is store
    assert resolve_oauth_account_store(object()) is None


def test_manager_init_wires_services_and_configuration() -> None:
    """Manager initialization should preserve config and wire service collaborators once."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    verification_secret = "0123456789abcdef" * 4
    reset_secret = "fedcba9876543210" * 4
    organization_invitation_secret = "c4b7e9a13f6d8c2059ab7e3041f8d6e2" * 2
    verification_lifetime = manager_module.DEFAULT_VERIFY_TOKEN_LIFETIME * 2
    reset_lifetime = manager_module.DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME * 3
    organization_invitation_lifetime = manager_module.DEFAULT_ORGANIZATION_INVITATION_TOKEN_LIFETIME * 4
    password_validator = require_password_length
    backends = (object(),)
    totp_keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key(), "old": _fernet_key()})
    lifecycle_service = object()
    token_security_service = object()
    account_tokens_service = type("AccountTokensServiceStub", (), {"security": token_security_service})()
    totp_secrets_service = object()

    class DummyOAuthAccountStore:
        async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> ExampleUser | None:
            return None

        async def upsert_oauth_account(
            self,
            user: ExampleUser,
            *,
            account: OAuthAccountData,
        ) -> None:
            pass

    oauth_account_store = DummyOAuthAccountStore()

    with (
        patch.object(manager_module, "UserLifecycleService", return_value=lifecycle_service) as user_lifecycle_service,
        patch.object(
            manager_module,
            "AccountTokenSecurityService",
            return_value=token_security_service,
        ) as account_token_security_service,
        patch.object(manager_module, "AccountTokensService", return_value=account_tokens_service) as account_tokens,
        patch.object(manager_module, "TotpSecretsService", return_value=totp_secrets_service) as totp_secrets,
    ):
        manager = BaseUserManager(
            user_db,
            oauth_account_store=oauth_account_store,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret=verification_secret,
                reset_password_token_secret=reset_secret,
                organization_invitation_token_secret=organization_invitation_secret,
                totp_secret_keyring=totp_keyring,
                id_parser=UUID,
            ),
            verification_token_lifetime=verification_lifetime,
            reset_password_token_lifetime=reset_lifetime,
            organization_invitation_token_lifetime=organization_invitation_lifetime,
            password_validator=password_validator,
            reset_verification_on_email_change=False,
            backends=backends,
            login_identifier="username",
        )

    assert manager.user_db is user_db
    assert manager.oauth_account_store is oauth_account_store
    assert manager.password_helper is password_helper
    _assert_manager_account_token_settings(
        manager,
        _AccountTokenSettings(
            verification_secret=verification_secret,
            reset_secret=reset_secret,
            organization_invitation_secret=organization_invitation_secret,
            verification_lifetime=verification_lifetime,
            reset_lifetime=reset_lifetime,
            organization_invitation_lifetime=organization_invitation_lifetime,
        ),
    )
    assert manager.id_parser is UUID
    assert manager.password_validator is password_validator
    assert manager.reset_verification_on_email_change is False
    assert manager.totp_secret_key is None
    assert manager.totp_secret_keyring is totp_keyring
    assert manager.backends == backends
    assert manager.login_identifier == "username"
    assert manager.policy.password_helper is password_helper
    assert manager.policy.password_validator is password_validator
    assert manager._user_lifecycle is lifecycle_service
    assert manager._account_token_security is token_security_service
    assert manager._account_tokens is account_tokens_service
    assert manager._totp_secrets is totp_secrets_service
    assert manager.users is lifecycle_service
    assert manager.tokens is account_tokens_service
    assert manager.tokens.security is token_security_service
    assert manager.totp is totp_secrets_service
    user_lifecycle_service.assert_called_once_with(manager, hook_bus=manager.hook_bus, policy=manager.policy)
    account_token_security_service.assert_called_once_with(
        manager,
        logger=manager_logger,
        reset_password_token_audience=RESET_PASSWORD_TOKEN_AUDIENCE,
    )
    _assert_account_token_service_dependencies(account_tokens, manager, token_security_service)
    totp_secrets.assert_called_once_with(
        manager,
        prefix=manager_module.ENCRYPTED_TOTP_SECRET_PREFIX,
        active_key_id="current",
        keys=totp_keyring.keys,
        load_cryptography_fernet=manager_module._load_cryptography_fernet,
    )


def test_manager_init_without_explicit_password_helper_uses_current_default_helper() -> None:
    """Omitting password_helper still yields the current Argon2-only default helper."""
    manager = BaseUserManager(
        AsyncMock(),
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
        ),
    )

    assert manager.password_helper is manager.policy.password_helper
    assert len(manager.password_helper.password_hash.hashers) == 1
    assert manager.password_helper.password_hash.hashers[0].__class__.__name__ == "Argon2Hasher"
    assert manager.password_helper.verify("test-password", "not-a-password-hash") is False


def test_manager_init_without_explicit_password_helper_uses_named_default_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The manager default helper path goes through ``PasswordHelper.from_defaults()``."""
    helper = PasswordHelper()

    def build_default(_cls: type[PasswordHelper]) -> PasswordHelper:
        return helper

    monkeypatch.setattr(
        manager_module.PasswordHelper,
        "from_defaults",
        classmethod(build_default),
    )

    manager = BaseUserManager(
        AsyncMock(),
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
        ),
    )

    assert manager.password_helper is helper
    assert manager.policy.password_helper is helper


async def test_create_password_validation_success_and_failure() -> None:
    """Create validates passwords before hashing when a validator is configured."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, password_validator=require_password_length)
    created_user = _build_user(password_helper)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    result = await manager.create(UserCreate(email=created_user.email, password="strong-pass-12"))

    assert result is created_user
    user_db.create.assert_awaited_once()

    with pytest.raises(InvalidPasswordError, match="at least 12 characters"):
        await manager.create(UserCreate(email="user@example.com", password="short"))


async def test_get_delegates_to_user_database() -> None:
    """get() returns the user from the configured user database."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get.return_value = user

    assert await manager.get(user.id) is user
    user_db.get.assert_awaited_once_with(user.id)


async def test_create_defaults_to_safe_and_strips_non_safe_fields() -> None:
    """Default create strips fields outside SAFE_FIELDS before persistence."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    created_user = _build_user(password_helper)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    payload: dict[str, object] = {
        "email": created_user.email,
        "password": "test-password",
        "is_active": False,
        "roles": ["admin"],
    }
    result = await manager.create(payload)

    assert result is created_user
    create_payload = user_db.create.await_args.args[0]
    assert "is_active" not in create_payload
    assert "roles" not in create_payload
    assert "password" not in create_payload
    assert create_payload["email"] == created_user.email


async def test_create_safe_false_rejects_undeclared_fields_by_default() -> None:
    """Unsafe create fails closed on fields outside the manager policy."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    created_user = _build_user(password_helper)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    payload: dict[str, object] = {
        "email": created_user.email,
        "password": "test-password",
        "nickname": "visible",
        "is_active": False,
        "is_verified": True,
        "roles": [" Billing ", "admin", "ADMIN"],
    }
    with pytest.raises(AuthorizationError, match="nickname"):
        await manager.create(payload, safe=False)

    user_db.create.assert_not_awaited()


async def test_create_safe_false_accepts_declared_custom_fields() -> None:
    """Manager-specific create policies opt custom user fields into persistence."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(
        user_db,
        password_helper,
        creatable_fields=frozenset({"email", "password", "nickname"}),
    )
    created_user = _build_user(password_helper)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    payload: dict[str, object] = {
        "email": created_user.email,
        "password": "test-password",
        "nickname": "visible",
        "is_active": False,
        "is_verified": True,
        "roles": [" Billing ", "admin", "ADMIN"],
    }
    result = await manager.create(payload, safe=False)

    assert result is created_user
    create_payload = user_db.create.await_args.args[0]
    assert create_payload["nickname"] == "visible"
    assert PRIVILEGED_FIELDS.isdisjoint(create_payload)
    assert "password" not in create_payload
    assert create_payload["email"] == created_user.email


async def test_create_allow_privileged_true_preserves_current_privilege_fields() -> None:
    """Explicit privileged create preserves the supported role/state fields."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    created_user = _build_user(password_helper)
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    payload: dict[str, object] = {
        "email": created_user.email,
        "password": "test-password",
        "is_active": False,
        "is_verified": True,
        "roles": [" Billing ", "admin", "ADMIN"],
    }
    result = await manager.create(payload, safe=False, allow_privileged=True)

    assert result is created_user
    create_payload = user_db.create.await_args.args[0]
    assert create_payload["is_active"] is False
    assert create_payload["is_verified"] is True
    assert create_payload["roles"] == ["admin", "billing"]
    assert isinstance(create_payload["roles"], list)
    assert "password" not in create_payload
    assert create_payload["email"] == created_user.email


async def test_authenticate_returns_none_for_unknown_email_or_wrong_password() -> None:
    """Authentication does not reveal whether the email or password failed."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    existing_user = _build_user(password_helper)
    user_db.get_by_field.side_effect = [None, existing_user, existing_user]

    assert await manager.authenticate("missing@example.com", "test-password") is None
    assert await manager.authenticate(existing_user.email, "wrong-password") is None

    result = await manager.authenticate(existing_user.email, "test-password")

    assert result is existing_user
    assert manager.logged_in_users == []


async def test_authenticate_upgrades_password_hash_when_deprecated() -> None:
    """Authentication updates the stored hash when a new hash is returned."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    upgraded_user = replace(user, hashed_password="upgraded-hash")
    user_db.get_by_field.return_value = user
    user_db.update.return_value = upgraded_user

    def verify_and_update(_: str, __: str) -> tuple[bool, str | None]:
        return (True, "upgraded-hash")

    with patch.object(password_helper, "verify_and_update", side_effect=verify_and_update):
        result = await manager.authenticate(user.email, "test-password")

    assert result is upgraded_user
    user_db.update.assert_awaited_once_with(user, {"hashed_password": "upgraded-hash"})


async def test_authenticate_logs_password_upgrade_skip_on_update_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Authentication succeeds even when upgrading the stored hash fails."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get_by_field.return_value = user
    user_db.update.side_effect = RuntimeError("db down")

    def verify_and_update(_: str, __: str) -> tuple[bool, str | None]:
        return (True, "upgraded-hash")

    with (
        caplog.at_level(logging.WARNING, logger=manager_logger.name),
        patch.object(password_helper, "verify_and_update", side_effect=verify_and_update),
    ):
        assert await manager.authenticate(user.email, "test-password") is user

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert "password_upgrade_skipped" in events


async def test_authenticate_verifies_dummy_hash_for_unknown_email() -> None:
    """Missing users still trigger password verification against the dummy hash."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user_db.get_by_field.return_value = None

    verify_calls: list[tuple[str, str]] = []

    def record_verify_and_update(password: str, hashed: str) -> tuple[bool, str | None]:
        verify_calls.append((password, hashed))
        return (False, None)

    with patch.object(password_helper, "verify_and_update", side_effect=record_verify_and_update):
        assert await manager.authenticate("missing@example.com", "test-password") is None

    assert len(verify_calls) == 1
    assert verify_calls[0][0] == "test-password"
    assert verify_calls[0][1] == await manager._get_dummy_hash()


def test_manager_module_does_not_hash_dummy_password_at_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reloading the module should not hash a dummy password during import."""
    hash_calls: list[str] = []
    original_hash = PasswordHelper.hash

    def record_hash(self: PasswordHelper, password: str) -> str:
        hash_calls.append(password)
        return original_hash(self, password)

    monkeypatch.setattr(PasswordHelper, "hash", record_hash, raising=True)

    importlib.reload(manager_module)

    assert hash_calls == []
    helper = PasswordHelper()
    dummy_hash = concurrency_module.build_dummy_hash(helper)

    assert isinstance(dummy_hash, str)
    assert len(hash_calls) == 1


async def test_manager_get_dummy_hash_is_offloaded_and_cached_per_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Managers sharing a helper reuse one offloaded dummy hash."""
    password_helper = PasswordHelper()
    first_manager = TrackingUserManager(AsyncMock(), password_helper)
    second_manager = TrackingUserManager(AsyncMock(), password_helper)
    hash_calls: list[PasswordHelper] = []

    def build_dummy_hash(helper: PasswordHelper) -> str:
        hash_calls.append(helper)
        return f"dummy-hash-{len(hash_calls)}"

    run_sync_spy, offloaded = make_run_sync_spy()

    monkeypatch.setattr(concurrency_module, "build_dummy_hash", build_dummy_hash)
    monkeypatch.setattr(concurrency_module, "run_password_op_in_worker_thread", run_sync_spy)

    first = await first_manager._get_dummy_hash()
    second = await first_manager._get_dummy_hash()
    shared = await second_manager._get_dummy_hash()

    assert first == "dummy-hash-1"
    assert first == second
    assert shared == first
    assert hash_calls == [password_helper]
    assert offloaded == ["build_dummy_hash"]


async def test_manager_get_dummy_hash_recomputes_for_new_helper_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replacing the helper identity warms one independent dummy hash."""
    first_helper = PasswordHelper()
    second_helper = PasswordHelper()
    first_manager = TrackingUserManager(AsyncMock(), first_helper)
    second_manager = TrackingUserManager(AsyncMock(), second_helper)
    hash_calls: list[PasswordHelper] = []

    def build_dummy_hash(helper: PasswordHelper) -> str:
        hash_calls.append(helper)
        return f"dummy-hash-{len(hash_calls)}"

    run_sync_spy, _offloaded = make_run_sync_spy()

    monkeypatch.setattr(concurrency_module, "build_dummy_hash", build_dummy_hash)
    monkeypatch.setattr(concurrency_module, "run_password_op_in_worker_thread", run_sync_spy)

    assert await first_manager._get_dummy_hash() == "dummy-hash-1"
    assert await second_manager._get_dummy_hash() == "dummy-hash-2"
    assert await first_manager._get_dummy_hash() == "dummy-hash-1"
    assert await second_manager._get_dummy_hash() == "dummy-hash-2"
    assert hash_calls == [first_helper, second_helper]


async def test_manager_get_dummy_hash_concurrent_cold_misses_allow_duplicate_warmups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent cold lookups may duplicate helper-scoped dummy-hash construction."""
    password_helper = PasswordHelper()
    managers = [TrackingUserManager(AsyncMock(), password_helper) for _ in range(3)]
    hash_calls: list[PasswordHelper] = []
    offloaded: list[str] = []
    all_offloads_started = asyncio.Event()

    def build_dummy_hash(helper: PasswordHelper) -> str:
        hash_calls.append(helper)
        return f"dummy-hash-{len(hash_calls)}"

    async def run_password_op_spy(func: Callable[[PasswordHelper], str], helper: PasswordHelper) -> str:
        call_index = len(offloaded)
        offloaded.append(getattr(func, "__name__", type(func).__name__))
        if len(offloaded) == len(managers):
            all_offloads_started.set()
        await all_offloads_started.wait()
        await asyncio.sleep((len(managers) - call_index) / 1000)
        return func(helper)

    monkeypatch.setattr(concurrency_module, "build_dummy_hash", build_dummy_hash)
    monkeypatch.setattr(concurrency_module, "run_password_op_in_worker_thread", run_password_op_spy)

    async with asyncio.timeout(5), asyncio.TaskGroup() as task_group:
        tasks = [task_group.create_task(manager._get_dummy_hash()) for manager in managers]

    assert sorted(task.result() for task in tasks) == ["dummy-hash-1", "dummy-hash-2", "dummy-hash-3"]
    assert hash_calls == [password_helper] * len(managers)
    assert offloaded == ["build_dummy_hash"] * len(managers)
    assert await managers[0]._get_dummy_hash() == "dummy-hash-3"
    assert offloaded == ["build_dummy_hash"] * len(managers)


def test_get_dummy_hash_returns_valid_password_hash() -> None:
    """The dummy hash helper should return a valid password hash value."""
    password_helper = PasswordHelper()
    dummy_hash = concurrency_module.build_dummy_hash(password_helper)

    assert password_helper.verify("not-the-secret", dummy_hash) is False


def test_login_identifier_digest_normalizes_identifier_and_accepts_long_keys() -> None:
    """Failed-login correlation digests avoid PII and tolerate long operator secrets."""
    long_key = "k" * 200

    digest = manager_module._login_identifier_digest(" User@Example.COM ", key=long_key)

    assert digest == manager_module._login_identifier_digest("user@example.com", key=long_key)
    assert digest != manager_module._login_identifier_digest("other@example.com", key=long_key)
    assert "user@example.com" not in digest


async def test_authenticate_logs_success_and_failure(caplog: pytest.LogCaptureFixture) -> None:
    """Authentication logs successful and failed login events without secrets."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    existing_user = _build_user(password_helper)
    user_db.get_by_field.side_effect = [existing_user, existing_user]

    with caplog.at_level(logging.INFO, logger=manager_logger.name):
        assert await manager.authenticate(existing_user.email, "test-password") is existing_user
        assert await manager.authenticate(existing_user.email, "wrong-password") is None

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["login", "login_failed"]
    assert getattr(caplog.records[0], "user_id", None) == str(existing_user.id)
    failed_record = caplog.records[1]
    assert getattr(failed_record, "login_identifier_type", None) == "email"
    assert getattr(failed_record, "identifier_digest", None) == manager_module._login_identifier_digest(
        existing_user.email,
        key=LOGIN_IDENTIFIER_TELEMETRY_SECRET,
    )
    assert existing_user.email not in failed_record.__dict__.values()
    assert all("token" not in record.getMessage().lower() for record in caplog.records)
    assert all("password" not in record.getMessage().lower() for record in caplog.records)


async def test_authenticate_omits_identifier_digest_without_telemetry_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Failed-login logs stay PII-safe when no dedicated telemetry secret is configured."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, login_identifier_telemetry_secret=None)
    existing_user = _build_user(password_helper)
    user_db.get_by_field.return_value = existing_user

    with caplog.at_level(logging.INFO, logger=manager_logger.name):
        assert await manager.authenticate(existing_user.email, "wrong-password") is None

    failed_record = caplog.records[0]
    assert getattr(failed_record, "event", None) == "login_failed"
    assert getattr(failed_record, "login_identifier_type", None) == "email"
    assert not hasattr(failed_record, "identifier_digest")
    assert existing_user.email not in failed_record.__dict__.values()


async def test_list_users_delegates_to_user_database() -> None:
    """Listing users delegates pagination to the configured user database."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    users = [_build_user(password_helper), _build_user(password_helper, email="second@example.com")]
    user_db.list_users.return_value = (users, 4)

    result = await manager.list_users(offset=2, limit=2)

    assert result == (users, 4)
    user_db.list_users.assert_awaited_once_with(offset=2, limit=2)


async def test_verify_marks_user_verified_and_calls_hook() -> None:
    """Verification decodes the token and persists the verified flag."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    verified_user = replace(user, is_verified=True)
    user_db.get.return_value = user
    user_db.update.return_value = verified_user
    token = manager.write_verify_token(user)

    result = await manager.verify(token)

    assert result is verified_user
    user_db.get.assert_awaited_once_with(user.id)
    user_db.update.assert_awaited_once_with(user, {"is_verified": True})
    assert manager.verified_users == [verified_user]


async def test_verify_rejects_invalid_token() -> None:
    """Malformed verification tokens raise the project token error."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    with pytest.raises(InvalidVerifyTokenError):
        await manager.verify("not-a-valid-token")


async def test_verify_rejects_token_with_wrong_audience() -> None:
    """Verification tokens must include the expected audience."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    token = BaseUserManager._write_token_subject(
        subject=str(uuid4()),
        secret=manager.verification_token_secret.get_secret_value(),
        audience=RESET_PASSWORD_TOKEN_AUDIENCE,
        lifetime=manager.verification_token_lifetime,
    )

    with pytest.raises(InvalidVerifyTokenError):
        await manager.verify(token)


async def test_verify_logs_token_validation_failure(caplog: pytest.LogCaptureFixture) -> None:
    """Invalid manager tokens are logged as validation failures."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    with caplog.at_level(logging.WARNING, logger=manager_logger.name), pytest.raises(InvalidVerifyTokenError):
        await manager.verify("not-a-valid-token")

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["token_validation_failed"]


async def test_verify_rejects_already_verified_user() -> None:
    """Reusing a verification token for an already-verified user raises an error."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    verified_user = replace(user, is_verified=True)
    user_db.get.return_value = verified_user
    token = manager.write_verify_token(user)

    with pytest.raises(InvalidVerifyTokenError, match="already verified"):
        await manager.verify(token)


async def test_request_verify_token_generates_token_for_existing_unverified_user() -> None:
    """Requesting a verify token fires the dedicated hook for eligible users."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get_by_email.return_value = user

    assert await manager.request_verify_token(user.email) is None

    assert len(manager.request_verify_events) == 1
    event_user, token = manager.request_verify_events[0]
    assert event_user is user
    assert isinstance(token, str)


async def test_request_verify_token_hides_missing_and_verified_users() -> None:
    """Requesting a verify token always runs the hook with redacted public data."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    verified_user = replace(_build_user(password_helper), is_verified=True)
    user_db.get_by_email.side_effect = [None, verified_user]

    assert await manager.request_verify_token("missing@example.com") is None
    assert await manager.request_verify_token(verified_user.email) is None

    assert manager.request_verify_events == [(None, None), (None, None)]


async def test_forgot_password_generates_token_and_hides_missing_users() -> None:
    """Forgot-password fires hook for both existing and missing users."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get_by_email.side_effect = [None, user]

    assert await manager.forgot_password("missing@example.com") is None
    assert len(manager.forgot_password_events) == 1
    missing_user, missing_token = manager.forgot_password_events[0]
    assert missing_user is None
    assert missing_token is None

    assert await manager.forgot_password(user.email) is None
    event_user, token = manager.forgot_password_events[-1]
    assert event_user is user
    assert isinstance(token, str)


async def test_forgot_password_uses_dummy_fingerprint_for_missing_users() -> None:
    """Forgot-password performs the same fingerprint work for missing users."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user_db.get_by_email.return_value = None

    with patch.object(
        manager.tokens.security.token_writer,
        "_password_fingerprint",
        wraps=manager.tokens.security.token_writer._password_fingerprint,
    ) as fingerprint:
        assert await manager.forgot_password("missing@example.com") is None

    fingerprint.assert_called_once_with(await manager._get_dummy_hash())
    assert len(manager.forgot_password_events) == 1
    assert manager.forgot_password_events[0] == (None, None)


async def test_forgot_password_uses_real_fingerprint_for_existing_users() -> None:
    """Forgot-password fingerprints the stored password hash for existing users."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get_by_email.return_value = user

    with patch.object(
        manager.tokens.security.token_writer,
        "_password_fingerprint",
        wraps=manager.tokens.security.token_writer._password_fingerprint,
    ) as fingerprint:
        assert await manager.forgot_password(user.email) is None

    fingerprint.assert_called_once_with(user.hashed_password)
    assert len(manager.forgot_password_events) == 1
    assert manager.forgot_password_events[0][0] is user


async def test_create_mixedcase_email_allows_lowercase_login() -> None:
    """Mixed-case registration normalizes email and allows lowercase login."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    created_user = _build_user(password_helper, email="mixedcase@example.com")
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    await manager.create(UserCreate(email="MixedCase@Example.com", password="test-password"))

    user_db.get_by_email.assert_awaited_once_with("mixedcase@example.com")

    user_db.get_by_field.reset_mock()
    user_db.get_by_field.return_value = created_user
    assert await manager.authenticate("mixedcase@example.com", "test-password") is created_user
    user_db.get_by_field.assert_awaited_once_with("email", "mixedcase@example.com")


async def test_authenticate_username_mode_uses_get_by_field() -> None:
    """Username login mode looks up via get_by_field('username', ...) after strip/lower."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, login_identifier="username")
    existing_user = _build_user(password_helper, username="alice")
    user_db.get_by_field.return_value = existing_user

    result = await manager.authenticate("  Alice  ", "test-password")

    assert result is existing_user
    user_db.get_by_field.assert_awaited_once_with("username", "alice")


async def test_authenticate_explicit_login_identifier_overrides_manager_default() -> None:
    """Per-call login_identifier wins over the manager default."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, login_identifier="username")
    existing_user = _build_user(password_helper)
    user_db.get_by_field.return_value = existing_user

    result = await manager.authenticate(existing_user.email, "test-password", login_identifier="email")

    assert result is existing_user
    user_db.get_by_field.assert_awaited_once_with("email", existing_user.email)


@pytest.mark.parametrize(
    ("manager_login_identifier", "call_login_identifier", "expected_mode"),
    [
        pytest.param("email", None, "email", id="manager_default"),
        pytest.param("username", "email", "email", id="per_call_override"),
    ],
)
async def test_authenticate_delegates_to_lifecycle_service_with_effective_mode(
    manager_login_identifier: Literal["email", "username"],
    call_login_identifier: Literal["email", "username"] | None,
    expected_mode: Literal["email", "username"],
) -> None:
    """authenticate() should delegate with the resolved login identifier and dummy hash."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, login_identifier=manager_login_identifier)
    user = _build_user(password_helper)

    with patch.object(manager.users, "authenticate", new=AsyncMock(return_value=user)) as authenticate:
        result = await manager.authenticate("lookup-value", "test-password", login_identifier=call_login_identifier)

    assert result is user
    authenticate.assert_awaited_once_with(
        "lookup-value",
        "test-password",
        login_identifier=expected_mode,
        dummy_hash=await manager._get_dummy_hash(),
        logger=manager_logger,
    )


def test_require_account_state_delegates_to_user_policy() -> None:
    """require_account_state() should remain a thin wrapper over UserPolicy."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    with patch.object(manager_module.UserPolicy, "require_account_state") as require_account_state:
        manager.require_account_state(user, require_verified=True)

    require_account_state.assert_called_once_with(user, require_verified=True)


async def test_reset_password_hashes_new_password_and_calls_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resetting a password replaces the stored hash."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, hashed_password=password_helper.hash("new-password"))
    user_db.get.return_value = user
    user_db.update.return_value = updated_user
    reset_token = manager.tokens.write_reset_password_token(user, dummy_hash=await manager._get_dummy_hash())
    run_sync_spy, offloaded = make_run_sync_spy()

    monkeypatch.setattr("litestar_auth._manager.account_tokens._run_password_op", run_sync_spy)

    result = await manager.reset_password(reset_token, "new-password")

    assert result is updated_user
    assert offloaded == ["hash"]
    user_db.update.assert_awaited_once()
    update_payload = user_db.update.await_args.args[1]
    assert update_payload["hashed_password"] != "new-password"
    assert password_helper.verify("new-password", update_payload["hashed_password"]) is True
    assert manager.reset_users == [updated_user]


async def test_reset_password_consumes_jti_and_rejects_replay() -> None:
    """A configured denylist makes reset-password tokens single-use server-side (VULN-3)."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, account_token_denylist_store=InMemoryJWTDenylistStore())
    user = _build_user(password_helper)
    updated_user = replace(user, hashed_password=password_helper.hash("new-password"))
    # user_db.get returns the *unchanged* user on replay, so the password fingerprint still
    # matches: any rejection on the second call is the jti denylist, not fingerprint rotation.
    user_db.get.return_value = user
    user_db.update.return_value = updated_user
    reset_token = manager.tokens.write_reset_password_token(user, dummy_hash=await manager._get_dummy_hash())

    assert await manager.reset_password(reset_token, "new-password") is updated_user

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager.reset_password(reset_token, "another-password")


async def test_verify_consumes_jti_and_rejects_replay() -> None:
    """A configured denylist makes verification tokens single-use server-side (VULN-3)."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, account_token_denylist_store=InMemoryJWTDenylistStore())
    user = _build_user(password_helper)
    verified_user = replace(user, is_verified=True)
    # user_db.get keeps returning the unverified user, so the "already verified" guard never
    # fires on replay: the second-call rejection is the jti denylist.
    user_db.get.return_value = user
    user_db.update.return_value = verified_user
    token = manager.write_verify_token(user)

    assert await manager.verify(token) is verified_user

    with pytest.raises(InvalidVerifyTokenError):
        await manager.verify(token)


async def test_reset_password_rejects_invalid_token() -> None:
    """Malformed reset-password tokens raise the project token error."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager.reset_password("not-a-valid-token", "new-password")


async def test_reset_password_rejects_token_with_wrong_audience() -> None:
    """Reset-password tokens must include the expected audience."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    token = BaseUserManager._write_token_subject(
        subject=str(uuid4()),
        secret=manager.reset_password_token_secret.get_secret_value(),
        audience="litestar-auth:verify",
        lifetime=manager.reset_password_token_lifetime,
    )

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager.reset_password(token, "new-password")


async def test_reset_password_rejects_weak_password_before_hashing() -> None:
    """Reset-password validation runs before hashing when configured."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, password_validator=require_password_length)
    user = _build_user(password_helper)
    user_db.get.return_value = user
    reset_token = manager.tokens.write_reset_password_token(user, dummy_hash=await manager._get_dummy_hash())

    with pytest.raises(InvalidPasswordError, match="at least 12 characters"):
        await manager.reset_password(reset_token, "short")

    user_db.update.assert_not_awaited()


async def test_verify_and_account_token_flows_delegate_to_account_tokens_service() -> None:
    """Thin wrapper methods should delegate to the account-tokens service with stable arguments."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    expected_user = _build_user(password_helper)

    with (
        patch.object(manager.tokens, "verify", new=AsyncMock(return_value=expected_user)) as verify,
        patch.object(manager.tokens, "request_verify_token", new=AsyncMock()) as request_verify_token,
        patch.object(manager.tokens, "forgot_password", new=AsyncMock()) as forgot_password,
        patch.object(
            manager.tokens,
            "reset_password",
            new=AsyncMock(return_value=expected_user),
        ) as reset_password,
    ):
        assert await manager.verify("verify-token") is expected_user
        assert await manager.request_verify_token("user@example.com") is None
        assert await manager.forgot_password("user@example.com") is None
        assert await manager.reset_password("reset-token", "new-password") is expected_user

    verify.assert_awaited_once_with("verify-token")
    request_verify_token.assert_awaited_once_with("user@example.com")
    forgot_password.assert_awaited_once_with("user@example.com", dummy_hash=await manager._get_dummy_hash())
    reset_password.assert_awaited_once_with("reset-token", "new-password")


async def test_forgot_password_token_includes_password_fingerprint() -> None:
    """Reset-password token from forgot_password includes password_fingerprint in JWT payload."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get_by_email.return_value = user

    await manager.forgot_password(user.email)

    assert len(manager.forgot_password_events) == 1
    _, token = manager.forgot_password_events[0]
    assert token is not None
    payload = jwt.decode(
        token,
        manager.reset_password_token_secret.get_secret_value(),
        algorithms=["HS256"],
        audience=RESET_PASSWORD_TOKEN_AUDIENCE,
    )
    assert "password_fingerprint" in payload
    assert isinstance(payload["password_fingerprint"], str)
    assert isinstance(payload.get("jti"), str)
    assert len(payload["jti"]) == JTI_HEX_LENGTH
    int(payload["jti"], 16)


async def test_reset_password_token_valid_before_password_change() -> None:
    """Reset-password token issued by forgot_password is valid until password is changed."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, hashed_password=password_helper.hash("new-password"))
    user_db.get_by_email.return_value = user
    user_db.get.return_value = user
    user_db.update.return_value = updated_user

    await manager.forgot_password(user.email)
    _, token = manager.forgot_password_events[0]
    assert token is not None
    result = await manager.reset_password(token, "new-password")

    assert result is updated_user
    user_db.update.assert_awaited_once()


async def test_reset_password_token_invalid_after_password_change() -> None:
    """Reset-password token is invalid after the user's password has been changed."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get_by_email.return_value = user
    await manager.forgot_password(user.email)
    _, token = manager.forgot_password_events[0]
    assert token is not None

    changed_user = replace(
        user,
        hashed_password=password_helper.hash("other-password"),
    )
    user_db.get.return_value = changed_user

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager.reset_password(token, "new-password")

    user_db.update.assert_not_awaited()


def test_on_after_forgot_password_docstring_mentions_background_tasks() -> None:
    """Forgot-password hook docs advise moving external I/O off the request path."""
    docstring = BaseUserManager.on_after_forgot_password.__doc__

    assert docstring is not None
    assert "background task" in docstring.lower()


def test_on_after_register_duplicate_docstring_mentions_timing_oracle() -> None:
    """Duplicate-register hook docs warn against request-path external I/O."""
    docstring = BaseUserManager.on_after_register_duplicate.__doc__

    assert docstring is not None
    assert "timing oracle" in docstring.lower()


def test_require_password_length_allows_minimum_length() -> None:
    """The built-in validator accepts passwords that meet the minimum length."""
    require_password_length("123456789012")


def test_require_password_length_rejects_password_longer_than_maximum() -> None:
    """The built-in validator rejects passwords longer than the maximum length."""
    with pytest.raises(ValueError, match="at most 128 characters"):
        require_password_length("p" * 129)


def test_require_password_length_rejects_password_shorter_than_minimum() -> None:
    """The built-in validator rejects passwords shorter than the minimum length."""
    with pytest.raises(ValueError, match="at least 12 characters"):
        require_password_length("short")


async def test_update_returns_original_user_when_no_changes() -> None:
    """update() returns the original user when there are no non-None fields."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    result = await manager.update(UserUpdate(), user)

    assert result is user
    user_db.update.assert_not_awaited()


async def test_update_email_change_resets_verification_and_requests_new_token() -> None:
    """Changing email clears verification and triggers the verify-token hook by default."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = replace(_build_user(password_helper), is_verified=True)
    existing_other_user = _build_user(password_helper, email="taken@example.com")
    updated_user = ExampleUser(
        id=user.id,
        email="updated@example.com",
        hashed_password=password_helper.hash("new-password"),
        is_active=True,
        is_verified=False,
    )
    user_db.get_by_email.side_effect = [existing_other_user, None]
    user_db.update.return_value = updated_user

    with pytest.raises(UserAlreadyExistsError):
        await manager.update(UserUpdate(email="taken@example.com"), user)

    result = await manager.update(
        AdminUserUpdate(email="updated@example.com", password="new-password"),
        user,
    )

    assert result is updated_user
    user_db.update.assert_awaited_once()
    update_payload = user_db.update.await_args.args[1]
    assert update_payload["email"] == "updated@example.com"
    assert update_payload["is_verified"] is False
    assert update_payload["hashed_password"] != "new-password"
    assert "password" not in update_payload
    assert password_helper.verify("new-password", update_payload["hashed_password"]) is True
    assert len(manager.request_verify_events) == 1
    event_user, token = manager.request_verify_events[0]
    assert event_user is updated_user
    assert isinstance(token, str)


async def test_update_email_change_respects_reset_verification_flag() -> None:
    """Opting out keeps the previous verification state and skips the verify-token hook."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(
        user_db,
        password_helper,
        reset_verification_on_email_change=False,
    )
    user = replace(_build_user(password_helper), is_verified=True)
    updated_user = replace(user, email="updated@example.com")
    user_db.get_by_email.return_value = None
    user_db.update.return_value = updated_user

    result = await manager.update(UserUpdate(email="updated@example.com"), user)

    assert result is updated_user
    user_db.update.assert_awaited_once_with(user, {"email": "updated@example.com"})
    assert manager.request_verify_events == []


async def test_update_calls_on_after_update_with_correct_arguments() -> None:
    """Explicit privileged updates still call on_after_update with the applied payload."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, is_active=False)
    user_db.update.return_value = updated_user

    result = await manager.update(AdminUserUpdate(is_active=False), user, allow_privileged=True)

    assert result is updated_user
    assert len(manager.after_update_events) == 1
    event_user, event_dict = manager.after_update_events[0]
    assert event_user is updated_user
    assert event_dict == {"is_active": False}


async def test_update_rejects_privileged_fields_without_explicit_opt_in() -> None:
    """Privileged manager updates fail closed unless the caller opts in explicitly."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    with pytest.raises(AuthorizationError, match="allow_privileged=True"):
        await manager.update(AdminUserUpdate(is_active=False), user)

    user_db.update.assert_not_awaited()
    assert manager.after_update_events == []


async def test_update_rejects_undeclared_fields_by_default() -> None:
    """Manager updates fail closed on non-privileged fields outside the policy."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    with pytest.raises(AuthorizationError, match="nickname"):
        await manager.update({"nickname": "visible"}, user)

    user_db.update.assert_not_awaited()
    assert manager.after_update_events == []


async def test_update_accepts_declared_custom_fields() -> None:
    """Manager-specific update policies opt custom user fields into persistence."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(
        user_db,
        password_helper,
        updatable_fields=frozenset({"email", "password", "nickname"}),
    )
    user = _build_user(password_helper)
    updated_user = replace(user)
    user_db.update.return_value = updated_user

    result = await manager.update({"nickname": "visible"}, user)

    assert result is updated_user
    user_db.update.assert_awaited_once_with(user, {"nickname": "visible"})
    assert manager.after_update_events == [(updated_user, {"nickname": "visible"})]


async def test_update_normalizes_roles_from_mapping_payload() -> None:
    """Explicit privileged mapping updates still normalize roles before persistence."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user)
    user_db.update.return_value = updated_user

    result = await manager.update(
        {"roles": [" Support ", "admin", "ADMIN"]},
        user,
        allow_privileged=True,
    )

    assert result is updated_user
    user_db.update.assert_awaited_once_with(user, {"roles": ["admin", "support"]})
    assert manager.after_update_events == [(updated_user, {"roles": ["admin", "support"]})]


async def test_update_normalizes_roles_from_builtin_update_schema() -> None:
    """Explicit privileged DTO updates preserve the normalized ``list[str]`` role contract."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user)
    user_db.update.return_value = updated_user

    result = await manager.update(
        AdminUserUpdate(roles=[" Support ", "admin", "ADMIN"]),
        user,
        allow_privileged=True,
    )

    assert result is updated_user
    user_db.update.assert_awaited_once_with(user, {"roles": ["admin", "support"]})
    assert manager.after_update_events == [(updated_user, {"roles": ["admin", "support"]})]


async def test_update_rejects_weak_password_before_hashing() -> None:
    """update() validates new passwords and rejects weak values before persistence."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper, password_validator=require_password_length)
    user = _build_user(password_helper)

    with pytest.raises(InvalidPasswordError, match="at least 12 characters"):
        await manager.update(AdminUserUpdate(password="short"), user)

    user_db.update.assert_not_awaited()
    assert manager.after_update_events == []


async def test_delete_removes_user_and_calls_hook() -> None:
    """Hard deletes delegate to the database and run the post-delete hook."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get.return_value = user

    delete_result = await manager.delete(user.id)
    assert delete_result is None

    user_db.get.assert_awaited_once_with(user.id)
    assert manager.before_delete_users == [user]
    user_db.delete.assert_awaited_once_with(user.id)
    assert manager.deleted_users == [user]


async def test_delete_rejects_missing_users() -> None:
    """Hard delete raises when the requested user does not exist."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    missing_user_id = uuid4()
    user_db.get.return_value = None

    with pytest.raises(UserNotExistsError):
        await manager.delete(missing_user_id)

    user_db.delete.assert_not_awaited()
    assert manager.deleted_users == []


async def test_on_before_delete_exception_cancels_deletion() -> None:
    """When on_before_delete raises, the user is not deleted and on_after_delete is not run."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    class CancelDeleteManager(TrackingUserManager):
        """Raises in on_before_delete to cancel deletion."""

        async def on_before_delete(self, user: ExampleUser) -> None:
            await super().on_before_delete(user)
            msg = "cancel delete"
            raise ValueError(msg)

    manager = CancelDeleteManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get.return_value = user

    with pytest.raises(ValueError, match="cancel delete"):
        await manager.delete(user.id)

    assert manager.before_delete_users == [user]
    user_db.delete.assert_not_awaited()
    assert manager.deleted_users == []


@pytest.mark.parametrize(
    "decode_payload",
    [pytest.param({"sub": ""}, id="empty_subject"), pytest.param({"sub": "not-a-uuid"}, id="unparseable_subject")],
)
async def test_reset_password_rejects_invalid_token_subject(
    monkeypatch: pytest.MonkeyPatch,
    decode_payload: dict,
) -> None:
    """reset_password rejects tokens that decode without a usable subject."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    monkeypatch.setattr(manager._account_token_security, "decode_token", lambda *_args, **_kwargs: decode_payload)
    with pytest.raises(InvalidResetPasswordTokenError):
        await manager.reset_password("token", "new-password")


async def test_reset_password_raises_invalid_token_when_subject_user_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """reset_password normalizes missing users into an invalid-token error."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user_db.get.return_value = None
    user_id = uuid4()

    monkeypatch.setattr(
        manager._account_token_security,
        "decode_token",
        lambda *_args, **_kwargs: {"sub": str(user_id)},
    )
    with pytest.raises(InvalidResetPasswordTokenError):
        await manager.reset_password("token", "new-password")


async def test_get_user_and_payload_from_token_raises_user_not_exists_error() -> None:
    """Token security raises when the token resolves to a missing user."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user_db.get.return_value = None
    token = BaseUserManager._write_token_subject(
        subject=str(uuid4()),
        secret=manager.verification_token_secret.get_secret_value(),
        audience=manager_module.VERIFY_TOKEN_AUDIENCE,
        lifetime=manager.verification_token_lifetime,
    )

    with pytest.raises(UserNotExistsError):
        await manager.tokens.security.get_user_and_payload_from_token(
            token,
            secret=manager.verification_token_secret.get_secret_value(),
            audience=manager_module.VERIFY_TOKEN_AUDIENCE,
            invalid_token_error=InvalidVerifyTokenError,
            user_db=manager.user_db,
        )


async def test_public_token_services_delegate_to_account_token_security_service() -> None:
    """Public token facades remain thin layers over the extracted token-security service."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    expected_user = _build_user(password_helper)
    expected_user_id = uuid4()

    with (
        patch.object(manager.tokens.security.token_writer, "write", return_value="signed-token") as write_token,
        patch.object(
            manager.tokens.security,
            "get_user_and_payload_from_token",
            new=AsyncMock(return_value=(expected_user, {})),
        ) as get_user_and_payload_from_token,
        patch.object(
            manager.tokens.security,
            "read_token_subject",
            return_value=expected_user_id,
        ) as read_token_subject,
    ):
        written = manager.tokens.write_user_token(
            expected_user,
            secret=manager.verification_token_secret.get_secret_value(),
            audience=manager_module.VERIFY_TOKEN_AUDIENCE,
            lifetime=manager.verification_token_lifetime,
        )
        resolved_user, _payload = await manager.tokens.security.get_user_and_payload_from_token(
            "signed-token",
            secret=manager.verification_token_secret.get_secret_value(),
            audience=manager_module.VERIFY_TOKEN_AUDIENCE,
            invalid_token_error=InvalidVerifyTokenError,
            user_db=manager.user_db,
        )
        resolved_user_id = manager.tokens.security.read_token_subject(
            "signed-token",
            secret=manager.verification_token_secret.get_secret_value(),
            audience=manager_module.VERIFY_TOKEN_AUDIENCE,
            invalid_token_error=InvalidVerifyTokenError,
        )

    assert written == "signed-token"
    assert resolved_user is expected_user
    assert resolved_user_id is expected_user_id
    write_token.assert_called_once_with(
        account_tokens_module.TokenWriteRequest(
            subject=str(expected_user.id),
            secret=manager.verification_token_secret.get_secret_value(),
            audience=manager_module.VERIFY_TOKEN_AUDIENCE,
            lifetime=manager.verification_token_lifetime,
        ),
        password_fingerprint_source=expected_user.hashed_password,
    )
    get_user_and_payload_from_token.assert_awaited_once_with(
        "signed-token",
        user_db=manager.user_db,
        secret=manager.verification_token_secret.get_secret_value(),
        audience=manager_module.VERIFY_TOKEN_AUDIENCE,
        invalid_token_error=InvalidVerifyTokenError,
    )
    read_token_subject.assert_called_once_with(
        "signed-token",
        secret=manager.verification_token_secret.get_secret_value(),
        audience=manager_module.VERIFY_TOKEN_AUDIENCE,
        invalid_token_error=InvalidVerifyTokenError,
    )


def test_read_token_rejects_payload_without_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    """Token security rejects payloads missing the subject string."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    monkeypatch.setattr(manager.tokens.security, "decode_token", lambda *_args, **_kwargs: {"sub": ""})
    with pytest.raises(InvalidVerifyTokenError):
        manager.tokens.security.read_token_subject(
            "token",
            secret=manager.verification_token_secret.get_secret_value(),
            audience=manager_module.VERIFY_TOKEN_AUDIENCE,
            invalid_token_error=InvalidVerifyTokenError,
        )


def test_read_token_rejects_unparseable_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    """Token security rejects payloads whose subject cannot be parsed by id_parser."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    monkeypatch.setattr(
        manager.tokens.security,
        "decode_token",
        lambda *_args, **_kwargs: {"sub": "not-a-uuid"},
    )
    with pytest.raises(InvalidVerifyTokenError):
        manager.tokens.security.read_token_subject(
            "token",
            secret=manager.verification_token_secret.get_secret_value(),
            audience=manager_module.VERIFY_TOKEN_AUDIENCE,
            invalid_token_error=InvalidVerifyTokenError,
        )


def test_as_dict_accepts_mapping() -> None:
    """_as_dict returns a plain dict for mapping inputs."""
    assert _as_dict({"email": "user@example.com"}) == {"email": "user@example.com"}


@pytest.mark.parametrize("data", [{}, {"email": 123}], ids=["missing_field", "non_string_value"])
def test_require_str_raises_when_field_missing_or_not_string(data: dict) -> None:
    """_require_str rejects missing fields and non-string values."""
    with pytest.raises(TypeError, match="email must be a string"):
        _require_str(data, "email")


def test_managed_user_and_account_state_user_accept_protocol_compatible_users() -> None:
    """Internal coercion helpers should preserve access to manager-required fields."""
    password_helper = PasswordHelper()
    user = _build_user(password_helper)

    assert _managed_user(user).hashed_password == user.hashed_password
    assert _account_state_user(user).is_active is user.is_active


def test_validate_password_propagates_invalid_password_error() -> None:
    """policy.validate_password should not wrap InvalidPasswordError from a validator."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    def raise_invalid(_: str) -> None:
        msg = "nope"
        raise InvalidPasswordError(message=msg)

    manager = TrackingUserManager(user_db, password_helper, password_validator=raise_invalid)
    with pytest.raises(InvalidPasswordError, match="nope"):
        manager.policy.validate_password("any-password")


async def test_invalidate_all_tokens_skips_when_no_backends() -> None:
    """_invalidate_all_tokens is a no-op when the manager has no backends."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    assert await manager._invalidate_all_tokens(user) is None


async def test_invalidate_all_tokens_calls_backend_strategies() -> None:
    """_invalidate_all_tokens only dispatches to strategies matching the protocol."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    invalidate_one = AsyncMock()
    invalidate_two = AsyncMock()

    @dataclass(slots=True)
    class Backend:
        strategy: object

    valid_strategy_one = type("S1", (), {"invalidate_all_tokens": invalidate_one})()
    valid_strategy_two = type("S2", (), {"invalidate_all_tokens": invalidate_two})()
    invalid_strategy = object()

    assert isinstance(valid_strategy_one, TokenInvalidationCapable)
    assert isinstance(valid_strategy_two, TokenInvalidationCapable)
    assert not isinstance(invalid_strategy, TokenInvalidationCapable)

    manager.backends = (
        Backend(strategy=valid_strategy_one),
        Backend(strategy=valid_strategy_two),
        Backend(strategy=invalid_strategy),
        object(),
    )

    await manager._invalidate_all_tokens(user)

    invalidate_one.assert_awaited_once_with(user)
    invalidate_two.assert_awaited_once_with(user)


async def test_set_totp_secret_requires_key_for_non_null_secret() -> None:
    """set_totp_secret fails closed instead of storing plaintext without a key."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)

    with pytest.raises(RuntimeError, match="totp_secret_key is required"):
        await manager.set_totp_secret(user, "plain-secret")

    user_db.update.assert_not_awaited()


async def test_totp_secret_helpers_delegate_to_totp_service() -> None:
    """TOTP helper methods should delegate to the constructor-bound TotpSecretsService."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, totp_secret="encrypted")

    with (
        patch.object(manager.totp, "set_secret", new=AsyncMock(return_value=updated_user)) as set_secret,
        patch.object(manager.totp, "read_secret", new=AsyncMock(return_value="plain-secret")) as read_secret,
        patch.object(manager.totp, "requires_reencrypt", return_value=True) as requires_reencrypt,
        patch.object(manager.totp, "reencrypt_secret_for_storage", return_value="rewritten-secret") as reencrypt_secret,
    ):
        assert await manager.set_totp_secret(user, None) is updated_user
        assert await manager.read_totp_secret("encrypted-value") == "plain-secret"
        assert manager.totp_secret_requires_reencrypt("encrypted-value") is True
        assert manager.reencrypt_totp_secret_for_storage("encrypted-value") == "rewritten-secret"

    set_secret.assert_awaited_once_with(user, None)
    read_secret.assert_awaited_once_with("encrypted-value")
    requires_reencrypt.assert_called_once_with("encrypted-value")
    reencrypt_secret.assert_called_once_with("encrypted-value")


async def test_recovery_code_hash_helpers_delegate_to_user_store() -> None:
    """TOTP recovery-code lookup-index helper methods delegate to the persistence store."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    code_index = {"lookup-1": "hash-1", "lookup-2": "hash-2"}
    updated_user = replace(user, recovery_codes=code_index)
    user_db.set_recovery_code_hashes.return_value = updated_user
    user_db.find_recovery_code_hash_by_lookup.return_value = "hash-1"
    user_db.consume_recovery_code_by_lookup.return_value = True

    assert await manager.set_recovery_code_hashes(user, code_index) is updated_user
    assert await manager.find_recovery_code_hash_by_lookup(user, "lookup-1") == "hash-1"
    assert await manager.consume_recovery_code_by_lookup(user, "lookup-1") is True

    user_db.set_recovery_code_hashes.assert_awaited_once_with(user, code_index)
    user_db.find_recovery_code_hash_by_lookup.assert_awaited_once_with(user, "lookup-1")
    user_db.consume_recovery_code_by_lookup.assert_awaited_once_with(user, "lookup-1")


def test_recovery_code_lookup_secret_returns_none_when_unconfigured() -> None:
    """Managers without TOTP recovery-code lookup material expose no lookup secret."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    assert manager.recovery_code_lookup_secret is None


async def test_read_totp_secret_requires_key_when_encrypted() -> None:
    """Encrypted secrets require totp_secret_key to decrypt."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    with pytest.raises(RuntimeError, match="totp_secret_key"):
        await manager.read_totp_secret(f"{manager_module.ENCRYPTED_TOTP_SECRET_PREFIX}encrypted")


async def test_read_totp_secret_returns_none_when_totp_disabled() -> None:
    """Missing TOTP secrets still read as disabled."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)

    assert await manager.read_totp_secret(None) is None


async def test_read_totp_secret_rejects_unprefixed_plaintext_value() -> None:
    """Non-null TOTP secrets must use the encrypted storage prefix."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    manager.totp_secret_key = "89abcdef01234567" * 4

    with pytest.raises(RuntimeError, match="encrypted at rest"):
        await manager.read_totp_secret("plain")


async def test_read_totp_secret_raises_when_decryption_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decryption failures are surfaced as RuntimeError with a stable message."""

    class FakeInvalidTokenError(Exception):
        pass

    class FakeFernet:
        def __init__(self, _: bytes) -> None:
            pass

        def decrypt(self, _: bytes) -> bytes:
            raise FakeInvalidTokenError

    fake_module = type("FakeFernetModule", (), {"Fernet": FakeFernet, "InvalidToken": FakeInvalidTokenError})()
    monkeypatch.setattr(totp_facade_module, "_load_cryptography_fernet", lambda: fake_module)
    monkeypatch.setattr(manager_module, "_load_cryptography_fernet", lambda: fake_module)
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    manager.totp_secret_key = "89abcdef01234567" * 4

    with pytest.raises(RuntimeError, match="TOTP secret decryption failed"):
        await manager.read_totp_secret(f"{manager_module.ENCRYPTED_TOTP_SECRET_PREFIX}v1:default:encrypted")


def test_prepare_totp_secret_encrypts_and_prefixes_when_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Encrypted TOTP storage prefixes values and uses Fernet.encrypt()."""

    class FakeFernet:
        def __init__(self, _: bytes) -> None:
            pass

        def encrypt(self, _: bytes) -> bytes:
            return b"encrypted-value"

    fake_module = type("FakeFernetModule", (), {"Fernet": FakeFernet, "InvalidToken": Exception})()
    monkeypatch.setattr(totp_facade_module, "_load_cryptography_fernet", lambda: fake_module)
    monkeypatch.setattr(manager_module, "_load_cryptography_fernet", lambda: fake_module)
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    manager.totp_secret_key = "89abcdef01234567" * 4

    stored = manager._prepare_totp_secret_for_storage("secret")
    assert stored == f"{manager_module.ENCRYPTED_TOTP_SECRET_PREFIX}v1:default:encrypted-value"

    stored_via_service = manager.totp.prepare_secret_for_storage("secret")
    assert stored_via_service == f"{manager_module.ENCRYPTED_TOTP_SECRET_PREFIX}v1:default:encrypted-value"


def test_load_cryptography_fernet_raises_with_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Optional TOTP encryption import errors include an extras install hint."""
    monkeypatch.setattr(
        optional_deps_module.importlib,
        "import_module",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ImportError),
    )
    with pytest.raises(ImportError, match=r"Install litestar-auth\[totp\]"):
        totp_facade_module._load_cryptography_fernet()


async def test_base_hooks_are_noops() -> None:
    """Base hooks are safe no-ops and accept the required parameters."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
    )
    user = _build_user(password_helper)

    assert await manager.on_after_register(user, "token") is None
    assert await manager.on_after_register_duplicate(user) is None
    assert await manager.on_after_login(user) is None
    assert await manager.on_after_verify(user) is None
    assert await manager.on_after_request_verify_token(user, "token") is None
    assert await manager.on_after_request_verify_token(None, None) is None
    assert await manager.on_after_forgot_password(user, "token") is None
    assert await manager.on_after_reset_password(user) is None
    assert await manager.on_after_update(user, {"email": user.email}) is None
    assert await manager.on_before_delete(user) is None
    assert await manager.on_after_delete(user) is None
    assert await manager.on_after_api_key_created(user, object()) is None
    assert await manager.on_after_api_key_revoked(user, object()) is None
    assert await manager.on_after_api_key_used(object()) is None


async def test_hook_bus_fires_named_events_with_argument_shapes() -> None:
    """Hook bus subscribers receive canonical names and positional hook arguments."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
    )
    user = _build_user(password_helper)
    api_key = object()
    update_dict = {"email": user.email}
    events: list[ManagerHookEvent] = []

    async def record(event: ManagerHookEvent) -> None:
        await asyncio.sleep(0)
        events.append(event)

    manager.hook_bus.subscribe(record)

    await manager.hook_bus.fire("after_register", user, "verify-token")
    await manager.hook_bus.fire("after_register_duplicate", user)
    await manager.hook_bus.fire("after_login", user)
    await manager.hook_bus.fire("after_verify", user)
    await manager.hook_bus.fire("after_request_verify_token", user, "verify-token")
    await manager.hook_bus.fire("after_forgot_password", None, None)
    await manager.hook_bus.fire("after_reset_password", user)
    await manager.hook_bus.fire("after_update", user, update_dict)
    await manager.hook_bus.fire("before_delete", user)
    await manager.hook_bus.fire("after_delete", user)
    await manager.hook_bus.fire("after_api_key_created", user, api_key)
    await manager.hook_bus.fire("after_api_key_revoked", user, api_key)
    await manager.hook_bus.fire("after_api_key_used", api_key)

    assert [(event.name, event.args) for event in events] == [
        ("after_register", (user, "verify-token")),
        ("after_register_duplicate", (user,)),
        ("after_login", (user,)),
        ("after_verify", (user,)),
        ("after_request_verify_token", (user, "verify-token")),
        ("after_forgot_password", (None, None)),
        ("after_reset_password", (user,)),
        ("after_update", (user, update_dict)),
        ("before_delete", (user,)),
        ("after_delete", (user,)),
        ("after_api_key_created", (user, api_key)),
        ("after_api_key_revoked", (user, api_key)),
        ("after_api_key_used", (api_key,)),
    ]


def test_require_account_state_raises_for_inactive_user() -> None:
    """Account-state policy rejects inactive users."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = replace(_build_user(password_helper), is_active=False)

    with pytest.raises(InactiveUserError):
        manager.require_account_state(user)


def test_require_account_state_raises_for_unverified_when_required() -> None:
    """Account-state policy rejects unverified users when verification is required."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = replace(_build_user(password_helper), is_verified=False)

    with pytest.raises(UnverifiedUserError):
        manager.require_account_state(user, require_verified=True)


def test_require_account_state_allows_unverified_when_not_required() -> None:
    """Account-state policy accepts active unverified users when verification is optional."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = replace(_build_user(password_helper), is_active=True, is_verified=False)

    manager.require_account_state(user, require_verified=False)
