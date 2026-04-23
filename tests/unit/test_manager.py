"""Tests for the base user manager."""

from __future__ import annotations

import importlib
import inspect
import logging
import warnings
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import jwt
import pytest
from pwdlib.hashers.bcrypt import BcryptHasher

import litestar_auth.manager as manager_module
from litestar_auth._manager._coercions import _account_state_user, _as_dict, _managed_user, _require_str
from litestar_auth._manager.user_lifecycle import PRIVILEGED_FIELDS
from litestar_auth._manager.user_policy import UserPolicy
from litestar_auth.authentication.strategy.base import TokenInvalidationCapable
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
from litestar_auth.manager import (
    RESET_PASSWORD_TOKEN_AUDIENCE,
    BaseUserManager,
    UserManagerSecurity,
    _SecretValue,
)
from litestar_auth.manager import logger as manager_logger
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import UserCreate, UserUpdate
from litestar_auth.totp import SecurityWarning
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from collections.abc import Callable

JTI_HEX_LENGTH = 32
# ``secrets.token_hex(32)`` is 64 lowercase hex characters.
EXPECTED_TOKEN_HEX_32_LEN = 64
EXPECTED_SECRET_FALLBACK_WARNINGS = 2
EXPECTED_SHARED_HELPER_DUMMY_HASH_CALLS = 2

pytestmark = pytest.mark.unit


def test_manager_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and class execution."""
    reloaded_module = importlib.reload(manager_module)

    assert reloaded_module.BaseUserManager.__name__ == BaseUserManager.__name__
    assert reloaded_module._SecretValue.__name__ == _SecretValue.__name__


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
    ) -> None:
        """Initialize the tracking manager with predictable secrets."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret="reset-secret-1234567890-1234567890",
                id_parser=UUID,
            ),
            password_validator=password_validator,
            reset_verification_on_email_change=reset_verification_on_email_change,
            backends=backends,
            login_identifier=login_identifier,
        )
        self.registered_users: list[ExampleUser] = []
        self.registration_events: list[tuple[ExampleUser, str]] = []
        self.logged_in_users: list[ExampleUser] = []
        self.verified_users: list[ExampleUser] = []
        self.request_verify_events: list[tuple[ExampleUser | None, str | None]] = []
        self.forgot_password_events: list[tuple[ExampleUser | None, str | None]] = []
        self.reset_users: list[ExampleUser] = []
        self.after_update_events: list[tuple[ExampleUser, dict]] = []
        self.before_delete_users: list[ExampleUser] = []
        self.deleted_users: list[ExampleUser] = []

    async def on_after_register(self, user: ExampleUser, token: str) -> None:
        """Record a successful registration."""
        self.registered_users.append(user)
        self.registration_events.append((user, token))

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
        verification_token_secret="verify-secret-1234567890-1234567890",
        reset_password_token_secret="reset-secret-1234567890-1234567890",
        totp_secret_key="a" * 32,
        id_parser=UUID,
    )

    rendered = repr(security)

    assert "verify-secret-1234567890-1234567890" not in rendered
    assert "reset-secret-1234567890-1234567890" not in rendered
    assert "a" * 32 not in rendered
    assert "**********" in rendered
    assert "UUID" in rendered
    assert str(security) == rendered


def test_manager_init_accepts_typed_security_contract() -> None:
    """The public security dataclass wires manager secrets and id parsing in one bundle."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    security = UserManagerSecurity[UUID](
        verification_token_secret="verify-secret-1234567890-1234567890",
        reset_password_token_secret="reset-secret-1234567890-1234567890",
        totp_secret_key="a" * 32,
        id_parser=UUID,
    )

    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=security,
    )

    assert manager.verification_token_secret.get_secret_value() == security.verification_token_secret
    assert manager.reset_password_token_secret.get_secret_value() == security.reset_password_token_secret
    assert manager.totp_secret_key == security.totp_secret_key
    assert manager.id_parser is UUID


def test_manager_init_stores_normalized_superuser_role_name() -> None:
    """The manager exposes the normalized superuser role name used by guards."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    security = UserManagerSecurity[UUID](
        verification_token_secret="verify-secret-1234567890-1234567890",
        reset_password_token_secret="reset-secret-1234567890-1234567890",
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
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
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
            totp_secret_key="t" * 32,
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
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret="reset-secret-1234567890-1234567890",
            ),
            verification_token_secret="other-verify-secret-1234567890",
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
    secret = _SecretValue("verify-secret-1234567890-1234567890")

    assert secret.get_secret_value() == "verify-secret-1234567890-1234567890"
    assert str(secret) == "**********"
    assert repr(secret) == "_SecretValue('**********')"
    assert "verify-secret-1234567890-1234567890" not in repr(secret)


def test_manager_repr_does_not_expose_token_secrets() -> None:
    """Manager text representations must not leak configured token secrets."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
        ),
    )

    assert "verify-secret-1234567890-1234567890" not in repr(manager)
    assert "reset-secret-1234567890-1234567890" not in repr(manager)
    assert "verify-secret-1234567890-1234567890" not in str(manager)
    assert "reset-secret-1234567890-1234567890" not in str(manager)


def test_manager_init_requires_reset_password_secret_when_verification_secret_present() -> None:
    """Missing reset password secret should fail fast when verify secret is provided."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()

    with pytest.raises(ConfigurationError, match="reset_password_token_secret not provided"):
        BaseUserManager(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret=None,
            ),
        )


def test_resolve_oauth_account_store_returns_matching_protocol_instance() -> None:
    """OAuth store resolution returns the store only when the structural protocol matches."""

    class DummyOAuthAccountStore:
        async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> ExampleUser | None:
            del oauth_name, account_id
            return None

        async def upsert_oauth_account(  # noqa: PLR0913
            self,
            user: ExampleUser,
            *,
            oauth_name: str,
            account_id: str,
            account_email: str,
            access_token: str,
            expires_at: int | None,
            refresh_token: str | None,
        ) -> None:
            del (
                user,
                oauth_name,
                account_id,
                account_email,
                access_token,
                expires_at,
                refresh_token,
            )

    store = DummyOAuthAccountStore()

    assert manager_module._resolve_oauth_account_store(store) is store
    assert manager_module._resolve_oauth_account_store(object()) is None


def test_manager_init_wires_services_and_configuration() -> None:
    """Manager initialization should preserve config and wire service collaborators once."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    verification_secret = "verify-secret-1234567890-1234567890"
    reset_secret = "reset-secret-1234567890-1234567890"
    verification_lifetime = manager_module.DEFAULT_VERIFY_TOKEN_LIFETIME * 2
    reset_lifetime = manager_module.DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME * 3
    password_validator = require_password_length
    backends = (object(),)
    lifecycle_service = object()
    token_security_service = object()
    account_tokens_service = type("AccountTokensServiceStub", (), {"security": token_security_service})()
    totp_secrets_service = object()

    class DummyOAuthAccountStore:
        async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> ExampleUser | None:
            del oauth_name
            del account_id
            return None

        async def upsert_oauth_account(  # noqa: PLR0913
            self,
            user: ExampleUser,
            *,
            oauth_name: str,
            account_id: str,
            account_email: str,
            access_token: str,
            expires_at: int | None,
            refresh_token: str | None,
        ) -> None:
            del user
            del oauth_name
            del account_id
            del account_email
            del access_token
            del expires_at
            del refresh_token

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
                totp_secret_key="a" * 32,
                id_parser=UUID,
            ),
            verification_token_lifetime=verification_lifetime,
            reset_password_token_lifetime=reset_lifetime,
            password_validator=password_validator,
            reset_verification_on_email_change=False,
            backends=backends,
            login_identifier="username",
        )

    assert manager.user_db is user_db
    assert manager.oauth_account_store is oauth_account_store
    assert manager.password_helper is password_helper
    assert manager.verification_token_secret.get_secret_value() == verification_secret
    assert manager.reset_password_token_secret.get_secret_value() == reset_secret
    assert manager.account_token_secrets.verification_token_secret is manager.verification_token_secret
    assert manager.account_token_secrets.reset_password_token_secret is manager.reset_password_token_secret
    assert manager.verification_token_lifetime == verification_lifetime
    assert manager.reset_password_token_lifetime == reset_lifetime
    assert manager.id_parser is UUID
    assert manager.password_validator is password_validator
    assert manager.reset_verification_on_email_change is False
    assert manager.totp_secret_key == "a" * 32
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
    user_lifecycle_service.assert_called_once_with(manager, policy=manager.policy)
    account_token_security_service.assert_called_once_with(
        manager,
        logger=manager_logger,
        reset_password_token_audience=RESET_PASSWORD_TOKEN_AUDIENCE,
    )
    account_tokens.assert_called_once_with(
        manager,
        verify_token_audience=manager_module.VERIFY_TOKEN_AUDIENCE,
        reset_password_token_audience=RESET_PASSWORD_TOKEN_AUDIENCE,
        token_security=token_security_service,
        logger=manager_logger,
        policy=manager.policy,
    )
    totp_secrets.assert_called_once_with(manager, prefix=manager_module.ENCRYPTED_TOTP_SECRET_PREFIX)


def test_manager_init_without_explicit_password_helper_uses_current_default_helper() -> None:
    """Omitting password_helper still yields the current Argon2+bcrypt helper surface."""
    manager = BaseUserManager(
        AsyncMock(),
        security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
        ),
    )

    assert manager.password_helper is manager.policy.password_helper
    assert manager.password_helper.password_hash.hashers[0].__class__.__name__ == "Argon2Hasher"
    assert manager.password_helper.password_hash.hashers[1].__class__.__name__ == "BcryptHasher"

    bcrypt_hash = BcryptHasher().hash("legacy-password")

    assert manager.password_helper.verify("legacy-password", bcrypt_hash) is True


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
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
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


async def test_create_safe_false_still_strips_privilege_fields_by_default() -> None:
    """Unsafe create preserves custom fields but strips privileged fields unless explicitly allowed."""
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
    assert verify_calls[0][1] == manager._get_dummy_hash()


def test_manager_module_does_not_hash_dummy_password_at_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reloading the module should not hash a dummy password during import."""
    hash_calls: list[str] = []
    original_hash = PasswordHelper.hash

    def record_hash(self: PasswordHelper, password: str) -> str:
        hash_calls.append(password)
        return original_hash(self, password)

    monkeypatch.setattr(PasswordHelper, "hash", record_hash, raising=True)

    reloaded_module = importlib.reload(manager_module)

    assert hash_calls == []
    helper = PasswordHelper()
    dummy_hash = reloaded_module._get_dummy_hash(helper)

    assert isinstance(dummy_hash, str)
    assert len(hash_calls) == 1


def test_manager_get_dummy_hash_is_lazy_and_cached_per_instance() -> None:
    """A manager computes one dummy hash lazily and reuses it across later lookups."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    hash_calls: list[str] = []
    original_hash = password_helper.hash

    def record_hash(password: str) -> str:
        hash_calls.append(password)
        return original_hash(password)

    with patch.object(password_helper, "hash", side_effect=record_hash):
        first = manager._get_dummy_hash()
        second = manager._get_dummy_hash()

    assert first == second
    assert len(hash_calls) == 1


def test_manager_get_dummy_hash_is_scoped_per_manager() -> None:
    """Managers do not share cached dummy hashes, even when they share a helper."""
    password_helper = PasswordHelper()
    first_manager = TrackingUserManager(AsyncMock(), password_helper)
    second_manager = TrackingUserManager(AsyncMock(), password_helper)
    hash_calls: list[str] = []
    original_hash = password_helper.hash

    def record_hash(password: str) -> str:
        hash_calls.append(password)
        return original_hash(password)

    with patch.object(password_helper, "hash", side_effect=record_hash):
        first_dummy_hash = first_manager._get_dummy_hash()
        second_dummy_hash = second_manager._get_dummy_hash()
        assert first_manager._get_dummy_hash() == first_dummy_hash
        assert second_manager._get_dummy_hash() == second_dummy_hash

    assert len(hash_calls) == EXPECTED_SHARED_HELPER_DUMMY_HASH_CALLS


def test_get_dummy_hash_returns_valid_password_hash() -> None:
    """The dummy hash helper should return a valid password hash value."""
    password_helper = PasswordHelper()
    dummy_hash = manager_module._get_dummy_hash(password_helper)

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
        key=manager.reset_password_token_secret.get_secret_value(),
    )
    assert existing_user.email not in failed_record.__dict__.values()
    assert all("token" not in record.getMessage().lower() for record in caplog.records)
    assert all("password" not in record.getMessage().lower() for record in caplog.records)


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

    with patch.object(manager.tokens, "password_fingerprint", wraps=manager.tokens.password_fingerprint) as fingerprint:
        assert await manager.forgot_password("missing@example.com") is None

    fingerprint.assert_called_once_with(manager._get_dummy_hash())
    assert len(manager.forgot_password_events) == 1
    assert manager.forgot_password_events[0] == (None, None)


async def test_forgot_password_uses_real_fingerprint_for_existing_users() -> None:
    """Forgot-password fingerprints the stored password hash for existing users."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get_by_email.return_value = user

    with patch.object(manager.tokens, "password_fingerprint", wraps=manager.tokens.password_fingerprint) as fingerprint:
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
        dummy_hash=manager._get_dummy_hash(),
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


async def test_reset_password_hashes_new_password_and_calls_hook() -> None:
    """Resetting a password replaces the stored hash."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, hashed_password=password_helper.hash("new-password"))
    user_db.get.return_value = user
    user_db.update.return_value = updated_user
    reset_token = manager.tokens.write_reset_password_token(user, dummy_hash=manager._get_dummy_hash())

    result = await manager.reset_password(reset_token, "new-password")

    assert result is updated_user
    user_db.update.assert_awaited_once()
    update_payload = user_db.update.await_args.args[1]
    assert update_payload["hashed_password"] != "new-password"
    assert password_helper.verify("new-password", update_payload["hashed_password"]) is True
    assert manager.reset_users == [updated_user]


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
    reset_token = manager.tokens.write_reset_password_token(user, dummy_hash=manager._get_dummy_hash())

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
    forgot_password.assert_awaited_once_with("user@example.com", dummy_hash=manager._get_dummy_hash())
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
        UserUpdate(email="updated@example.com", password="new-password"),
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

    result = await manager.update(UserUpdate(is_active=False), user, allow_privileged=True)

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
        await manager.update(UserUpdate(is_active=False), user)

    user_db.update.assert_not_awaited()
    assert manager.after_update_events == []


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
        UserUpdate(roles=[" Support ", "admin", "ADMIN"]),
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
        await manager.update(UserUpdate(password="short"), user)

    user_db.update.assert_not_awaited()
    assert manager.after_update_events == []


async def test_delete_removes_user_and_calls_hook() -> None:
    """Hard deletes delegate to the database and run the post-delete hook."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get.return_value = user

    assert await manager.delete(user.id) is None

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


async def test_get_user_from_token_raises_user_not_exists_error() -> None:
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
        await manager.tokens.security.get_user_from_token(
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
        patch.object(manager.tokens.security, "write_token", return_value="signed-token") as write_token,
        patch.object(
            manager.tokens.security,
            "get_user_from_token",
            new=AsyncMock(return_value=expected_user),
        ) as get_user_from_token,
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
        resolved_user = await manager.tokens.security.get_user_from_token(
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
        subject=str(expected_user.id),
        secret=manager.verification_token_secret.get_secret_value(),
        audience=manager_module.VERIFY_TOKEN_AUDIENCE,
        lifetime=manager.verification_token_lifetime,
        extra_claims=None,
    )
    get_user_from_token.assert_awaited_once_with(
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
    """TOTP helper methods should delegate to TotpSecretsService with the loader callback."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, totp_secret="encrypted")

    with (
        patch.object(manager.totp, "set_secret", new=AsyncMock(return_value=updated_user)) as set_secret,
        patch.object(manager.totp, "read_secret", new=AsyncMock(return_value="plain-secret")) as read_secret,
    ):
        assert await manager.set_totp_secret(user, None) is updated_user
        assert await manager.read_totp_secret("encrypted-value") == "plain-secret"

    set_secret.assert_awaited_once_with(
        user,
        None,
        load_cryptography_fernet=manager_module._load_cryptography_fernet,
    )
    read_secret.assert_awaited_once_with(
        "encrypted-value",
        load_cryptography_fernet=manager_module._load_cryptography_fernet,
    )


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
    manager.totp_secret_key = "a" * 32

    with pytest.raises(RuntimeError, match="encrypted at rest"):
        await manager.read_totp_secret("plain")


async def test_read_totp_secret_raises_when_decryption_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decryption failures are surfaced as RuntimeError with a stable message."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    manager.totp_secret_key = "a" * 32

    class FakeInvalidTokenError(Exception):
        pass

    class FakeFernet:
        def __init__(self, _: bytes) -> None:
            pass

        def decrypt(self, _: bytes) -> bytes:
            raise FakeInvalidTokenError

    fake_module = type("FakeFernetModule", (), {"Fernet": FakeFernet, "InvalidToken": FakeInvalidTokenError})()
    monkeypatch.setattr(manager_module, "_load_cryptography_fernet", lambda: fake_module)

    with pytest.raises(RuntimeError, match="TOTP secret decryption failed"):
        await manager.read_totp_secret(f"{manager_module.ENCRYPTED_TOTP_SECRET_PREFIX}encrypted")


def test_prepare_totp_secret_encrypts_and_prefixes_when_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Encrypted TOTP storage prefixes values and uses Fernet.encrypt()."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    manager.totp_secret_key = "a" * 32

    class FakeFernet:
        def __init__(self, _: bytes) -> None:
            pass

        def encrypt(self, _: bytes) -> bytes:
            return b"encrypted-value"

    fake_module = type("FakeFernetModule", (), {"Fernet": FakeFernet})()
    monkeypatch.setattr(manager_module, "_load_cryptography_fernet", lambda: fake_module)

    stored = manager._prepare_totp_secret_for_storage("secret")
    assert stored == f"{manager_module.ENCRYPTED_TOTP_SECRET_PREFIX}encrypted-value"

    stored_via_service = manager.totp.prepare_secret_for_storage(
        "secret",
        load_cryptography_fernet=manager_module._load_cryptography_fernet,
    )
    assert stored_via_service == f"{manager_module.ENCRYPTED_TOTP_SECRET_PREFIX}encrypted-value"


def test_load_cryptography_fernet_raises_with_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Optional TOTP encryption import errors include an extras install hint."""
    monkeypatch.setattr(
        manager_module.importlib,
        "import_module",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ImportError),
    )
    with pytest.raises(ImportError, match=r"Install litestar-auth\[totp\]"):
        manager_module._load_cryptography_fernet()


async def test_base_hooks_are_noops() -> None:
    """Base hooks are safe no-ops and accept the required parameters."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            id_parser=UUID,
        ),
    )
    user = _build_user(password_helper)

    assert await manager.on_after_register(user, "token") is None
    assert await manager.on_after_login(user) is None
    assert await manager.on_after_verify(user) is None
    assert await manager.on_after_request_verify_token(user, "token") is None
    assert await manager.on_after_request_verify_token(None, None) is None
    assert await manager.on_after_forgot_password(user, "token") is None
    assert await manager.on_after_reset_password(user) is None
    assert await manager.on_after_update(user, {"email": user.email}) is None
    assert await manager.on_before_delete(user) is None
    assert await manager.on_after_delete(user) is None


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
