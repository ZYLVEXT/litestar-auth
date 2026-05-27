"""Unit tests for users-controller helper branches."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.exceptions import ClientException, NotFoundException
from litestar.status_codes import HTTP_400_BAD_REQUEST

import litestar_auth._account_state as account_state_module
import litestar_auth.controllers.users as users_module
from litestar_auth.controllers._step_up import (
    PasswordStepUpCheck,
    TotpStepUpCheck,
    require_password_step_up,
    require_totp_stepup,
)
from litestar_auth.controllers._step_up_payloads import AdminUserDeleteStepUpRequest
from litestar_auth.controllers._users_helpers import (
    _build_change_password_rate_limit_key,
    _build_safe_self_update,
    _reject_blocked_self_update_fields,
    _self_update_includes_email,
)
from litestar_auth.controllers._utils import _require_account_state
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.exceptions import AuthorizationError, ErrorCode, UnverifiedUserError
from litestar_auth.ratelimit import EndpointRateLimit, InMemoryRateLimiter
from litestar_auth.ratelimit._helpers import _safe_key_part
from litestar_auth.schemas import AdminUserUpdate, ChangePasswordRequest, UserRead, UserUpdate
from litestar_auth.totp import _current_counter, _generate_totp_code, generate_totp_secret

UsersControllerConfig = users_module.UsersControllerConfig
_users_get_user_or_404 = users_module._users_get_user_or_404
_users_handle_change_password = users_module._users_handle_change_password
_users_handle_delete_user = users_module._users_handle_delete_user
_users_handle_get_me = users_module._users_handle_get_me
_users_handle_update_me = users_module._users_handle_update_me
_users_handle_update_user = users_module._users_handle_update_user
_UsersControllerContext = users_module._UsersControllerContext
create_users_controller = users_module.create_users_controller

pytestmark = pytest.mark.unit
HTTP_FORBIDDEN = 403
HTTP_UNAUTHORIZED = 401
_UNSET_AUTHENTICATED_USER = object()
type RequestHandlerStub = Callable[[object], Awaitable[None]]


def test_self_update_forbidden_fields_cover_only_live_privileged_state() -> None:
    """Self-update privilege stripping is role-based and limited to live privileged fields."""
    assert frozenset({"is_active", "is_verified", "roles"}) == users_module.SELF_UPDATE_FORBIDDEN_FIELDS


class DummyUser(msgspec.Struct):
    """Minimal user struct for account-state helper tests."""

    id: UUID
    email: str
    is_active: bool = True
    is_verified: bool = False
    roles: list[str] = msgspec.field(default_factory=list)
    totp_secret: str | None = None


class DummyUserManager:
    """Manager stub exposing the explicit account-state validator contract."""

    def require_account_state(self, user: DummyUser, *, require_verified: bool) -> None:
        """Reject unverified users via the explicit controller contract.

        Raises:
            UnverifiedUserError: Always, to exercise the controller helper mapping.
        """
        msg = "The user account is not verified."
        raise UnverifiedUserError(msg)


class RecordingUserManager:
    """Manager stub for direct users-controller helper coverage."""

    def __init__(
        self,
        *,
        user_to_get: DummyUser | None = None,
        authenticated_user: DummyUser | object | None = _UNSET_AUTHENTICATED_USER,
    ) -> None:
        """Store the user that helper lookups should resolve."""
        self.user_to_get = user_to_get
        self.authenticated_user = user_to_get if authenticated_user is _UNSET_AUTHENTICATED_USER else authenticated_user
        self.authenticate_calls: list[tuple[str, str, str | None]] = []
        self.require_account_state_calls: list[tuple[DummyUser, bool]] = []
        self.update_calls: list[tuple[object, DummyUser, bool]] = []
        self.delete_calls: list[UUID] = []
        self.backends: tuple[object, ...] = ()

    def require_account_state(self, user: DummyUser, *, require_verified: bool) -> None:
        """Record account-state validation requests."""
        self.require_account_state_calls.append((user, require_verified))

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: str | None = None,
    ) -> DummyUser | None:
        """Record authentication requests and return the configured user.

        Returns:
            The configured authenticated user result for the helper test.
        """
        self.authenticate_calls.append((identifier, password, login_identifier))
        return cast("DummyUser | None", self.authenticated_user)

    async def get(self, user_id: UUID) -> DummyUser | None:
        """Return the configured user for the requested identifier."""
        if self.user_to_get is None or self.user_to_get.id != user_id:
            return None
        return self.user_to_get

    async def update(
        self,
        user_update: object,
        user: DummyUser,
        *,
        allow_privileged: bool = False,
    ) -> DummyUser:
        """Record the update payload and return a mutated copy.

        Returns:
            Updated dummy user reflecting the provided changes.

        Raises:
            TypeError: If the helper forwards an unexpected payload type.
        """
        self.update_calls.append((user_update, user, allow_privileged))
        if isinstance(user_update, msgspec.Struct):
            payload = cast("dict[str, Any]", msgspec.to_builtins(user_update))
        elif isinstance(user_update, Mapping):
            payload = dict(user_update)
        else:
            msg = "Expected update payload to be a mapping or msgspec struct."
            raise TypeError(msg)
        return DummyUser(
            id=user.id,
            email=str(payload.get("email", user.email)),
            is_active=bool(payload.get("is_active", user.is_active)),
            is_verified=bool(payload.get("is_verified", user.is_verified)),
            roles=list(cast("list[str]", payload.get("roles", user.roles))),
        )

    async def delete(self, user_id: UUID) -> None:
        """Record hard-delete requests."""
        self.delete_calls.append(user_id)

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return the stored test TOTP secret."""
        return secret

    async def has_recent_totp_verification(self, user: DummyUser, session_id: str) -> bool:
        """Return no recent marker for direct helper tests."""
        return False


class MarkerUserManager(RecordingUserManager):
    """Manager stub with configurable TOTP marker and secret behavior."""

    def __init__(
        self,
        *,
        user_to_get: DummyUser | None = None,
        secret_result: str | None = None,
        marker_session_id: str | None = None,
        backends: tuple[object, ...] = (),
    ) -> None:
        """Store configurable TOTP marker behavior."""
        super().__init__(user_to_get=user_to_get)
        self.secret_result = secret_result
        self.marker_session_id = marker_session_id
        self.backends = backends

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return the configured plain secret result."""
        return self.secret_result

    async def has_recent_totp_verification(self, user: DummyUser, session_id: str) -> bool:
        """Return whether the supplied session matches the configured marker."""
        return session_id == self.marker_session_id


class DummyRequest:
    """Minimal request stub for controller helper tests."""

    def __init__(
        self,
        *,
        user: DummyUser | None,
        body_bytes: bytes = b"{}",
        json_payload: object | None = None,
    ) -> None:
        """Store a request user plus optional JSON body bytes."""
        self.user = user
        self._body_bytes = body_bytes
        self._json_payload = {} if json_payload is None else json_payload
        self.client = type("Client", (), {"host": "127.0.0.1"})()
        self.headers: dict[str, str] = {}

    async def body(self) -> bytes:
        """Return the configured request body."""
        return self._body_bytes

    async def json(self) -> object:
        """Return the configured JSON payload."""
        return self._json_payload


class _TokenTransport:
    """Transport stub exposing a token reader."""

    def __init__(self, token: object) -> None:
        self.token = token

    async def read_token(self, _request: object) -> object:
        """Return the configured token."""
        return self.token


@dataclass(frozen=True, slots=True)
class _Backend:
    """Backend stub with a transport attribute."""

    transport: object


class ExtendedSelfUpdate(msgspec.Struct, omit_defaults=True):
    """Custom self-update payload with one safe extra field."""

    email: str | None = None
    current_password: str | None = None
    password: str | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    roles: list[str] | None = None
    hashed_password: str | None = None
    bio: str | None = None
    totp_code: str | None = None


async def _noop_request_handler(_request: object) -> None:
    """No-op request hook for direct users-controller helper tests."""


def build_context(
    *,
    hard_delete: bool = False,
    user_update_schema: type[msgspec.Struct] = UserUpdate,
    admin_user_update_schema: type[msgspec.Struct] = AdminUserUpdate,
    change_password_rate_limit_increment: RequestHandlerStub = _noop_request_handler,
    change_password_rate_limit_reset: RequestHandlerStub = _noop_request_handler,
) -> _UsersControllerContext[Any, UUID]:
    """Create a controller context for direct helper tests.

    Returns:
        Users-controller context using UUID path parsing and the requested update schema.
    """
    return _UsersControllerContext(
        id_parser=UUID,
        user_read_schema_type=UserRead,
        user_update_schema_type=user_update_schema,
        admin_user_update_schema_type=admin_user_update_schema,
        users_page_schema_type=msgspec.defstruct(
            "UsersPageSchema",
            [
                ("items", list[object]),
                ("total", int),
                ("limit", int),
                ("offset", int),
            ],
        ),
        hard_delete=hard_delete,
        default_limit=50,
        max_limit=100,
        change_password_before_request=None,
        change_password_rate_limit_increment=cast("Any", change_password_rate_limit_increment),
        change_password_rate_limit_reset=cast("Any", change_password_rate_limit_reset),
        unsafe_testing=False,
    )


async def test_require_account_state_uses_explicit_manager_contract_for_unverified_users() -> None:
    """The shared helper maps explicit-manager UnverifiedUserError into the unified account-state error."""
    user = DummyUser(id=uuid4(), email="user@example.com")

    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(user, user_manager=cast("Any", DummyUserManager()), require_verified=False)

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == account_state_module._GENERIC_ACCOUNT_UNAVAILABLE_DETAIL
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE}


async def test_require_account_state_uses_attribute_fallback_without_manager_contract() -> None:
    """The shared helper falls back to direct user attributes when no manager is provided."""
    await _require_account_state(
        DummyUser(id=uuid4(), email="user@example.com"),
        require_verified=False,
    )


async def test_users_get_user_or_404_rejects_unparseable_ids() -> None:
    """User lookups map parser failures into consistent 404 responses."""
    manager = RecordingUserManager()

    with pytest.raises(NotFoundException, match="User not found\\."):
        await _users_get_user_or_404(
            "not-a-valid-id",
            user_manager=cast("Any", manager),
            id_parser=UUID,
        )


async def test_users_get_user_or_404_rejects_missing_users() -> None:
    """User lookups return 404 when the manager cannot find the user."""
    manager = RecordingUserManager()

    missing_user_id = uuid4()

    with pytest.raises(NotFoundException, match="User not found\\."):
        await _users_get_user_or_404(
            str(missing_user_id),
            user_manager=cast("Any", manager),
            id_parser=UUID,
        )


async def test_users_handle_get_me_validates_account_state_and_serializes_user() -> None:
    """The self-read helper validates state and returns the configured schema."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)

    result = await _users_handle_get_me(
        cast("Any", DummyRequest(user=user)),
        ctx=build_context(),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email=user.email,
        is_active=True,
        is_verified=True,
        roles=["member"],
    )
    assert manager.require_account_state_calls == [(user, False)]


async def test_users_handle_update_me_forwards_safe_fields() -> None:
    """Self-updates only forward safe fields to the manager."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)
    rate_limit_reset = AsyncMock()

    result = await _users_handle_update_me(
        cast("Any", DummyRequest(user=user)),
        ExtendedSelfUpdate(
            email="updated@example.com",
            current_password="current-password",
            bio="still-allowed",
        ),
        ctx=build_context(change_password_rate_limit_reset=rate_limit_reset),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email="updated@example.com",
        is_active=True,
        is_verified=True,
        roles=["member"],
    )
    assert manager.require_account_state_calls == [(user, False)]
    assert manager.authenticate_calls == [(user.email, "current-password", "email")]
    assert manager.update_calls == [({"bio": "still-allowed", "email": "updated@example.com"}, user, False)]
    rate_limit_reset.assert_awaited_once()


async def test_users_handle_update_me_requires_totp_stepup_before_email_mutation() -> None:
    """Enrolled users need a recent TOTP proof before self-service email mutation."""
    secret = generate_totp_secret()
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"], totp_secret=secret)
    manager = RecordingUserManager(user_to_get=user)

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_update_me(
            cast("Any", DummyRequest(user=user)),
            ExtendedSelfUpdate(email="updated@example.com", current_password="current-password"),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_FORBIDDEN
    assert exc_info.value.extra == {"code": ErrorCode.TOTP_STEPUP_REQUIRED}
    assert manager.update_calls == []


async def test_users_handle_update_me_accepts_inline_totp_code_for_email_change() -> None:
    """A valid inline TOTP code satisfies the email-change step-up gate."""
    secret = generate_totp_secret()
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"], totp_secret=secret)
    manager = RecordingUserManager(user_to_get=user)

    result = await _users_handle_update_me(
        cast("Any", DummyRequest(user=user)),
        ExtendedSelfUpdate(
            email="updated@example.com",
            current_password="current-password",
            totp_code=_generate_totp_code(secret, _current_counter()),
        ),
        ctx=build_context(),
        user_manager=cast("Any", manager),
    )

    assert cast("UserRead", result).email == "updated@example.com"


async def test_require_totp_stepup_policy_off_skips_enforcement() -> None:
    """An explicit off policy leaves enrolled users unblocked."""
    user = DummyUser(id=uuid4(), email="user@example.com", totp_secret="stored-secret")
    manager = MarkerUserManager(user_to_get=user, secret_result=None)

    await require_totp_stepup(
        cast("Any", DummyRequest(user=user)),
        TotpStepUpCheck(endpoint="users.update_self", policy={"users.update_self": "off"}, user_manager=manager),
    )


@pytest.mark.parametrize("stored_secret", [None, "stored-secret"])
async def test_require_totp_stepup_always_required_blocks_missing_enrollment_or_secret(
    stored_secret: str | None,
) -> None:
    """The always-required mode fails closed when no usable TOTP secret is available."""
    user = DummyUser(id=uuid4(), email="user@example.com", totp_secret=stored_secret)
    manager = MarkerUserManager(user_to_get=user, secret_result=None)

    with pytest.raises(ClientException) as exc_info:
        await require_totp_stepup(
            cast("Any", DummyRequest(user=user)),
            TotpStepUpCheck(
                endpoint="users.update_self",
                policy={"users.update_self": "always_required"},
                user_manager=manager,
            ),
        )

    assert exc_info.value.extra == {"code": ErrorCode.TOTP_STEPUP_REQUIRED}


async def test_require_totp_stepup_ignores_unreadable_secret_when_not_always_required() -> None:
    """Required-when-enrolled mode does not block when the manager reports no usable TOTP secret."""
    user = DummyUser(id=uuid4(), email="user@example.com", totp_secret="stored-secret")
    manager = MarkerUserManager(user_to_get=user, secret_result=None)

    await require_totp_stepup(
        cast("Any", DummyRequest(user=user)),
        TotpStepUpCheck(endpoint="users.update_self", policy={}, user_manager=manager),
    )


async def test_require_totp_stepup_accepts_recent_session_marker() -> None:
    """A recent marker on the current transport token satisfies the TOTP gate."""
    user = DummyUser(id=uuid4(), email="user@example.com", totp_secret="stored-secret")
    manager = MarkerUserManager(
        user_to_get=user,
        secret_result="plain-secret",
        marker_session_id="session-token",
        backends=(
            _Backend(object()),
            _Backend(_TokenTransport("")),
            _Backend(_TokenTransport("session-token")),
        ),
    )

    await require_totp_stepup(
        cast("Any", DummyRequest(user=user)),
        TotpStepUpCheck(endpoint="users.update_self", policy={}, user_manager=manager),
    )


async def test_require_password_step_up_calls_failure_callback_for_wrong_password() -> None:
    """Current-password step-up failures share the same callback and error contract."""
    user = DummyUser(id=uuid4(), email="user@example.com")
    manager = RecordingUserManager(user_to_get=user, authenticated_user=None)
    on_failure = AsyncMock()
    on_success = AsyncMock()

    with pytest.raises(ClientException) as exc_info:
        await require_password_step_up(
            PasswordStepUpCheck(
                user=user,
                user_manager=manager,
                current_password="wrong-password",
                on_failure=on_failure,
                on_success=on_success,
            ),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == INVALID_CREDENTIALS_DETAIL
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_BAD_CREDENTIALS}
    assert manager.authenticate_calls == [(user.email, "wrong-password", "email")]
    on_failure.assert_awaited_once()
    on_success.assert_not_awaited()


async def test_require_password_step_up_calls_success_callback_for_matching_user() -> None:
    """Current-password step-up success can reset the endpoint rate-limit bucket."""
    user = DummyUser(id=uuid4(), email="user@example.com")
    manager = RecordingUserManager(user_to_get=user)
    on_failure = AsyncMock()
    on_success = AsyncMock()

    await require_password_step_up(
        PasswordStepUpCheck(
            user=user,
            user_manager=manager,
            current_password="current-password",
            on_failure=on_failure,
            on_success=on_success,
        ),
    )

    assert manager.authenticate_calls == [(user.email, "current-password", "email")]
    on_failure.assert_not_awaited()
    on_success.assert_awaited_once()


async def test_users_handle_update_me_requires_current_password_for_email_change() -> None:
    """Email changes require current-password re-authentication before persistence."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)
    rate_limit_increment = AsyncMock()

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_update_me(
            cast("Any", DummyRequest(user=user)),
            ExtendedSelfUpdate(email="updated@example.com"),
            ctx=build_context(change_password_rate_limit_increment=rate_limit_increment),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == INVALID_CREDENTIALS_DETAIL
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_BAD_CREDENTIALS}
    assert manager.require_account_state_calls == [(user, False)]
    assert manager.authenticate_calls == []
    assert manager.update_calls == []
    rate_limit_increment.assert_awaited_once()


async def test_users_handle_update_me_rejects_wrong_current_password_for_email_change() -> None:
    """Wrong current-password email changes reuse the password-rotation failure surface."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user, authenticated_user=None)
    rate_limit_increment = AsyncMock()

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_update_me(
            cast("Any", DummyRequest(user=user)),
            ExtendedSelfUpdate(email="updated@example.com", current_password="wrong-password"),
            ctx=build_context(change_password_rate_limit_increment=rate_limit_increment),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == INVALID_CREDENTIALS_DETAIL
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_BAD_CREDENTIALS}
    assert manager.require_account_state_calls == [(user, False)]
    assert manager.authenticate_calls == [(user.email, "wrong-password", "email")]
    assert manager.update_calls == []
    rate_limit_increment.assert_awaited_once()


async def test_users_handle_update_me_does_not_reauthenticate_without_email_change() -> None:
    """Non-identity self-updates keep the existing path and do not call authenticate()."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)

    result = await _users_handle_update_me(
        cast("Any", DummyRequest(user=user)),
        ExtendedSelfUpdate(bio="still-allowed"),
        ctx=build_context(),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email=user.email,
        is_active=True,
        is_verified=True,
        roles=["member"],
    )
    assert manager.require_account_state_calls == [(user, False)]
    assert manager.authenticate_calls == []
    assert manager.update_calls == [({"bio": "still-allowed"}, user, False)]


def test_change_password_request_round_trips_through_msgspec() -> None:
    """The built-in change-password schema preserves the required password fields."""
    payload = ChangePasswordRequest(current_password="current-password", new_password="new-password")

    assert msgspec.to_builtins(payload) == {
        "current_password": "current-password",
        "new_password": "new-password",
    }


def test_change_password_request_requires_both_fields() -> None:
    """Missing fields are rejected because the schema has no defaults."""
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"current_password":"current-password"}',
            type=ChangePasswordRequest,
        )


def test_change_password_request_rejects_unknown_fields() -> None:
    """The built-in change-password schema rejects undeclared JSON keys."""
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"current_password":"current-password","new_password":"new-password","extra":true}',
            type=ChangePasswordRequest,
        )


async def test_change_password_rate_limit_key_uses_endpoint_key_for_ip_scope() -> None:
    """IP-scoped password-rotation limiters keep the standard endpoint key behavior."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
        scope="ip",
        namespace="change-password",
    )
    request = cast("Any", DummyRequest(user=DummyUser(id=uuid4(), email="User@Example.com")))

    key = await _build_change_password_rate_limit_key(limiter, request)

    assert key == f"change-password:{_safe_key_part('127.0.0.1')}"


async def test_change_password_rate_limit_key_falls_back_to_body_identity_without_user_email() -> None:
    """The authenticated-email key builder falls back to the endpoint key when no user email exists."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
        scope="ip_email",
        namespace="change-password",
    )
    request = cast("Any", DummyRequest(user=None, json_payload={"email": "Body@Example.com"}))

    key = await _build_change_password_rate_limit_key(limiter, request)

    assert key == f"change-password:{_safe_key_part('127.0.0.1')}:{_safe_key_part('body@example.com')}"


async def test_users_handle_change_password_reverifies_current_password_and_updates_user() -> None:
    """Password rotation reuses manager authentication before calling update()."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)
    rate_limit_reset = AsyncMock()

    result = await _users_handle_change_password(
        cast("Any", DummyRequest(user=user)),
        ChangePasswordRequest(current_password="current-password", new_password="new-password"),
        ctx=build_context(change_password_rate_limit_reset=rate_limit_reset),
        user_manager=cast("Any", manager),
    )

    assert result is None
    assert manager.require_account_state_calls == [(user, False)]
    assert manager.authenticate_calls == [(user.email, "current-password", "email")]
    assert manager.update_calls == [({"password": "new-password"}, user, True)]
    rate_limit_reset.assert_awaited_once()


async def test_users_handle_change_password_rejects_invalid_current_password() -> None:
    """Wrong current-password failures reuse the generic login error surface."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user, authenticated_user=None)
    rate_limit_increment = AsyncMock()

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_change_password(
            cast("Any", DummyRequest(user=user)),
            ChangePasswordRequest(current_password="wrong-password", new_password="new-password"),
            ctx=build_context(change_password_rate_limit_increment=rate_limit_increment),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == INVALID_CREDENTIALS_DETAIL
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_BAD_CREDENTIALS}
    assert manager.require_account_state_calls == [(user, False)]
    assert manager.authenticate_calls == [(user.email, "wrong-password", "email")]
    assert manager.update_calls == []
    rate_limit_increment.assert_awaited_once()


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        (ExtendedSelfUpdate(password="new-password"), "password"),
        (ExtendedSelfUpdate(is_active=False), "is_active"),
        (ExtendedSelfUpdate(is_verified=False), "is_verified"),
        (ExtendedSelfUpdate(roles=[" Billing ", "ADMIN"]), "roles"),
        (ExtendedSelfUpdate(hashed_password="forbidden"), "hashed_password"),
    ],
)
async def test_users_handle_update_me_rejects_blocked_fields(
    payload: ExtendedSelfUpdate,
    field_name: str,
) -> None:
    """Self-updates fail closed when blocked fields are present in the decoded DTO."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_update_me(
            cast("Any", DummyRequest(user=user)),
            payload,
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == f"Self-service updates cannot set the following fields: {field_name}."
    assert exc_info.value.extra == {"code": ErrorCode.REQUEST_BODY_INVALID}
    assert manager.update_calls == []


async def test_users_handle_update_me_maps_authorization_errors_to_400() -> None:
    """The handler turns manager ``AuthorizationError`` failures into 400 responses."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)
    manager.update = cast(
        "Any",
        AsyncMock(side_effect=AuthorizationError("Custom policy rejected this self-update.")),
    )

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_update_me(
            cast("Any", DummyRequest(user=user)),
            ExtendedSelfUpdate(email="updated@example.com", current_password="current-password"),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.extra == {"code": ErrorCode.REQUEST_BODY_INVALID}


async def test_reject_blocked_self_update_fields_rejects_password_in_raw_request_body() -> None:
    """The preflight hook returns the controller 400 contract for blocked raw JSON keys."""
    request = DummyRequest(user=None, body_bytes=b'{"password":"new-password"}')

    with pytest.raises(ClientException) as exc_info:
        await _reject_blocked_self_update_fields(cast("Any", request))

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Self-service updates cannot set the following fields: password."
    assert exc_info.value.extra == {"code": ErrorCode.REQUEST_BODY_INVALID}


async def test_reject_blocked_self_update_fields_ignores_non_mapping_json_bodies() -> None:
    """The preflight hook ignores valid non-object JSON and leaves later validation to the route."""
    await _reject_blocked_self_update_fields(cast("Any", DummyRequest(user=None, body_bytes=b'["not","a","mapping"]')))


async def test_self_update_includes_email_detects_email_mapping_field() -> None:
    """The update route preflight only rate-limit checks requests that include email."""
    assert await _self_update_includes_email(
        cast("Any", DummyRequest(user=None, body_bytes=b'{"email":"updated@example.com"}')),
    )
    assert not await _self_update_includes_email(cast("Any", DummyRequest(user=None, body_bytes=b'{"bio":"ok"}')))
    assert not await _self_update_includes_email(cast("Any", DummyRequest(user=None, body_bytes=b'["not","mapping"]')))
    assert not await _self_update_includes_email(cast("Any", DummyRequest(user=None, body_bytes=b'{"email":')))


async def test_users_handle_delete_user_rejects_superuser_self_delete() -> None:
    """Superusers receive the dedicated 403 error when deleting themselves."""
    user = DummyUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    manager = RecordingUserManager(user_to_get=user)

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_delete_user(
            str(user.id),
            cast("Any", DummyRequest(user=user)),
            AdminUserDeleteStepUpRequest(current_password="current-password"),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_FORBIDDEN
    assert exc_info.value.detail == "Superusers cannot delete their own account."
    assert exc_info.value.extra == {"code": ErrorCode.SUPERUSER_CANNOT_DELETE_SELF}


async def test_users_handle_update_user_requires_admin_current_password_and_strips_step_up_fields() -> None:
    """Admin updates authenticate the admin and never forward step-up credentials to persistence."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    admin_user = DummyUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    manager = RecordingUserManager(user_to_get=user, authenticated_user=admin_user)
    ctx = build_context()
    ctx.totp_stepup_policy = {"users.update": "off"}

    result = await _users_handle_update_user(
        str(user.id),
        cast("Any", DummyRequest(user=admin_user)),
        AdminUserUpdate(
            email="updated@example.com",
            roles=["admin"],
            current_password="admin-password",
            totp_code="123456",
        ),
        ctx=ctx,
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email="updated@example.com",
        is_active=True,
        is_verified=True,
        roles=["admin"],
    )
    assert manager.require_account_state_calls == [(admin_user, False)]
    assert manager.authenticate_calls == [(admin_user.email, "admin-password", "email")]
    assert manager.update_calls == [({"email": "updated@example.com", "roles": ["admin"]}, user, True)]


async def test_users_handle_update_user_rejects_wrong_admin_current_password() -> None:
    """Wrong admin passwords block privileged target-user updates before persistence."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    admin_user = DummyUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    manager = RecordingUserManager(user_to_get=user, authenticated_user=None)

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_update_user(
            str(user.id),
            cast("Any", DummyRequest(user=admin_user)),
            AdminUserUpdate(email="updated@example.com", current_password="wrong-password"),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == INVALID_CREDENTIALS_DETAIL
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_BAD_CREDENTIALS}
    assert manager.authenticate_calls == [(admin_user.email, "wrong-password", "email")]
    assert manager.update_calls == []


async def test_users_handle_update_user_rejects_missing_authenticated_admin() -> None:
    """The admin update helper fails closed if called without an authenticated request user."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_update_user(
            str(user.id),
            cast("Any", DummyRequest(user=None)),
            AdminUserUpdate(email="updated@example.com", current_password="admin-password"),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_UNAUTHORIZED
    assert exc_info.value.detail == "Authentication credentials were not provided."
    assert manager.update_calls == []


async def test_users_handle_update_user_rejects_non_mapping_update_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admin update payload extraction defends against unexpected msgspec conversion output."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    admin_user = DummyUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    manager = RecordingUserManager(user_to_get=user, authenticated_user=admin_user)
    monkeypatch.setattr("litestar_auth.controllers.users.msgspec.to_builtins", lambda _value: ["bad"])

    with pytest.raises(TypeError, match="Expected a mapping from msgspec\\.to_builtins\\."):
        await _users_handle_update_user(
            str(user.id),
            cast("Any", DummyRequest(user=admin_user)),
            AdminUserUpdate(email="updated@example.com", current_password="admin-password"),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert manager.update_calls == []


async def test_users_handle_delete_user_rejects_missing_authenticated_admin() -> None:
    """The admin delete helper fails closed if called without an authenticated request user."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    manager = RecordingUserManager(user_to_get=user)

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_delete_user(
            str(user.id),
            cast("Any", DummyRequest(user=None)),
            AdminUserDeleteStepUpRequest(current_password="admin-password"),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_UNAUTHORIZED
    assert exc_info.value.detail == "Authentication credentials were not provided."
    assert manager.update_calls == []
    assert manager.delete_calls == []


async def test_users_handle_delete_user_soft_deletes_by_disabling_user() -> None:
    """Soft-delete mode updates the user instead of calling hard delete."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    admin_user = DummyUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    manager = RecordingUserManager(user_to_get=user, authenticated_user=admin_user)

    result = await _users_handle_delete_user(
        str(user.id),
        cast("Any", DummyRequest(user=admin_user)),
        AdminUserDeleteStepUpRequest(current_password="admin-password"),
        ctx=build_context(),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email=user.email,
        is_active=False,
        is_verified=True,
        roles=["member"],
    )
    assert len(manager.update_calls) == 1
    assert manager.delete_calls == []
    payload, updated_user, allow_privileged = manager.update_calls[0]
    # Soft-delete is admin-only: ``is_active`` is a privileged field, so the
    # controller forwards an AdminUserUpdate body, not the email-only
    # self-service UserUpdate.
    assert isinstance(payload, AdminUserUpdate)
    assert payload.is_active is False
    assert updated_user is user
    assert allow_privileged is True
    assert manager.authenticate_calls == [(admin_user.email, "admin-password", "email")]


async def test_users_handle_delete_user_hard_deletes_when_enabled() -> None:
    """Hard-delete mode calls the manager delete hook and returns the original user schema."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True, roles=["member"])
    admin_user = DummyUser(id=uuid4(), email="admin@example.com", is_verified=True, roles=["superuser"])
    manager = RecordingUserManager(user_to_get=user, authenticated_user=admin_user)

    result = await _users_handle_delete_user(
        str(user.id),
        cast("Any", DummyRequest(user=admin_user)),
        AdminUserDeleteStepUpRequest(current_password="admin-password"),
        ctx=build_context(hard_delete=True),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email=user.email,
        is_active=True,
        is_verified=True,
        roles=["member"],
    )
    assert manager.delete_calls == [user.id]
    assert manager.update_calls == []
    assert manager.authenticate_calls == [(admin_user.email, "admin-password", "email")]


def test_build_safe_self_update_preserves_custom_safe_fields() -> None:
    """The deny-list preserves app-owned safe DTO fields when no blocked keys are present."""
    payload = _build_safe_self_update(ExtendedSelfUpdate(email="updated@example.com", bio="still-allowed"))

    assert payload == {"bio": "still-allowed", "email": "updated@example.com"}


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        (ExtendedSelfUpdate(password="new-password"), "password"),
        (ExtendedSelfUpdate(is_active=False), "is_active"),
        (ExtendedSelfUpdate(is_verified=False), "is_verified"),
        (ExtendedSelfUpdate(roles=[" Billing ", "ADMIN"]), "roles"),
        (ExtendedSelfUpdate(hashed_password="forbidden"), "hashed_password"),
    ],
)
def test_build_safe_self_update_rejects_each_blocked_field(
    payload: ExtendedSelfUpdate,
    field_name: str,
) -> None:
    """The deny-list fails closed for every blocked self-update field."""
    with pytest.raises(
        AuthorizationError,
        match=rf"Self-service updates cannot set the following fields: {field_name}\.",
    ):
        _build_safe_self_update(payload)


def test_build_safe_self_update_rejects_non_mapping_builtins(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unexpected `msgspec.to_builtins()` output raises a defensive `TypeError`."""
    monkeypatch.setattr("litestar_auth.controllers.users.msgspec.to_builtins", lambda _value: ["not", "a", "mapping"])

    with pytest.raises(TypeError, match="Expected a mapping from msgspec\\.to_builtins\\."):
        _build_safe_self_update(ExtendedSelfUpdate(email="updated@example.com"))


def test_create_users_controller_uses_requested_path() -> None:
    """Controller factory preserves the configured base path."""
    controller = create_users_controller(path="/admin-users")

    assert controller.path == "/admin-users"
    assert controller.__module__ == "litestar_auth.controllers.users"


def test_create_users_controller_accepts_config_object() -> None:
    """The public users controller factory can receive settings as one typed config."""
    controller = create_users_controller(config=UsersControllerConfig[UUID](path="/profile-users"))

    assert controller.path == "/profile-users"
    assert controller.__module__ == "litestar_auth.controllers.users"


def test_create_users_controller_rejects_config_combined_with_keyword_options() -> None:
    """The users controller factory accepts either config or keyword options."""
    with pytest.raises(ValueError, match="UsersControllerConfig or keyword options"):
        create_users_controller(config=UsersControllerConfig[UUID](), path="/admin-users")


def test_create_users_controller_rejects_permissive_admin_update_schema() -> None:
    """Admin update schemas must reject unknown fields just like self-update schemas."""

    class PermissiveAdminUpdate(msgspec.Struct, omit_defaults=True):
        email: str | None = None

    with pytest.raises(
        TypeError,
        match=r"admin_user_update_schema must set forbid_unknown_fields=True so unknown request fields are rejected\.",
    ):
        create_users_controller(admin_user_update_schema=PermissiveAdminUpdate)
