"""Unit tests for `litestar_auth.controllers._utils` helpers."""

from __future__ import annotations

import importlib
import inspect
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import uuid4

import msgspec
import pytest
from litestar.exceptions import ClientException, NotAuthorizedException, PermissionDeniedException, ValidationException

import litestar_auth._account_state as account_state_module
import litestar_auth.oauth.service as oauth_service_module
from litestar_auth.controllers import _utils
from litestar_auth.controllers._utils import (
    _build_controller_name,
    _configure_request_body_handler,
    _create_before_request_handler,
    _create_rate_limit_handlers,
    _create_request_body_exception_handlers,
    _decode_request_body,
    _map_domain_exceptions,
    _require_account_state,
    _require_account_state_from_attributes,
    _require_msgspec_struct,
    _resolve_account_state_validator,
    _resolve_domain_error_response,
    _to_user_schema,
)
from litestar_auth.exceptions import (
    ConfigurationError,
    ErrorCode,
    InactiveUserError,
    InvalidPasswordError,
    UnverifiedUserError,
    UserAlreadyExistsError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

STATUS_BAD_REQUEST = 400
STATUS_TOO_MANY_REQUESTS = 429
STATUS_UNPROCESSABLE_ENTITY = 422
STATUS_UNAUTHORIZED = 401

pytestmark = pytest.mark.unit


class _MinimalStruct(msgspec.Struct):
    value: int


class _UserReadSchema(msgspec.Struct):
    id: str
    email: str
    roles: list[str]


class _SensitiveUserReadSchema(msgspec.Struct):
    id: str
    hashed_password: str


class _MockRequest:
    def __init__(self, body_bytes: bytes) -> None:
        self._body_bytes = body_bytes

    async def body(self) -> bytes:  # pragma: no cover - exercised via _decode_request_body
        return self._body_bytes


class _DummyUser(msgspec.Struct):
    id: str = "user-id"
    email: str = "user@example.com"
    is_active: bool = True
    is_verified: bool = True
    is_superuser: bool = False
    roles: list[str] = msgspec.field(default_factory=lambda: ["member"])
    hashed_password: str = "hashed-secret"


class _UserWithoutAccountState:
    """User with only ``id`` and missing guarded account-state attributes."""

    id: str

    def __init__(self) -> None:
        self.id = str(uuid4())


class _MockRateLimit:
    def __init__(self) -> None:
        self.increment = AsyncMock()
        self.reset = AsyncMock()
        self.before_request = AsyncMock()


class _MockRouteHandler:
    def __init__(self, fn: Callable[..., object]) -> None:
        self.fn: Callable[..., object] = fn
        self.exception_handlers: dict[type[Exception], object] | None = None


def _raise_user_already_exists() -> None:
    """Raise ``UserAlreadyExistsError`` for exception-mapping tests.

    Raises:
        UserAlreadyExistsError: Always.
    """
    msg = "Email already registered"
    raise UserAlreadyExistsError(msg)


def _raise_invalid_password() -> None:
    """Raise ``InvalidPasswordError`` for exception-mapping tests.

    Raises:
        InvalidPasswordError: Always.
    """
    msg = "too weak"
    raise InvalidPasswordError(msg)


async def _raise_runtime_error_in_mapped_context() -> None:
    """Raise an unmapped runtime error inside the exception-mapping context.

    Raises:
        RuntimeError: Always.
    """
    async with _map_domain_exceptions({UserAlreadyExistsError: (400, ErrorCode.REGISTER_USER_ALREADY_EXISTS)}):
        msg = "boom"
        raise RuntimeError(msg)


def test_module_reload_executes_controller_utils_module_body() -> None:
    """Reloading the module executes its top-level definitions under coverage."""
    for name in ("ConfigurationError", "ErrorCode", "InactiveUserError", "UnverifiedUserError"):
        delattr(_utils, name)
    reloaded_module = importlib.reload(_utils)

    assert frozenset({"hashed_password", "totp_secret", "password"}) == reloaded_module._SENSITIVE_FIELD_BLOCKLIST
    assert reloaded_module._build_controller_name("oauth_google-provider") == "OauthGoogleProvider"


def test_account_state_module_executes_under_coverage() -> None:
    """Reload the shared account-state module so coverage records its top-level definitions."""
    reloaded_module = importlib.reload(account_state_module)

    assert reloaded_module.AccountStateErrorTypes.__name__ == "AccountStateErrorTypes"
    assert reloaded_module.resolve_account_state_client_error("inactive") == (
        STATUS_BAD_REQUEST,
        ErrorCode.LOGIN_USER_INACTIVE,
    )


def test_shared_account_state_client_error_helper_maps_inactive_users() -> None:
    """Shared account-state helpers preserve the stable inactive-user client payload."""
    with pytest.raises(ClientException) as exc_info:
        account_state_module.require_account_state_with_client_error(
            _DummyUser(is_active=False),
            require_verified=False,
            prioritize_unverified=False,
            user_manager=None,
            error_types=account_state_module.AccountStateErrorTypes(
                inactive_error=InactiveUserError,
                unverified_error=UnverifiedUserError,
            ),
        )

    assert exc_info.value.status_code == STATUS_BAD_REQUEST
    assert exc_info.value.detail == "The user account is inactive."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_INACTIVE}


@pytest.mark.asyncio
async def test_decode_request_body_returns_decoded_struct() -> None:
    """Valid JSON is decoded into the configured struct."""
    request: Any = _MockRequest(b'{"value": 3}')

    decoded = await _decode_request_body(cast("Any", request), schema=_MinimalStruct)

    assert decoded == _MinimalStruct(value=3)


@pytest.mark.asyncio
async def test_decode_request_body_malformed_json() -> None:
    """Malformed JSON surfaces as a 400 `ClientException`."""
    request: Any = _MockRequest(b"not-json")

    with pytest.raises(ClientException) as exc_info:
        await _decode_request_body(cast("Any", request), schema=_MinimalStruct)

    exc = exc_info.value
    assert exc.status_code == STATUS_BAD_REQUEST
    assert exc.detail == "Invalid request body."


@pytest.mark.asyncio
async def test_decode_request_body_schema_mismatch() -> None:
    """Schema-mismatched JSON surfaces as a 422 `ClientException`."""
    request: Any = _MockRequest(b'{"value": "not-an-int"}')

    with pytest.raises(ClientException) as exc_info:
        await _decode_request_body(cast("Any", request), schema=_MinimalStruct)

    exc = exc_info.value
    assert exc.status_code == STATUS_UNPROCESSABLE_ENTITY
    assert exc.detail == "Invalid request payload."


@pytest.mark.asyncio
async def test_decode_request_body_uses_custom_validation_metadata() -> None:
    """Custom validation error details and codes are preserved."""
    request: Any = _MockRequest(b'{"value": "not-an-int"}')

    with pytest.raises(ClientException) as exc_info:
        await _decode_request_body(
            cast("Any", request),
            schema=_MinimalStruct,
            validation_detail="Invalid login payload.",
            validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
        )

    exc = exc_info.value
    assert exc.status_code == STATUS_UNPROCESSABLE_ENTITY
    assert exc.detail == "Invalid login payload."
    assert exc.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}


@pytest.mark.asyncio
async def test_decode_request_body_calls_error_callback_for_decode_errors() -> None:
    """The optional error callback runs before malformed-body errors are raised."""
    request: Any = _MockRequest(b"not-json")
    on_error = AsyncMock()

    with pytest.raises(ClientException):
        await _decode_request_body(cast("Any", request), schema=_MinimalStruct, on_error=on_error)

    on_error.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_decode_request_body_calls_error_callback_for_validation_errors() -> None:
    """The optional error callback also runs before validation failures."""
    request: Any = _MockRequest(b'{"value": "not-an-int"}')
    on_error = AsyncMock()

    with pytest.raises(ClientException):
        await _decode_request_body(cast("Any", request), schema=_MinimalStruct, on_error=on_error)

    on_error.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_decode_request_body_uses_custom_decode_metadata() -> None:
    """Custom decode error details and codes are preserved."""
    request: Any = _MockRequest(b"not-json")

    with pytest.raises(ClientException) as exc_info:
        await _decode_request_body(
            cast("Any", request),
            schema=_MinimalStruct,
            decode_detail="Body parsing failed.",
            decode_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
        )

    exc = exc_info.value
    assert exc.status_code == STATUS_BAD_REQUEST
    assert exc.detail == "Body parsing failed."
    assert exc.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}


def test_configure_request_body_handler_updates_data_signature_and_handlers() -> None:
    """Request-body helper rewrites the ``data`` annotation and installs legacy error handlers."""

    def handler(self: object, request: object, data: msgspec.Struct) -> msgspec.Struct:
        del self
        del request
        return data

    route_handler = _MockRouteHandler(handler)

    _configure_request_body_handler(cast("Any", route_handler), schema=_MinimalStruct)

    signature = inspect.signature(route_handler.fn)
    assert signature.parameters["data"].annotation is _MinimalStruct
    assert route_handler.fn.__annotations__["data"] is _MinimalStruct
    assert route_handler.exception_handlers is not None
    assert set(route_handler.exception_handlers) == {ValidationException, ClientException}


def test_configure_request_body_handler_requires_data_parameter() -> None:
    """Request-body helper rejects handlers that do not expose a ``data`` parameter."""

    def handler(self: object, request: object) -> None:
        del self
        del request

    route_handler = _MockRouteHandler(handler)

    with pytest.raises(TypeError, match=r"Request-body handlers must declare a `data` parameter\."):
        _configure_request_body_handler(cast("Any", route_handler), schema=_MinimalStruct)


def test_request_body_exception_handlers_preserve_non_decode_client_exceptions() -> None:
    """Route-local body handlers keep unrelated client exceptions intact."""
    handlers = _create_request_body_exception_handlers()
    response = cast("Any", handlers[ClientException])(
        cast("Any", _MockRequest(b"{}")),
        NotAuthorizedException(detail="Authentication credentials were not provided."),
    )

    assert response.status_code == STATUS_UNAUTHORIZED
    assert response.content == {
        "status_code": STATUS_UNAUTHORIZED,
        "detail": "Authentication credentials were not provided.",
    }


def test_request_body_exception_handlers_preserve_non_decode_headers() -> None:
    """Route-local body handlers keep unrelated client-exception headers intact."""
    handlers = _create_request_body_exception_handlers()
    response = cast("Any", handlers[ClientException])(
        cast("Any", _MockRequest(b"{}")),
        ClientException(status_code=429, detail="Rate limit exceeded.", headers={"Retry-After": "2"}),
    )

    assert response.status_code == STATUS_TOO_MANY_REQUESTS
    assert response.headers["Retry-After"] == "2"


@pytest.mark.asyncio
async def test_map_domain_exceptions_maps_first_matching_error() -> None:
    """Mapped domain exceptions surface as client errors with configured metadata."""
    with pytest.raises(ClientException) as exc_info:
        async with _map_domain_exceptions(
            {
                UserAlreadyExistsError: (400, ErrorCode.REGISTER_USER_ALREADY_EXISTS),
                InvalidPasswordError: (400, ErrorCode.REGISTER_INVALID_PASSWORD),
            },
        ):
            _raise_user_already_exists()

    assert exc_info.value.status_code == STATUS_BAD_REQUEST
    assert exc_info.value.detail == "Email already registered"
    assert exc_info.value.extra == {"code": ErrorCode.REGISTER_USER_ALREADY_EXISTS}


@pytest.mark.asyncio
async def test_map_domain_exceptions_invokes_failure_callback_before_raising() -> None:
    """Mapped domain exceptions trigger the optional failure callback."""
    on_error = AsyncMock()

    with pytest.raises(ClientException) as exc_info:
        async with _map_domain_exceptions(
            {
                InvalidPasswordError: (400, ErrorCode.RESET_PASSWORD_INVALID_PASSWORD),
            },
            on_error=on_error,
        ):
            _raise_invalid_password()

    on_error.assert_awaited_once_with()
    assert exc_info.value.extra == {"code": ErrorCode.RESET_PASSWORD_INVALID_PASSWORD}


@pytest.mark.asyncio
async def test_map_domain_exceptions_maps_later_matching_error() -> None:
    """Later mapping entries still resolve when earlier ones do not match."""
    with pytest.raises(ClientException) as exc_info:
        async with _map_domain_exceptions(
            {
                UserAlreadyExistsError: (400, ErrorCode.REGISTER_USER_ALREADY_EXISTS),
                InvalidPasswordError: (400, ErrorCode.RESET_PASSWORD_INVALID_PASSWORD),
            },
        ):
            _raise_invalid_password()

    assert exc_info.value.status_code == STATUS_BAD_REQUEST
    assert exc_info.value.detail == "too weak"
    assert exc_info.value.extra == {"code": ErrorCode.RESET_PASSWORD_INVALID_PASSWORD}


@pytest.mark.asyncio
async def test_map_domain_exceptions_ignores_unmapped_exceptions() -> None:
    """Unmapped exceptions propagate unchanged."""
    with pytest.raises(RuntimeError, match="boom"):
        await _raise_runtime_error_in_mapped_context()


def test_require_msgspec_struct_accepts_msgspec_subclasses() -> None:
    """Msgspec structs are accepted without error."""
    _require_msgspec_struct(_MinimalStruct, parameter_name="schema")


def test_require_msgspec_struct_rejects_non_msgspec_types() -> None:
    """Non-msgspec types raise a clear type error."""
    with pytest.raises(TypeError, match=r"schema must be a msgspec\.Struct subclass\."):
        _require_msgspec_struct(dict, parameter_name="schema")


def test_to_user_schema_detects_multiple_sensitive_fields_outside_testing() -> None:
    """Production mode rejects any sensitive response fields present on the schema."""

    class _SensitivePasswordSchema(msgspec.Struct):
        id: str
        password: str
        totp_secret: str

    with pytest.raises(ConfigurationError, match="includes sensitive fields"):
        _to_user_schema(_DummyUser(), _SensitivePasswordSchema)


def test_to_user_schema_builds_safe_payload() -> None:
    """Public schemas are populated directly from user attributes."""
    user = _DummyUser()

    assert _to_user_schema(user, _UserReadSchema) == _UserReadSchema(
        id=user.id,
        email=user.email,
        roles=["member"],
    )


def test_to_user_schema_rejects_schema_fields_missing_from_user_object() -> None:
    """Misaligned public user schemas fail with a configuration error instead of raw AttributeError."""

    class _RolelessUser(msgspec.Struct):
        id: str = "user-id"
        email: str = "user@example.com"

    with pytest.raises(ConfigurationError, match=r"requires field 'roles'"):
        _to_user_schema(_RolelessUser(), _UserReadSchema)


def test_to_user_schema_rejects_sensitive_fields_outside_testing() -> None:
    """Sensitive response fields are rejected in production mode."""
    with pytest.raises(ConfigurationError, match="includes sensitive fields"):
        _to_user_schema(_DummyUser(), _SensitiveUserReadSchema)


def test_to_user_schema_allows_sensitive_fields_in_testing_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Testing mode keeps legacy behavior but emits a warning."""
    with caplog.at_level("WARNING"):
        result = _to_user_schema(_DummyUser(), _SensitiveUserReadSchema, unsafe_testing=True)

    assert result == _SensitiveUserReadSchema(id="user-id", hashed_password="hashed-secret")
    assert "sensitive fields" in caplog.text


def test_build_controller_name_normalizes_identifiers() -> None:
    """Underscores and hyphens are collapsed into title-cased class names."""
    assert _build_controller_name("oauth_google-provider") == "OauthGoogleProvider"


def test_build_controller_name_falls_back_for_empty_values() -> None:
    """Blank names produce the generated fallback prefix."""
    assert _build_controller_name("---") == "Generated"


def test_resolve_domain_error_response_prefers_first_matching_mapping() -> None:
    """The first compatible exception mapping wins for subclass matches."""
    mapping = cast(
        "dict[type[Exception], tuple[int, str]]",
        {
            Exception: (409, "GENERIC"),
            UserAlreadyExistsError: (400, ErrorCode.REGISTER_USER_ALREADY_EXISTS),
        },
    )

    assert _resolve_domain_error_response(UserAlreadyExistsError("dup"), mapping) == (409, "GENERIC")


def test_resolve_domain_error_response_raises_for_unmapped_errors() -> None:
    """Unexpected exceptions raise a lookup failure."""
    with pytest.raises(LookupError, match="Unmapped domain exception: RuntimeError"):
        _resolve_domain_error_response(RuntimeError("boom"), {})


@pytest.mark.asyncio
async def test_create_rate_limit_handlers_are_noops_without_rate_limit() -> None:
    """Missing rate-limit configuration produces no-op handlers."""
    increment, reset = _create_rate_limit_handlers(None)
    request: Any = object()

    await increment(cast("Any", request))
    await reset(cast("Any", request))


@pytest.mark.asyncio
async def test_create_rate_limit_handlers_delegate_to_rate_limit() -> None:
    """Increment and reset handlers delegate to the configured rate limit."""
    rate_limit = _MockRateLimit()
    request: Any = object()
    increment, reset = _create_rate_limit_handlers(cast("Any", rate_limit))

    await increment(cast("Any", request))
    await reset(cast("Any", request))

    rate_limit.increment.assert_awaited_once_with(request)
    rate_limit.reset.assert_awaited_once_with(request)


def test_create_before_request_handler_returns_none_without_rate_limit() -> None:
    """No before-request hook is created when rate limiting is disabled."""
    assert _create_before_request_handler(None) is None


@pytest.mark.asyncio
async def test_create_before_request_handler_delegates_to_rate_limit() -> None:
    """The generated before-request hook delegates to the configured limiter."""
    rate_limit = _MockRateLimit()
    request: Any = object()
    before_request = _create_before_request_handler(cast("Any", rate_limit))

    assert before_request is not None
    await before_request(cast("Any", request))

    rate_limit.before_request.assert_awaited_once_with(request)


def test_resolve_account_state_validator_returns_none_for_missing_manager() -> None:
    """No manager means no dedicated validator."""
    assert _resolve_account_state_validator(None) is None


def test_account_state_helper_aliases_point_to_shared_core() -> None:
    """Controllers and OAuth service share the same resolver core."""
    reloaded_utils = importlib.reload(_utils)
    reloaded_oauth_service = importlib.reload(oauth_service_module)

    assert reloaded_utils._resolve_account_state_validator is account_state_module.resolve_account_state_validator
    assert (
        reloaded_oauth_service._resolve_account_state_validator is account_state_module.resolve_account_state_validator
    )


def test_resolve_account_state_validator_returns_none_for_non_callable_attribute() -> None:
    """Managers without a callable validator fall back to attribute inspection."""

    class _Manager:
        require_account_state = "not-callable"

    assert _resolve_account_state_validator(cast("Any", _Manager())) is None


def test_resolve_account_state_validator_returns_callable_validator() -> None:
    """Callable manager validators are returned unchanged."""

    class _Manager:
        def require_account_state(self, user: object, *, require_verified: bool = False) -> None:
            return None

    manager = _Manager()
    validator = _resolve_account_state_validator(cast("Any", manager))
    assert validator is not None
    assert validator == manager.require_account_state


def test_require_account_state_from_attributes_allows_unverified_users_when_not_required() -> None:
    """Verification is skipped when the caller does not require it."""
    _require_account_state_from_attributes(
        _DummyUser(is_verified=False),
        require_verified=False,
        prioritize_unverified=False,
    )


def test_require_account_state_from_attributes_accepts_valid_user() -> None:
    """Valid guarded users pass attribute-based checks."""
    _require_account_state_from_attributes(
        _DummyUser(),
        require_verified=True,
        prioritize_unverified=False,
    )


def test_require_account_state_from_attributes_raises_inactive_first_by_default() -> None:
    """Inactive accounts take precedence over verification failures by default."""
    with pytest.raises(InactiveUserError):
        _require_account_state_from_attributes(
            _DummyUser(is_active=False, is_verified=False),
            require_verified=True,
            prioritize_unverified=False,
        )


def test_require_account_state_from_attributes_raises_unverified_when_required() -> None:
    """Verification failures raise the dedicated domain exception."""
    with pytest.raises(UnverifiedUserError):
        _require_account_state_from_attributes(
            _DummyUser(is_verified=False),
            require_verified=True,
            prioritize_unverified=False,
        )


def test_require_account_state_from_attributes_can_prioritize_unverified_first() -> None:
    """Attribute-based validation can preserve unverified-first ordering."""
    with pytest.raises(UnverifiedUserError):
        _require_account_state_from_attributes(
            _DummyUser(is_active=False, is_verified=False),
            require_verified=True,
            prioritize_unverified=True,
        )


@pytest.mark.asyncio
async def test_require_account_state_uses_manager_validator() -> None:
    """The shared helper delegates to an instance validator when available."""

    class _Manager:
        def __init__(self) -> None:
            self.calls: list[tuple[object, bool]] = []

        def require_account_state(self, user: object, *, require_verified: bool) -> None:
            self.calls.append((user, require_verified))

    manager = _Manager()
    user = _DummyUser()

    await _require_account_state(user, user_manager=cast("Any", manager), require_verified=False)

    assert manager.calls == [(user, False)]


@pytest.mark.asyncio
async def test_require_account_state_falls_back_when_manager_has_no_validator() -> None:
    """Managers without a callable validator use attribute-based validation."""

    class _Manager:
        require_account_state = "missing"

    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(
            _DummyUser(is_verified=False),
            user_manager=cast("Any", _Manager()),
            require_verified=True,
        )

    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_NOT_VERIFIED}


@pytest.mark.asyncio
async def test_require_account_state_falls_back_to_user_attributes_without_manager() -> None:
    """The shared helper still validates directly from user attributes when no validator is provided."""
    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(_DummyUser(is_verified=False), require_verified=True)

    assert exc_info.value.status_code == STATUS_BAD_REQUEST
    assert exc_info.value.detail == "The user account is not verified."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_NOT_VERIFIED}


@pytest.mark.asyncio
async def test_require_account_state_maps_inactive_manager_errors() -> None:
    """Inactive domain errors raised by a manager map to client errors."""

    class _Manager:
        def require_account_state(self, user: object, *, require_verified: bool) -> None:
            del user, require_verified
            raise InactiveUserError

    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(_DummyUser(), user_manager=cast("Any", _Manager()))

    assert exc_info.value.status_code == STATUS_BAD_REQUEST
    assert exc_info.value.detail == "The user account is inactive."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_INACTIVE}


@pytest.mark.asyncio
async def test_require_account_state_maps_unverified_manager_errors() -> None:
    """Unverified domain errors raised by a manager map to client errors."""

    class _Manager:
        def require_account_state(self, user: object, *, require_verified: bool) -> None:
            del user, require_verified
            raise UnverifiedUserError

    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(
            _DummyUser(),
            user_manager=cast("Any", _Manager()),
            require_verified=True,
        )

    assert exc_info.value.status_code == STATUS_BAD_REQUEST
    assert exc_info.value.detail == "The user account is not verified."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_NOT_VERIFIED}


@pytest.mark.asyncio
async def test_require_account_state_rejects_user_without_guarded_protocol_on_attribute_fallback() -> None:
    """Attribute fallback requires guarded account-state attributes."""
    with pytest.raises(PermissionDeniedException) as exc_info:
        await _require_account_state(_UserWithoutAccountState(), require_verified=False)

    assert "account state" in (exc_info.value.detail or "").lower()


@pytest.mark.asyncio
async def test_require_account_state_invokes_failure_callback_before_raising() -> None:
    """Failure callbacks run before the mapped client error is raised."""
    on_failure = AsyncMock()

    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(
            _DummyUser(is_active=False),
            require_verified=False,
            on_failure=on_failure,
        )

    on_failure.assert_awaited_once_with()
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_INACTIVE}


@pytest.mark.asyncio
async def test_require_account_state_invokes_failure_callback_for_unverified_errors() -> None:
    """Failure callbacks also run for unverified-account errors."""
    on_failure = AsyncMock()

    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(
            _DummyUser(is_verified=False),
            require_verified=True,
            on_failure=on_failure,
        )

    on_failure.assert_awaited_once_with()
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_NOT_VERIFIED}


@pytest.mark.asyncio
async def test_require_account_state_prioritizes_inactive_by_default() -> None:
    """Default ordering preserves inactive-account precedence."""
    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(
            _DummyUser(is_active=False, is_verified=False),
            require_verified=True,
        )

    assert exc_info.value.detail == "The user account is inactive."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_INACTIVE}


@pytest.mark.asyncio
async def test_require_account_state_can_prioritize_unverified_before_inactive() -> None:
    """Legacy login and TOTP flows can preserve unverified-first ordering when both checks fail."""
    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(
            _DummyUser(is_active=False, is_verified=False),
            require_verified=True,
            prioritize_unverified=True,
        )

    assert exc_info.value.detail == "The user account is not verified."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_NOT_VERIFIED}
