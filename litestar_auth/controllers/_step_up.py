"""Centralized step-up policy helpers for generated controllers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example

from litestar_auth.controllers._error_responses import raise_step_up_required, raise_wrong_current_password
from litestar_auth.exceptions import ErrorCode
from litestar_auth.totp import verify_totp
from litestar_auth.types import LoginIdentifier, TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.totp import TotpAlgorithm

type TotpStepUpEndpoint = Literal[
    "totp.disable",
    "totp.regenerate_recovery_codes",
    "api_keys.create",
    "api_keys.update",
    "api_keys.revoke",
    "users.update",
    "users.delete",
    "users.update_self",
    "oauth.associate",
]
type TotpStepUpPolicyMode = Literal["required_when_enrolled", "always_required", "off"]
type StepUpCallback = Callable[[], Awaitable[None]]

_DEFAULT_TOTP_STEPUP_POLICY: dict[TotpStepUpEndpoint, TotpStepUpPolicyMode] = {
    "totp.disable": "required_when_enrolled",
    "totp.regenerate_recovery_codes": "required_when_enrolled",
    "api_keys.create": "required_when_enrolled",
    "api_keys.update": "required_when_enrolled",
    "api_keys.revoke": "required_when_enrolled",
    "users.update": "required_when_enrolled",
    "users.delete": "required_when_enrolled",
    "users.update_self": "required_when_enrolled",
    "oauth.associate": "required_when_enrolled",
}

TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE = ResponseSpec(
    data_container=dict[str, object],
    generate_examples=False,
    description="The operation requires a recent TOTP verification (`TOTP_STEPUP_REQUIRED`).",
    examples=[
        Example(
            id="totp_stepup_required",
            summary="Recent TOTP verification required",
            value={
                "status_code": 403,
                "detail": "Recent TOTP verification is required.",
                "extra": {"code": ErrorCode.TOTP_STEPUP_REQUIRED.value},
            },
        ),
    ],
)


class PasswordStepUpUserProtocol[ID](UserProtocol[ID], Protocol):
    """User fields required by current-password step-up checks."""

    email: str


class PasswordStepUpAuthenticatorProtocol(Protocol):
    """User-manager behavior required by current-password step-up checks."""

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: LoginIdentifier | None = None,
    ) -> UserProtocol[Any] | None:
        """Return the authenticated user for valid credentials."""


@dataclass(frozen=True, slots=True)
class PasswordStepUpCheck[UP: PasswordStepUpUserProtocol[Any]]:
    """Inputs for a current-password step-up check."""

    user: UP
    user_manager: PasswordStepUpAuthenticatorProtocol
    current_password: str | None
    on_failure: StepUpCallback
    on_success: StepUpCallback | None = None
    login_identifier: LoginIdentifier = "email"


async def require_password_step_up[UP: PasswordStepUpUserProtocol[Any]](check: PasswordStepUpCheck[UP]) -> None:
    """Re-authenticate ``check.user`` with their current password before a sensitive mutation."""
    authenticated = (
        await check.user_manager.authenticate(
            check.user.email,
            check.current_password,
            login_identifier=check.login_identifier,
        )
        if check.current_password is not None
        else None
    )
    if authenticated is None or getattr(authenticated, "id", None) != getattr(check.user, "id", None):
        await check.on_failure()
        raise_wrong_current_password()
    if check.on_success is not None:
        await check.on_success()


class TotpStepUpVerifierProtocol[UP: UserProtocol[Any]](Protocol):
    """User-manager behavior required by downstream TOTP step-up checks."""

    backends: tuple[object, ...]

    async def has_recent_totp_verification(self, user: UP, session_id: str) -> bool:
        """Return whether the current session has a recent TOTP marker."""

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return the plain TOTP secret for verification."""


@dataclass(frozen=True, slots=True)
class TotpStepUpCheck[UP: UserProtocol[Any]]:
    """Inputs for an endpoint-level TOTP step-up check."""

    endpoint: TotpStepUpEndpoint
    policy: dict[str, TotpStepUpPolicyMode]
    user_manager: TotpStepUpVerifierProtocol[UP]
    totp_code: str | None = None
    totp_algorithm: TotpAlgorithm = "SHA256"


async def require_totp_stepup[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    check: TotpStepUpCheck[UP],
) -> None:
    """Enforce endpoint-level TOTP step-up policy before sensitive mutations."""
    mode = check.policy.get(check.endpoint, _DEFAULT_TOTP_STEPUP_POLICY[check.endpoint])
    if mode == "off":
        return
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        return
    if user.totp_secret is None:
        if mode == "always_required":
            raise_step_up_required()
        return
    secret = await check.user_manager.read_totp_secret(user.totp_secret)
    if secret is None:
        if mode == "always_required":
            raise_step_up_required()
        return
    if check.totp_code is not None and verify_totp(secret, check.totp_code, algorithm=check.totp_algorithm):
        return
    session_id = await _resolve_current_session_id(request, user_manager=check.user_manager)
    if session_id is not None and await check.user_manager.has_recent_totp_verification(cast("UP", user), session_id):
        return
    raise_step_up_required()


async def _resolve_current_session_id[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    *,
    user_manager: TotpStepUpVerifierProtocol[UP],
) -> str | None:
    """Return the current transport token to use as the step-up marker session id."""
    for backend in user_manager.backends:
        transport = getattr(backend, "transport", None)
        read_token = getattr(transport, "read_token", None)
        if read_token is None:
            continue
        token = await read_token(request)
        if isinstance(token, str) and token:
            return token
    return None
