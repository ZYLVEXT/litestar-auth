"""Regression tests for secret-safe object representations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from litestar_auth._jwt_headers import JwtDecodeConfig
from litestar_auth._manager.account_tokens import OrganizationInvitationToken, TokenWriteRequest
from litestar_auth._secret_roles import SecretRoleValues
from litestar_auth._totp_enrollment import _EnrollmentTokenIssueConfig
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategyConfig
from litestar_auth.authentication.strategy.redis import RedisTokenStrategyConfig
from litestar_auth.config import OAuthProviderConfig
from litestar_auth.contrib.organization_admin._schemas import OrganizationInvitationTokenRequest
from litestar_auth.controllers._step_up import TotpStepUpCheck
from litestar_auth.controllers.auth import AuthControllerConfig
from litestar_auth.controllers.oauth import OAuthAssociateControllerConfig, OAuthControllerConfig
from litestar_auth.db import OAuthAccountData
from litestar_auth.oauth._authorization import OAuthAuthorization
from litestar_auth.oauth._pkce import PkceMaterial
from litestar_auth.oauth.fapi import FAPIAuthorization
from litestar_auth.oauth.router import ProviderOAuthControllerConfig
from litestar_auth.payloads import (
    LoginCredentials,
    ResetPassword,
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpEnableResponse,
    TotpRecoveryCodesResponse,
    TotpRegenerateRecoveryCodesRequest,
    TotpVerifyRequest,
    VerifyToken,
)
from litestar_auth.schemas import AdminUserUpdate, ChangePasswordRequest, UserCreate, UserUpdate
from litestar_auth.totp_flow import TotpLoginFlowConfig

pytestmark = pytest.mark.unit

_SECRET_CANARY = "SECRET_CANARY_7f53"
_DEPENDENCY: Any = object()


class _SecretBearingOAuthClient:
    def __repr__(self) -> str:
        return _SECRET_CANARY


_SECRET_BEARING_OAUTH_CLIENT: Any = _SecretBearingOAuthClient()


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(
            TokenWriteRequest("subject", "audience", _SECRET_CANARY, timedelta(minutes=5)),
            id="token-write-request",
        ),
        pytest.param(
            JwtDecodeConfig(
                key=_SECRET_CANARY,
                algorithms=("HS256",),
                audience="audience",
                options={},
            ),
            id="jwt-decode-config",
        ),
        pytest.param(
            OrganizationInvitationToken(
                _SECRET_CANARY,
                _SECRET_CANARY.encode(),
                datetime(2026, 8, 1, tzinfo=UTC),
            ),
            id="organization-invitation-token",
        ),
        pytest.param(
            DatabaseTokenStrategyConfig(session=_DEPENDENCY, token_hash_secret=_SECRET_CANARY),
            id="database-token-strategy",
        ),
        pytest.param(
            RedisTokenStrategyConfig(redis=_DEPENDENCY, token_hash_secret=_SECRET_CANARY),
            id="redis-token-strategy",
        ),
        pytest.param(
            AuthControllerConfig(
                backend=_DEPENDENCY,
                account_lockout_key_secret=_SECRET_CANARY,
                totp_pending_secret=_SECRET_CANARY,
            ),
            id="auth-controller",
        ),
        pytest.param(
            OAuthControllerConfig(
                provider_name="provider",
                backend=_DEPENDENCY,
                user_manager=_DEPENDENCY,
                oauth_client=_SECRET_BEARING_OAUTH_CLIENT,
                redirect_base_url="https://app.example/callback",
                oauth_flow_cookie_secret=_SECRET_CANARY,
            ),
            id="oauth-controller",
        ),
        pytest.param(
            OAuthAssociateControllerConfig(
                provider_name="provider",
                oauth_client=_SECRET_BEARING_OAUTH_CLIENT,
                redirect_base_url="https://app.example/callback",
                oauth_flow_cookie_secret=_SECRET_CANARY,
            ),
            id="oauth-associate-controller",
        ),
        pytest.param(
            ProviderOAuthControllerConfig(
                provider_name="provider",
                backend=_DEPENDENCY,
                user_manager=_DEPENDENCY,
                redirect_base_url="https://app.example/callback",
                oauth_flow_cookie_secret=_SECRET_CANARY,
                oauth_client_kwargs={"client_secret": _SECRET_CANARY},
            ),
            id="provider-oauth-controller",
        ),
        pytest.param(
            OAuthProviderConfig("provider", _SECRET_BEARING_OAUTH_CLIENT),
            id="oauth-provider",
        ),
        pytest.param(
            TotpStepUpCheck(
                endpoint="users.update_self",
                policy={},
                user_manager=_DEPENDENCY,
                totp_code=_SECRET_CANARY,
            ),
            id="totp-step-up",
        ),
        pytest.param(
            _EnrollmentTokenIssueConfig(
                signing_key=_SECRET_CANARY,
                cipher=_DEPENDENCY,
                enrollment_store=_DEPENDENCY,
            ),
            id="totp-enrollment-issue",
        ),
        pytest.param(
            OAuthAccountData(
                oauth_name="provider",
                account_id="account",
                account_email="user@example.com",
                access_token=_SECRET_CANARY,
                expires_at=None,
                refresh_token=_SECRET_CANARY,
            ),
            id="oauth-account-data",
        ),
        pytest.param(TotpLoginFlowConfig(_SECRET_CANARY), id="totp-login-flow"),
        pytest.param(
            OAuthAuthorization(_SECRET_CANARY, _SECRET_CANARY, _SECRET_CANARY),
            id="oauth-authorization",
        ),
        pytest.param(PkceMaterial(_SECRET_CANARY, "challenge", "S256"), id="pkce-material"),
        pytest.param(
            FAPIAuthorization(
                authorization_url=_SECRET_CANARY,
                request_uri=_SECRET_CANARY,
                expires_in=60,
                state=_SECRET_CANARY,
                nonce=_SECRET_CANARY,
                code_verifier=_SECRET_CANARY,
            ),
            id="fapi-authorization",
        ),
        pytest.param(
            SecretRoleValues(
                verification_token_secret=_SECRET_CANARY,
                reset_password_token_secret=_SECRET_CANARY,
                organization_invitation_token_secret=_SECRET_CANARY,
                login_identifier_telemetry_secret=_SECRET_CANARY,
                totp_secret_key=_SECRET_CANARY,
                totp_pending_secret=_SECRET_CANARY,
                totp_recovery_code_lookup_secret=_SECRET_CANARY,
                oauth_flow_cookie_secret=_SECRET_CANARY,
            ),
            id="secret-role-values",
        ),
    ],
)
def test_dataclass_representations_do_not_expose_secrets(value: object) -> None:
    """Credential-bearing dataclasses must not render raw secret values."""
    assert _SECRET_CANARY not in repr(value)
    assert _SECRET_CANARY not in str(value)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(LoginCredentials("user@example.com", _SECRET_CANARY), id="login-credentials"),
        pytest.param(ResetPassword(_SECRET_CANARY, _SECRET_CANARY), id="reset-password"),
        pytest.param(VerifyToken(_SECRET_CANARY), id="verify-token"),
        pytest.param(
            TotpEnableResponse(_SECRET_CANARY, _SECRET_CANARY, _SECRET_CANARY),
            id="totp-enable-response",
        ),
        pytest.param(TotpEnableRequest(_SECRET_CANARY), id="totp-enable-request"),
        pytest.param(
            TotpRegenerateRecoveryCodesRequest(current_password=_SECRET_CANARY, totp_code=_SECRET_CANARY),
            id="totp-regenerate-recovery-codes",
        ),
        pytest.param(TotpRecoveryCodesResponse((_SECRET_CANARY,)), id="totp-recovery-codes-response"),
        pytest.param(TotpVerifyRequest(_SECRET_CANARY, _SECRET_CANARY), id="totp-verify-request"),
        pytest.param(TotpConfirmEnableRequest(_SECRET_CANARY, _SECRET_CANARY), id="totp-confirm-enable-request"),
        pytest.param(
            TotpConfirmEnableResponse(enabled=True, recovery_codes=(_SECRET_CANARY,)),
            id="totp-confirm-enable-response",
        ),
        pytest.param(TotpDisableRequest(_SECRET_CANARY), id="totp-disable-request"),
        pytest.param(UserCreate("user@example.com", _SECRET_CANARY), id="user-create"),
        pytest.param(UserUpdate(current_password=_SECRET_CANARY, totp_code=_SECRET_CANARY), id="user-update"),
        pytest.param(
            AdminUserUpdate(password=_SECRET_CANARY, current_password=_SECRET_CANARY, totp_code=_SECRET_CANARY),
            id="admin-user-update",
        ),
        pytest.param(ChangePasswordRequest(_SECRET_CANARY, _SECRET_CANARY), id="change-password"),
        pytest.param(OrganizationInvitationTokenRequest(_SECRET_CANARY), id="organization-invitation-request"),
    ],
)
def test_msgspec_representations_do_not_expose_secrets(value: object) -> None:
    """Credential-bearing request and response structs must redact every field."""
    assert _SECRET_CANARY not in repr(value)
    assert _SECRET_CANARY not in str(value)
