"""Reload-based coverage tests for small authentication and OAuth modules."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

import pytest

import litestar_auth._schema_fields as schema_fields_module
import litestar_auth.authentication.strategy._opaque_tokens as opaque_tokens_module
import litestar_auth.oauth as oauth_module
import litestar_auth.payloads as payloads_module
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key, digest_opaque_token
from litestar_auth.oauth.client_adapter import (
    OAuthEmailVerificationAsyncClientProtocol,
    OAuthEmailVerificationSyncClientProtocol,
    make_async_email_verification_client,
)
from litestar_auth.oauth.router import create_provider_oauth_controller, load_httpx_oauth_client
from litestar_auth.payloads import LoginCredentials
from litestar_auth.schemas import UserCreate

if TYPE_CHECKING:
    from types import ModuleType

pytestmark = [pytest.mark.unit, pytest.mark.imports]
EMAIL_MAX_LENGTH = 320
LOGIN_IDENTIFIER_MAX_LENGTH = 320
REFRESH_TOKEN_MAX_LENGTH = 512
LONG_LIVED_TOKEN_MAX_LENGTH = 2048
TOTP_CODE_LENGTH = 6


def _current_oauth_client_adapter_module() -> ModuleType:
    """Return the current OAuth client-adapter module after any reloads."""
    return importlib.import_module("litestar_auth.oauth.client_adapter")


def _current_oauth_router_module() -> ModuleType:
    """Return the current OAuth router module after any reloads."""
    return importlib.import_module("litestar_auth.oauth.router")


def test_opaque_tokens_module_executes_under_coverage() -> None:
    """Reload the opaque-token helpers so coverage records their module body."""
    reloaded_module = importlib.reload(opaque_tokens_module)

    assert reloaded_module is opaque_tokens_module
    assert reloaded_module.digest_opaque_token.__name__ == digest_opaque_token.__name__
    assert reloaded_module.build_opaque_token_key.__name__ == build_opaque_token_key.__name__


def test_digest_opaque_token_matches_expected_hmac_digest() -> None:
    """Digesting an opaque token should remain stable for persisted tokens."""
    digest = digest_opaque_token(
        token_hash_secret=b"small-auth-gap-secret",
        token="opaque-token",
    )

    assert digest == "ce0133e3cb70fc8d44594a89a14c808f408e0ab495eb02560931fea996b0849d"


def test_build_opaque_token_key_prefixes_digest() -> None:
    """Opaque-token storage keys should namespace the digest without leaking the raw token."""
    token_key = build_opaque_token_key(
        key_prefix="litestar_auth:opaque:",
        token_hash_secret=b"small-auth-gap-secret",
        token="opaque-token",
    )

    assert token_key == "litestar_auth:opaque:ce0133e3cb70fc8d44594a89a14c808f408e0ab495eb02560931fea996b0849d"
    assert "opaque-token" not in token_key


def test_oauth_init_module_executes_under_coverage() -> None:
    """Reload the OAuth package and verify its lazy exports remain accessible."""
    reloaded_module = importlib.reload(oauth_module)
    exported_names = reloaded_module.__all__
    current_client_adapter_module = _current_oauth_client_adapter_module()
    current_router_module = _current_oauth_router_module()

    assert exported_names == (
        "OAuthEmailVerificationAsyncClientProtocol",
        "OAuthEmailVerificationSyncClientProtocol",
        "create_provider_oauth_controller",
        "load_httpx_oauth_client",
        "make_async_email_verification_client",
    )
    assert (
        reloaded_module.OAuthEmailVerificationAsyncClientProtocol
        is current_client_adapter_module.OAuthEmailVerificationAsyncClientProtocol
    )
    assert (
        reloaded_module.OAuthEmailVerificationSyncClientProtocol
        is current_client_adapter_module.OAuthEmailVerificationSyncClientProtocol
    )
    assert reloaded_module.create_provider_oauth_controller is current_router_module.create_provider_oauth_controller
    assert reloaded_module.load_httpx_oauth_client is current_router_module.load_httpx_oauth_client
    assert (
        reloaded_module.make_async_email_verification_client
        is current_client_adapter_module.make_async_email_verification_client
    )
    assert (
        reloaded_module.OAuthEmailVerificationAsyncClientProtocol.__name__
        == OAuthEmailVerificationAsyncClientProtocol.__name__
    )
    assert (
        reloaded_module.OAuthEmailVerificationSyncClientProtocol.__name__
        == OAuthEmailVerificationSyncClientProtocol.__name__
    )
    assert reloaded_module.create_provider_oauth_controller.__name__ == create_provider_oauth_controller.__name__
    assert reloaded_module.load_httpx_oauth_client.__name__ == load_httpx_oauth_client.__name__
    assert (
        reloaded_module.make_async_email_verification_client.__name__ == make_async_email_verification_client.__name__
    )


def test_oauth_init_unknown_export_raises_attribute_error() -> None:
    """Unsupported lazy exports should raise the standard module attribute error."""
    missing_name = "does_not_exist"

    with pytest.raises(AttributeError, match="does_not_exist"):
        getattr(oauth_module, missing_name)


def test_oauth_init_does_not_reexport_advanced_controller_factory() -> None:
    """The advanced OAuth controller factory stays on ``litestar_auth.controllers``."""
    with pytest.raises(AttributeError, match="create_oauth_controller"):
        _ = oauth_module.create_oauth_controller


def test_payloads_module_executes_under_coverage() -> None:
    """Reload the payload boundary and keep its built-in structs reachable."""
    reloaded_module = importlib.reload(payloads_module)

    assert reloaded_module is payloads_module
    assert reloaded_module.__all__ == (
        "ForgotPassword",
        "LoginCredentials",
        "RefreshTokenRequest",
        "RequestVerifyToken",
        "ResetPassword",
        "TotpConfirmEnableRequest",
        "TotpConfirmEnableResponse",
        "TotpDisableRequest",
        "TotpEnableRequest",
        "TotpEnableResponse",
        "TotpVerifyRequest",
        "VerifyToken",
    )
    assert reloaded_module.LoginCredentials.__name__ == LoginCredentials.__name__
    assert UserCreate.__struct_fields__ == ("email", "password")
    assert not hasattr(reloaded_module, "UserCreate")


def test_schema_fields_module_executes_under_coverage() -> None:
    """Reload the shared schema-field module so coverage records its module body."""
    reloaded_module = importlib.reload(schema_fields_module)

    assert reloaded_module is schema_fields_module
    assert reloaded_module.EMAIL_PATTERN == r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    assert reloaded_module.EMAIL_MAX_LENGTH == EMAIL_MAX_LENGTH
    assert reloaded_module.LOGIN_IDENTIFIER_MAX_LENGTH == LOGIN_IDENTIFIER_MAX_LENGTH
    assert reloaded_module.REFRESH_TOKEN_MAX_LENGTH == REFRESH_TOKEN_MAX_LENGTH
    assert reloaded_module.LONG_LIVED_TOKEN_MAX_LENGTH == LONG_LIVED_TOKEN_MAX_LENGTH
    assert reloaded_module.TOTP_CODE_LENGTH == TOTP_CODE_LENGTH
