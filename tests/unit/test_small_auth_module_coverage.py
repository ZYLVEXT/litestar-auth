"""Reload-based coverage tests for small authentication and OAuth modules."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

import pytest

import litestar_auth.oauth as oauth_module
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key, digest_opaque_token

if TYPE_CHECKING:
    from types import ModuleType

pytestmark = [pytest.mark.unit, pytest.mark.imports]
EMAIL_MAX_LENGTH = 320
LOGIN_IDENTIFIER_MAX_LENGTH = 320
REFRESH_TOKEN_MAX_LENGTH = 512
LONG_LIVED_TOKEN_MAX_LENGTH = 2048
TOTP_CODE_LENGTH = 6
ACCOUNT_IDENTITY_LENGTH = 2


def _current_oauth_client_adapter_module() -> ModuleType:
    """Return the current OAuth client-adapter module after any reloads."""
    return importlib.import_module("litestar_auth.oauth.client_adapter")


def _current_oauth_router_module() -> ModuleType:
    """Return the current OAuth router module after any reloads."""
    return importlib.import_module("litestar_auth.oauth.router")


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


def test_oauth_init_unknown_export_raises_attribute_error() -> None:
    """Unsupported lazy exports should raise the standard module attribute error."""
    missing_name = "does_not_exist"

    with pytest.raises(AttributeError, match="does_not_exist"):
        getattr(oauth_module, missing_name)


def test_oauth_init_does_not_reexport_advanced_controller_factory() -> None:
    """The advanced OAuth controller factory stays on ``litestar_auth.controllers``."""
    with pytest.raises(AttributeError, match="create_oauth_controller"):
        _ = oauth_module.create_oauth_controller
