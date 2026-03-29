"""Reload-based coverage tests for small authentication and OAuth modules."""

from __future__ import annotations

import importlib

import pytest

import litestar_auth.authentication.strategy._opaque_tokens as opaque_tokens_module
import litestar_auth.oauth as oauth_module
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key, digest_opaque_token
from litestar_auth.oauth.router import create_provider_oauth_controller, load_httpx_oauth_client

pytestmark = [pytest.mark.unit, pytest.mark.imports]


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

    assert exported_names == ("create_provider_oauth_controller", "load_httpx_oauth_client")
    assert reloaded_module.create_provider_oauth_controller is getattr(oauth_module, exported_names[0])
    assert reloaded_module.load_httpx_oauth_client is getattr(oauth_module, exported_names[1])
    assert reloaded_module.create_provider_oauth_controller.__name__ == create_provider_oauth_controller.__name__
    assert reloaded_module.load_httpx_oauth_client.__name__ == load_httpx_oauth_client.__name__


def test_oauth_init_unknown_export_raises_attribute_error() -> None:
    """Unsupported lazy exports should raise the standard module attribute error."""
    missing_name = "does_not_exist"

    with pytest.raises(AttributeError, match="does_not_exist"):
        getattr(oauth_module, missing_name)
