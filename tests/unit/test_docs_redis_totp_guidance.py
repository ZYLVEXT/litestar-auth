"""Regression coverage for Redis/TOTP secondary documentation guidance."""

from __future__ import annotations

from pathlib import Path

import pytest

DOCS_ROOT = Path("docs")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "config_link"),
    [
        ("docs/deployment.md", "configuration.md#redis-backed-auth-surface"),
        ("docs/guides/totp.md", "../configuration.md#redis-backed-auth-surface"),
        ("docs/guides/rate_limiting.md", "../configuration.md#redis-backed-auth-surface"),
    ],
)
def test_secondary_redis_totp_docs_link_to_shared_client_recipe(path: str, config_link: str) -> None:
    """Secondary Redis/TOTP docs should point back to the shared-client configuration recipe."""
    content = Path(path).read_text(encoding="utf-8")

    assert config_link in content


@pytest.mark.unit
@pytest.mark.parametrize(
    "path",
    [
        "docs/deployment.md",
        "docs/guides/totp.md",
        "docs/guides/rate_limiting.md",
    ],
)
def test_secondary_redis_totp_docs_keep_store_roles_visible(path: str) -> None:
    """Secondary Redis/TOTP docs should keep enrollment, pending-token, and used-code stores distinct."""
    content = Path(path).read_text(encoding="utf-8")

    assert "totp_enrollment_store" in content
    assert "totp_pending_jti_store" in content
    assert "totp_used_tokens_store" in content


@pytest.mark.unit
def test_docs_avoid_legacy_path_vocabulary() -> None:
    """Documentation should use direct decision rules instead of canonical/shim framing."""
    banned_terms = ("canonical", "compatibility shim", "preferred one-client", "escape hatch")

    for doc_path in DOCS_ROOT.rglob("*.md"):
        content = doc_path.read_text(encoding="utf-8").lower()
        for banned_term in banned_terms:
            assert banned_term not in content, f"{doc_path} still contains {banned_term!r}"
