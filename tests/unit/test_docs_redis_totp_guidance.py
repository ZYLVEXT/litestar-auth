"""Regression coverage for Redis/TOTP secondary documentation guidance."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "canonical_link"),
    [
        ("docs/deployment.md", "configuration.md#canonical-redis-backed-auth-surface"),
        ("docs/guides/totp.md", "../configuration.md#canonical-redis-backed-auth-surface"),
        ("docs/guides/rate_limiting.md", "../configuration.md#canonical-redis-backed-auth-surface"),
    ],
)
def test_secondary_redis_totp_docs_link_to_canonical_recipe(path: str, canonical_link: str) -> None:
    """Secondary Redis/TOTP docs should point back to the canonical configuration recipe."""
    content = Path(path).read_text(encoding="utf-8")

    assert canonical_link in content


@pytest.mark.unit
@pytest.mark.parametrize(
    "path",
    [
        "docs/deployment.md",
        "docs/guides/totp.md",
        "docs/guides/rate_limiting.md",
    ],
)
def test_secondary_redis_totp_docs_keep_both_store_roles_visible(path: str) -> None:
    """Secondary Redis/TOTP docs should keep pending-token and used-code stores distinct."""
    content = Path(path).read_text(encoding="utf-8")

    assert "totp_pending_jti_store" in content
    assert "totp_used_tokens_store" in content
