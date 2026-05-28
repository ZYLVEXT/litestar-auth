"""Regression coverage for Redis/TOTP secondary documentation guidance."""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path

import pytest

from litestar_auth import ApiKeyConfig, LitestarAuthConfig, OAuthConfig, UserManagerSecurity
from litestar_auth.authentication.transport.cookie import CookieTransportConfig
from litestar_auth.ratelimit import EndpointRateLimit


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "config_link"),
    [
        ("docs/deployment.md", "configuration/redis.md#redis-backed-auth-surface"),
        ("docs/guides/totp.md", "../configuration/redis.md#redis-backed-auth-surface"),
        ("docs/guides/rate_limiting.md", "../configuration/redis.md#redis-backed-auth-surface"),
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
def test_totp_stepup_docs_keep_security_contract_discoverable() -> None:
    """TOTP step-up docs should keep the public config and endpoint table anchored."""
    totp_content = Path("docs/configuration/totp.md").read_text(encoding="utf-8")
    security_content = Path("docs/security.md").read_text(encoding="utf-8")
    http_api_content = Path("docs/http_api.md").read_text(encoding="utf-8")
    errors_content = Path("docs/errors.md").read_text(encoding="utf-8")

    anchor = "#totp-step-up-for-sensitive-operations"
    assert "## TOTP step-up for sensitive operations {#totp-step-up-for-sensitive-operations}" in totp_content
    assert f"configuration/totp.md{anchor}" in security_content
    assert f"configuration/totp.md{anchor}" in http_api_content
    assert f"configuration/totp.md{anchor}" in errors_content

    for field_name in ("totp_stepup_ttl_seconds", "totp_stepup_policy", "totp_stepup_allow_recovery"):
        assert field_name in totp_content

    for endpoint_key in (
        "users.update_self",
        "api_keys.create",
        "api_keys.update",
        "api_keys.revoke",
        "oauth.associate",
        "totp.disable",
        "totp.regenerate_recovery_codes",
    ):
        assert endpoint_key in totp_content

    assert "`TOTP_STEPUP_REQUIRED`" in totp_content
    assert "`required_when_enrolled`" in totp_content
    assert "`always_required`" in totp_content
    assert "`off`" in totp_content
    assert "API-key authenticated requests cannot complete an interactive TOTP challenge." in totp_content


@pytest.mark.unit
def test_deployment_security_contract_references_runtime_config_fields() -> None:
    """Deployment security docs should name the real public config fields they constrain."""
    deployment_content = Path("docs/deployment.md").read_text(encoding="utf-8")
    security_content = Path("docs/security.md").read_text(encoding="utf-8")
    readme_content = Path("README.md").read_text(encoding="utf-8")

    assert "### Reverse-proxy and trust boundaries" in deployment_content
    assert "### Cookie transport security requirements" in deployment_content
    assert "### Secrets at rest and key rotation" in deployment_content
    assert "rightmost" in deployment_content
    assert "X-Forwarded-For" in deployment_content

    endpoint_limit_fields = {field.name for field in fields(EndpointRateLimit)}
    assert {"trusted_proxy", "trusted_headers"} <= endpoint_limit_fields
    for field_name in ("trusted_proxy", "trusted_headers"):
        assert field_name in deployment_content

    cookie_fields = {field.name for field in fields(CookieTransportConfig)}
    plugin_fields = {field.name for field in fields(LitestarAuthConfig)}
    assert {"secure", "samesite", "allow_insecure_cookie_auth"} <= cookie_fields
    assert {"csrf_secret", "csrf_header_name"} <= plugin_fields
    for field_name in ("secure", "samesite", "allow_insecure_cookie_auth", "csrf_secret", "csrf_header_name"):
        assert field_name in deployment_content

    oauth_fields = {field.name for field in fields(OAuthConfig)}
    manager_security_fields = {field.name for field in fields(UserManagerSecurity)}
    api_key_fields = {field.name for field in fields(ApiKeyConfig)}
    assert {"oauth_token_encryption_keyring", "oauth_token_encryption_key"} <= oauth_fields
    assert {"totp_secret_keyring", "totp_secret_key"} <= manager_security_fields
    assert "secret_encryption_keyring" in api_key_fields
    for field_name in (
        "oauth_token_encryption_keyring",
        "oauth_token_encryption_key",
        "totp_secret_keyring",
        "totp_secret_key",
        "secret_encryption_keyring",
    ):
        assert field_name in deployment_content

    for anchor in (
        "deployment.md#reverse-proxy-and-trust-boundaries",
        "deployment.md#cookie-transport-security-requirements",
        "deployment.md#secrets-at-rest-and-key-rotation",
    ):
        assert anchor in security_content

    assert "#deployment-security-contract" in readme_content
