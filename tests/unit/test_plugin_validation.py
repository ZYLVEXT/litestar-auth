"""Unit tests for plugin validation and runtime helper checks."""

from __future__ import annotations

import importlib
import warnings
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast, get_args
from uuid import UUID

import msgspec
import pytest
from cryptography.fernet import Fernet
from litestar.config.app import AppConfig

import litestar_auth._plugin._redirect_validation as redirect_validation_module
import litestar_auth._plugin.config as plugin_config_module
import litestar_auth._plugin.rate_limit as rate_limit_module
import litestar_auth._plugin.security_policy as plugin_security_policy_module
import litestar_auth._plugin.startup as startup_module
import litestar_auth._plugin.user_manager_builder as user_manager_builder_module
import litestar_auth._plugin.validation as validation_module
import litestar_auth._plugin.validation.request_security as request_security_validation_module
from litestar_auth._plugin import api_key_validation, oauth_validation, totp_validation
from litestar_auth._plugin.features import ApiKeyLastUsedWriteStrategy
from litestar_auth._plugin.middleware import build_csrf_config, get_cookie_transports
from litestar_auth._plugin.validation._core import (
    IssueCollector,
    ValidationIssue,
    format_configuration_message,
    format_validation_issues,
    raise_configuration_error,
    require_callable,
    require_non_empty,
    require_secret_length,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy import InMemoryApiKeyNonceStore
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.transport.api_key import ApiKeyTransport
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.config import (
    RESET_PASSWORD_TOKEN_AUDIENCE,
    TOTP_ENROLL_AUDIENCE,
    TOTP_PENDING_AUDIENCE,
    VERIFY_TOKEN_AUDIENCE,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.manager import BaseUserManager, TotpSecretStoragePosture, UserManagerSecurity
from litestar_auth.models import User as OrmUser
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import FernetKeyringConfig
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter, RateLimiterBackend
from litestar_auth.totp import InMemoryUsedTotpCodeStore
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryRefreshTokenStrategy,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

DEFAULT_CSRF_COOKIE_NAME = plugin_config_module.DEFAULT_CSRF_COOKIE_NAME
API_KEY_HASH_SECRET = "api-key-hash-secret-0123456789abcdef"
ApiKeyConfig = plugin_config_module.ApiKeyConfig
DatabaseTokenAuthConfig = plugin_config_module.DatabaseTokenAuthConfig
LitestarAuthConfig = plugin_config_module.LitestarAuthConfig
OAuthConfig = plugin_config_module.OAuthConfig
TotpConfig = plugin_config_module.TotpConfig
iter_rate_limit_endpoints = rate_limit_module.iter_rate_limit_endpoints
has_configured_oauth_providers = startup_module.has_configured_oauth_providers
has_configured_oauth_providers_for = startup_module.has_configured_oauth_providers_for
require_oauth_token_encryption_for_configured_providers = (
    startup_module.require_oauth_token_encryption_for_configured_providers
)
require_secure_oauth_redirect_in_production = startup_module.require_secure_oauth_redirect_in_production
warn_insecure_plugin_startup_defaults = startup_module.warn_insecure_plugin_startup_defaults
_validate_backend_strategy_security = validation_module._validate_backend_strategy_security
_validate_totp_encryption_key = validation_module._validate_totp_encryption_key
_validate_totp_pending_secret_config = validation_module._validate_totp_pending_secret_config
validate_config = validation_module.validate_config
validate_api_key_config = validation_module.validate_api_key_config
validate_cookie_auth_config = validation_module.validate_cookie_auth_config
validate_password_validator_config = validation_module.validate_password_validator_config
validate_rate_limit_config = validation_module.validate_rate_limit_config
validate_session_maker_or_external_db_session = validation_module.validate_session_maker_or_external_db_session
validate_superuser_role_name_config = validation_module.validate_superuser_role_name_config
validate_totp_config = validation_module.validate_totp_config
validate_totp_sub_config = validation_module.validate_totp_sub_config
validate_totp_user_model_protocol = validation_module.validate_totp_user_model_protocol
validate_user_manager_security_config = validation_module.validate_user_manager_security_config
validate_user_model_login_identifier_fields = validation_module.validate_user_model_login_identifier_fields

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.authentication.strategy.jwt import JWTStrategy
    from litestar_auth.config import OAuthProviderConfig

pytestmark = pytest.mark.unit
OAUTH_FLOW_COOKIE_SECRET = "oauth-flow-cookie-secret-1234567890"

JWT_SECRET = "0123456789abcdef" * 4
TOKEN_HASH_SECRET = "fedcba9876543210" * 4
VERIFICATION_SECRET = "89abcdef01234567" * 4
RESET_PASSWORD_SECRET = "76543210fedcba98" * 4
TOTP_SECRET_KEY = "456789abcdef0123" * 4
TOTP_PENDING_SECRET = "3210fedcba987654" * 4
TOTP_RECOVERY_CODE_LOOKUP_SECRET = "13579bdf02468ace" * 4


def test_validation_issue_collector_formats_single_and_multiple_configuration_errors() -> None:
    """Shared validation kernel preserves single-message wording and combines multiple issues."""
    collector = IssueCollector()
    collector.add("first setting is invalid.", field="first")

    with pytest.raises(ConfigurationError, match=r"^first setting is invalid\.$"):
        collector.raise_if_any()

    message = format_validation_issues(
        (
            ValidationIssue("first setting is invalid.", field="first"),
            ValidationIssue("second setting is invalid.", field="second"),
        ),
    )

    assert message == "Invalid LitestarAuth configuration:\n- first setting is invalid.\n- second setting is invalid."


def test_validation_issue_collector_allows_empty_and_extended_issue_sets() -> None:
    """The shared collector supports empty, extended, and explicit one-shot formatting paths."""
    collector = IssueCollector()
    collector.raise_if_any()
    collector.extend((ValidationIssue("extended setting is invalid.", field="extended"),))

    with pytest.raises(ConfigurationError, match=r"^extended setting is invalid\.$"):
        collector.raise_if_any()

    assert format_validation_issues(()) == "Invalid LitestarAuth configuration."
    assert format_configuration_message("one setting is invalid.", field="one") == "one setting is invalid."
    with pytest.raises(ConfigurationError, match=r"^raised setting is invalid\.$"):
        raise_configuration_error("raised setting is invalid.", field="raised")


def test_validation_core_predicates_collect_expected_issues() -> None:
    """Common validation predicates add issues without raising until the caller decides."""
    collector = IssueCollector()

    require_non_empty(collector, "", field="empty_setting")
    require_callable(collector, object(), field="callable_setting")
    require_secret_length(collector, "short", field="secret_setting", minimum_length=8)

    assert collector.issues == (
        ValidationIssue("empty_setting must be configured.", field="empty_setting"),
        ValidationIssue("callable_setting must be callable.", field="callable_setting"),
        ValidationIssue("secret_setting must be at least 8 characters.", field="secret_setting"),
    )


def test_validation_core_predicates_accept_valid_values_without_issues() -> None:
    """Common validation predicates are no-ops for valid inputs."""
    collector = IssueCollector()

    require_non_empty(collector, "value", field="empty_setting")
    require_callable(collector, lambda: None, field="callable_setting")
    require_secret_length(collector, b"long-enough", field="secret_setting", minimum_length=8)

    assert collector.issues == ()


def test_legacy_feature_validation_modules_reexport_package_implementations() -> None:
    """Legacy validation module imports remain stable after moving implementation into the package."""
    assert api_key_validation.validate_api_key_config is validation_module.validate_api_key_config
    assert (
        oauth_validation.validate_oauth_route_registration_config.__module__ == "litestar_auth._plugin.validation.oauth"
    )
    assert totp_validation.validate_totp_config is validation_module.validate_totp_config
    assert totp_validation.validate_totp_sub_config is validation_module.validate_totp_sub_config


def _fernet_key() -> str:
    """Return a valid Fernet key for keyring validation tests."""
    return Fernet.generate_key().decode()


def _oauth_provider(*, name: str, client: object) -> OAuthProviderConfig:
    """Build an OAuthProviderConfig using the current runtime class.

    Returns:
        The current-runtime OAuthProviderConfig instance.
    """
    config_module = importlib.import_module("litestar_auth.config")
    oauth_provider_config_type = cast("type[Any]", config_module.OAuthProviderConfig)
    return oauth_provider_config_type(name=name, client=client)


def _current_inmemory_jwt_denylist_store() -> object:
    """Return a JWT denylist store instance from the current strategy module."""
    jwt_module = importlib.import_module("litestar_auth.authentication.strategy.jwt")
    store_type = cast("type[Any]", jwt_module.InMemoryJWTDenylistStore)
    return store_type()


def _current_jwt_strategy(*, denylist_store: object | None = None) -> JWTStrategy[Any, Any]:
    """Return a JWT strategy instance from the current strategy module."""
    jwt_module = importlib.import_module("litestar_auth.authentication.strategy.jwt")
    strategy_type = cast("type[JWTStrategy[Any, Any]]", jwt_module.JWTStrategy)
    if denylist_store is None:
        return strategy_type(secret=JWT_SECRET, allow_inmemory_denylist=True)
    return strategy_type(secret=JWT_SECRET, denylist_store=cast("Any", denylist_store))


def _current_inmemory_used_totp_code_store() -> object:
    """Return a used-code store instance from the current TOTP module."""
    totp_module = importlib.import_module("litestar_auth.totp")
    store_type = cast("type[Any]", totp_module.InMemoryUsedTotpCodeStore)
    return store_type()


def _current_inmemory_totp_enrollment_store() -> object:
    """Return an enrollment store instance from the current TOTP module."""
    totp_module = importlib.import_module("litestar_auth.totp")
    store_type = cast("type[Any]", totp_module.InMemoryTotpEnrollmentStore)
    return store_type()


class _DurableDenylistStore:
    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        return True

    async def is_denied(self, jti: str) -> bool:
        return False


@dataclass(slots=True, frozen=True)
class _StructuralJWTRevocationPosture:
    key: str = "in_memory"
    requires_explicit_production_opt_in: bool = False
    production_validation_error: str | None = None
    startup_warning: str | None = "process-local in-memory denylist"


class _DurableEnrollmentStore:
    @property
    def is_shared_across_workers(self) -> bool:
        return True

    async def save(self, *, user_id: str, jti: str, secret: str, ttl_seconds: int) -> bool:
        return True

    async def consume(self, *, user_id: str, jti: str) -> str | None:
        return None

    async def clear(self, *, user_id: str) -> None:
        pass


def _configured_totp_config(
    *,
    totp_pending_secret: str = TOTP_PENDING_SECRET,
    totp_algorithm: str = "SHA256",
    totp_used_tokens_store: object | None = None,
    totp_require_replay_protection: bool = True,
    totp_enable_requires_password: bool = True,
) -> TotpConfig:
    """Build a production-valid TOTP config for validation-focused tests.

    Returns:
        ``TotpConfig`` with a non-`None` pending-token denylist store.
    """
    return TotpConfig(
        totp_pending_secret=totp_pending_secret,
        totp_algorithm=cast("Any", totp_algorithm),
        totp_pending_jti_store=cast("Any", _DurableDenylistStore()),
        totp_enrollment_store=cast("Any", _DurableEnrollmentStore()),
        totp_used_tokens_store=cast("Any", totp_used_tokens_store),
        totp_require_replay_protection=totp_require_replay_protection,
        totp_enable_requires_password=totp_enable_requires_password,
    )


@dataclass(slots=True, frozen=True)
class _SharedRateLimitBackend:
    @property
    def is_shared_across_workers(self) -> bool:
        return True

    async def check(self, key: str) -> bool:
        return True

    async def increment(self, key: str) -> None:
        pass

    async def reset(self, key: str) -> None:
        pass

    async def retry_after(self, key: str) -> int:
        return 0


@dataclass(slots=True, frozen=True)
class _ProcessLocalRateLimitBackend:
    @property
    def is_shared_across_workers(self) -> bool:
        return False

    async def check(self, key: str) -> bool:
        return True

    async def increment(self, key: str) -> None:
        pass

    async def reset(self, key: str) -> None:
        pass

    async def retry_after(self, key: str) -> int:
        return 0


def test_plugin_security_policy_docs_snippet_matches_shared_policy_wording() -> None:
    """The shared docs snippet stays aligned with the plugin-owned security policy source."""
    snippet = Path("docs/snippets/plugin_security_tradeoffs.md").read_text(encoding="utf-8")

    for policy in plugin_security_policy_module._iter_plugin_security_policies():
        assert policy.plugin_surface in snippet
        assert policy.contract_reference in snippet
        assert policy.docs_summary in snippet
        assert policy.production_requirement in snippet


def test_describe_jwt_revocation_policy_accepts_current_posture() -> None:
    """Plugin notices reuse the direct JWT posture contract for current strategy objects."""
    strategy = _current_jwt_strategy()

    notice = plugin_security_policy_module._describe_jwt_revocation_policy(strategy.revocation_posture)

    assert notice is not None
    assert notice.policy.key == "jwt_revocation"
    assert notice.posture_key == "in_memory"
    assert notice.requires_explicit_production_opt_in is strategy.revocation_posture.requires_explicit_production_opt_in
    assert notice.production_validation_error == strategy.revocation_posture.production_validation_error
    assert notice.startup_warning == strategy.revocation_posture.startup_warning


def test_describe_jwt_revocation_policy_rejects_structural_posture() -> None:
    """Policy-shaped objects do not satisfy the concrete JWT posture contract."""
    notice = plugin_security_policy_module._describe_jwt_revocation_policy(_StructuralJWTRevocationPosture())

    assert notice is None


def test_describe_jwt_revocation_policy_rejects_reload_shaped_posture() -> None:
    """Old posture-shaped twins do not satisfy the concrete JWT posture contract."""
    stale_posture = type(
        "JWTRevocationPosture",
        (),
        {
            "__module__": "litestar_auth.authentication.strategy.jwt",
            "key": "in_memory",
            "requires_explicit_production_opt_in": False,
            "production_validation_error": None,
            "startup_warning": "process-local in-memory denylist",
        },
    )()

    notice = plugin_security_policy_module._describe_jwt_revocation_policy(stale_posture)

    assert notice is None


def _build_direct_manager(*, totp_secret_key: str | None = None) -> BaseUserManager[ExampleUser, UUID]:
    """Build a direct manager instance for posture-contract comparisons.

    Returns:
        Direct ``BaseUserManager`` wired with the requested TOTP secret posture.
    """
    return BaseUserManager(
        InMemoryUserDatabase([]),
        password_helper=PasswordHelper(),
        security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_key=totp_secret_key,
            id_parser=UUID,
        ),
    )


def test_resolve_plugin_managed_totp_secret_storage_policy_matches_missing_key_posture() -> None:
    """Plugin-owned TOTP wiring reuses the same direct-manager missing-key posture contract."""
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET))
    posture = _build_direct_manager().totp_secret_storage_posture

    notice = plugin_config_module._resolve_plugin_managed_totp_secret_storage_policy(config)

    assert notice is not None
    assert notice.policy.key == "totp_secret_storage"
    assert notice.posture_key == posture.key
    assert notice.requires_explicit_production_opt_in is posture.requires_explicit_production_opt_in
    assert notice.production_validation_error == posture.production_validation_error
    assert notice.startup_warning is None


def test_resolve_plugin_managed_totp_secret_storage_policy_returns_none_without_totp() -> None:
    """Configs without TOTP do not report a plugin-managed TOTP storage policy notice."""
    notice = plugin_config_module._resolve_plugin_managed_totp_secret_storage_policy(_minimal_config())

    assert notice is None


def test_resolve_plugin_managed_totp_secret_storage_policy_skips_factory_owned_wiring() -> None:
    """Custom manager factories can own TOTP-secret storage without plugin validation interference."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
        user_manager_security=None,
    )
    config.user_manager_security = None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])

    notice = plugin_config_module._resolve_plugin_managed_totp_secret_storage_policy(config)

    assert notice is None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        pytest.param("localhost", True, id="lowercase-localhost"),
        pytest.param("LOCALHOST", False, id="uppercase-localhost-preserves-case-sensitivity"),
        pytest.param("127.0.0.1", True, id="ipv4-loopback"),
        pytest.param("::1", True, id="ipv6-loopback"),
        pytest.param("192.0.2.1", False, id="non-loopback-ip"),
        pytest.param("app.example.com", False, id="non-ip-host"),
    ],
)
def test_redirect_validation_loopback_host_helper_preserves_startup_contract(
    host: str,
    expected: object,
) -> None:
    """The relocated plugin redirect helper preserves exact localhost and IP-loopback behavior."""
    assert redirect_validation_module._is_loopback_host(host) is expected


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        # Loopback — same as the narrow helper.
        pytest.param("localhost", True, id="lowercase-localhost"),
        pytest.param("LOCALHOST", True, id="uppercase-localhost-casefolded"),
        pytest.param("ip6-localhost", True, id="ipv6-localhost-alias"),
        pytest.param("127.0.0.1", True, id="ipv4-loopback"),
        pytest.param("::1", True, id="ipv6-loopback"),
        # RFC 1918 private space.
        pytest.param("10.0.0.5", True, id="rfc1918-10/8"),
        pytest.param("172.16.0.1", True, id="rfc1918-172.16/12"),
        pytest.param("192.168.1.1", True, id="rfc1918-192.168/16"),
        # RFC 3927 link-local incl. cloud IMDS.
        pytest.param("169.254.169.254", True, id="link-local-imds"),
        pytest.param("fe80::1", True, id="ipv6-link-local"),
        # Multicast / reserved / unspecified.
        pytest.param("224.0.0.1", True, id="ipv4-multicast"),
        pytest.param("0.0.0.0", True, id="ipv4-unspecified"),
        pytest.param("240.0.0.1", True, id="ipv4-reserved"),
        # Public hosts must pass.
        pytest.param("8.8.8.8", False, id="public-ipv4"),
        pytest.param("1.1.1.1", False, id="public-ipv4-cloudflare"),
        # Hostname path with DNS resolution disabled — the predicate falls
        # through to the historical accept-hostname behaviour when resolution
        # is unavailable, which ``monkeypatch`` simulates here so the test
        # stays deterministic regardless of the CI host's DNS posture.
        pytest.param("app.example.com", False, id="public-hostname-without-dns"),
    ],
)
def test_redirect_validation_unsafe_redirect_host_helper_blocks_non_routable_ips(
    host: str,
    expected: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The broader SSRF-aware predicate rejects every non-routable IP family."""

    def _no_dns(*_args: object, **_kwargs: object) -> list[object]:
        raise redirect_validation_module.socket.gaierror

    monkeypatch.setattr(redirect_validation_module.socket, "getaddrinfo", _no_dns)
    assert redirect_validation_module._is_unsafe_redirect_host(host) is expected


def _stub_addrinfo(*resolved_hosts: str) -> list[tuple[object, object, object, object, tuple[str, int]]]:
    """Build a ``socket.getaddrinfo`` return value matching the indexing the helper uses.

    ``_hostname_resolves_to_unsafe_ip`` only reads ``sockaddr[0]`` so the
    other tuple slots can be filler.

    Returns:
        A list of fake ``getaddrinfo`` records carrying ``resolved_hosts`` in
        the ``sockaddr`` slot.
    """
    return [(0, 0, 0, "", (resolved, 0)) for resolved in resolved_hosts]


def test_unsafe_redirect_host_resolves_hostname_to_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hostname whose A-record points at a private range is rejected."""
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _stub_addrinfo("169.254.169.254"),
    )
    assert redirect_validation_module._is_unsafe_redirect_host("metadata.example.com") is True


def test_unsafe_redirect_host_strict_mode_rejects_hostname_resolving_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict mode preserves existing private-address rejection."""
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _stub_addrinfo("169.254.169.254"),
    )
    assert redirect_validation_module._is_unsafe_redirect_host("metadata.example.com", strict=True) is True


def test_unsafe_redirect_host_accepts_hostname_resolving_to_public_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hostname whose A-record points at a public address is accepted."""
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _stub_addrinfo("8.8.8.8"),
    )
    assert redirect_validation_module._is_unsafe_redirect_host("dns.google") is False


def test_unsafe_redirect_host_strict_mode_accepts_hostname_resolving_to_public_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict mode still accepts hostnames with usable public DNS answers."""
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _stub_addrinfo("8.8.8.8"),
    )
    assert redirect_validation_module._is_unsafe_redirect_host("dns.google", strict=True) is False


def test_unsafe_redirect_host_rejects_hostname_with_mixed_routability(monkeypatch: pytest.MonkeyPatch) -> None:
    """If any resolved address is unsafe, the hostname is rejected.

    Multi-homed hosts that publish both a public and a private record cannot
    be trusted: the OAuth provider could pick the private address at runtime
    and leak the ``code`` to internal infrastructure.
    """
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _stub_addrinfo("8.8.8.8", "10.0.0.1"),
    )
    assert redirect_validation_module._is_unsafe_redirect_host("dual-homed.example.com") is True


def test_unsafe_redirect_host_falls_through_when_dns_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolution failures fall through to the historical accept-hostname behaviour.

    Operators running offline CI or sandboxed startup paths must still be
    able to validate hostnames structurally; runtime egress firewalls cover
    the path the resolver could not.
    """

    def _gaierror(*_args: object, **_kwargs: object) -> list[object]:
        raise redirect_validation_module.socket.gaierror

    monkeypatch.setattr(redirect_validation_module.socket, "getaddrinfo", _gaierror)
    assert redirect_validation_module._is_unsafe_redirect_host("offline.example.com") is False


def test_unsafe_redirect_host_strict_mode_rejects_dns_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict mode treats resolver failures as unsafe instead of falling open."""

    def _gaierror(*_args: object, **_kwargs: object) -> list[object]:
        raise redirect_validation_module.socket.gaierror

    monkeypatch.setattr(redirect_validation_module.socket, "getaddrinfo", _gaierror)
    assert redirect_validation_module._is_unsafe_redirect_host("offline.example.com", strict=True) is True


def test_unsafe_redirect_host_skips_unparseable_resolution_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    """``getaddrinfo`` results that do not parse as IPs are skipped, not raised on."""
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(0, 0, 0, "", ("not-an-ip", 0)), (0, 0, 0, "", ("8.8.8.8", 0))],
    )
    assert redirect_validation_module._is_unsafe_redirect_host("partial.example.com") is False


def test_unsafe_redirect_host_non_strict_mode_accepts_unusable_resolution_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-strict mode preserves the historical fail-open behavior for unusable DNS answers."""
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(0, 0, 0, "", ("not-an-ip", 0))],
    )
    assert redirect_validation_module._is_unsafe_redirect_host("partial.example.com") is False


@pytest.mark.parametrize(
    "addrinfo_records",
    [
        pytest.param([], id="empty-addrinfo"),
        pytest.param([(0, 0, 0, "", ("not-an-ip", 0))], id="unusable-addrinfo"),
    ],
)
def test_unsafe_redirect_host_strict_mode_rejects_empty_or_unusable_resolution_entries(
    addrinfo_records: list[tuple[object, object, object, object, tuple[str, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict mode treats empty or unusable resolver results as unsafe."""
    monkeypatch.setattr(
        redirect_validation_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: addrinfo_records,
    )
    assert redirect_validation_module._is_unsafe_redirect_host("partial.example.com", strict=True) is True


def test_warn_insecure_plugin_startup_defaults_emits_all_expected_security_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production startup emits warnings for each insecure default this task targets."""
    config = _minimal_config(
        backends=[
            _cookie_backend(),
            _jwt_backend(),
        ],
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
        rate_limit_config=_rate_limit_config(backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60)),
        totp_config=TotpConfig(
            totp_pending_secret=TOTP_PENDING_SECRET,
            totp_pending_jti_store=cast("Any", _current_inmemory_jwt_denylist_store()),
            totp_enrollment_store=cast("Any", _current_inmemory_totp_enrollment_store()),
            totp_used_tokens_store=cast("Any", _current_inmemory_used_totp_code_store()),
        ),
    )
    config.enable_refresh = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert any("OAuth token encryption key material is not set" in message for message in messages)
    assert any("process-local in-memory denylist" in message for message in messages)
    assert any("process-local in-memory backend" in message for message in messages)
    assert any("InMemoryUsedTotpCodeStore" in message for message in messages)
    assert any("InMemoryTotpEnrollmentStore" in message for message in messages)
    assert any("TOTP pending-token replay protection uses InMemoryJWTDenylistStore" in message for message in messages)
    assert any("refresh_max_age is not set" in message for message in messages)


def test_warn_insecure_plugin_startup_defaults_warns_for_current_jwt_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT denylist warnings use current strategy posture objects."""
    strategy = _current_jwt_strategy()
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="jwt",
                transport=BearerTransport(),
                strategy=cast("Any", strategy),
            ),
        ],
    )

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert strategy.revocation_posture.startup_warning in messages


def test_warn_insecure_plugin_startup_defaults_warns_for_unbounded_api_key_default_ttl() -> None:
    """Production API-key creation warns when the configured default expiry is unbounded."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(enabled=True, allowed_scopes=("read",), default_ttl=None)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert any("API-key creation default_ttl is None" in str(record.message) for record in records)


class _PasskeyOnlyUser:
    """User-model stub mirroring passkey/OAuth-only models that omit `hashed_password`.

    The startup warner only inspects the class — never instantiates it — so a
    minimal stub is enough to exercise the gap-detection branch. ``id`` and
    ``email`` are declared as type-only annotations to mirror real Protocol/
    dataclass user contracts and to confirm the annotation walk does not pick
    up `hashed_password` from elsewhere in the MRO.
    """

    id: UUID
    email: str


class _UserModelWithHashedPasswordAttribute:
    """User-model stub that declares `hashed_password` only via class annotation."""

    id: UUID
    email: str
    hashed_password: str


def test_warn_insecure_plugin_startup_defaults_warns_for_default_jwt_fingerprint_when_user_model_lacks_hashed_password() -> (
    None
):
    """Default JWT fingerprint silently degrades for passkey-only models — surface it."""
    config = _minimal_config(backends=[_jwt_backend(denylist_store=_DurableDenylistStore())])
    config.user_model = cast("Any", _PasskeyOnlyUser)

    with pytest.warns(startup_module.SecurityWarning, match="does not expose 'hashed_password'"):
        warn_insecure_plugin_startup_defaults(config)


def test_warn_insecure_plugin_startup_defaults_skips_default_fingerprint_warning_for_user_model_with_hashed_password() -> (
    None
):
    """Annotation-only `hashed_password` is enough to keep the default fingerprint usable."""
    config = _minimal_config(backends=[_jwt_backend(denylist_store=_DurableDenylistStore())])
    config.user_model = cast("Any", _UserModelWithHashedPasswordAttribute)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert not any("does not expose 'hashed_password'" in message for message in messages)


def test_warn_insecure_plugin_startup_defaults_skips_default_fingerprint_warning_when_custom_getter_is_configured() -> (
    None
):
    """A custom session_fingerprint_getter is the caller's contract — no warning."""
    jwt_module = importlib.import_module("litestar_auth.authentication.strategy.jwt")
    strategy_type = cast("type[JWTStrategy[Any, Any]]", jwt_module.JWTStrategy)
    strategy = strategy_type(
        secret=JWT_SECRET,
        denylist_store=cast("Any", _DurableDenylistStore()),
        session_fingerprint_getter=lambda _user: "custom-fingerprint",
    )
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="jwt-custom-fingerprint",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = _minimal_config(backends=[backend])
    config.user_model = cast("Any", _PasskeyOnlyUser)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert not any("does not expose 'hashed_password'" in message for message in messages)


def test_warn_insecure_plugin_startup_defaults_is_silent_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode suppresses the insecure-default warnings."""
    config = _minimal_config(
        backends=[_cookie_backend(), _jwt_backend()],
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
        rate_limit_config=_rate_limit_config(backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60)),
        totp_config=TotpConfig(
            totp_pending_secret=TOTP_PENDING_SECRET,
            totp_pending_jti_store=cast("Any", _current_inmemory_jwt_denylist_store()),
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )
    config.enable_refresh = True
    config.unsafe_testing = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert not records


def test_warn_insecure_plugin_startup_defaults_is_silent_for_safe_production_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Safe production settings avoid the insecure-default warnings entirely."""
    config = _minimal_config(
        backends=[
            _cookie_backend(refresh_max_age=604800),
            _jwt_backend(denylist_store=_DurableDenylistStore()),
        ],
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_token_encryption_key="a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
        rate_limit_config=_rate_limit_config(backend=_SharedRateLimitBackend()),
        totp_config=_configured_totp_config(
            totp_used_tokens_store=cast("Any", object()),
        ),
    )
    config.csrf_secret = JWT_SECRET
    config.enable_refresh = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert not records


def test_warn_insecure_plugin_startup_defaults_warns_for_missing_refresh_cookie_max_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refresh-cookie startup warnings stay with the startup helper owner."""
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = JWT_SECRET
    config.enable_refresh = True

    with pytest.warns(startup_module.SecurityWarning, match="refresh_max_age is not set"):
        warn_insecure_plugin_startup_defaults(config)


def test_warn_insecure_plugin_startup_defaults_skips_refresh_warning_when_cookie_max_age_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit refresh-cookie lifetimes suppress the startup helper warning."""
    config = _minimal_config(backends=[_cookie_backend(refresh_max_age=604800)])
    config.csrf_secret = JWT_SECRET
    config.enable_refresh = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert not [record for record in records if "refresh_max_age" in str(record.message)]


def test_warn_insecure_plugin_startup_defaults_skips_refresh_warning_when_refresh_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disable-refresh configs do not warn about refresh-cookie max age."""
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = JWT_SECRET
    config.enable_refresh = False

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert not [record for record in records if "refresh_max_age" in str(record.message)]


def test_validate_backend_strategy_security_skips_non_database_strategies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-database strategies do not enter the legacy-plaintext validation path."""
    config = _minimal_config(backends=[_non_jwt_backend()])

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_warns_for_jwt_named_non_jwt_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT-like backend names emit an advisory warning when the strategy is not JWT-based."""
    backend = _database_backend()
    backend.name = "Jwt-database"
    config = _minimal_config(backends=[backend])

    with pytest.warns(
        UserWarning,
        match=r"Jwt-database.*DatabaseTokenStrategy.*'bearer' or 'database'",
    ):
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_does_not_warn_for_jwt_named_jwt_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT-backed strategies remain warning-free even when the backend name contains JWT."""
    config = _minimal_config(backends=[_jwt_backend(denylist_store=_DurableDenylistStore())])

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_does_not_warn_for_neutral_backend_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neutral backend names stay silent even when the strategy is not JWT-based."""
    config = _minimal_config(backends=[_database_backend()])

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_explicit_inmemory_jwt_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWTStrategy owns the explicit process-local revocation opt-in."""
    config = _minimal_config(backends=[_jwt_backend()])

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_durable_jwt_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable denylist store satisfies the JWT revocation validation."""
    config = _minimal_config(backends=[_jwt_backend(denylist_store=_DurableDenylistStore())])

    _validate_backend_strategy_security(config)


def test_validate_session_maker_or_external_db_session_requires_one_source() -> None:
    """Startup requires either a session factory or an external session dependency."""
    config = _minimal_config()
    config.session_maker = None
    config.db_session_dependency_provided_externally = False

    with pytest.raises(ValueError, match="requires session_maker or db_session_dependency_provided_externally=True"):
        validate_session_maker_or_external_db_session(config)


def test_validate_session_maker_or_external_db_session_allows_external_binding() -> None:
    """An explicitly external db-session binding satisfies the session requirement."""
    config = _minimal_config()
    config.session_maker = None
    config.db_session_dependency_provided_externally = True

    validate_session_maker_or_external_db_session(config)


def test_validate_user_model_login_identifier_fields_accepts_present_attribute() -> None:
    """Plain user-model attributes satisfy the login-identifier validation."""

    class _UserModel:
        username = "present"

    config = _minimal_config()
    config.user_model = cast("type[ExampleUser]", _UserModel)
    config.login_identifier = "username"

    validate_user_model_login_identifier_fields(config)


def test_validate_user_model_login_identifier_fields_rejects_missing_attribute() -> None:
    """A missing login field raises a configuration error with the model name."""

    class _UserModel:
        email = "present"

    config = _minimal_config()
    config.user_model = cast("type[ExampleUser]", _UserModel)
    config.login_identifier = "username"

    with pytest.raises(validation_module.ConfigurationError, match="has no 'username'"):
        validate_user_model_login_identifier_fields(config)


def test_validate_user_model_login_identifier_fields_rejects_missing_email_attribute() -> None:
    """Email login mode also validates the required user-model attribute."""

    class _UserModel:
        username = "present"

    config = _minimal_config()
    config.user_model = cast("type[ExampleUser]", _UserModel)
    config.login_identifier = "email"

    with pytest.raises(validation_module.ConfigurationError, match="has no 'email'"):
        validate_user_model_login_identifier_fields(config)


def test_validate_user_model_login_identifier_fields_rejects_missing_orm_username() -> None:
    """ORM-backed models are checked through SQLAlchemy mapper state, not only hasattr()."""
    config = _minimal_config()
    config.user_model = OrmUser  # ty: ignore[invalid-assignment]
    config.login_identifier = "username"

    with pytest.raises(validation_module.ConfigurationError, match="has no 'username'"):
        validate_user_model_login_identifier_fields(config)


def test_validate_user_model_login_identifier_fields_accepts_present_orm_email() -> None:
    """The reference ORM user model still satisfies email login mode."""
    config = _minimal_config()
    config.user_model = OrmUser  # ty: ignore[invalid-assignment]
    config.login_identifier = "email"

    validate_user_model_login_identifier_fields(config)


def test_validate_config_rejects_role_aware_builtin_surfaces_for_roleless_user_model() -> None:
    """Plugin validation fails fast when built-in role-aware schemas target a role-less user model."""

    class _RolelessUserModel:
        id = UUID(int=0)
        email = "roleless@example.com"
        hashed_password = "hashed-password"
        is_active = True
        is_verified = False

    config = _minimal_config()
    config.user_model = cast("type[ExampleUser]", _RolelessUserModel)

    with pytest.raises(validation_module.ConfigurationError, match=r"has no 'roles'.*schema fields that include"):
        validate_config(config)


def test_validate_config_allows_roleless_user_model_with_roleless_custom_schemas() -> None:
    """Custom schemas that omit roles keep the supported role-less user-model path valid."""

    class _RolelessUserModel:
        id = UUID(int=0)
        email = "roleless@example.com"
        hashed_password = "hashed-password"
        is_active = True
        is_verified = False

    class _RolelessUserRead(msgspec.Struct):
        id: UUID
        email: str
        is_active: bool
        is_verified: bool

    class _RolelessUserUpdate(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
        email: str | None = None

    config = _minimal_config()
    config.user_model = cast("type[ExampleUser]", _RolelessUserModel)
    config.user_read_schema = _RolelessUserRead
    config.user_update_schema = _RolelessUserUpdate
    config.include_users = True

    validate_config(config)


def test_validate_config_rejects_roleless_user_model_for_users_surface_with_role_aware_schemas() -> None:
    """The users controller also fails fast when its effective schemas still require roles.

    With the self-service ``UserUpdate`` closed to email plus current-password
    proof, the default ``UserRead`` is the only schema in the users surface that still requires
    a ``roles`` attribute — so the validator's diagnostic now points at
    "users responses" alone. ``AdminUserUpdate`` keeps ``roles`` for
    privileged writes; that path is still rejected when the model lacks
    the attribute, but is exercised by a separate validator call that does
    not collapse into the same diagnostic.
    """

    class _RolelessUserModel:
        id = UUID(int=0)
        email = "roleless@example.com"
        hashed_password = "hashed-password"
        is_active = True
        is_verified = False

    config = _minimal_config()
    config.user_model = cast("type[ExampleUser]", _RolelessUserModel)
    config.include_register = False
    config.include_verify = False
    config.include_reset_password = False
    config.include_users = True

    with pytest.raises(validation_module.ConfigurationError, match=r"users responses"):
        validate_config(config)


def test_validate_config_rejects_roleless_user_model_when_custom_update_schema_requires_roles() -> None:
    """A custom ``user_update_schema`` that re-introduces ``roles`` still triggers the validator.

    The library default ``UserUpdate`` has no role fields, but apps may legitimately provide a
    custom schema that restores the privileged shape. The validator must keep flagging the
    "users update requests" surface for any such custom schema, otherwise a roleless user
    model paired with a roles-bearing custom update schema would slip past startup
    validation and surface as a runtime ``AttributeError`` on the first PATCH.
    """

    class _RolelessUserModel:
        id = UUID(int=0)
        email = "roleless@example.com"
        hashed_password = "hashed-password"
        is_active = True
        is_verified = False

    class _RolesBearingUpdate(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
        email: str | None = None
        roles: list[str] | None = None

    class _RolelessUserRead(msgspec.Struct):
        id: UUID
        email: str
        is_active: bool
        is_verified: bool

    config = _minimal_config()
    config.user_model = cast("type[ExampleUser]", _RolelessUserModel)
    # The user_read_schema is roleless so this test isolates the update-side
    # diagnostic that the email-only default UserUpdate would otherwise hide.
    config.user_read_schema = _RolelessUserRead
    config.user_update_schema = cast("type[msgspec.Struct]", _RolesBearingUpdate)
    config.include_register = False
    config.include_verify = False
    config.include_reset_password = False
    config.include_users = True

    with pytest.raises(validation_module.ConfigurationError, match=r"users update requests"):
        validate_config(config)


def test_validate_password_validator_config_accepts_password_validator_factory() -> None:
    """The canonical contract accepts plugin-owned password-validator factories."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: None

    validate_password_validator_config(config)


def test_validate_password_validator_config_accepts_none_returning_factory() -> None:
    """A factory may intentionally resolve to ``None`` without legacy-overlap checks."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: None

    validate_password_validator_config(config)


def test_validate_password_validator_config_allows_explicit_user_manager_factory() -> None:
    """A custom builder may own password-validator injection itself."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])

    validate_password_validator_config(config)


def test_validate_config_allows_factory_owned_noncanonical_manager_surface() -> None:
    """Non-canonical manager constructors remain valid when `user_manager_factory` owns the build."""

    class _FactoryOwnedManager:
        def __init__(self, user_db: object, *, legacy_dependency: object) -> None:
            pass

        @staticmethod
        async def authenticate(identifier: str, password: str) -> None:
            pass

    config = _minimal_config()
    config.user_manager_class = cast("type[Any]", _FactoryOwnedManager)
    config.password_validator_factory = lambda _config: None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])

    validate_config(config)


def test_validate_password_validator_config_does_not_probe_manager_signature() -> None:
    """Validation no longer introspects custom manager constructors for password-validator support."""

    class _ManagerWithoutPasswordValidator:
        def __init__(self, user_db: object) -> None:
            pass

    config = _minimal_config()
    config.password_validator_factory = lambda _config: None
    config.user_manager_class = cast("type[Any]", _ManagerWithoutPasswordValidator)

    validate_password_validator_config(config)


def test_validate_config_accepts_default_user_manager_requiring_password_helper() -> None:
    """Constructor-shape validation should include the default ``password_helper`` slot."""

    class _PasswordHelperRequiredManager(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper,
            security: UserManagerSecurity[UUID] | None = None,
            password_validator: Callable[[str], None] | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            superuser_role_name: str = "superuser",
            unsafe_testing: bool = False,
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=password_validator,
                backends=backends,
                login_identifier=login_identifier,
                superuser_role_name=superuser_role_name,
                unsafe_testing=unsafe_testing,
            )

    config = _minimal_config()
    config.user_manager_class = cast("type[Any]", _PasswordHelperRequiredManager)

    validate_config(config)


def test_validate_config_does_not_invoke_password_validator_factory_for_constructor_shape() -> None:
    """Startup constructor validation must not execute runtime password-validator factories."""
    config = _minimal_config()
    calls = 0

    def _factory(_config: object) -> None:
        nonlocal calls
        calls += 1

    config.password_validator_factory = _factory

    validate_config(config)

    assert calls == 0


def test_resolve_user_manager_account_state_validator_returns_callable_contract() -> None:
    """The shared helper returns the supported account-state callable surface."""
    calls: list[tuple[ExampleUser, bool]] = []
    user = ExampleUser(
        id=UUID(int=1),
        email="user@example.com",
        hashed_password=PasswordHelper().hash("correct-password"),
    )

    class _CallableValidatorManager:
        @staticmethod
        def require_account_state(user: ExampleUser, *, require_verified: bool = False) -> None:
            calls.append((user, require_verified))

    validator = validation_module.resolve_user_manager_account_state_validator(_CallableValidatorManager)

    validator(user, require_verified=True)

    assert calls == [(user, True)]


def test_resolve_user_manager_account_state_validator_raises_for_missing_callable() -> None:
    """Missing or non-callable account-state validators fail with the shared contract error."""

    class _MissingValidatorManager:
        require_account_state = None

    with pytest.raises(TypeError, match="require_account_state"):
        validation_module.resolve_user_manager_account_state_validator(_MissingValidatorManager)


def test_resolve_user_manager_account_state_validator_raises_for_missing_manager_class() -> None:
    """Factory-owned manager paths still fail with the shared contract error when no class is set."""
    with pytest.raises(TypeError, match="require_account_state"):
        validation_module.resolve_user_manager_account_state_validator(None)


def test_validate_default_user_manager_constructor_contract_rejects_missing_manager_class() -> None:
    """Default builder validation rejects configs with neither manager class nor factory."""
    config = _minimal_config()
    config.user_manager_class = None

    with pytest.raises(validation_module.ConfigurationError, match="user_manager_class must be configured"):
        validation_module.validate_default_user_manager_constructor_contract(config)


@pytest.mark.parametrize(("use_typed_security"), [True, False])
def test_default_user_manager_contract_keeps_runtime_and_validation_surfaces_aligned(
    *,
    use_typed_security: bool,
) -> None:
    """The shared default-builder contract keeps runtime and validation kwargs in sync."""
    config = _minimal_config(id_parser=UUID)
    if not use_typed_security:
        config.user_manager_security = None

    runtime_contract = user_manager_builder_module._build_default_user_manager_contract(
        config,
        password_helper=PasswordHelper(),
        password_validator=None,
        backends=("bound-backend",),
    )
    validation_contract = user_manager_builder_module._build_default_user_manager_contract(
        config,
        password_helper=PasswordHelper(),
        password_validator=None,
        backends=("bound-backend",),
    )

    runtime_kwargs = runtime_contract.build_kwargs()
    validation_kwargs = validation_contract.build_kwargs()

    assert runtime_kwargs.keys() == validation_kwargs.keys()
    assert runtime_kwargs["backends"] == ("bound-backend",)
    assert validation_kwargs["backends"] == ("bound-backend",)
    assert runtime_kwargs["unsafe_testing"] is False
    assert validation_kwargs["unsafe_testing"] is False
    assert runtime_kwargs["password_validator"] is None
    assert validation_kwargs["password_validator"] is None

    if use_typed_security:
        assert runtime_kwargs["security"] == validation_kwargs["security"]
        assert "id_parser" not in runtime_kwargs
        assert "id_parser" not in validation_kwargs
    else:
        assert runtime_kwargs["security"] == validation_kwargs["security"]
        security = runtime_kwargs["security"]
        assert security is not None
        assert security.id_parser is UUID
        assert "id_parser" not in runtime_kwargs
        assert "id_parser" not in validation_kwargs


def test_validate_config_rejects_non_canonical_default_user_manager_constructor() -> None:
    """Plugin construction should fail fast for managers that do not accept ``security=...``."""

    class _LegacyManagerWithoutSecurity(PluginUserManager):
        """Constructor intentionally omits ``security=`` so the default builder cannot bind."""

        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            password_validator: object | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            unsafe_testing: bool = False,
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=UserManagerSecurity[UUID](
                    verification_token_secret=VERIFICATION_SECRET,
                    reset_password_token_secret=RESET_PASSWORD_SECRET,
                ),
                password_validator=cast("Any", password_validator),
                backends=backends,
                login_identifier=login_identifier,
                unsafe_testing=unsafe_testing,
            )

    config = _minimal_config()
    config.user_manager_class = cast("type[Any]", _LegacyManagerWithoutSecurity)

    with pytest.raises(validation_module.ConfigurationError, match=r"user_manager_factory.*security"):
        validate_config(config)


def test_validate_config_rejects_default_user_manager_missing_unsafe_testing_kwarg() -> None:
    """The default builder contract includes ``unsafe_testing`` and should fail fast when missing."""

    class _ManagerWithoutUnsafeTesting(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            security: UserManagerSecurity[UUID] | None = None,
            password_validator: Callable[[str], None] | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            superuser_role_name: str = "superuser",
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=password_validator,
                backends=backends,
                login_identifier=login_identifier,
                superuser_role_name=superuser_role_name,
            )

    config = _minimal_config()
    config.user_manager_class = cast("type[Any]", _ManagerWithoutUnsafeTesting)

    with pytest.raises(validation_module.ConfigurationError, match=r"user_manager_factory.*unsafe_testing"):
        validate_config(config)


def test_validate_config_rejects_non_introspectable_default_user_manager_constructor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default builder requires an introspectable constructor surface."""

    def _raise_signature_error(_manager_class: object) -> object:
        msg = "signature unavailable"
        raise ValueError(msg)

    config = _minimal_config()
    monkeypatch.setattr(validation_module.inspect, "signature", _raise_signature_error)

    with pytest.raises(validation_module.ConfigurationError, match="introspectable constructor"):
        validate_config(config)


def test_validate_rate_limit_config_rejects_non_boolean_trusted_proxy() -> None:
    """Trusted-proxy validation is delegated to the shared config helper."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="login",
        trusted_proxy=cast("bool", "yes"),
    )

    with pytest.raises(Exception, match="trusted_proxy must be a boolean") as exc_info:
        validate_rate_limit_config(AuthRateLimitConfig(login=rate_limit))
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_rate_limit_config_rejects_invalid_trusted_proxy_hops() -> None:
    """Trusted-proxy hop-count validation is delegated to the shared config helper."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="login",
        trusted_proxy_hops=cast("int", 0),
    )

    with pytest.raises(Exception, match="trusted_proxy_hops must be a positive integer") as exc_info:
        validate_rate_limit_config(AuthRateLimitConfig(login=rate_limit))
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_rate_limit_config_accepts_none() -> None:
    """Omitting rate limiting is a valid configuration."""
    validate_rate_limit_config(None)


@pytest.mark.parametrize("unsafe_testing", [False, True])
def test_validate_config_does_not_consume_deployment_worker_count_for_rate_limit_yet(
    unsafe_testing: object,
) -> None:
    """REFAC-002 only records topology; startup fail-closed validation is introduced later."""
    config = _minimal_config(
        deployment_worker_count=2,
        rate_limit_config=_rate_limit_config(backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60)),
    )
    config.unsafe_testing = cast("bool", unsafe_testing)

    validate_config(config)


def test_iter_rate_limit_endpoints_includes_request_verify_token() -> None:
    """The shared iterator covers the late-bound verify-token request endpoint."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="request-verify-token",
    )

    endpoints = iter_rate_limit_endpoints(AuthRateLimitConfig(request_verify_token=rate_limit))

    assert rate_limit in endpoints


def test_iter_rate_limit_endpoints_includes_change_password() -> None:
    """The shared iterator covers the users-controller password-rotation endpoint."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip_email",
        namespace="change-password",
    )

    endpoints = iter_rate_limit_endpoints(AuthRateLimitConfig(change_password=rate_limit))

    assert rate_limit in endpoints


def test_iter_rate_limit_endpoints_includes_totp_confirm_enable() -> None:
    """The shared iterator covers the TOTP confirm-enrollment endpoint."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="totp-confirm-enable",
    )

    endpoints = iter_rate_limit_endpoints(AuthRateLimitConfig(totp_confirm_enable=rate_limit))

    assert rate_limit in endpoints


def test_iter_rate_limit_endpoint_items_include_supported_slot_names() -> None:
    """The shared iterator exposes endpoint slot names for startup diagnostics."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="totp-regenerate-recovery-codes",
    )

    items = rate_limit_module.iter_rate_limit_endpoint_items(
        AuthRateLimitConfig(totp_regenerate_recovery_codes=rate_limit),
    )
    item_map = dict(items)

    assert item_map["totp_regenerate_recovery_codes"] is rate_limit
    assert item_map["verify_token"] is None
    assert item_map["request_verify_token"] is None
    assert item_map["api_key_update"] is None


def test_collect_process_local_rate_limit_endpoint_names_accepts_no_rate_limit_config() -> None:
    """Omitting rate limits leaves no process-local endpoint posture."""
    config = _minimal_config(rate_limit_config=None)

    assert startup_module._collect_process_local_rate_limit_endpoint_names(config) == ()


def test_collect_process_local_rate_limit_endpoint_names_ignores_disabled_slots() -> None:
    """Disabled endpoint slots are ignored by the startup posture collector."""
    config = _minimal_config(rate_limit_config=AuthRateLimitConfig.disabled())

    assert startup_module._collect_process_local_rate_limit_endpoint_names(config) == ()


def test_collect_process_local_rate_limit_endpoint_names_returns_one_process_local_slot() -> None:
    """The collector names a configured endpoint that uses process-local state."""
    config = _minimal_config(
        rate_limit_config=AuthRateLimitConfig(
            request_verify_token=EndpointRateLimit(
                backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
                scope="ip",
                namespace="request-verify-token",
            ),
        ),
    )

    assert startup_module._collect_process_local_rate_limit_endpoint_names(config) == ("request_verify_token",)


def test_collect_process_local_rate_limit_endpoint_names_returns_multiple_process_local_slots() -> None:
    """The collector preserves configured slot order when multiple endpoints are process-local."""
    process_local_backend = _ProcessLocalRateLimitBackend()
    config = _minimal_config(
        rate_limit_config=AuthRateLimitConfig(
            login=EndpointRateLimit(
                backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
                scope="ip_email",
                namespace="login",
            ),
            totp_confirm_enable=EndpointRateLimit(
                backend=process_local_backend,
                scope="ip",
                namespace="totp-confirm-enable",
            ),
            request_verify_token=EndpointRateLimit(
                backend=process_local_backend,
                scope="ip_email",
                namespace="request-verify-token",
            ),
        ),
    )

    assert startup_module._collect_process_local_rate_limit_endpoint_names(config) == (
        "login",
        "totp_confirm_enable",
        "request_verify_token",
    )


def test_collect_process_local_rate_limit_endpoint_names_accepts_shared_custom_backend() -> None:
    """Shared custom backends do not produce process-local startup posture."""
    config = _minimal_config(
        rate_limit_config=AuthRateLimitConfig(
            login=EndpointRateLimit(
                backend=_SharedRateLimitBackend(),
                scope="ip_email",
                namespace="login",
            ),
        ),
    )

    assert startup_module._collect_process_local_rate_limit_endpoint_names(config) == ()


def test_collect_process_local_rate_limit_endpoint_names_uses_backend_protocol() -> None:
    """The collector follows the backend contract instead of checking concrete classes."""
    config = _minimal_config(
        rate_limit_config=AuthRateLimitConfig(
            forgot_password=EndpointRateLimit(
                backend=_ProcessLocalRateLimitBackend(),
                scope="ip_email",
                namespace="forgot-password",
            ),
        ),
    )

    assert startup_module._collect_process_local_rate_limit_endpoint_names(config) == ("forgot_password",)


def test_require_shared_rate_limit_backends_for_multiworker_rejects_process_local_backend() -> None:
    """Declared multi-worker deployments require auth rate-limit state shared across workers."""
    config = _minimal_config(
        deployment_worker_count=2,
        rate_limit_config=AuthRateLimitConfig(
            request_verify_token=EndpointRateLimit(
                backend=_ProcessLocalRateLimitBackend(),
                scope="ip",
                namespace="request-verify-token",
            ),
        ),
    )

    with pytest.raises(ConfigurationError) as exc_info:
        startup_module.require_shared_rate_limit_backends_for_multiworker(config)

    message = str(exc_info.value)
    assert "request_verify_token" in message
    assert "RedisRateLimiter" in message
    assert "RedisAuthPreset" in message


def test_require_shared_rate_limit_backends_for_multiworker_accepts_shared_backend() -> None:
    """Shared rate-limit backends satisfy the declared multi-worker startup guard."""
    config = _minimal_config(
        deployment_worker_count=2,
        rate_limit_config=AuthRateLimitConfig(
            request_verify_token=EndpointRateLimit(
                backend=_SharedRateLimitBackend(),
                scope="ip",
                namespace="request-verify-token",
            ),
        ),
    )

    startup_module.require_shared_rate_limit_backends_for_multiworker(config)


def test_require_refreshable_strategy_when_enable_refresh_skips_when_refresh_disabled() -> None:
    """Refresh-capability startup validation is inactive when refresh routes are disabled."""
    config = _minimal_config()

    startup_module.require_refreshable_strategy_when_enable_refresh(config)


def test_require_refreshable_strategy_when_enable_refresh_accepts_refreshable_strategy() -> None:
    """Refresh-enabled configs require each backend to expose refresh-token operations."""
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="refreshable",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryRefreshTokenStrategy(token_prefix="refreshable")),
            ),
        ],
    )
    config.enable_refresh = True

    startup_module.require_refreshable_strategy_when_enable_refresh(config)


def test_require_refreshable_strategy_when_enable_refresh_ignores_api_key_backend() -> None:
    """API-key backends are standalone authenticators outside refresh-token flows."""
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="refreshable",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryRefreshTokenStrategy(token_prefix="refreshable")),
            ),
        ],
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(enabled=True, allowed_scopes=("read",))
    config.enable_refresh = True

    startup_backends = config.resolve_startup_backends()
    assert [backend.name for backend in startup_backends] == ["refreshable", "api_key"]
    assert isinstance(startup_backends[1].transport, ApiKeyTransport)

    startup_module.require_refreshable_strategy_when_enable_refresh(config)


def test_require_refreshable_strategy_when_enable_refresh_rejects_non_refreshable_strategy() -> None:
    """Refresh-enabled configs fail at startup when a backend cannot issue refresh tokens."""
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="primary")),
            ),
        ],
    )
    config.enable_refresh = True

    with pytest.raises(ConfigurationError) as exc_info:
        startup_module.require_refreshable_strategy_when_enable_refresh(config)

    message = str(exc_info.value)
    assert "primary" in message
    assert "InMemoryTokenStrategy" in message
    assert "does not implement RefreshableStrategy" in message
    assert "enable_refresh=False" in message


def test_warn_insecure_plugin_startup_defaults_warns_for_request_verify_token_inmemory_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startup warnings still inspect non-login endpoint rate-limit settings."""
    config = _minimal_config(
        rate_limit_config=AuthRateLimitConfig(
            request_verify_token=EndpointRateLimit(
                backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
                scope="ip",
                namespace="request-verify-token",
            ),
        ),
    )

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert any("process-local in-memory backend" in str(record.message) for record in records)


def test_warn_insecure_plugin_startup_defaults_warns_for_totp_confirm_enable_inmemory_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startup warnings still inspect TOTP confirm-enrollment rate-limit settings."""
    config = _minimal_config(
        rate_limit_config=AuthRateLimitConfig(
            totp_confirm_enable=EndpointRateLimit(
                backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
                scope="ip",
                namespace="totp-confirm-enable",
            ),
        ),
    )

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert any("process-local in-memory backend" in str(record.message) for record in records)


def test_validate_rate_limit_config_rejects_invalid_request_verify_token_trusted_proxy() -> None:
    """Trusted-proxy validation still inspects non-login endpoint rate-limit settings."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="request-verify-token",
        trusted_proxy=cast("bool", "yes"),
    )

    with pytest.raises(Exception, match="trusted_proxy must be a boolean") as exc_info:
        validate_rate_limit_config(AuthRateLimitConfig(request_verify_token=rate_limit))
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_rate_limit_config_rejects_invalid_totp_confirm_enable_trusted_proxy() -> None:
    """Trusted-proxy validation still inspects TOTP confirm-enrollment settings."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="totp-confirm-enable",
        trusted_proxy=cast("bool", "yes"),
    )

    with pytest.raises(Exception, match="trusted_proxy must be a boolean") as exc_info:
        validate_rate_limit_config(AuthRateLimitConfig(totp_confirm_enable=rate_limit))
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_totp_pending_secret_config_rejects_unsupported_algorithm() -> None:
    """Production validation rejects algorithms outside the supported TOTP set."""
    config = _minimal_config(
        totp_config=_configured_totp_config(totp_algorithm="SHA1"),
    )

    with pytest.raises(ValueError, match="totp_algorithm must be one of: SHA256, SHA512"):
        _validate_totp_pending_secret_config(config)


def test_validate_totp_pending_secret_config_requires_algorithm() -> None:
    """A configured TOTP block still needs an explicit algorithm."""
    config = _minimal_config()
    config.totp_config = cast(
        "Any",
        type("Config", (), {"totp_pending_secret": "0123456789abcdef" * 4, "totp_algorithm": ""})(),
    )

    with pytest.raises(ValueError, match="totp_algorithm must be configured"):
        _validate_totp_pending_secret_config(config)


def test_validate_totp_pending_secret_config_rejects_short_secret() -> None:
    """Configured TOTP pending secrets still go through shared minimum-length validation."""
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="short",
            totp_pending_jti_store=cast("Any", _DurableDenylistStore()),
            totp_used_tokens_store=cast("Any", object()),
        ),
    )

    with pytest.raises(Exception, match="at least 32") as exc_info:
        _validate_totp_pending_secret_config(config)
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_totp_pending_secret_config_requires_recovery_code_lookup_secret() -> None:
    """TOTP startup validation requires lookup secret material for recovery codes."""
    config = _minimal_config(
        totp_config=_configured_totp_config(),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
        ),
    )

    with pytest.raises(ConfigurationError, match="totp_recovery_code_lookup_secret is required"):
        _validate_totp_pending_secret_config(config)


def test_validate_totp_user_model_protocol_accepts_totp_user_model() -> None:
    """TOTP startup validation accepts a model exposing the required protocol fields."""
    config = _minimal_config(totp_config=_configured_totp_config())

    validate_totp_user_model_protocol(config)


def test_validate_config_rejects_totp_enabled_user_model_without_totp_fields() -> None:
    """TOTP-enabled startup validation fails before serving requests for incompatible user models."""

    class _UserModelWithoutTotpSecret:
        id = UUID(int=0)
        email = "user@example.com"
        hashed_password = "hashed-password"
        is_active = True
        is_verified = False
        roles = ()

    config = _minimal_config(
        totp_config=_configured_totp_config(totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore())),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_key=TOTP_SECRET_KEY,
            totp_recovery_code_lookup_secret=TOTP_RECOVERY_CODE_LOOKUP_SECRET,
            id_parser=UUID,
        ),
    )
    config.user_model = cast("type[ExampleUser]", _UserModelWithoutTotpSecret)

    with pytest.raises(
        validation_module.ConfigurationError,
        match=r"TotpUserProtocol: 'totp_secret'",
    ):
        validate_config(config)


def test_validate_totp_user_model_protocol_rejects_missing_email_and_totp_fields() -> None:
    """The startup validator reports every missing TOTP protocol field."""

    class _UserModelWithoutTotpFields:
        id = UUID(int=0)

    config = _minimal_config(totp_config=_configured_totp_config())
    config.user_model = cast("type[ExampleUser]", _UserModelWithoutTotpFields)

    with pytest.raises(
        validation_module.ConfigurationError,
        match=r"TotpUserProtocol: 'email', 'totp_secret'",
    ):
        validate_totp_user_model_protocol(config)


def test_validate_totp_encryption_key_requires_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production TOTP validation requires an at-rest encryption key."""
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET))

    with pytest.raises(
        validation_module.ConfigurationError,
        match="totp_secret_keyring or totp_secret_key is required in production",
    ) as exc_info:
        _validate_totp_encryption_key(config)
    assert (
        str(exc_info.value)
        == TotpSecretStoragePosture.fernet_encrypted(
            key_configured=False,
        ).production_validation_error
    )


def test_validate_totp_encryption_key_allows_configured_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Providing the encryption key satisfies the production-only TOTP requirement."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_key=TOTP_SECRET_KEY,
            totp_recovery_code_lookup_secret=TOTP_RECOVERY_CODE_LOOKUP_SECRET,
        ),
    )

    _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_allows_configured_keyring_in_production() -> None:
    """Providing a TOTP Fernet keyring satisfies the production encryption requirement."""
    keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key(), "old": _fernet_key()})
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_keyring=keyring,
        ),
    )

    _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_allows_typed_security_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical typed security bundle satisfies the production TOTP requirement."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
        user_manager_security=UserManagerSecurity[UUID](
            totp_secret_key=TOTP_SECRET_KEY,
            totp_recovery_code_lookup_secret=TOTP_RECOVERY_CODE_LOOKUP_SECRET,
        ),
    )

    _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_allows_factory_owned_totp_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Custom factories own TOTP encryption wiring when the typed contract is omitted."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
        user_manager_security=None,
    )
    config.user_manager_security = None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])

    _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_rejects_empty_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty typed TOTP secret still fails the production encryption check."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_key="",
        ),
    )

    with pytest.raises(
        validation_module.ConfigurationError,
        match="totp_secret_keyring or totp_secret_key is required in production",
    ) as exc_info:
        _validate_totp_encryption_key(config)
    assert (
        str(exc_info.value)
        == TotpSecretStoragePosture.fernet_encrypted(
            key_configured=False,
        ).production_validation_error
    )


def test_validate_user_manager_security_config_allows_factory_owned_manager_without_typed_security() -> None:
    """Custom factories remain the escape hatch when plugin-managed security is omitted."""
    config = _minimal_config()
    config.user_manager_security = None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])

    validate_user_manager_security_config(config)


def test_validate_user_manager_security_config_rejects_mismatched_top_level_id_parser() -> None:
    """Top-level and typed id_parser declarations must agree."""

    def _parse_uuid(raw: str) -> UUID:
        return UUID(raw)

    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](id_parser=UUID),
        id_parser=_parse_uuid,
    )

    with pytest.raises(validation_module.ConfigurationError, match="Configure id_parser via"):
        validate_user_manager_security_config(config)


def test_validate_config_accepts_typed_user_manager_security_contract() -> None:
    """Plugin validation accepts the canonical typed security path without legacy overlap."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_key=TOTP_SECRET_KEY,
            totp_recovery_code_lookup_secret=TOTP_RECOVERY_CODE_LOOKUP_SECRET,
            id_parser=UUID,
        ),
        id_parser=UUID,
        totp_config=_configured_totp_config(totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore())),
    )

    validate_user_manager_security_config(config)


def test_validate_user_manager_security_config_rejects_when_secret_roles_share_one_value() -> None:
    """Production validation fails closed when auth secret roles reuse one value."""
    shared_secret = "shared-secret-role-value-1234567890"
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=shared_secret,
            reset_password_token_secret=shared_secret,
            login_identifier_telemetry_secret=shared_secret,
            totp_secret_key=shared_secret,
            totp_recovery_code_lookup_secret=shared_secret,
        ),
        totp_config=_configured_totp_config(
            totp_pending_secret=shared_secret,
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )

    with pytest.raises(ConfigurationError, match="Distinct secrets/keys") as exc_info:
        validate_user_manager_security_config(config)

    message = str(exc_info.value)
    assert "verification_token_secret" in message
    assert "reset_password_token_secret" in message
    assert "login_identifier_telemetry_secret" in message
    assert "totp_secret_key" in message
    assert "totp_pending_secret" in message
    assert "totp_recovery_code_lookup_secret" in message
    assert VERIFY_TOKEN_AUDIENCE in message
    assert RESET_PASSWORD_TOKEN_AUDIENCE in message
    assert TOTP_PENDING_AUDIENCE in message
    assert TOTP_ENROLL_AUDIENCE in message
    assert shared_secret not in message


def test_validate_api_key_config_rejects_missing_hash_secret() -> None:
    """API-key auth cannot be enabled without dedicated HMAC key material."""
    config = _minimal_config()
    config.api_keys = ApiKeyConfig(enabled=True, allowed_scopes=("read",))

    with pytest.raises(ConfigurationError, match="api_key_hash_secret is required"):
        validate_api_key_config(config)


def test_validate_api_key_config_rejects_non_positive_max_keys() -> None:
    """API-key max key count must fail closed when enabled."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(enabled=True, max_keys_per_user=0, allowed_scopes=("read",))

    with pytest.raises(ConfigurationError, match="max_keys_per_user"):
        validate_api_key_config(config)


def test_validate_api_key_config_rejects_empty_allowed_scopes_when_subset_check_enabled() -> None:
    """API-key scope subset checks require an explicit whitelist."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(enabled=True)

    with pytest.raises(ConfigurationError, match="allowed_scopes"):
        validate_api_key_config(config)


def test_validate_api_key_config_accepts_disabled_config_without_hash_secret() -> None:
    """Disabled API-key auth does not require API-key secret material."""
    config = _minimal_config()

    validation_module._api_key_validation._validate_api_key_signing_secret_distinctness(config)


def test_validate_api_key_config_accepts_enabled_production_shape() -> None:
    """A complete API-key config passes startup validation."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(enabled=True, allowed_scopes=("read",))

    validate_api_key_config(config)


def test_validate_api_key_config_rejects_signing_without_keyring() -> None:
    """Signing mode requires API-key secret-at-rest encryption material."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read",),
        signing_enabled=True,
        nonce_store=InMemoryApiKeyNonceStore(),
    )

    with pytest.raises(ConfigurationError, match="secret_encryption_keyring"):
        validate_api_key_config(config)


def test_validate_api_key_config_rejects_signing_without_nonce_store() -> None:
    """Signing mode requires replay protection outside unsafe testing."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read",),
        signing_enabled=True,
        secret_encryption_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key()}),
    )

    with pytest.raises(ConfigurationError, match="nonce_store"):
        validate_api_key_config(config)


def test_validate_api_key_config_rejects_signing_key_reuse() -> None:
    """API-key signing encryption keys must not reuse API-key hash material."""
    shared_secret = _fernet_key()
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=shared_secret,
        ),
    )
    config.api_keys = ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read",),
        signing_enabled=True,
        nonce_store=InMemoryApiKeyNonceStore(),
        secret_encryption_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": shared_secret}),
    )

    with pytest.raises(ConfigurationError, match="api_key_secret_encryption_keyring"):
        validate_api_key_config(config)


def test_validate_api_key_config_rejects_process_local_nonce_store_for_multiworker() -> None:
    """Signing nonce stores must be shared in declared multi-worker deployments."""
    config = _minimal_config(
        deployment_worker_count=2,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read",),
        signing_enabled=True,
        nonce_store=InMemoryApiKeyNonceStore(),
        secret_encryption_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key()}),
    )

    with pytest.raises(ConfigurationError, match="shared across workers"):
        validate_api_key_config(config)


def test_validate_api_key_config_accepts_shared_nonce_store_for_multiworker() -> None:
    """Shared signing nonce stores satisfy declared multi-worker validation."""

    class SharedNonceStore:
        is_shared_across_workers = True

    config = _minimal_config(
        deployment_worker_count=2,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read",),
        signing_enabled=True,
        nonce_store=SharedNonceStore(),
        secret_encryption_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key()}),
    )

    validate_api_key_config(config)


def test_validate_api_key_signing_distinctness_skips_without_security() -> None:
    """Signing distinctness validation is a no-op without manager security material."""
    config = _minimal_config()
    config.api_keys = ApiKeyConfig(
        enabled=False,
        signing_enabled=True,
        secret_encryption_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key()}),
    )

    validate_api_key_config(config)


@pytest.mark.parametrize(
    ("api_key_config", "match"),
    [
        pytest.param(
            ApiKeyConfig(enabled=True, allowed_scopes=("read",), last_used_throttle_seconds=-1),
            "last_used_throttle_seconds",
            id="negative-throttle",
        ),
        pytest.param(
            ApiKeyConfig(
                enabled=True,
                allowed_scopes=("read",),
                last_used_write_strategy=cast("Any", "sometimes"),
            ),
            "last_used_write_strategy",
            id="invalid-last-used-strategy",
        ),
        pytest.param(
            ApiKeyConfig(enabled=True, allowed_scopes=("read",), environment_marker="_prod"),
            "environment_marker",
            id="invalid-environment-marker",
        ),
        pytest.param(
            ApiKeyConfig(enabled=True, allowed_scopes=("read",), prefix="1ak"),
            "prefix",
            id="invalid-prefix",
        ),
        pytest.param(
            ApiKeyConfig(enabled=True, allowed_scopes=("read",), signing_skew_seconds=0),
            "signing_skew_seconds",
            id="invalid-signing-skew",
        ),
        pytest.param(
            ApiKeyConfig(enabled=True, allowed_scopes=("read",), signed_body_max_bytes=0),
            "signed_body_max_bytes",
            id="invalid-signed-body-limit",
        ),
    ],
)
def test_validate_api_key_config_rejects_invalid_policy_fields(api_key_config: ApiKeyConfig, match: str) -> None:
    """API-key policy fields are validated before backend wiring."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = api_key_config

    with pytest.raises(ConfigurationError, match=match):
        validate_api_key_config(config)


@pytest.mark.parametrize("strategy", get_args(ApiKeyLastUsedWriteStrategy))
def test_validate_api_key_config_accepts_declared_last_used_write_strategies(strategy: str) -> None:
    """Every declared last-used write strategy is accepted by plugin validation."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read",),
        last_used_write_strategy=cast("Any", strategy),
    )

    validate_api_key_config(config)


def test_validate_api_key_config_lists_declared_last_used_write_strategies() -> None:
    """Invalid last-used write strategy errors list the declared strategy values."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            api_key_hash_secret=API_KEY_HASH_SECRET,
        ),
    )
    config.api_keys = ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read",),
        last_used_write_strategy=cast("Any", "sometimes"),
    )

    with pytest.raises(ConfigurationError) as exc_info:
        validate_api_key_config(config)

    message = str(exc_info.value)
    for strategy in get_args(ApiKeyLastUsedWriteStrategy):
        assert repr(strategy) in message


def test_validate_user_manager_security_config_rejects_short_login_telemetry_secret() -> None:
    """Plugin validation catches short failed-login telemetry secrets before manager construction."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            login_identifier_telemetry_secret="short",
        ),
    )

    with pytest.raises(ConfigurationError, match="login_identifier_telemetry_secret"):
        validate_user_manager_security_config(config)


def test_validate_user_manager_security_config_rejects_keyring_secret_role_reuse() -> None:
    """Distinct-role validation checks every configured TOTP keyring value."""
    shared_secret = _fernet_key()
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=shared_secret,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_keyring=FernetKeyringConfig(active_key_id="current", keys={"current": shared_secret}),
        ),
    )

    with pytest.raises(ConfigurationError, match="Distinct secrets/keys") as exc_info:
        validate_user_manager_security_config(config)

    message = str(exc_info.value)
    assert "verification_token_secret" in message
    assert "totp_secret_key" in message
    assert shared_secret not in message


def test_validate_user_manager_security_config_allows_reused_roles_under_unsafe_testing() -> None:
    """The reused-secret validation bypass is explicit and scoped to unsafe testing."""
    shared_secret = "shared-secret-role-value-1234567890"
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=shared_secret,
            reset_password_token_secret=shared_secret,
            totp_secret_key=shared_secret,
        ),
        totp_config=_configured_totp_config(
            totp_pending_secret=shared_secret,
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )
    config.unsafe_testing = True

    validate_user_manager_security_config(config)


def test_validate_totp_config_warns_for_insecure_cookie_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production TOTP validation warns when the enable endpoint can travel over insecure cookies."""
    config = _minimal_config(
        backends=[_cookie_backend()],
        totp_config=_configured_totp_config(totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore())),
    )

    with pytest.warns(validation_module.SecurityWarning, match="CookieTransport.secure=False"):
        validate_totp_config(config)


def test_validate_totp_config_skips_insecure_cookie_warning_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode suppresses the insecure-cookie warning branch for TOTP validation."""
    config = _minimal_config(
        backends=[_cookie_backend()],
        totp_config=_configured_totp_config(totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore())),
    )
    config.unsafe_testing = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        validate_totp_config(config)

    assert not records


def test_validate_totp_sub_config_rejects_missing_pending_jti_store_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pending-token replay protection requires a configured denylist outside explicit unsafe testing."""
    with pytest.raises(ValueError, match="totp_pending_jti_store is required"):
        validate_totp_sub_config(
            TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
            user_manager_class=PluginUserManager,
        )


def test_validate_totp_sub_config_rejects_missing_enrollment_store_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pending enrollment state requires a configured store outside explicit unsafe testing."""
    with pytest.raises(ValueError, match="totp_enrollment_store is required"):
        validate_totp_sub_config(
            TotpConfig(
                totp_pending_secret=TOTP_PENDING_SECRET,
                totp_pending_jti_store=cast("Any", _DurableDenylistStore()),
            ),
            user_manager_class=PluginUserManager,
        )


def test_validate_totp_sub_config_rejects_missing_pending_secret() -> None:
    """The TOTP helper owns the missing-pending-secret branch directly."""
    with pytest.raises(ValueError, match="totp_pending_secret"):
        validate_totp_sub_config(
            TotpConfig(totp_pending_secret=""),
            user_manager_class=PluginUserManager,
        )


def test_validate_totp_sub_config_rejects_missing_authenticate_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Password-gated TOTP enrollment requires an authenticate hook."""

    class _ManagerWithoutAuthenticate:
        pass

    with pytest.raises(ValueError, match=r"user_manager_class\.authenticate"):
        validate_totp_sub_config(
            _configured_totp_config(totp_enable_requires_password=True),
            user_manager_class=_ManagerWithoutAuthenticate,
            unsafe_testing=True,
        )


def test_validate_cookie_auth_config_rejects_missing_csrf_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cookie auth in production requires either a CSRF secret or an explicit unsafe override."""
    config = _minimal_config(backends=[_cookie_backend()])

    with pytest.raises(validation_module.ConfigurationError, match="requires csrf_secret"):
        validate_cookie_auth_config(config)


def test_validate_cookie_auth_config_rejects_short_csrf_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configured CSRF secrets still have to satisfy minimum-length validation."""
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = "short"

    with pytest.raises(Exception, match="csrf_secret") as exc_info:
        validate_cookie_auth_config(config)
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_cookie_auth_config_allows_explicit_insecure_cookie_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compatibility override keeps the legacy cookie path available when chosen explicitly."""
    config = _minimal_config(
        backends=[_cookie_backend(allow_insecure_cookie_auth=True)],
    )

    validate_cookie_auth_config(config)


def test_validate_cookie_auth_config_returns_without_cookie_transports() -> None:
    """Bearer-only configurations skip the cookie-auth validation branch."""
    validate_cookie_auth_config(_minimal_config(backends=[_non_jwt_backend()]))


def test_get_cookie_transports_returns_only_cookie_backends() -> None:
    """Cookie transport extraction ignores bearer-only backends."""
    cookie_backend = _cookie_backend()
    cookie_transports = get_cookie_transports([cookie_backend, _non_jwt_backend()])

    assert cookie_transports == [cookie_backend.transport]


def test_build_csrf_config_rejects_heterogeneous_cookie_transports() -> None:
    """Plugin-managed CSRF setup requires homogeneous cookie transport settings."""
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = JWT_SECRET
    cookie_transports = [
        CookieTransport(path="/auth", secure=False, samesite="strict"),
        CookieTransport(path="/other-auth", secure=False, samesite="strict"),
    ]

    with pytest.raises(ValueError, match="must share path, domain, secure, and samesite"):
        build_csrf_config(config, cookie_transports)


def test_build_csrf_config_rejects_missing_csrf_secret() -> None:
    """Runtime CSRF construction keeps the csrf_secret invariant local."""
    config = _minimal_config(backends=[_cookie_backend()])

    with pytest.raises(ValueError, match="csrf_secret must be configured"):
        build_csrf_config(config, [CookieTransport()])


def test_build_csrf_config_returns_expected_cookie_settings() -> None:
    """A homogeneous cookie transport set produces the shared CSRF config."""
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = JWT_SECRET
    cookie_transports = [
        CookieTransport(path="/auth", domain="example.com", secure=False, samesite="strict"),
        CookieTransport(path="/auth", domain="example.com", secure=False, samesite="strict"),
    ]

    csrf_config = build_csrf_config(config, cookie_transports)

    assert csrf_config.secret == config.csrf_secret
    assert csrf_config.cookie_name == DEFAULT_CSRF_COOKIE_NAME
    assert csrf_config.cookie_path == "/auth"
    assert csrf_config.cookie_domain == "example.com"
    assert csrf_config.cookie_secure is False
    assert csrf_config.cookie_samesite == "strict"


@pytest.mark.parametrize(
    "route_variant",
    [
        pytest.param("login-only", id="login-providers"),
        pytest.param("login-and-associate", id="login-and-associate"),
    ],
)
def test_require_oauth_token_encryption_for_configured_providers_calls_require_key(
    route_variant: str,
) -> None:
    """Either configured OAuth provider inventory triggers the fail-closed key requirement."""
    oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        include_oauth_associate=route_variant == "login-and-associate",
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )
    config = _minimal_config(oauth_config=oauth_config)
    seen: list[str] = []

    def _require_key(*, context: str) -> None:
        seen.append(context)

    require_oauth_token_encryption_for_configured_providers(config=config, require_key=_require_key)

    assert seen == ["OAuth providers are configured"]


def test_require_oauth_token_encryption_for_configured_providers_skips_unconfigured_oauth() -> None:
    """Without providers, the fail-closed callback is not invoked."""
    seen: list[str] = []

    require_oauth_token_encryption_for_configured_providers(
        config=_minimal_config(oauth_config=OAuthConfig()),
        require_key=lambda *, context: seen.append(context),
    )

    assert not seen


def test_has_configured_oauth_provider_helpers_report_expected_state() -> None:
    """Both provider helper variants agree on configured and unconfigured OAuth state."""
    empty_config = OAuthConfig()
    login_only_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )
    login_and_associate_config = OAuthConfig(
        include_oauth_associate=True,
        oauth_providers=[_oauth_provider(name="github", client=object())],
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )

    assert has_configured_oauth_providers(_minimal_config(oauth_config=None)) is False
    assert has_configured_oauth_providers(_minimal_config(oauth_config=login_only_config)) is True
    assert has_configured_oauth_providers(_minimal_config(oauth_config=login_and_associate_config)) is True
    assert has_configured_oauth_providers_for(empty_config) is False
    assert has_configured_oauth_providers_for(login_only_config) is True
    assert has_configured_oauth_providers_for(login_and_associate_config) is True


def test_require_secure_oauth_redirect_in_production_accepts_public_https_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production startup accepts public HTTPS plugin redirect origins."""

    def _public_host(_host: str, *, strict: bool = False) -> bool:
        return False

    monkeypatch.setattr(startup_module, "_is_unsafe_redirect_host", _public_host)
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


def test_require_secure_oauth_redirect_in_production_forwards_strict_dns_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict DNS mode lets operators fail closed when plugin redirect-host DNS is unusable."""

    def _unsafe_only_when_strict(_host: str, *, strict: bool = False) -> bool:
        return strict

    monkeypatch.setattr(startup_module, "_is_unsafe_redirect_host", _unsafe_only_when_strict)
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_redirect_dns_strict=True,
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    with pytest.raises(ConfigurationError, match="routable public HTTPS origin"):
        require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


def test_require_secure_oauth_redirect_in_production_opt_out_restores_fail_open_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit ``oauth_redirect_dns_strict=False`` restores the fail-open DNS posture."""

    def _unsafe_only_when_strict(_host: str, *, strict: bool = False) -> bool:
        return strict

    monkeypatch.setattr(startup_module, "_is_unsafe_redirect_host", _unsafe_only_when_strict)
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_redirect_dns_strict=False,
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


def test_require_secure_oauth_redirect_in_production_fails_closed_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fail-closed DNS default rejects unusable plugin redirect-host resolution."""

    def _unsafe_only_when_strict(_host: str, *, strict: bool = False) -> bool:
        return strict

    monkeypatch.setattr(startup_module, "_is_unsafe_redirect_host", _unsafe_only_when_strict)
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    with pytest.raises(ConfigurationError, match="routable public HTTPS origin"):
        require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


@pytest.mark.parametrize(
    ("redirect_base_url", "message"),
    [
        pytest.param(
            "http://app.example.com/auth",
            "public HTTPS origin",
            id="public-http-origin",
        ),
        pytest.param(
            "https://localhost/auth",
            "routable public HTTPS origin",
            id="loopback-https-origin",
        ),
        pytest.param(
            "https://10.0.0.5/auth",
            "routable public HTTPS origin",
            id="rfc1918-private-ip",
        ),
        pytest.param(
            "https://169.254.169.254/auth",
            "routable public HTTPS origin",
            id="link-local-imds",
        ),
        pytest.param(
            "https://[::1]/auth",
            "routable public HTTPS origin",
            id="ipv6-loopback",
        ),
        pytest.param(
            "https://[fe80::1]/auth",
            "routable public HTTPS origin",
            id="ipv6-link-local",
        ),
    ],
)
def test_require_secure_oauth_redirect_in_production_rejects_insecure_origins(
    redirect_base_url: str,
    message: str,
) -> None:
    """Production startup fails closed for public HTTP and non-routable OAuth redirect bases."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url=redirect_base_url,
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    with pytest.raises(ConfigurationError, match=message):
        require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


def test_require_secure_oauth_redirect_in_production_skips_debug_mode() -> None:
    """Debug mode keeps explicit localhost redirect recipes available."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url="http://localhost/auth",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=True))


def test_require_secure_oauth_redirect_in_production_skips_unsafe_testing() -> None:
    """unsafe_testing keeps explicit localhost redirect recipes available for tests."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url="http://localhost/auth",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )
    config.unsafe_testing = True

    require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


def test_validate_config_rejects_include_oauth_associate_without_provider_inventory() -> None:
    """Associate-route enablement still requires the single plugin-owned provider inventory."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            include_oauth_associate=True,
        ),
    )

    with pytest.raises(ValueError, match="include_oauth_associate=True requires oauth_providers"):
        validate_config(config)


def test_validate_config_rejects_missing_redirect_base_url_for_plugin_owned_oauth_routes() -> None:
    """Plugin-owned OAuth routes require an explicit public redirect base URL."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    with pytest.raises(ValueError, match="oauth_redirect_base_url is required when oauth_providers are configured"):
        validate_config(config)


@pytest.mark.parametrize(
    ("oauth_flow_cookie_secret", "expected_message"),
    [
        pytest.param(None, "oauth_flow_cookie_secret is required", id="missing"),
        pytest.param("too-short", "oauth_flow_cookie_secret must be at least", id="too-short"),
    ],
)
def test_validate_config_rejects_missing_or_short_oauth_flow_cookie_secret(
    oauth_flow_cookie_secret: str | None,
    expected_message: str,
) -> None:
    """Plugin-owned OAuth routes require a dedicated secret for encrypted flow cookies."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            oauth_flow_cookie_secret=oauth_flow_cookie_secret,
        ),
    )

    with pytest.raises(ConfigurationError, match=expected_message):
        validate_config(config)


def test_validate_config_rejects_orphan_redirect_base_url() -> None:
    """OAuth redirect-base settings must correspond to plugin-owned OAuth routes."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    with pytest.raises(ValueError, match="oauth_redirect_base_url requires oauth_providers to be configured"):
        validate_config(config)


def test_validate_config_rejects_duplicate_login_provider_names() -> None:
    """Duplicate login-provider names would make explicit route ownership ambiguous."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[
                _oauth_provider(name="github", client=object()),
                _oauth_provider(name="github", client=object()),
            ],
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
        ),
    )

    with pytest.raises(ValueError, match=r"oauth_providers must not contain duplicate provider names: github"):
        validate_config(config)


def test_validate_config_rejects_oauth_associate_by_email_without_login_provider_inventory() -> None:
    """Associate-by-email cannot be declared without plugin-owned OAuth login routes."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_associate_by_email=True,
            oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        ),
    )

    with pytest.raises(ValueError, match="oauth_associate_by_email only affects plugin-owned OAuth login routes"):
        validate_config(config)


def test_validate_config_rejects_oauth_trust_provider_email_verified_without_provider_inventory() -> None:
    """Provider-email trust cannot be declared without plugin-owned OAuth login routes."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_trust_provider_email_verified=True,
            oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        ),
    )

    with pytest.raises(
        ValueError,
        match="oauth_trust_provider_email_verified only affects plugin-owned OAuth login routes",
    ):
        validate_config(config)


def test_validate_config_runs_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The top-level validator exercises the expected startup validation sequence."""
    config = _minimal_config()

    validate_config(config)


def test_validate_config_runs_happy_path_for_database_token_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The DB bearer preset flows through the same top-level validator path as manual backends."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret=TOKEN_HASH_SECRET,
            max_age=timedelta(minutes=10),
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
        ),
    )

    validate_config(config)


def test_litestar_auth_config_rejects_negative_totp_stepup_ttl() -> None:
    """TOTP step-up TTL must be non-negative at construction time."""
    with pytest.raises(ConfigurationError, match="totp_stepup_ttl_seconds"):
        LitestarAuthConfig[ExampleUser, UUID](
            backends=[_jwt_backend()],
            session_maker=cast("Any", DummySessionMaker()),
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            user_manager_security=UserManagerSecurity[UUID](
                verification_token_secret=VERIFICATION_SECRET,
                reset_password_token_secret=RESET_PASSWORD_SECRET,
            ),
            totp_stepup_ttl_seconds=-1,
        )


def test_validate_config_rejects_unknown_totp_stepup_policy_key() -> None:
    """Startup validation rejects policy entries for unknown endpoint ids."""
    config = _minimal_config(totp_config=_configured_totp_config())
    config.totp_stepup_policy = {"unknown.endpoint": "required_when_enrolled"}

    with pytest.raises(ConfigurationError, match="Unknown totp_stepup_policy endpoint"):
        validate_config(config)


def test_validate_config_rejects_invalid_totp_stepup_policy_mode() -> None:
    """Startup validation rejects unsupported TOTP step-up policy modes."""
    config = _minimal_config(totp_config=_configured_totp_config())
    config.totp_stepup_policy = {"api_keys.create": cast("Any", "required")}

    with pytest.raises(ConfigurationError, match="Invalid totp_stepup_policy mode"):
        validate_config(config)


def test_validate_config_accepts_known_totp_stepup_policy_entry() -> None:
    """Startup validation accepts documented TOTP step-up endpoint policy entries."""
    config = _minimal_config(
        totp_config=_configured_totp_config(totp_require_replay_protection=False),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            totp_secret_key=TOTP_SECRET_KEY,
            totp_recovery_code_lookup_secret=TOTP_RECOVERY_CODE_LOOKUP_SECRET,
        ),
    )
    config.totp_stepup_policy = {"api_keys.create": "required_when_enrolled"}

    validate_config(config)


def test_validate_config_allows_explicit_unsafe_testing_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit unsafe testing, not runtime globals, controls relaxed validation."""
    config = _minimal_config(
        backends=[_cookie_backend(), _jwt_backend()],
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
    )
    config.unsafe_testing = True

    validate_config(config)


def test_validate_config_keeps_unsafe_testing_instance_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsafe-testing relaxations stay instance-scoped instead of process-global."""
    strict_config = _minimal_config(
        backends=[_cookie_backend(), _jwt_backend()],
        totp_config=_configured_totp_config(),
    )
    relaxed_config = _minimal_config(
        backends=[_cookie_backend(), _jwt_backend()],
        totp_config=TotpConfig(totp_pending_secret=TOTP_PENDING_SECRET),
    )
    relaxed_config.unsafe_testing = True

    with pytest.raises(ValueError, match="totp_require_replay_protection=True requires"):
        validate_config(strict_config)

    validate_config(relaxed_config)


def test_validate_config_reports_missing_backends_before_later_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core startup prerequisites fail before later user-manager contract checks."""
    config = _minimal_config(backends=[])

    class _ManagerWithoutListUsers(PluginUserManager):
        list_users = None

    config.include_users = True
    config.user_manager_class = cast("type[Any]", _ManagerWithoutListUsers)

    with pytest.raises(ValueError, match="at least one authentication backend"):
        validate_config(config)


def test_validate_config_preserves_session_prerequisite_for_database_token_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The DB bearer preset still requires the same session source as the manual backend path."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
        ),
    )

    with pytest.raises(ValueError, match=r"requires session_maker or db_session_dependency_provided_externally"):
        validate_config(config)


def test_validate_config_reports_user_manager_contract_errors_before_request_security_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Credential-contract failures surface before later cookie-auth validation errors."""

    class _ManagerWithoutListUsers(PluginUserManager):
        list_users = None

    config = _minimal_config(backends=[_cookie_backend()])
    config.include_users = True
    config.user_manager_class = cast("type[Any]", _ManagerWithoutListUsers)

    with pytest.raises(ValueError, match="define list_users"):
        validate_config(config)


def test_validate_config_reports_totp_shape_errors_before_encryption_key_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed TOTP config surfaces before the production encryption-key requirement."""
    config = _minimal_config()
    config.totp_config = cast(
        "Any",
        type(
            "InvalidTotpConfig",
            (),
            {
                "totp_pending_secret": "0123456789abcdef" * 4,
                "totp_algorithm": "",
                "totp_used_tokens_store": object(),
                "totp_require_replay_protection": True,
                "totp_enable_requires_password": True,
            },
        )(),
    )

    with pytest.raises(ValueError, match="totp_algorithm must be configured"):
        validate_config(config)


def test_validate_request_security_config_checks_rate_limit_before_cookie_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Request-facing validation preserves rate-limit checks before cookie-auth checks."""
    config = _minimal_config()
    calls: list[tuple[str, object]] = []

    def _record_rate_limit(rate_limit_config: object) -> None:
        calls.append(("rate_limit", rate_limit_config))

    def _record_cookie(config_arg: object) -> None:
        calls.append(("cookie", config_arg))

    monkeypatch.setattr(request_security_validation_module, "validate_rate_limit_config", _record_rate_limit)
    monkeypatch.setattr(request_security_validation_module, "validate_cookie_auth_config", _record_cookie)

    validation_module.validate_request_security_config(config)

    assert calls == [
        ("rate_limit", config.rate_limit_config),
        ("cookie", config),
    ]


@pytest.mark.parametrize("role_name", ["", "   "])
def test_validate_superuser_role_name_config_rejects_empty_values(role_name: str) -> None:
    """Configured superuser role names must be non-empty after normalization."""
    with pytest.raises(ConfigurationError, match="non-empty role name"):
        _minimal_config(superuser_role_name=role_name)


def test_validate_superuser_role_name_config_revalidates_mutated_config_value() -> None:
    """Startup validation fails closed if callers mutate the config after construction."""
    config = _minimal_config(superuser_role_name=" Admin ")
    config.superuser_role_name = "   "

    with pytest.raises(ConfigurationError, match="non-empty role name"):
        validate_superuser_role_name_config(config)


def _minimal_config(  # noqa: PLR0913
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    deployment_worker_count: int | None = None,
    oauth_config: OAuthConfig | None = None,
    rate_limit_config: AuthRateLimitConfig | None = None,
    totp_config: TotpConfig | None = None,
    user_manager_security: UserManagerSecurity[UUID] | None = None,
    id_parser: object | None = None,
    superuser_role_name: str = "superuser",
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for validation-focused unit tests.

    Returns:
        Minimal config object with overridable backends and optional nested auth settings.
    """
    resolved_manager_security = user_manager_security or UserManagerSecurity[UUID](
        verification_token_secret=VERIFICATION_SECRET,
        reset_password_token_secret=RESET_PASSWORD_SECRET,
        totp_recovery_code_lookup_secret=TOTP_RECOVERY_CODE_LOOKUP_SECRET if totp_config is not None else None,
    )
    user_db = InMemoryUserDatabase([])
    configured_backends = (
        backends
        if backends is not None
        else [
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-validation")),
            ),
        ]
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=configured_backends,
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=resolved_manager_security,
        deployment_worker_count=deployment_worker_count,
        id_parser=cast("Any", id_parser),
        oauth_config=oauth_config,
        rate_limit_config=rate_limit_config,
        totp_config=totp_config,
        superuser_role_name=superuser_role_name,
    )


def _cookie_backend(
    *,
    allow_insecure_cookie_auth: bool = False,
    refresh_max_age: int | None = None,
) -> AuthenticationBackend[ExampleUser, UUID]:
    return AuthenticationBackend[ExampleUser, UUID](
        name="cookie",
        transport=CookieTransport(
            secure=False,
            samesite="strict",
            allow_insecure_cookie_auth=allow_insecure_cookie_auth,
            refresh_max_age=refresh_max_age,
        ),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie")),
    )


def _jwt_backend(*, denylist_store: object | None = None) -> AuthenticationBackend[ExampleUser, UUID]:
    strategy = _current_jwt_strategy(denylist_store=denylist_store)
    return AuthenticationBackend[ExampleUser, UUID](
        name="jwt",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )


def _non_jwt_backend() -> AuthenticationBackend[ExampleUser, UUID]:
    return AuthenticationBackend[ExampleUser, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="bearer")),
    )


def _database_backend() -> AuthenticationBackend[ExampleUser, UUID]:
    return AuthenticationBackend[ExampleUser, UUID](
        name="db",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            DatabaseTokenStrategy(
                session=cast("Any", object()),
                token_hash_secret=TOKEN_HASH_SECRET,
            ),
        ),
    )


def _rate_limit_config(*, backend: RateLimiterBackend) -> AuthRateLimitConfig:
    return AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=backend,
            scope="ip",
            namespace="login",
        ),
    )
