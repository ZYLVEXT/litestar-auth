"""Unit tests for plugin validation and runtime helper checks."""

from __future__ import annotations

import importlib
import logging
import warnings
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID

import pytest
from litestar.config.app import AppConfig

import litestar_auth._plugin.config as plugin_config_module
import litestar_auth._plugin.middleware as middleware_module
import litestar_auth._plugin.rate_limit as rate_limit_module
import litestar_auth._plugin.startup as startup_module
import litestar_auth._plugin.validation as validation_module
import litestar_auth.authentication.strategy.jwt as jwt_strategy_module
from litestar_auth._plugin.config import (
    DEFAULT_CSRF_COOKIE_NAME,
    DatabaseTokenAuthConfig,
    LitestarAuthConfig,
    OAuthConfig,
    TotpConfig,
)
from litestar_auth._plugin.middleware import build_csrf_config, get_cookie_transports
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoints
from litestar_auth._plugin.startup import (
    has_configured_oauth_providers,
    has_configured_oauth_providers_for,
    require_oauth_token_encryption_for_configured_providers,
    require_secure_oauth_redirect_in_production,
    warn_insecure_plugin_startup_defaults,
)
from litestar_auth._plugin.validation import (
    _validate_backend_strategy_security,
    _validate_totp_encryption_key,
    _validate_totp_pending_secret_config,
    validate_config,
    validate_cookie_auth_config,
    validate_password_validator_config,
    validate_rate_limit_config,
    validate_session_maker_or_external_db_session,
    validate_totp_config,
    validate_totp_sub_config,
    validate_user_manager_security_config,
    validate_user_model_login_identifier_fields,
)
from litestar_auth.authentication.backend import AuthenticationBackend
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
from litestar_auth.plugin import LitestarAuth
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter, RateLimiterBackend
from litestar_auth.totp import InMemoryUsedTotpCodeStore
from tests.integration.test_orchestrator import (
    DummySession,
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.unit

JWT_SECRET = "s" * 32
TOKEN_HASH_SECRET = "t" * 32
TOTP_SECRET_KEY = "u" * 32


class _DurableDenylistStore:
    async def deny(self, jti: str, *, ttl_seconds: int) -> None:
        del jti, ttl_seconds

    async def is_denied(self, jti: str) -> bool:
        del jti
        return False


def _configured_totp_config(
    *,
    totp_pending_secret: str = "p" * 32,
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
        del key
        return True

    async def increment(self, key: str) -> None:
        del key

    async def reset(self, key: str) -> None:
        del key

    async def retry_after(self, key: str) -> int:
        del key
        return 0


def test_plugin_validation_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(validation_module)

    assert reloaded_module.validate_config.__name__ == validation_module.validate_config.__name__


def test_plugin_middleware_module_executes_under_coverage() -> None:
    """Reload the middleware helper module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(middleware_module)

    assert reloaded_module.build_csrf_config.__name__ == build_csrf_config.__name__
    assert reloaded_module.get_cookie_transports.__name__ == get_cookie_transports.__name__


def test_plugin_rate_limit_module_executes_under_coverage() -> None:
    """Reload the shared rate-limit helper module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(rate_limit_module)

    assert reloaded_module.iter_rate_limit_endpoints.__name__ == iter_rate_limit_endpoints.__name__


def test_plugin_security_tradeoff_docs_snippet_matches_shared_policy_wording() -> None:
    """The shared docs snippet stays aligned with the plugin-owned tradeoff policy source."""
    snippet = Path("docs/snippets/plugin_security_tradeoffs.md").read_text(encoding="utf-8")

    for policy in plugin_config_module._iter_plugin_security_tradeoff_policies():
        assert policy.plugin_surface in snippet
        assert policy.contract_reference in snippet
        assert policy.docs_summary in snippet
        assert policy.production_requirement in snippet


def test_describe_jwt_revocation_tradeoff_accepts_reloaded_posture() -> None:
    """Plugin validation reuses the direct JWT posture contract even after reloads."""
    reloaded_jwt_module = importlib.reload(jwt_strategy_module)
    strategy = reloaded_jwt_module.JWTStrategy(secret=JWT_SECRET)

    notice = plugin_config_module._describe_jwt_revocation_tradeoff(strategy.revocation_posture)

    assert notice is not None
    assert notice.policy.key == "jwt_revocation"
    assert notice.posture_key == "compatibility_in_memory"
    assert notice.requires_explicit_production_opt_in is strategy.revocation_posture.requires_explicit_production_opt_in
    assert notice.production_validation_error == strategy.revocation_posture.production_validation_error
    assert notice.startup_warning == strategy.revocation_posture.startup_warning


def _build_direct_manager(*, totp_secret_key: str | None = None) -> BaseUserManager[ExampleUser, UUID]:
    """Build a direct manager instance for posture-contract comparisons.

    Returns:
        Direct ``BaseUserManager`` wired with the requested TOTP secret posture.
    """
    return BaseUserManager(
        InMemoryUserDatabase([]),
        password_helper=PasswordHelper(),
        security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
            totp_secret_key=totp_secret_key,
            id_parser=UUID,
        ),
    )


def test_resolve_plugin_managed_totp_secret_storage_tradeoff_matches_plaintext_posture() -> None:
    """Plugin-owned TOTP wiring reuses the same direct-manager plaintext posture contract."""
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="p" * 32))
    posture = _build_direct_manager().totp_secret_storage_posture

    notice = plugin_config_module._resolve_plugin_managed_totp_secret_storage_tradeoff(config)

    assert notice is not None
    assert notice.policy.key == "totp_secret_storage"
    assert notice.posture_key == posture.key
    assert notice.requires_explicit_production_opt_in is posture.requires_explicit_production_opt_in
    assert notice.production_validation_error == posture.production_validation_error
    assert notice.startup_warning is None


def test_resolve_plugin_managed_totp_secret_storage_tradeoff_returns_none_without_totp() -> None:
    """Configs without TOTP do not report a plugin-managed TOTP storage tradeoff."""
    notice = plugin_config_module._resolve_plugin_managed_totp_secret_storage_tradeoff(_minimal_config())

    assert notice is None


def test_resolve_plugin_managed_totp_secret_storage_tradeoff_skips_factory_owned_wiring() -> None:
    """Custom manager factories can own TOTP-secret storage without plugin validation interference."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
        user_manager_security=None,
    )
    config.user_manager_security = None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])

    notice = plugin_config_module._resolve_plugin_managed_totp_secret_storage_tradeoff(config)

    assert notice is None


def test_plugin_startup_module_executes_under_coverage() -> None:
    """Reload the startup helper module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(startup_module)

    assert reloaded_module.warn_insecure_plugin_startup_defaults.__name__ == (
        startup_module.warn_insecure_plugin_startup_defaults.__name__
    )
    assert reloaded_module.require_oauth_token_encryption_for_configured_providers.__name__ == (
        require_oauth_token_encryption_for_configured_providers.__name__
    )
    assert reloaded_module.require_secure_oauth_redirect_in_production.__name__ == (
        require_secure_oauth_redirect_in_production.__name__
    )


def test_warn_insecure_plugin_startup_defaults_emits_all_expected_security_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production startup emits warnings for each insecure default this task targets."""
    config = _minimal_config(
        backends=[
            _cookie_backend(),
            _jwt_backend(),
        ],
        oauth_config=OAuthConfig(oauth_providers=[("github", object())]),
        rate_limit_config=_rate_limit_config(backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60)),
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_pending_jti_store=jwt_strategy_module.InMemoryJWTDenylistStore(),
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )
    config.enable_refresh = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert any("oauth_token_encryption_key is not set" in message for message in messages)
    assert any("process-local in-memory denylist" in message for message in messages)
    assert any("process-local in-memory backend" in message for message in messages)
    assert any("InMemoryUsedTotpCodeStore" in message for message in messages)
    assert any("TOTP pending-token replay protection uses InMemoryJWTDenylistStore" in message for message in messages)
    assert any("refresh_max_age is not set" in message for message in messages)


def test_warn_insecure_plugin_startup_defaults_warns_for_reloaded_jwt_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT denylist warnings survive strategy-module reloads used in coverage tests."""
    del monkeypatch
    reloaded_jwt_module = importlib.reload(jwt_strategy_module)
    strategy = reloaded_jwt_module.JWTStrategy(secret=JWT_SECRET)
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="jwt",
                transport=BearerTransport(),
                strategy=strategy,
            ),
        ],
    )

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert strategy.revocation_posture.startup_warning in messages


def test_warn_insecure_plugin_startup_defaults_is_silent_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode suppresses the insecure-default warnings."""
    config = _minimal_config(
        backends=[_cookie_backend(), _jwt_backend()],
        oauth_config=OAuthConfig(oauth_providers=[("github", object())]),
        rate_limit_config=_rate_limit_config(backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60)),
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_pending_jti_store=jwt_strategy_module.InMemoryJWTDenylistStore(),
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
            oauth_providers=[("github", object())],
            oauth_token_encryption_key="k" * 44,
        ),
        rate_limit_config=_rate_limit_config(backend=_SharedRateLimitBackend()),
        totp_config=_configured_totp_config(
            totp_used_tokens_store=cast("Any", object()),
        ),
    )
    config.csrf_secret = "c" * 32
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
    config.csrf_secret = "c" * 32
    config.enable_refresh = True

    with pytest.warns(startup_module.SecurityWarning, match="refresh_max_age is not set"):
        warn_insecure_plugin_startup_defaults(config)


def test_warn_insecure_plugin_startup_defaults_skips_refresh_warning_when_cookie_max_age_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit refresh-cookie lifetimes suppress the startup helper warning."""
    config = _minimal_config(backends=[_cookie_backend(refresh_max_age=604800)])
    config.csrf_secret = "c" * 32
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
    config.csrf_secret = "c" * 32
    config.enable_refresh = False

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert not [record for record in records if "refresh_max_age" in str(record.message)]


def test_validate_backend_strategy_security_rejects_legacy_plaintext_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production validation rejects migration-only plaintext-token compatibility mode."""
    config = _minimal_config(
        backends=[_database_backend(accept_legacy_plaintext_tokens=True)],
    )

    with pytest.raises(ValueError, match="migration-only"):
        _validate_backend_strategy_security(config)


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
    backend = _database_backend(accept_legacy_plaintext_tokens=False)
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
    config = _minimal_config(backends=[_database_backend(accept_legacy_plaintext_tokens=False)])

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_explicit_plaintext_token_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit compatibility override keeps the legacy DB-token mode available."""
    config = _minimal_config(
        backends=[_database_backend(accept_legacy_plaintext_tokens=True)],
    )
    config.allow_legacy_plaintext_tokens = True

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_database_token_preset_legacy_mode_without_top_level_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical DB-token preset uses its nested settings as the rollout source of truth."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret=TOKEN_HASH_SECRET,
            accept_legacy_plaintext_tokens=True,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
        ),
    )

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_uses_database_token_preset_rollout_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preset validation errors point callers to the nested DB-token settings object."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
        ),
    )
    legacy_backend = AuthenticationBackend[ExampleUser, UUID](
        name="database",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            validation_module.DatabaseTokenStrategy(
                session=cast("Any", object()),
                token_hash_secret=TOKEN_HASH_SECRET,
                accept_legacy_plaintext_tokens=True,
            ),
        ),
    )

    def _build_legacy_backend(
        _database_token_auth: DatabaseTokenAuthConfig,
        *,
        session: object | None = None,
        unsafe_testing: bool = False,
    ) -> AuthenticationBackend[ExampleUser, UUID]:
        del _database_token_auth
        del session
        del unsafe_testing
        return legacy_backend

    monkeypatch.setattr(
        plugin_config_module,
        "_build_database_token_backend",
        _build_legacy_backend,
    )

    with pytest.raises(ValueError, match=r"DatabaseTokenAuthConfig\.accept_legacy_plaintext_tokens=True"):
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_rejects_nondurable_jwt_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production validation rejects JWT denylist storage that is only process-local."""
    del monkeypatch
    backend = _jwt_backend()
    config = _minimal_config(backends=[backend])
    strategy = cast("Any", backend.strategy)

    with pytest.raises(ValueError, match="process-local in-memory denylist") as exc_info:
        _validate_backend_strategy_security(config)
    assert str(exc_info.value) == strategy.revocation_posture.production_validation_error


def test_validate_backend_strategy_security_allows_durable_jwt_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable denylist store satisfies the JWT revocation validation."""
    config = _minimal_config(backends=[_jwt_backend(denylist_store=_DurableDenylistStore())])

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_nondurable_jwt_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit nondurable-JWT override keeps the production config valid."""
    config = _minimal_config(backends=[_jwt_backend()])
    config.allow_nondurable_jwt_revocation = True

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_nondurable_jwt_revocation_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit unsafe testing preserves the single-process JWT denylist branch."""
    config = _minimal_config(backends=[_jwt_backend()])
    config.unsafe_testing = True

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


def test_validate_password_validator_config_rejects_mixed_configuration() -> None:
    """The factory seam and legacy kwargs seam cannot both provide a password validator."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: None
    config.user_manager_kwargs["password_validator"] = lambda password: password

    with pytest.raises(ValueError, match="not both"):
        validate_password_validator_config(config)


def test_validate_password_validator_config_rejects_none_placeholder_configuration() -> None:
    """A placeholder ``password_validator=None`` still counts as legacy kwargs wiring."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: None
    config.user_manager_kwargs["password_validator"] = None

    with pytest.raises(ValueError, match="not both"):
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
            del user_db, legacy_dependency

        @staticmethod
        async def authenticate(identifier: str, password: str) -> None:
            del identifier, password

    config = _minimal_config()
    config.user_manager_class = cast("type[Any]", _FactoryOwnedManager)
    config.password_validator_factory = lambda _config: None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])
    config.user_manager_kwargs = {"legacy_dependency": object()}

    validate_config(config)


def test_validate_password_validator_config_does_not_probe_manager_signature() -> None:
    """Validation no longer introspects custom manager constructors for password-validator support."""

    class _ManagerWithoutPasswordValidator:
        def __init__(self, user_db: object) -> None:
            del user_db

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
            unsafe_testing: bool = False,
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=password_validator,
                backends=backends,
                login_identifier=login_identifier,
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


@pytest.mark.parametrize(("use_typed_security"), [True, False])
def test_default_user_manager_contract_keeps_runtime_and_validation_surfaces_aligned(
    *,
    use_typed_security: bool,
) -> None:
    """The shared default-builder contract keeps runtime and validation kwargs in sync."""
    config = _minimal_config(id_parser=UUID)
    if not use_typed_security:
        config.user_manager_security = None

    runtime_contract = plugin_config_module._build_default_user_manager_contract(
        config,
        password_helper=PasswordHelper(),
        password_validator=None,
        backends=("bound-backend",),
    )
    validation_contract = plugin_config_module._build_default_user_manager_contract(
        config,
        password_helper=object(),
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
        assert "security" not in runtime_kwargs
        assert "security" not in validation_kwargs
        assert runtime_kwargs["id_parser"] is UUID
        assert validation_kwargs["id_parser"] is UUID


def test_validate_config_rejects_non_canonical_default_user_manager_constructor() -> None:
    """Plugin construction should fail fast for managers that do not accept ``security=...``."""

    class _LegacyManagerWithoutSecurity(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            password_validator: object | None = None,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                password_validator=cast("Any", password_validator),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
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
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=password_validator,
                backends=backends,
                login_identifier=login_identifier,
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


def test_validate_rate_limit_config_accepts_none() -> None:
    """Omitting rate limiting is a valid configuration."""
    validate_rate_limit_config(None)


def test_iter_rate_limit_endpoints_includes_request_verify_token() -> None:
    """The shared iterator covers the late-bound verify-token request endpoint."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="request-verify-token",
    )

    endpoints = iter_rate_limit_endpoints(AuthRateLimitConfig(request_verify_token=rate_limit))

    assert endpoints[-1] is rate_limit


def test_iter_rate_limit_endpoints_includes_totp_confirm_enable() -> None:
    """The shared iterator covers the TOTP confirm-enrollment endpoint."""
    rate_limit = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
        scope="ip",
        namespace="totp-confirm-enable",
    )

    endpoints = iter_rate_limit_endpoints(AuthRateLimitConfig(totp_confirm_enable=rate_limit))

    assert rate_limit in endpoints


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


def test_validate_totp_pending_secret_config_logs_sha1_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Production validation logs when TOTP is configured with SHA1."""
    config = _minimal_config(
        totp_config=_configured_totp_config(totp_algorithm="SHA1"),
    )

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        _validate_totp_pending_secret_config(config)

    assert "SHA1" in caplog.text
    assert "SHA256 or SHA512" in caplog.text


def test_validate_totp_pending_secret_config_is_silent_for_non_sha1(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Non-SHA1 algorithms skip the production warning path."""
    config = _minimal_config(
        totp_config=_configured_totp_config(totp_algorithm="SHA256"),
    )

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        _validate_totp_pending_secret_config(config)

    assert not caplog.text


def test_validate_totp_pending_secret_config_requires_algorithm() -> None:
    """A configured TOTP block still needs an explicit algorithm."""
    config = _minimal_config()
    config.totp_config = cast("Any", type("Config", (), {"totp_pending_secret": "p" * 32, "totp_algorithm": ""})())

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


def test_validate_totp_encryption_key_requires_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production TOTP validation requires an at-rest encryption key."""
    del monkeypatch
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="p" * 32))

    with pytest.raises(
        validation_module.ConfigurationError,
        match="totp_secret_key is required in production",
    ) as exc_info:
        _validate_totp_encryption_key(config)
    assert str(exc_info.value) == TotpSecretStoragePosture.compatibility_plaintext().production_validation_error


def test_validate_totp_encryption_key_allows_configured_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Providing the encryption key satisfies the production-only TOTP requirement."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
            totp_secret_key=TOTP_SECRET_KEY,
        ),
    )

    _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_allows_typed_security_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical typed security bundle satisfies the production TOTP requirement."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
        user_manager_security=UserManagerSecurity[UUID](totp_secret_key=TOTP_SECRET_KEY),
    )
    config.user_manager_kwargs = {
        "password_helper": object(),
    }

    _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_allows_factory_owned_totp_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Custom factories own TOTP encryption wiring when the typed contract is omitted."""
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
        user_manager_security=None,
    )
    config.user_manager_security = None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])
    config.user_manager_kwargs = {"totp_secret_key": TOTP_SECRET_KEY}

    _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_rejects_empty_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty typed TOTP secret still fails the production encryption check."""
    del monkeypatch
    config = _minimal_config(
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
            totp_secret_key="",
        ),
    )

    with pytest.raises(
        validation_module.ConfigurationError,
        match="totp_secret_key is required in production",
    ) as exc_info:
        _validate_totp_encryption_key(config)
    assert str(exc_info.value) == TotpSecretStoragePosture.compatibility_plaintext().production_validation_error


def test_validate_user_manager_security_config_rejects_legacy_security_kwargs_without_factory() -> None:
    """Default plugin construction rejects legacy security kwargs outright."""
    config = _minimal_config()
    config.user_manager_security = None
    config.user_manager_kwargs = {
        "verification_token_secret": "s" * 32,
        "reset_password_token_secret": "r" * 32,
    }

    with pytest.raises(validation_module.ConfigurationError, match="canonical plugin-managed path"):
        validate_user_manager_security_config(config)


def test_validate_user_manager_security_config_rejects_legacy_secret_overlap() -> None:
    """The typed security contract cannot overlap with legacy secret kwargs."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="s" * 32,
            reset_password_token_secret="r" * 32,
        ),
    )
    config.user_manager_kwargs = {
        "verification_token_secret": "s" * 32,
        "reset_password_token_secret": "r" * 32,
    }

    with pytest.raises(validation_module.ConfigurationError, match="overlapping entries"):
        validate_user_manager_security_config(config)


def test_validate_user_manager_security_config_allows_factory_owned_legacy_security_kwargs() -> None:
    """Custom factories remain the explicit escape hatch for non-standard manager construction."""
    config = _minimal_config()
    config.user_manager_security = None
    config.user_manager_kwargs = {
        "verification_token_secret": "s" * 32,
        "reset_password_token_secret": "r" * 32,
        "totp_secret_key": TOTP_SECRET_KEY,
        "id_parser": UUID,
    }
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
    config.user_manager_kwargs = {"password_helper": object()}

    with pytest.raises(validation_module.ConfigurationError, match="Configure id_parser via"):
        validate_user_manager_security_config(config)


def test_validate_config_accepts_typed_user_manager_security_contract() -> None:
    """Plugin validation accepts the canonical typed security path without legacy overlap."""
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="s" * 32,
            reset_password_token_secret="r" * 32,
            totp_secret_key=TOTP_SECRET_KEY,
            id_parser=UUID,
        ),
        id_parser=UUID,
        totp_config=_configured_totp_config(totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore())),
    )
    config.user_manager_kwargs = {"password_helper": object()}

    validate_user_manager_security_config(config)


def test_validate_user_manager_security_config_warns_when_secret_roles_share_one_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production validation warns when verify/reset/TOTP roles reuse one value."""
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
    config.user_manager_kwargs = {"password_helper": PasswordHelper()}

    with pytest.warns(validation_module.SecurityWarning, match="supported production posture") as records:
        validate_user_manager_security_config(config)

    assert len(records) == 1
    message = str(records[0].message)
    assert "verification_token_secret" in message
    assert "reset_password_token_secret" in message
    assert "totp_secret_key" in message
    assert "totp_pending_secret" in message
    assert VERIFY_TOKEN_AUDIENCE in message
    assert RESET_PASSWORD_TOKEN_AUDIENCE in message
    assert TOTP_PENDING_AUDIENCE in message
    assert TOTP_ENROLL_AUDIENCE in message


def test_plugin_managed_secret_role_reuse_warning_is_owned_by_validation() -> None:
    """Plugin-managed configs warn once during validation, not again during manager construction."""
    shared_secret = "shared-plugin-secret-role-value-1234567890"
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
    config.user_manager_kwargs = {"password_helper": PasswordHelper()}

    def _build_plugin_managed_manager() -> None:
        plugin = LitestarAuth(config)
        plugin._build_user_manager(cast("Any", DummySession()))

    with pytest.warns(validation_module.SecurityWarning, match="supported production posture") as records:
        _build_plugin_managed_manager()

    assert len(records) == 1
    message = str(records[0].message)
    assert "totp_pending_secret" in message
    assert TOTP_PENDING_AUDIENCE in message
    assert TOTP_ENROLL_AUDIENCE in message


def test_custom_user_manager_factory_does_not_duplicate_aligned_secret_role_warning() -> None:
    """Aligned custom factories inherit the validated secret baseline without duplicating the warning."""
    shared_secret = "shared-aligned-custom-factory-secret"
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
    config.user_manager_kwargs = {"password_helper": PasswordHelper()}

    def _factory(**kwargs: object) -> PluginUserManager:
        return PluginUserManager(
            cast("Any", kwargs["user_db"]),
            password_helper=PasswordHelper(),
            security=cast("UserManagerSecurity[UUID]", config.user_manager_security),
            backends=cast("tuple[object, ...]", kwargs["backends"]),
        )

    def _build_aligned_custom_manager() -> None:
        plugin = LitestarAuth(config)
        plugin._build_user_manager(cast("Any", DummySession()))

    config.user_manager_factory = _factory

    with pytest.warns(validation_module.SecurityWarning, match="supported production posture") as records:
        _build_aligned_custom_manager()

    assert len(records) == 1
    message = str(records[0].message)
    assert "totp_pending_secret" in message
    assert TOTP_PENDING_AUDIENCE in message
    assert TOTP_ENROLL_AUDIENCE in message


def test_custom_user_manager_factory_surfaces_divergent_manager_secret_role_warning() -> None:
    """Custom factories cannot silence manager-owned warnings by diverging from config-owned secrets."""
    shared_secret = "shared-custom-factory-secret-role-12"
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-custom-config-secret-123456",
            reset_password_token_secret="reset-custom-config-secret-1234567",
            totp_secret_key=TOTP_SECRET_KEY,
        ),
    )
    config.user_manager_kwargs = {"password_helper": PasswordHelper()}

    def _factory(**kwargs: object) -> PluginUserManager:
        return PluginUserManager(
            cast("Any", kwargs["user_db"]),
            password_helper=PasswordHelper(),
            security=UserManagerSecurity[UUID](
                verification_token_secret=shared_secret,
                reset_password_token_secret=shared_secret,
                totp_secret_key=shared_secret,
            ),
            backends=cast("tuple[object, ...]", kwargs["backends"]),
        )

    config.user_manager_factory = _factory
    plugin = LitestarAuth(config)

    with pytest.warns(validation_module.SecurityWarning, match="supported production posture") as records:
        plugin._build_user_manager(cast("Any", DummySession()))

    assert len(records) == 1
    message = str(records[0].message)
    assert "verification_token_secret" in message
    assert "reset_password_token_secret" in message
    assert "totp_secret_key" in message
    assert VERIFY_TOKEN_AUDIENCE in message
    assert RESET_PASSWORD_TOKEN_AUDIENCE in message


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
            TotpConfig(totp_pending_secret="p" * 32),
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
    config.csrf_secret = "c" * 32
    cookie_transports = [
        CookieTransport(path="/auth", secure=False, samesite="strict"),
        CookieTransport(path="/other-auth", secure=False, samesite="strict"),
    ]

    with pytest.raises(ValueError, match="must share path, domain, secure, and samesite"):
        build_csrf_config(config, cookie_transports)


def test_build_csrf_config_returns_expected_cookie_settings() -> None:
    """A homogeneous cookie transport set produces the shared CSRF config."""
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = "c" * 32
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
    "oauth_config",
    [
        pytest.param(
            OAuthConfig(oauth_providers=[("github", object())]),
            id="login-providers",
        ),
        pytest.param(
            OAuthConfig(
                oauth_providers=[("github", object())],
                include_oauth_associate=True,
            ),
            id="login-and-associate",
        ),
    ],
)
def test_require_oauth_token_encryption_for_configured_providers_calls_require_key(
    oauth_config: OAuthConfig,
) -> None:
    """Either configured OAuth provider inventory triggers the fail-closed key requirement."""
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
    login_only_config = OAuthConfig(oauth_providers=[("github", object())])
    login_and_associate_config = OAuthConfig(
        include_oauth_associate=True,
        oauth_providers=[("github", object())],
    )

    assert has_configured_oauth_providers(_minimal_config(oauth_config=None)) is False
    assert has_configured_oauth_providers(_minimal_config(oauth_config=login_only_config)) is True
    assert has_configured_oauth_providers(_minimal_config(oauth_config=login_and_associate_config)) is True
    assert has_configured_oauth_providers_for(empty_config) is False
    assert has_configured_oauth_providers_for(login_only_config) is True
    assert has_configured_oauth_providers_for(login_and_associate_config) is True


def test_require_secure_oauth_redirect_in_production_accepts_public_https_origin() -> None:
    """Production startup accepts public HTTPS plugin redirect origins."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object())],
            oauth_redirect_base_url="https://app.example.com/auth",
        ),
    )

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
            "non-loopback public HTTPS origin",
            id="loopback-https-origin",
        ),
    ],
)
def test_require_secure_oauth_redirect_in_production_rejects_insecure_origins(
    redirect_base_url: str,
    message: str,
) -> None:
    """Production startup fails closed for public HTTP and loopback OAuth redirect bases."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object())],
            oauth_redirect_base_url=redirect_base_url,
        ),
    )

    with pytest.raises(ConfigurationError, match=message):
        require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


def test_require_secure_oauth_redirect_in_production_skips_debug_mode() -> None:
    """Debug mode keeps explicit localhost redirect recipes available."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object())],
            oauth_redirect_base_url="http://localhost/auth",
        ),
    )

    require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=True))


def test_require_secure_oauth_redirect_in_production_skips_unsafe_testing() -> None:
    """unsafe_testing keeps explicit localhost redirect recipes available for tests."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object())],
            oauth_redirect_base_url="http://localhost/auth",
        ),
    )
    config.unsafe_testing = True

    require_secure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))


def test_validate_config_rejects_include_oauth_associate_without_provider_inventory() -> None:
    """Associate-route enablement still requires the single plugin-owned provider inventory."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_token_encryption_key="a" * 44,
            include_oauth_associate=True,
        ),
    )

    with pytest.raises(ValueError, match="include_oauth_associate=True requires oauth_providers"):
        validate_config(config)


def test_validate_config_rejects_missing_redirect_base_url_for_plugin_owned_oauth_routes() -> None:
    """Plugin-owned OAuth routes require an explicit public redirect base URL."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object())],
            oauth_token_encryption_key="a" * 44,
        ),
    )

    with pytest.raises(ValueError, match="oauth_redirect_base_url is required when oauth_providers are configured"):
        validate_config(config)


def test_validate_config_rejects_orphan_redirect_base_url() -> None:
    """OAuth redirect-base settings must correspond to plugin-owned OAuth routes."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_token_encryption_key="a" * 44,
        ),
    )

    with pytest.raises(ValueError, match="oauth_redirect_base_url requires oauth_providers to be configured"):
        validate_config(config)


def test_validate_config_rejects_duplicate_login_provider_names() -> None:
    """Duplicate login-provider names would make explicit route ownership ambiguous."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object()), ("github", object())],
            oauth_redirect_base_url="https://app.example.com/auth",
            oauth_token_encryption_key="a" * 44,
        ),
    )

    with pytest.raises(ValueError, match=r"oauth_providers must not contain duplicate provider names: github"):
        validate_config(config)


def test_validate_config_rejects_oauth_associate_by_email_without_login_provider_inventory() -> None:
    """Associate-by-email cannot be declared without plugin-owned OAuth login routes."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_associate_by_email=True,
            oauth_token_encryption_key="a" * 44,
        ),
    )

    with pytest.raises(ValueError, match="oauth_associate_by_email only affects plugin-owned OAuth login routes"):
        validate_config(config)


def test_validate_config_rejects_oauth_trust_provider_email_verified_without_provider_inventory() -> None:
    """Provider-email trust cannot be declared without plugin-owned OAuth login routes."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            oauth_trust_provider_email_verified=True,
            oauth_token_encryption_key="a" * 44,
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
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
        ),
    )

    validate_config(config)


def test_validate_config_allows_explicit_unsafe_testing_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit unsafe testing, not runtime globals, controls relaxed validation."""
    config = _minimal_config(
        backends=[_cookie_backend(), _jwt_backend()],
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
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
        totp_config=TotpConfig(totp_pending_secret="p" * 32),
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
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
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
                "totp_pending_secret": "p" * 32,
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

    monkeypatch.setattr(validation_module, "validate_rate_limit_config", _record_rate_limit)
    monkeypatch.setattr(validation_module, "validate_cookie_auth_config", _record_cookie)

    validation_module.validate_request_security_config(config)

    assert calls == [
        ("rate_limit", config.rate_limit_config),
        ("cookie", config),
    ]


def _minimal_config(  # noqa: PLR0913
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    oauth_config: OAuthConfig | None = None,
    rate_limit_config: AuthRateLimitConfig | None = None,
    totp_config: TotpConfig | None = None,
    user_manager_security: UserManagerSecurity[UUID] | None = None,
    id_parser: object | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for validation-focused unit tests.

    Returns:
        Minimal config object with overridable backends and optional nested auth settings.
    """
    resolved_manager_security = user_manager_security or UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
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
        user_manager_kwargs={},
        id_parser=cast("Any", id_parser),
        oauth_config=oauth_config,
        rate_limit_config=rate_limit_config,
        totp_config=totp_config,
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
    strategy = (
        validation_module.JWTStrategy(secret=JWT_SECRET)
        if denylist_store is None
        else validation_module.JWTStrategy(
            # Build from the class object currently referenced by validation.py to
            # stay stable across other test modules that reload strategy modules.
            secret=JWT_SECRET,
            denylist_store=cast("Any", denylist_store),
        )
    )
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


def _database_backend(*, accept_legacy_plaintext_tokens: bool) -> AuthenticationBackend[ExampleUser, UUID]:
    return AuthenticationBackend[ExampleUser, UUID](
        name="db",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            validation_module.DatabaseTokenStrategy(
                session=cast("Any", object()),
                token_hash_secret=TOKEN_HASH_SECRET,
                accept_legacy_plaintext_tokens=accept_legacy_plaintext_tokens,
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
