"""Unit tests for plugin validation and runtime helper checks."""

from __future__ import annotations

import importlib
import logging
import warnings
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

import pytest
from litestar.config.app import AppConfig

import litestar_auth._plugin.middleware as middleware_module
import litestar_auth._plugin.rate_limit as rate_limit_module
import litestar_auth._plugin.startup as startup_module
import litestar_auth._plugin.validation as validation_module
import litestar_auth.authentication.strategy.jwt as jwt_strategy_module
from litestar_auth._plugin.config import DEFAULT_CSRF_COOKIE_NAME, LitestarAuthConfig, OAuthConfig, TotpConfig
from litestar_auth._plugin.middleware import build_csrf_config, get_cookie_transports
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoints
from litestar_auth._plugin.startup import (
    has_configured_oauth_providers,
    has_configured_oauth_providers_for,
    require_oauth_token_encryption_for_configured_providers,
    warn_if_insecure_oauth_redirect_in_production,
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
    validate_user_model_login_identifier_fields,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.models import User as OrmUser
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter, RateLimiterBackend
from litestar_auth.totp import InMemoryUsedTotpCodeStore
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit

JWT_SECRET = "s" * 32
TOKEN_HASH_SECRET = "t" * 32
TOTP_SECRET_KEY = "u" * 32
EXPECTED_SECURITY_WARNING_COUNT = 5


class _DurableDenylistStore:
    async def deny(self, jti: str, *, ttl_seconds: int) -> None:
        del jti, ttl_seconds

    async def is_denied(self, jti: str) -> bool:
        del jti
        return False


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


def test_plugin_startup_module_executes_under_coverage() -> None:
    """Reload the startup helper module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(startup_module)

    assert reloaded_module.warn_insecure_plugin_startup_defaults.__name__ == (
        startup_module.warn_insecure_plugin_startup_defaults.__name__
    )
    assert reloaded_module.require_oauth_token_encryption_for_configured_providers.__name__ == (
        require_oauth_token_encryption_for_configured_providers.__name__
    )


def test_warn_insecure_plugin_startup_defaults_emits_all_expected_security_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production startup emits warnings for each insecure default this task targets."""
    monkeypatch.setattr(startup_module, "is_testing", lambda: False)
    config = _minimal_config(
        backends=[
            _cookie_backend(),
            _jwt_backend(),
        ],
        oauth_config=OAuthConfig(oauth_providers=[("github", object())]),
        rate_limit_config=_rate_limit_config(backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60)),
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )
    config.enable_refresh = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert len(messages) == EXPECTED_SECURITY_WARNING_COUNT
    assert any("oauth_token_encryption_key is not set" in message for message in messages)
    assert any("process-local in-memory denylist" in message for message in messages)
    assert any("process-local in-memory backend" in message for message in messages)
    assert any("InMemoryUsedTotpCodeStore" in message for message in messages)
    assert any("refresh_max_age is not set" in message for message in messages)


def test_warn_insecure_plugin_startup_defaults_warns_for_reloaded_jwt_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT denylist warnings survive strategy-module reloads used in coverage tests."""
    monkeypatch.setattr(startup_module, "is_testing", lambda: False)
    reloaded_jwt_module = importlib.reload(jwt_strategy_module)
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="jwt",
                transport=BearerTransport(),
                strategy=reloaded_jwt_module.JWTStrategy(secret=JWT_SECRET),
            ),
        ],
    )

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    messages = [str(record.message) for record in records]
    assert any("process-local in-memory denylist" in message for message in messages)


def test_warn_insecure_plugin_startup_defaults_is_silent_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode suppresses the insecure-default warnings."""
    monkeypatch.setattr(startup_module, "is_testing", lambda: True)
    config = _minimal_config(
        backends=[_cookie_backend(), _jwt_backend()],
        oauth_config=OAuthConfig(oauth_providers=[("github", object())]),
        rate_limit_config=_rate_limit_config(backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60)),
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )
    config.enable_refresh = True

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        warn_insecure_plugin_startup_defaults(config)

    assert not records


def test_warn_insecure_plugin_startup_defaults_is_silent_for_safe_production_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Safe production settings avoid the insecure-default warnings entirely."""
    monkeypatch.setattr(startup_module, "is_testing", lambda: False)
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
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
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
    monkeypatch.setattr(startup_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = "c" * 32
    config.enable_refresh = True

    with pytest.warns(startup_module.SecurityWarning, match="refresh_max_age is not set"):
        warn_insecure_plugin_startup_defaults(config)


def test_warn_insecure_plugin_startup_defaults_skips_refresh_warning_when_cookie_max_age_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit refresh-cookie lifetimes suppress the startup helper warning."""
    monkeypatch.setattr(startup_module, "is_testing", lambda: False)
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
    monkeypatch.setattr(startup_module, "is_testing", lambda: False)
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
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(
        backends=[_database_backend(accept_legacy_plaintext_tokens=True)],
    )

    with pytest.raises(ValueError, match="migration-only"):
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_skips_non_database_strategies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-database strategies do not enter the legacy-plaintext validation path."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_non_jwt_backend()])

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_warns_for_jwt_named_non_jwt_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT-like backend names emit an advisory warning when the strategy is not JWT-based."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
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
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_jwt_backend(denylist_store=_DurableDenylistStore())])

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_does_not_warn_for_neutral_backend_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neutral backend names stay silent even when the strategy is not JWT-based."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_database_backend(accept_legacy_plaintext_tokens=False)])

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_explicit_plaintext_token_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit compatibility override keeps the legacy DB-token mode available."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(
        backends=[_database_backend(accept_legacy_plaintext_tokens=True)],
    )
    config.allow_legacy_plaintext_tokens = True

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_rejects_nondurable_jwt_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production validation rejects JWT denylist storage that is only process-local."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_jwt_backend()])

    with pytest.raises(ValueError, match="process-local in-memory denylist"):
        _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_durable_jwt_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable denylist store satisfies the JWT revocation validation."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_jwt_backend(denylist_store=_DurableDenylistStore())])

    _validate_backend_strategy_security(config)


def test_validate_backend_strategy_security_allows_nondurable_jwt_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit nondurable-JWT override keeps the production config valid."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_jwt_backend()])
    config.allow_nondurable_jwt_revocation = True

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


def test_validate_password_validator_config_allows_explicit_user_manager_factory() -> None:
    """A custom builder may own password-validator injection itself."""
    config = _minimal_config()
    config.password_validator_factory = lambda _config: None
    config.user_manager_factory = lambda **kwargs: cast("Any", kwargs["user_db"])

    validate_password_validator_config(config)


def test_validate_password_validator_config_rejects_incompatible_manager() -> None:
    """Factories targeting managers without password-validator support fail fast."""

    class _ManagerWithoutPasswordValidator:
        def __init__(self, user_db: object) -> None:
            del user_db

    config = _minimal_config()
    config.password_validator_factory = lambda _config: None
    config.user_manager_class = cast("type[Any]", _ManagerWithoutPasswordValidator)

    with pytest.raises(ValueError, match="requires user_manager_class to accept password_validator"):
        validate_password_validator_config(config)


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


def test_warn_insecure_plugin_startup_defaults_warns_for_request_verify_token_inmemory_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startup warnings still inspect non-login endpoint rate-limit settings."""
    monkeypatch.setattr(startup_module, "is_testing", lambda: False)
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


def test_validate_totp_pending_secret_config_logs_sha1_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Production validation logs when TOTP is configured with SHA1."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_algorithm="SHA1",
        ),
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
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_algorithm="SHA256",
        ),
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
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="p" * 32))

    with pytest.raises(validation_module.ConfigurationError, match="totp_secret_key is required in production"):
        _validate_totp_encryption_key(config)


def test_validate_totp_encryption_key_allows_configured_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Providing the encryption key satisfies the production-only TOTP requirement."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="p" * 32))
    config.user_manager_kwargs["totp_secret_key"] = TOTP_SECRET_KEY

    _validate_totp_encryption_key(config)


def test_validate_totp_config_warns_for_insecure_cookie_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production TOTP validation warns when the enable endpoint can travel over insecure cookies."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(
        backends=[_cookie_backend()],
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )

    with pytest.warns(validation_module.SecurityWarning, match="CookieTransport.secure=False"):
        validate_totp_config(config)


def test_validate_totp_config_skips_insecure_cookie_warning_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing mode suppresses the insecure-cookie warning branch for TOTP validation."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: True)
    config = _minimal_config(
        backends=[_cookie_backend()],
        totp_config=TotpConfig(
            totp_pending_secret="p" * 32,
            totp_used_tokens_store=cast("Any", InMemoryUsedTotpCodeStore()),
        ),
    )

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        validate_totp_config(config)

    assert not records


def test_validate_totp_sub_config_rejects_missing_replay_store_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replay protection requires a configured store outside testing mode."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)

    with pytest.raises(ValueError, match="totp_require_replay_protection=True requires"):
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
    monkeypatch.setattr(validation_module, "is_testing", lambda: True)

    class _ManagerWithoutAuthenticate:
        pass

    with pytest.raises(ValueError, match=r"user_manager_class\.authenticate"):
        validate_totp_sub_config(
            TotpConfig(
                totp_pending_secret="p" * 32,
                totp_enable_requires_password=True,
            ),
            user_manager_class=_ManagerWithoutAuthenticate,
        )


def test_validate_cookie_auth_config_rejects_missing_csrf_secret_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cookie auth in production requires either a CSRF secret or an explicit unsafe override."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_cookie_backend()])

    with pytest.raises(validation_module.ConfigurationError, match="requires csrf_secret"):
        validate_cookie_auth_config(config)


def test_validate_cookie_auth_config_rejects_short_csrf_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configured CSRF secrets still have to satisfy minimum-length validation."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
    config = _minimal_config(backends=[_cookie_backend()])
    config.csrf_secret = "short"

    with pytest.raises(Exception, match="csrf_secret") as exc_info:
        validate_cookie_auth_config(config)
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_cookie_auth_config_allows_explicit_insecure_cookie_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compatibility override keeps the legacy cookie path available when chosen explicitly."""
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
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


def test_require_oauth_token_encryption_for_configured_providers_calls_require_key() -> None:
    """Configured OAuth providers invoke the fail-closed key requirement callback."""
    config = _minimal_config(oauth_config=OAuthConfig(oauth_providers=[("github", object())]))
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
    configured_config = OAuthConfig(oauth_associate_providers=[("github", object())])

    assert has_configured_oauth_providers(_minimal_config(oauth_config=None)) is False
    assert has_configured_oauth_providers_for(empty_config) is False
    assert has_configured_oauth_providers_for(configured_config) is True


def test_warn_if_insecure_oauth_redirect_in_production_logs_localhost_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Production startup warns when associate redirects fall back to localhost."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            include_oauth_associate=True,
            oauth_associate_providers=[("github", object())],
        ),
    )

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        warn_if_insecure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))

    assert "localhost" in caplog.text
    assert "oauth_associate_redirect_base_url" in caplog.text


def test_warn_if_insecure_oauth_redirect_in_production_skips_public_origin(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Public OAuth redirect origins do not trigger the localhost warning."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            include_oauth_associate=True,
            oauth_associate_providers=[("github", object())],
            oauth_associate_redirect_base_url="https://app.example.com/auth/associate",
        ),
    )

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        warn_if_insecure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=False))

    assert not caplog.text


def test_warn_if_insecure_oauth_redirect_in_production_skips_debug_mode(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Debug mode bypasses the localhost redirect warning."""
    config = _minimal_config(
        oauth_config=OAuthConfig(
            include_oauth_associate=True,
            oauth_associate_providers=[("github", object())],
        ),
    )

    with caplog.at_level(logging.WARNING, logger="litestar_auth.plugin"):
        warn_if_insecure_oauth_redirect_in_production(config=config, app_config=AppConfig(debug=True))

    assert not caplog.text


def test_validate_config_runs_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The top-level validator exercises the expected startup validation sequence."""
    monkeypatch.setattr(validation_module, "validate_testing_mode_for_startup", lambda: None)
    config = _minimal_config()

    validate_config(config)


def test_validate_config_rejects_testing_mode_in_non_test_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Testing-mode startup is rejected by constructor-time validation outside pytest."""
    config = _minimal_config()
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    with pytest.raises(Exception, match=r"LITESTAR_AUTH_TESTING=1") as exc_info:
        validate_config(config)
    assert type(exc_info.value).__name__ == "ConfigurationError"


def test_validate_config_allows_testing_mode_under_pytest_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pytest execution keeps the testing-mode startup branch valid."""
    config = _minimal_config()
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/unit/test_plugin_validation.py::test_example")

    validate_config(config)


def test_validate_config_reports_missing_backends_before_later_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core startup prerequisites fail before later user-manager contract checks."""
    monkeypatch.setattr(validation_module, "validate_testing_mode_for_startup", lambda: None)
    config = _minimal_config(backends=[])

    class _ManagerWithoutListUsers(PluginUserManager):
        list_users = None

    config.include_users = True
    config.user_manager_class = cast("type[Any]", _ManagerWithoutListUsers)

    with pytest.raises(ValueError, match="at least one authentication backend"):
        validate_config(config)


def test_validate_config_reports_user_manager_contract_errors_before_request_security_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Credential-contract failures surface before later cookie-auth validation errors."""
    monkeypatch.setattr(validation_module, "validate_testing_mode_for_startup", lambda: None)
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)

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
    monkeypatch.setattr(validation_module, "validate_testing_mode_for_startup", lambda: None)
    monkeypatch.setattr(validation_module, "is_testing", lambda: False)
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


def _minimal_config(
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    oauth_config: OAuthConfig | None = None,
    rate_limit_config: AuthRateLimitConfig | None = None,
    totp_config: TotpConfig | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for validation-focused unit tests.

    Returns:
        Minimal config object with overridable backends and optional nested auth settings.
    """
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
        user_manager_kwargs={
            "verification_token_secret": "v" * 32,
            "reset_password_token_secret": "r" * 32,
        },
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
