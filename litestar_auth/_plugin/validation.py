"""Constructor-time validation helpers for the auth plugin."""

from __future__ import annotations

import logging
import warnings
from typing import Any, cast

from sqlalchemy import inspect as sa_inspect

from litestar_auth._plugin.config import (
    LitestarAuthConfig,
    TotpConfig,
    user_manager_accepts_password_validator,
)
from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoints
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.config import (
    MINIMUM_SECRET_LENGTH,
    is_testing,
    resolve_trusted_proxy_setting,
    validate_secret_length,
    validate_testing_mode_for_startup,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.totp import SecurityWarning
from litestar_auth.types import UserProtocol

logger = logging.getLogger("litestar_auth.plugin")


def validate_session_maker_or_external_db_session[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Ensure either a session factory or an external ``db_session`` DI binding exists.

    Raises:
        ValueError: If neither ``session_maker`` nor external session DI is configured.
    """
    has_session_maker = config.session_maker is not None
    has_external_db_session = config.db_session_dependency_provided_externally
    if not has_session_maker and not has_external_db_session:
        msg = (
            "LitestarAuth requires session_maker or db_session_dependency_provided_externally=True "
            f"(inject AsyncSession under dependency key {config.db_session_dependency_key!r})."
        )
        raise ValueError(msg)


def _user_model_defines_login_field(model_cls: object, field_name: str) -> bool:
    """Return whether ``user_model`` exposes ``field_name`` for credential lookup.

    For SQLAlchemy ORM-mapped classes, use :meth:`sqlalchemy.orm.Mapper.has_property`
    so mapped columns, hybrids, and similar mapper properties are recognized. Plain
    dataclasses and other types fall back to :func:`hasattr`.
    """
    mapper = sa_inspect(model_cls, raiseerr=False)
    if mapper is not None and hasattr(mapper, "has_property"):
        return bool(mapper.has_property(field_name))
    return hasattr(model_cls, field_name)


def validate_user_model_login_identifier_fields[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Ensure ``user_model`` defines the attribute implied by ``login_identifier``.

    Raises:
        ConfigurationError: When the model lacks ``email`` or ``username`` as required by
            ``login_identifier``.
    """
    field_name = config.login_identifier
    model_cls = config.user_model
    if not _user_model_defines_login_field(model_cls, field_name):
        msg = (
            f"LitestarAuthConfig.login_identifier is {field_name!r}, but user_model "
            f"{getattr(model_cls, '__name__', model_cls)!r} has no {field_name!r} mapped field or attribute."
        )
        raise ConfigurationError(msg)


def validate_core_session_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate constructor-time runtime-mode, backend, and session prerequisites.

    Raises:
        ValueError: If the plugin lacks a backend or a supported DB-session source.
    """
    validate_testing_mode_for_startup()

    if not config.backends:
        msg = "LitestarAuth requires at least one authentication backend."
        raise ValueError(msg)

    validate_session_maker_or_external_db_session(config)


def validate_credential_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate credential and user-manager contracts needed during construction.

    Raises:
        ValueError: If user-listing support is requested without ``list_users()``.
    """
    validate_password_validator_config(config)
    validate_user_model_login_identifier_fields(config)

    if config.include_users and not callable(getattr(config.user_manager_class, "list_users", None)):
        msg = "include_users=True requires user_manager_class to define list_users()."
        raise ValueError(msg)


def validate_totp_domain_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP feature-level configuration before deeper security checks."""
    validate_totp_config(config)


def validate_request_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate request-facing rate-limit and cookie-auth prerequisites."""
    validate_rate_limit_config(config.rate_limit_config)
    validate_cookie_auth_config(config)


def validate_totp_secret_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP secret-material and algorithm requirements."""
    _validate_totp_pending_secret_config(config)


def validate_backend_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend-strategy security posture for constructor-time setup."""
    _validate_backend_strategy_security(config)


def validate_totp_encryption_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate production encryption requirements for persisted TOTP secrets."""
    _validate_totp_encryption_key(config)


def validate_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate the requested plugin configuration during plugin construction."""
    for validator in (
        validate_core_session_config,
        validate_credential_config,
        validate_totp_domain_config,
        validate_request_security_config,
        validate_totp_secret_config,
        validate_backend_security_config,
        validate_totp_encryption_config,
    ):
        validator(config)


def _validate_totp_pending_secret_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP pending-secret and algorithm constraints.

    Raises:
        ValueError: If TOTP algorithm requirements are not satisfied.
    """
    if config.totp_config is None:
        return
    totp_config = config.totp_config

    validate_secret_length(
        totp_config.totp_pending_secret,
        label="totp_pending_secret",
        minimum_length=MINIMUM_SECRET_LENGTH,
    )
    if not getattr(totp_config, "totp_algorithm", None):
        msg = "totp_algorithm must be configured when totp_config is set."
        raise ValueError(msg)
    if totp_config.totp_algorithm == "SHA1" and not is_testing():
        logger.warning(
            "TOTP is configured with SHA1. For new deployments, consider using SHA256 or SHA512 "
            "if supported by your authenticator clients.",
            extra={"event": "totp_sha1_configured"},
        )


def _validate_backend_strategy_security[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend strategy security posture for non-test environments."""
    for backend in config.backends:
        _warn_backend_name_strategy_mismatch(
            backend_name=getattr(backend, "name", None),
            strategy=getattr(backend, "strategy", None),
        )

    for backend in config.backends:
        strategy = getattr(backend, "strategy", None)
        _validate_database_strategy_legacy_mode(config=config, strategy=strategy)
        if isinstance(strategy, JWTStrategy):
            _validate_jwt_strategy_revocation(config=config, strategy=strategy)
            break


def _warn_backend_name_strategy_mismatch(*, backend_name: object, strategy: object) -> None:
    """Warn when a backend name implies JWT but the configured strategy is not JWT-backed."""
    if not isinstance(backend_name, str) or "jwt" not in backend_name.casefold() or isinstance(strategy, JWTStrategy):
        return

    warnings.warn(
        f"AuthenticationBackend name {backend_name!r} suggests JWTStrategy semantics, but the configured "
        f"strategy is {type(strategy).__name__}. Consider a neutral name like 'bearer' or 'database' "
        "to avoid misleading logs and configuration.",
        UserWarning,
        stacklevel=4,
    )


def _validate_database_strategy_legacy_mode[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    strategy: object,
) -> None:
    """Validate temporary plaintext-token compatibility mode for DB strategy.

    Raises:
        ValueError: If migration-only plaintext token compatibility is enabled in production.
    """
    if not (
        isinstance(strategy, DatabaseTokenStrategy)
        and strategy.accept_legacy_plaintext_tokens
        and not config.allow_legacy_plaintext_tokens
        and not is_testing()
    ):
        return

    msg = (
        "DatabaseTokenStrategy accept_legacy_plaintext_tokens=True is migration-only and disabled by "
        "default in production. To explicitly accept temporary plaintext-token compatibility during a "
        "controlled rollout, set LitestarAuthConfig.allow_legacy_plaintext_tokens=True and remove it "
        "after rotating sessions and purging legacy rows."
    )
    raise ValueError(msg)


def _validate_jwt_strategy_revocation[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    strategy: JWTStrategy[UP, ID],
) -> None:
    """Validate durable revocation requirements for JWT strategy.

    Raises:
        ValueError: If JWT revocation storage is nondurable in production.
    """
    if getattr(strategy, "revocation_is_durable", False) or config.allow_nondurable_jwt_revocation or is_testing():
        return

    msg = (
        "JWTStrategy is configured with a process-local in-memory denylist. "
        "For production deployments, configure a durable denylist store (e.g. RedisJWTDenylistStore) "
        "or use RedisTokenStrategy / DatabaseTokenStrategy. "
        "To explicitly accept nondurable logout semantics, set allow_nondurable_jwt_revocation=True."
    )
    raise ValueError(msg)


def _validate_totp_encryption_key[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Require TOTP secret encryption key in production when TOTP is enabled.

    Raises:
        ConfigurationError: If TOTP is configured but ``totp_secret_key`` is missing
            outside of testing mode.
    """
    if config.totp_config is None or is_testing():
        return
    if not config.user_manager_kwargs.get("totp_secret_key"):
        msg = (
            "totp_secret_key is required in production when TOTP is enabled. "
            "TOTP secrets must be encrypted at rest. Generate a Fernet key with: "
            'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
        raise ConfigurationError(msg)


def validate_password_validator_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate password-validator wiring for the configured user-manager builder.

    Raises:
        ValueError: If explicit and legacy password-validator configuration are mixed, or if an
            explicit password-validator factory targets a manager without a compatible builder.
    """
    if config.password_validator_factory is None:
        return

    if "password_validator" in config.user_manager_kwargs:
        msg = (
            "Configure password validation via password_validator_factory or "
            "user_manager_kwargs['password_validator'], not both."
        )
        raise ValueError(msg)

    if config.user_manager_factory is not None:
        return

    if user_manager_accepts_password_validator(config.user_manager_class):
        return

    msg = (
        "password_validator_factory requires user_manager_class to accept password_validator or "
        "user_manager_factory to build the manager explicitly."
    )
    raise ValueError(msg)


def validate_rate_limit_config(rate_limit_config: object) -> None:
    """Validate rate-limit backend settings (trusted-proxy flags).

    In-memory rate-limit ``SecurityWarning`` emissions happen during
    ``LitestarAuth.on_app_init()`` in the startup runtime helper module.
    """
    if rate_limit_config is None:
        return

    for endpoint_limit in iter_rate_limit_endpoints(cast("Any", rate_limit_config)):
        if endpoint_limit is None:
            continue
        resolve_trusted_proxy_setting(trusted_proxy=endpoint_limit.trusted_proxy)


def validate_cookie_auth_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate cookie-auth prerequisites for production deployments.

    Raises:
        ConfigurationError: If cookie auth is enabled without a safe CSRF configuration.
    """
    cookie_transports = get_cookie_transports(config.backends)
    if not cookie_transports:
        return

    if config.csrf_secret is not None:
        validate_secret_length(
            config.csrf_secret,
            label="csrf_secret",
            minimum_length=MINIMUM_SECRET_LENGTH,
        )

    unsafe_cookie_transports = [transport for transport in cookie_transports if transport.allow_insecure_cookie_auth]
    if config.csrf_secret is not None or unsafe_cookie_transports or is_testing():
        return

    msg = (
        "CookieTransport in production requires csrf_secret. "
        'Generate one with `python -c "from secrets import token_urlsafe; print(token_urlsafe(32))"` '
        "or set allow_insecure_cookie_auth=True only for controlled non-browser scenarios."
    )
    raise ConfigurationError(msg)


def validate_totp_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP-specific configuration knobs."""
    if config.totp_config is None:
        return
    validate_totp_sub_config(config.totp_config, user_manager_class=config.user_manager_class)
    if not is_testing():
        cookie_transports = get_cookie_transports(config.backends)
        if cookie_transports and not all(t.secure for t in cookie_transports):
            warnings.warn(
                "TOTP is enabled but CookieTransport.secure=False; TOTP secrets returned by "
                "/2fa/enable may be transmitted over unencrypted connections.",
                SecurityWarning,
                stacklevel=2,
            )


def validate_totp_sub_config[UP: UserProtocol[Any]](
    totp_config: TotpConfig,
    *,
    user_manager_class: type[object],
) -> None:
    """Validate a concrete ``TotpConfig`` payload.

    Raises:
        ValueError: If required TOTP configuration is missing or incompatible.
    """
    if not totp_config.totp_pending_secret:
        msg = "totp_config requires totp_pending_secret."
        raise ValueError(msg)
    if totp_config.totp_require_replay_protection and totp_config.totp_used_tokens_store is None and not is_testing():
        msg = "totp_require_replay_protection=True requires totp_used_tokens_store to be configured."
        raise ValueError(msg)
    if totp_config.totp_enable_requires_password and not callable(
        getattr(user_manager_class, "authenticate", None),
    ):
        msg = (
            "TOTP step-up enrollment is enabled by default. "
            "Configure user_manager_class.authenticate(identifier, password) or set "
            "totp_enable_requires_password=False explicitly (not recommended)."
        )
        raise ValueError(msg)
