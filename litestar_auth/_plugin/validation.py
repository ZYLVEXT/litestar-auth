"""Constructor-time validation helpers for the auth plugin."""

from __future__ import annotations

import inspect
import logging
import warnings
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import inspect as sa_inspect

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._plugin.config import (
    _DEFAULT_USER_MANAGER_FACTORY_GUIDANCE,
    LitestarAuthConfig,
    TotpConfig,
    _build_default_user_manager_contract,
    _build_default_user_manager_validation_kwargs,
    _build_oauth_route_registration_contract,
    _describe_jwt_revocation_tradeoff,
    _format_default_user_manager_managed_security_error,
    _resolve_plugin_managed_totp_secret_storage_tradeoff,
)
from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoints
from litestar_auth.authentication.strategy.db import (
    DatabaseTokenStrategy,
    build_legacy_plaintext_tokens_validation_message,
)
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.config import (
    MINIMUM_SECRET_LENGTH,
    resolve_trusted_proxy_setting,
    validate_secret_length,
    warn_if_secret_roles_are_reused,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.totp import SecurityWarning
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.session_binding import _AccountStateValidator as PluginAccountStateValidator

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
    if not config.startup_backends():
        msg = "LitestarAuth requires at least one authentication backend."
        raise ValueError(msg)

    validate_session_maker_or_external_db_session(config)


def validate_credential_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate credential and user-manager contracts needed during construction.

    Raises:
        ValueError: If user-listing support is requested without ``list_users()``.
    """
    validate_user_manager_security_config(config)
    validate_password_validator_config(config)
    validate_default_user_manager_constructor_contract(config)
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


def validate_oauth_route_registration_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate the deterministic plugin OAuth route-registration contract.

    Raises:
        ValueError: If plugin-owned OAuth routes are declared with incomplete config.
    """
    oauth_config = config.oauth_config
    if oauth_config is None:
        return

    contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=oauth_config,
    )
    _validate_unique_oauth_provider_names(
        providers=contract.providers,
        field_name="oauth_providers",
    )

    if contract.include_oauth_associate and not contract.providers:
        msg = "include_oauth_associate=True requires oauth_providers to be configured."
        raise ValueError(msg)

    if oauth_config.oauth_redirect_base_url and not contract.providers:
        msg = "oauth_redirect_base_url requires oauth_providers to be configured."
        raise ValueError(msg)

    if contract.providers and contract.redirect_base_url is None:
        msg = "oauth_redirect_base_url is required when oauth_providers are configured."
        raise ValueError(msg)

    if contract.oauth_associate_by_email and not contract.providers:
        msg = "oauth_associate_by_email only affects plugin-owned OAuth login routes configured via oauth_providers."
        raise ValueError(msg)

    if contract.oauth_trust_provider_email_verified and not contract.providers:
        msg = (
            "oauth_trust_provider_email_verified only affects plugin-owned OAuth login routes configured "
            "via oauth_providers."
        )
        raise ValueError(msg)


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
        validate_totp_secret_config,
        validate_totp_domain_config,
        validate_request_security_config,
        validate_oauth_route_registration_config,
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
    if totp_config.totp_algorithm == "SHA1" and not config.unsafe_testing:
        logger.warning(
            "TOTP is configured with SHA1. For new deployments, consider using SHA256 or SHA512 "
            "if supported by your authenticator clients.",
            extra={"event": "totp_sha1_configured"},
        )


def _validate_backend_strategy_security[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend strategy security posture for non-test environments."""
    for backend in config.startup_backends():
        _warn_backend_name_strategy_mismatch(
            backend_name=getattr(backend, "name", None),
            strategy=getattr(backend, "strategy", None),
        )

    for backend in config.startup_backends():
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
        and not _database_strategy_legacy_rollout_enabled(config)
        and not config.unsafe_testing
    ):
        return

    msg = build_legacy_plaintext_tokens_validation_message(
        rollout_setting=_database_strategy_legacy_rollout_setting_hint(config),
    )
    raise ValueError(msg)


def _database_strategy_legacy_rollout_enabled[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> bool:
    """Return whether DB-token legacy plaintext rollout mode is explicitly enabled."""
    database_token_auth = config.database_token_auth
    if database_token_auth is not None:
        return database_token_auth.accept_legacy_plaintext_tokens
    return config.allow_legacy_plaintext_tokens


def _database_strategy_legacy_rollout_setting_hint[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> str:
    """Return the config knob that controls DB-token legacy plaintext rollout."""
    if config.database_token_auth is not None:
        return "DatabaseTokenAuthConfig.accept_legacy_plaintext_tokens=True"
    return "LitestarAuthConfig.allow_legacy_plaintext_tokens=True"


def _validate_jwt_strategy_revocation[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    strategy: JWTStrategy[UP, ID],
) -> None:
    """Validate durable revocation requirements for JWT strategy.

    Raises:
        ValueError: If JWT revocation storage is nondurable in production.
    """
    notice = _describe_jwt_revocation_tradeoff(strategy.revocation_posture)
    if (
        notice is None
        or not notice.requires_explicit_production_opt_in
        or config.allow_nondurable_jwt_revocation
        or config.unsafe_testing
    ):
        return

    msg = notice.production_validation_error
    if msg is None:  # pragma: no cover - posture branch above guarantees a message
        return
    raise ValueError(msg)


def _validate_totp_encryption_key[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Require TOTP secret encryption key in production when TOTP is enabled.

    Raises:
        ConfigurationError: If TOTP is configured but ``totp_secret_key`` is missing
            while ``config.unsafe_testing`` is false.
    """
    if config.totp_config is None or config.unsafe_testing:
        return
    notice = _resolve_plugin_managed_totp_secret_storage_tradeoff(config)
    if notice is None or not notice.requires_explicit_production_opt_in:
        return

    msg = notice.production_validation_error
    if msg is None:  # pragma: no cover - compatibility plaintext posture always provides a validation error
        return
    raise ConfigurationError(msg)


def validate_user_manager_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate manager secret wiring and the supported production secret posture.

    Raises:
        ConfigurationError: If the typed contract overlaps with legacy kwargs or an
            incompatible top-level ``id_parser`` declaration.
    """
    manager_inputs = ManagerConstructorInputs(
        manager_kwargs=config.user_manager_kwargs,
        manager_security=config.user_manager_security,
        id_parser=config.id_parser,
    )
    manager_security = config.user_manager_security
    if manager_security is not None:
        if manager_inputs.security_overlap_keys:
            overlap = ", ".join(manager_inputs.security_overlap_keys)
            msg = (
                "user_manager_security is the canonical plugin-managed path for manager secrets and id_parser. "
                "Remove the overlapping entries from user_manager_kwargs: "
                f"{overlap}."
            )
            raise ConfigurationError(msg)

        if (
            config.id_parser is not None
            and manager_security.id_parser is not None
            and config.id_parser is not manager_security.id_parser
        ):
            msg = (
                "Configure id_parser via user_manager_security.id_parser or LitestarAuthConfig.id_parser, "
                "not both with different values."
            )
            raise ConfigurationError(msg)

    if config.user_manager_factory is None and manager_inputs.managed_security_keys:
        msg = _format_default_user_manager_managed_security_error(manager_inputs.managed_security_keys)
        raise ConfigurationError(msg)

    if config.unsafe_testing:
        return

    effective_security = manager_inputs.effective_security
    warn_if_secret_roles_are_reused(
        verification_token_secret=effective_security.verification_token_secret,
        reset_password_token_secret=effective_security.reset_password_token_secret,
        totp_secret_key=effective_security.totp_secret_key,
        totp_pending_secret=config.totp_config.totp_pending_secret if config.totp_config is not None else None,
        warning_options=(SecurityWarning, 2),
    )


def validate_password_validator_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate password-validator wiring for the configured user-manager builder.

    Raises:
        ValueError: If explicit and legacy password-validator configuration are mixed.
    """
    if config.password_validator_factory is None:
        return

    manager_inputs = ManagerConstructorInputs(manager_kwargs=config.user_manager_kwargs)
    if manager_inputs.has_explicit_password_validator:
        msg = (
            "Configure password validation via password_validator_factory or "
            "user_manager_kwargs['password_validator'], not both."
        )
        raise ValueError(msg)

    if config.user_manager_factory is not None:
        return


def validate_default_user_manager_constructor_contract[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Fail fast when ``user_manager_class`` is incompatible with the default builder.

    Raises:
        ConfigurationError: If ``user_manager_factory`` is unset and the configured
            ``user_manager_class`` does not accept the default builder contract.
    """
    if config.user_manager_factory is not None:
        return

    manager_class = config.user_manager_class
    manager_name = getattr(manager_class, "__name__", repr(manager_class))
    contract = _build_default_user_manager_contract(
        config,
        password_helper=object(),
        password_validator=None,
    )
    try:
        constructor_signature = inspect.signature(manager_class)
    except (TypeError, ValueError) as exc:
        msg = (
            f"{manager_name!r} (user_manager_class) must expose an introspectable constructor when "
            f"user_manager_factory is unset. {_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE}"
        )
        raise ConfigurationError(msg) from exc

    try:
        constructor_signature.bind(
            object(),
            **_build_default_user_manager_validation_kwargs(config),
        )
    except TypeError as exc:
        msg = contract.build_constructor_mismatch_message(manager_name, exc)
        raise ConfigurationError(msg) from exc


def resolve_user_manager_account_state_validator[UP: UserProtocol[Any]](
    user_manager_class: type[object],
) -> PluginAccountStateValidator[UP]:
    """Resolve the plugin-managed manager-class account-state validator contract.

    Returns:
        The callable ``require_account_state(user, *, require_verified=False)``
        exposed by ``user_manager_class``.

    Raises:
        TypeError: If ``user_manager_class`` does not expose a callable
            ``require_account_state()``.
    """
    validator = getattr(user_manager_class, "require_account_state", None)
    if callable(validator):
        return cast("PluginAccountStateValidator[UP]", validator)

    manager_name = getattr(user_manager_class, "__name__", repr(user_manager_class))
    msg = (
        f"{manager_name!r} (user_manager_class) must expose "
        "require_account_state(user, *, require_verified=False). "
        "Subclass litestar_auth.manager.BaseUserManager for the default implementation, "
        "or define require_account_state on your manager class with the same contract."
    )
    raise TypeError(msg)


def _validate_unique_oauth_provider_names(
    *,
    providers: tuple[tuple[str, object], ...],
    field_name: str,
) -> None:
    """Reject duplicate provider names within one declared OAuth inventory.

    Raises:
        ValueError: If a provider name appears more than once in the same inventory.
    """
    seen: set[str] = set()
    duplicates: list[str] = []
    for provider in providers:
        provider_name = provider[0]
        if provider_name in seen and provider_name not in duplicates:
            duplicates.append(provider_name)
            continue
        seen.add(provider_name)

    if duplicates:
        duplicate_names = ", ".join(sorted(duplicates))
        msg = f"{field_name} must not contain duplicate provider names: {duplicate_names}."
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
    cookie_transports = get_cookie_transports(config.startup_backends())
    if not cookie_transports:
        return

    if config.csrf_secret is not None:
        validate_secret_length(
            config.csrf_secret,
            label="csrf_secret",
            minimum_length=MINIMUM_SECRET_LENGTH,
        )

    unsafe_cookie_transports = [transport for transport in cookie_transports if transport.allow_insecure_cookie_auth]
    if config.csrf_secret is not None or unsafe_cookie_transports or config.unsafe_testing:
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
    validate_totp_sub_config(
        config.totp_config,
        user_manager_class=config.user_manager_class,
        unsafe_testing=config.unsafe_testing,
    )
    if not config.unsafe_testing:
        cookie_transports = get_cookie_transports(config.startup_backends())
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
    unsafe_testing: bool = False,
) -> None:
    """Validate a concrete ``TotpConfig`` payload.

    Raises:
        ValueError: If required TOTP configuration is missing or incompatible.
    """
    if not totp_config.totp_pending_secret:
        msg = "totp_config requires totp_pending_secret."
        raise ValueError(msg)
    pending_jti_store = getattr(totp_config, "totp_pending_jti_store", None)
    if pending_jti_store is None and not unsafe_testing:
        msg = "totp_pending_jti_store is required unless unsafe_testing=True."
        raise ValueError(msg)
    require_replay_protection = bool(getattr(totp_config, "totp_require_replay_protection", False))
    used_tokens_store = getattr(totp_config, "totp_used_tokens_store", None)
    if require_replay_protection and used_tokens_store is None and not unsafe_testing:
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
