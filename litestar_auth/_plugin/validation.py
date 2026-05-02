"""Constructor-time validation helpers for the auth plugin."""

from __future__ import annotations

import inspect
import warnings
from importlib import import_module
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import inspect as sa_inspect

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._manager.security import validate_user_manager_security_secret_roles_are_distinct
from litestar_auth._plugin.config import (
    LitestarAuthConfig,
    _normalize_config_superuser_role_name,
)
from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.oauth_validation import validate_oauth_route_registration_config as _validate_oauth_routes
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoints
from litestar_auth._plugin.totp_validation import (
    _validate_totp_encryption_key,
    _validate_totp_pending_secret_config,
    validate_totp_config,
    validate_totp_encryption_config,
    validate_totp_secret_config,
    validate_totp_sub_config,
)
from litestar_auth.config import (
    MINIMUM_SECRET_LENGTH,
    resolve_trusted_proxy_setting,
    validate_secret_length,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.schemas import UserRead, UserUpdate
from litestar_auth.totp import SecurityWarning
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.session_binding import _AccountStateValidator as PluginAccountStateValidator
    from litestar_auth.authentication.strategy.jwt import JWTStrategy

__all__ = (
    "SecurityWarning",
    "_validate_totp_encryption_key",
    "_validate_totp_pending_secret_config",
    "validate_totp_config",
    "validate_totp_encryption_config",
    "validate_totp_secret_config",
    "validate_totp_sub_config",
)


def _current_jwt_strategy_type() -> type[JWTStrategy]:
    """Return the live JWT strategy class."""
    jwt_module = import_module("litestar_auth.authentication.strategy.jwt")
    return cast("type[JWTStrategy]", jwt_module.JWTStrategy)


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


def _user_model_defines_field(model_cls: object, field_name: str) -> bool:
    """Return whether ``user_model`` exposes ``field_name`` as a mapped or plain attribute.

    For SQLAlchemy ORM-mapped classes, use :meth:`sqlalchemy.orm.Mapper.has_property`
    so mapped columns, hybrids, and similar mapper properties are recognized. Plain
    dataclasses and other types fall back to :func:`hasattr`.
    """
    mapper = sa_inspect(model_cls, raiseerr=False)
    if mapper is not None and hasattr(mapper, "has_property") and mapper.has_property(field_name):
        return True
    return hasattr(model_cls, field_name)


def _schema_declares_field(schema: type[object], field_name: str) -> bool:
    """Return whether a msgspec schema declares ``field_name`` on its public contract."""
    return field_name in cast("tuple[str, ...]", getattr(schema, "__struct_fields__", ()))


def _role_schema_surfaces_requiring_role_capability[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> tuple[str, ...]:
    """Return plugin-owned schema surfaces that require ``user_model.roles``."""
    read_schema = config.user_read_schema or UserRead
    update_schema = config.user_update_schema or UserUpdate
    required_surfaces: list[str] = []

    if _schema_declares_field(read_schema, "roles"):
        if config.include_register:
            required_surfaces.append("register responses")
        if config.include_verify:
            required_surfaces.append("verify responses")
        if config.include_reset_password:
            required_surfaces.append("reset-password responses")
        if config.include_users:
            required_surfaces.append("users responses")

    if config.include_users and _schema_declares_field(update_schema, "roles"):
        required_surfaces.append("users update requests")

    return tuple(required_surfaces)


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
    if not _user_model_defines_field(model_cls, field_name):
        msg = (
            f"LitestarAuthConfig.login_identifier is {field_name!r}, but user_model "
            f"{getattr(model_cls, '__name__', model_cls)!r} has no {field_name!r} mapped field or attribute."
        )
        raise ConfigurationError(msg)


def validate_role_capable_user_model_surfaces[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Fail fast when plugin-owned schemas require ``roles`` but ``user_model`` does not expose it.

    Raises:
        ConfigurationError: If an enabled plugin-owned route surface uses a schema that includes
            ``roles`` while ``user_model`` has no matching mapped field or attribute.
    """
    if _user_model_defines_field(config.user_model, "roles"):
        return

    required_surfaces = _role_schema_surfaces_requiring_role_capability(config)
    if not required_surfaces:
        return

    user_model_name = getattr(config.user_model, "__name__", config.user_model)
    msg = (
        f"user_model {user_model_name!r} has no 'roles' mapped field or attribute, but "
        f"{', '.join(required_surfaces)} use schema fields that include 'roles'. "
        "Compose UserRoleRelationshipMixin (or an equivalent normalized roles attribute), "
        "or provide user_read_schema/user_update_schema types that omit 'roles'."
    )
    raise ConfigurationError(msg)


def validate_core_session_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate constructor-time runtime-mode, backend, and session prerequisites.

    Raises:
        ValueError: If the plugin lacks a backend or a supported DB-session source.
    """
    if not config.resolve_startup_backends():
        msg = "LitestarAuth requires at least one authentication backend."
        raise ValueError(msg)

    validate_session_maker_or_external_db_session(config)


def validate_credential_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate credential and user-manager contracts needed during construction.

    Raises:
        ValueError: If user-listing support is requested without ``list_users()``.
    """
    validate_user_manager_security_config(config)
    validate_superuser_role_name_config(config)
    validate_password_validator_config(config)
    validate_default_user_manager_constructor_contract(config)
    validate_user_model_login_identifier_fields(config)
    validate_role_capable_user_model_surfaces(config)

    if config.include_users and not callable(getattr(config.user_manager_class, "list_users", None)):
        msg = "include_users=True requires user_manager_class to define list_users()."
        raise ValueError(msg)


def validate_totp_domain_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP feature-level configuration before deeper security checks."""
    validate_totp_user_model_protocol(config)
    validate_totp_config(config)


def validate_request_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate request-facing rate-limit and cookie-auth prerequisites."""
    validate_rate_limit_config(config.rate_limit_config)
    validate_cookie_auth_config(config)


def validate_oauth_route_registration_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate the deterministic plugin OAuth route-registration contract."""
    _validate_oauth_routes(config.oauth_config, auth_path=config.auth_path)


def validate_backend_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend-strategy security posture for constructor-time setup."""
    _validate_backend_strategy_security(config)


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


def validate_superuser_role_name_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate and normalize the configured superuser role name."""
    config.superuser_role_name = _normalize_config_superuser_role_name(config.superuser_role_name)


def _validate_backend_strategy_security[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend strategy security posture for non-test environments."""
    for backend in config.resolve_startup_backends():
        _warn_backend_name_strategy_mismatch(
            backend_name=getattr(backend, "name", None),
            strategy=getattr(backend, "strategy", None),
        )


def _warn_backend_name_strategy_mismatch(*, backend_name: object, strategy: object) -> None:
    """Warn when a backend name implies JWT but the configured strategy is not JWT-backed."""
    if (
        not isinstance(backend_name, str)
        or "jwt" not in backend_name.casefold()
        or isinstance(strategy, _current_jwt_strategy_type())
    ):
        return

    warnings.warn(
        f"AuthenticationBackend name {backend_name!r} suggests JWTStrategy semantics, but the configured "
        f"strategy is {type(strategy).__name__}. Consider a neutral name like 'bearer' or 'database' "
        "to avoid misleading logs and configuration.",
        UserWarning,
        stacklevel=4,
    )


def validate_totp_user_model_protocol[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Ensure TOTP-enabled configs use a user model that exposes TOTP fields.

    Raises:
        ConfigurationError: If ``totp_config`` is set but ``user_model`` does not expose
            the fields required by ``TotpUserProtocol``.
    """
    if config.totp_config is None:
        return

    required_fields = ("email", "totp_secret")
    missing_fields = tuple(
        field_name for field_name in required_fields if not _user_model_defines_field(config.user_model, field_name)
    )
    if not missing_fields:
        return

    user_model_name = getattr(config.user_model, "__name__", config.user_model)
    missing_fields_list = ", ".join(repr(field_name) for field_name in missing_fields)
    msg = (
        f"TOTP is configured but user_model {user_model_name!r} does not expose "
        f"fields required by TotpUserProtocol: {missing_fields_list}."
    )
    raise ConfigurationError(msg)


def validate_user_manager_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate manager secret wiring and the supported production secret posture.

    Raises:
        ConfigurationError: If the typed contract conflicts with the top-level
            ``id_parser`` declaration.
    """
    manager_inputs = ManagerConstructorInputs(
        manager_security=config.user_manager_security,
        id_parser=config.id_parser,
    )
    manager_security = config.user_manager_security
    if manager_security is not None and (
        config.id_parser is not None
        and manager_security.id_parser is not None
        and config.id_parser is not manager_security.id_parser
    ):
        msg = (
            "Configure id_parser via user_manager_security.id_parser or LitestarAuthConfig.id_parser, "
            "not both with different values."
        )
        raise ConfigurationError(msg)

    if config.unsafe_testing:
        return

    effective_security = manager_inputs.effective_security
    if effective_security.login_identifier_telemetry_secret is not None:
        validate_secret_length(
            effective_security.login_identifier_telemetry_secret,
            label="login_identifier_telemetry_secret",
            minimum_length=MINIMUM_SECRET_LENGTH,
        )
    validate_user_manager_security_secret_roles_are_distinct(
        effective_security,
        totp_pending_secret=config.totp_config.totp_pending_secret if config.totp_config is not None else None,
        oauth_flow_cookie_secret=(
            config.oauth_config.oauth_flow_cookie_secret if config.oauth_config is not None else None
        ),
    )


def validate_password_validator_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate password-validator wiring for the configured user-manager builder.

    The plugin contract now sources password validation only from
    ``password_validator_factory`` when present.
    """
    del config


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

    from litestar_auth._plugin.user_manager_builder import (  # noqa: PLC0415
        _DEFAULT_USER_MANAGER_FACTORY_GUIDANCE,
        _build_default_user_manager_contract,
        _build_default_user_manager_validation_kwargs,
    )

    manager_class = config.user_manager_class
    if manager_class is None:
        msg = (
            "user_manager_class must be configured when user_manager_factory is unset. "
            f"{_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE}"
        )
        raise ConfigurationError(msg)
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
    user_manager_class: type[object] | None,
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
    cookie_transports = get_cookie_transports(config.resolve_startup_backends())
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
