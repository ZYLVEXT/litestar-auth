"""User response schema helpers for generated controllers."""

from __future__ import annotations

import logging

import msgspec

from litestar_auth.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

_SENSITIVE_FIELD_BLOCKLIST: frozenset[str] = frozenset(
    {
        "hashed_password",
        "totp_secret",
        "password",
    },
)
ALWAYS_BLOCKED_FIELDS: frozenset[str] = _SENSITIVE_FIELD_BLOCKLIST | frozenset(
    {
        "current_password",
        "new_password",
        "password_hash",
        "recovery_codes",
    },
)


def _require_msgspec_struct(
    schema: type[object],
    *,
    parameter_name: str,
    require_forbid_unknown_fields: bool = False,
) -> None:
    """Validate that a configurable schema is a msgspec struct type.

    Raises:
        TypeError: If ``schema`` is not a ``msgspec.Struct`` subclass or does not
            satisfy request-body strictness requirements.
    """
    if not issubclass(schema, msgspec.Struct):
        msg = f"{parameter_name} must be a msgspec.Struct subclass."
        raise TypeError(msg)

    if require_forbid_unknown_fields and not schema.__struct_config__.forbid_unknown_fields:
        msg = f"{parameter_name} must set forbid_unknown_fields=True so unknown request fields are rejected."
        raise TypeError(msg)


def _to_user_schema(
    user: object,
    schema: type[msgspec.Struct],
    *,
    unsafe_testing: bool = False,
) -> msgspec.Struct:
    """Build the configured public response struct from a user object.

    ``_SENSITIVE_FIELD_BLOCKLIST`` rejects unsafe schema definitions early.
    ``ALWAYS_BLOCKED_FIELDS`` is a runtime defense around attribute access for
    credential, TOTP, and recovery-code fields that must never be serialized.

    Returns:
        The configured response struct populated from ``user`` attributes.

    Raises:
        ConfigurationError: If the schema includes fields that must not be serialized.
    """
    leaked = _SENSITIVE_FIELD_BLOCKLIST & frozenset(schema.__struct_fields__)
    if leaked:
        if not unsafe_testing:
            msg = (
                f"UserRead schema includes sensitive fields {sorted(leaked)}; "
                "remove them from the response schema to prevent data leakage."
            )
            raise ConfigurationError(msg)
        logger.warning(
            "UserRead schema includes sensitive fields %s; these will appear in API responses",
            sorted(leaked),
        )
    payload: dict[str, object] = {}
    for field_name in schema.__struct_fields__:
        if field_name in ALWAYS_BLOCKED_FIELDS:
            msg = (
                f"UserRead schema includes blocked field {field_name!r}; remove it from the response schema "
                "to prevent sensitive data leakage."
            )
            raise ConfigurationError(msg)
        if not hasattr(user, field_name):
            msg = (
                f"User schema {schema.__name__!r} requires field {field_name!r}, but "
                f"{type(user).__name__!r} does not define it. Align your public user schema "
                "with the configured user model."
            )
            raise ConfigurationError(msg)
        payload[field_name] = getattr(user, field_name)
    return schema(**payload)
