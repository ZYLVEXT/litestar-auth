"""Shared secret resolution helpers for runnable demo applications."""

from __future__ import annotations

import os
import warnings
from typing import overload

type MissingValueMessage = str

DEFAULT_MISSING_VALUE_MESSAGE: MissingValueMessage = (
    "Missing {name}. Export strong secrets or set {insecure_flag}=1 for local demonstration only."
)


# Fixed-arity overloads give each call site a precisely sized tuple back, so
# unpacking ``a, b, c = resolve_demo_secrets(...)`` is statically checked
# against the number of ``secret_names`` requested. Requiring matching arities
# on ``insecure_defaults`` and ``secret_names`` also catches a mismatched
# insecure-defaults bundle at type-check time. The trailing variadic overload
# keeps the helper usable for any other arity a future demo might need.
@overload
def resolve_demo_secrets(
    *,
    insecure_flag: str,
    insecure_defaults: tuple[str, str, str],
    secret_names: tuple[str, str, str],
    missing_value_message: MissingValueMessage = ...,
) -> tuple[str, str, str]: ...
@overload
def resolve_demo_secrets(
    *,
    insecure_flag: str,
    insecure_defaults: tuple[str, str, str, str],
    secret_names: tuple[str, str, str, str],
    missing_value_message: MissingValueMessage = ...,
) -> tuple[str, str, str, str]: ...
@overload
def resolve_demo_secrets(
    *,
    insecure_flag: str,
    insecure_defaults: tuple[str, str, str, str, str],
    secret_names: tuple[str, str, str, str, str],
    missing_value_message: MissingValueMessage = ...,
) -> tuple[str, str, str, str, str]: ...
@overload
def resolve_demo_secrets(
    *,
    insecure_flag: str,
    insecure_defaults: tuple[str, str, str, str, str, str, str],
    secret_names: tuple[str, str, str, str, str, str, str],
    missing_value_message: MissingValueMessage = ...,
) -> tuple[str, str, str, str, str, str, str]: ...
@overload
def resolve_demo_secrets(
    *,
    insecure_flag: str,
    insecure_defaults: tuple[str, str, str, str, str, str, str, str],
    secret_names: tuple[str, str, str, str, str, str, str, str],
    missing_value_message: MissingValueMessage = ...,
) -> tuple[str, str, str, str, str, str, str, str]: ...
@overload
def resolve_demo_secrets(
    *,
    insecure_flag: str,
    insecure_defaults: tuple[str, ...],
    secret_names: tuple[str, ...],
    missing_value_message: MissingValueMessage = ...,
) -> tuple[str, ...]: ...
def resolve_demo_secrets(
    *,
    insecure_flag: str,
    insecure_defaults: tuple[str, ...],
    secret_names: tuple[str, ...],
    missing_value_message: MissingValueMessage = DEFAULT_MISSING_VALUE_MESSAGE,
) -> tuple[str, ...]:
    """Resolve demo secrets from env or the app-specific insecure defaults.

    Returns:
        Secret values in the same order as ``secret_names`` or ``insecure_defaults``.
    """
    if os.environ.get(insecure_flag) == "1":
        warnings.warn(
            f"{insecure_flag}=1 uses fixed secrets; never enable in production.",
            stacklevel=3,
        )
        return insecure_defaults

    return tuple(
        _required_secret(
            name,
            insecure_flag=insecure_flag,
            missing_value_message=missing_value_message,
        )
        for name in secret_names
    )


def _required_secret(
    name: str,
    *,
    insecure_flag: str,
    missing_value_message: MissingValueMessage,
) -> str:
    value = os.environ.get(name)
    if value:
        return value

    msg = missing_value_message.format(name=name, insecure_flag=insecure_flag)
    raise RuntimeError(msg)
