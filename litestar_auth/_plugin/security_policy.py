"""Plugin-managed TOTP security policy descriptions and notices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from litestar_auth._manager.totp_secrets import TotpSecretStoragePosture

type _PluginSecurityPolicyKey = Literal["totp_secret_storage"]


@dataclass(frozen=True, slots=True)
class _PluginSecurityPolicy:
    """Shared documentation and ownership wording for plugin-managed security policies."""

    key: _PluginSecurityPolicyKey
    plugin_surface: str
    contract_reference: str
    docs_summary: str
    production_requirement: str


@dataclass(frozen=True, slots=True)
class _PluginSecurityNotice:
    """One concrete runtime notice resolved from a strategy security contract."""

    policy: _PluginSecurityPolicy
    posture_key: str
    requires_explicit_production_opt_in: bool
    production_validation_error: str | None
    startup_warning: str | None


_TOTP_SECRET_STORAGE_POLICY = _PluginSecurityPolicy(
    key="totp_secret_storage",
    plugin_surface="user_manager_security.totp_secret_keyring",
    contract_reference="BaseUserManager.totp_secret_storage_posture",
    docs_summary=(
        "`BaseUserManager.totp_secret_storage_posture` is the Fernet-encrypted at-rest contract; "
        "omitting both `totp_secret_keyring` and `totp_secret_key` means non-null persisted TOTP secrets "
        "cannot be stored or read."
    ),
    production_requirement=(
        "With `totp_config` enabled, plugin-managed production requires `user_manager_security.totp_secret_keyring` "
        "or the one-key `totp_secret_key` shortcut unless `unsafe_testing=True` or a custom "
        "`user_manager_factory` explicitly owns that wiring."
    ),
)


def _describe_totp_secret_storage_policy(
    *,
    totp_secret_key: str | None,
    keyring_configured: bool = False,
) -> _PluginSecurityNotice:
    """Resolve the shared plugin notice for TOTP secret storage policy.

    Returns:
        The shared plugin notice for the resolved TOTP storage posture.
    """
    posture = TotpSecretStoragePosture.from_keyring_inputs(
        totp_secret_key=totp_secret_key,
        keyring_configured=keyring_configured,
    )
    return _PluginSecurityNotice(
        policy=_TOTP_SECRET_STORAGE_POLICY,
        posture_key=posture.key,
        requires_explicit_production_opt_in=posture.requires_explicit_production_opt_in,
        production_validation_error=posture.production_validation_error,
        startup_warning=None,
    )


def _iter_plugin_security_policies() -> tuple[_PluginSecurityPolicy, ...]:
    """Return the shared plugin-managed TOTP security policy descriptions."""
    return (_TOTP_SECRET_STORAGE_POLICY,)
