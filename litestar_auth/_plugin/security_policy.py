"""Plugin-managed JWT/TOTP security policy descriptions and notices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, TypeGuard

from litestar_auth._manager.totp_secrets import TotpSecretStoragePosture

type _PluginSecurityPolicyKey = Literal["jwt_revocation", "totp_secret_storage"]


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


class _JWTRevocationPolicyLike(Protocol):
    """Runtime JWT revocation policy contract used by plugin validation and startup warnings."""

    key: str
    requires_explicit_production_opt_in: bool
    production_validation_error: str | None
    startup_warning: str | None


_JWT_REVOCATION_POLICY = _PluginSecurityPolicy(
    key="jwt_revocation",
    plugin_surface="allow_nondurable_jwt_revocation=True",
    contract_reference="JWTStrategy.revocation_posture",
    docs_summary=(
        "`JWTStrategy(secret=...)` defaults to the compatibility-grade `compatibility_in_memory` posture "
        "unless you provide a shared denylist store."
    ),
    production_requirement=(
        "Plugin-managed production rejects this posture unless "
        "`allow_nondurable_jwt_revocation=True` or `unsafe_testing=True`; startup still warns when you "
        "explicitly accept the single-process tradeoff."
    ),
)
_TOTP_SECRET_STORAGE_POLICY = _PluginSecurityPolicy(
    key="totp_secret_storage",
    plugin_surface="user_manager_security.totp_secret_key",
    contract_reference="BaseUserManager.totp_secret_storage_posture",
    docs_summary=(
        "Omitting `totp_secret_key` keeps the compatibility-grade `compatibility_plaintext` posture "
        "so legacy plaintext TOTP secrets still round-trip."
    ),
    production_requirement=(
        "With `totp_config` enabled, plugin-managed production requires `user_manager_security.totp_secret_key` "
        "unless `unsafe_testing=True` or a custom `user_manager_factory` explicitly owns that wiring."
    ),
)


def _is_jwt_revocation_policy_like(posture: object) -> TypeGuard[_JWTRevocationPolicyLike]:
    """Return whether ``posture`` matches the JWT revocation policy contract.

    This uses attribute checks instead of ``isinstance()`` so strategy-module reloads in
    test coverage still satisfy the shared policy contract.
    """
    production_validation_error = getattr(posture, "production_validation_error", None)
    startup_warning = getattr(posture, "startup_warning", None)
    return (
        isinstance(getattr(posture, "key", None), str)
        and isinstance(getattr(posture, "requires_explicit_production_opt_in", None), bool)
        and (production_validation_error is None or isinstance(production_validation_error, str))
        and (startup_warning is None or isinstance(startup_warning, str))
    )


def _describe_jwt_revocation_policy(posture: object) -> _PluginSecurityNotice | None:
    """Resolve the shared plugin notice for a JWT revocation policy.

    Returns:
        The shared plugin notice when ``posture`` satisfies the JWT revocation
        contract, otherwise ``None``.
    """
    if not _is_jwt_revocation_policy_like(posture):
        return None
    return _PluginSecurityNotice(
        policy=_JWT_REVOCATION_POLICY,
        posture_key=posture.key,
        requires_explicit_production_opt_in=posture.requires_explicit_production_opt_in,
        production_validation_error=posture.production_validation_error,
        startup_warning=posture.startup_warning,
    )


def _describe_totp_secret_storage_policy(totp_secret_key: str | None) -> _PluginSecurityNotice:
    """Resolve the shared plugin notice for TOTP secret storage policy.

    Returns:
        The shared plugin notice for the resolved TOTP storage posture.
    """
    posture = TotpSecretStoragePosture.from_secret_key(totp_secret_key)
    return _PluginSecurityNotice(
        policy=_TOTP_SECRET_STORAGE_POLICY,
        posture_key=posture.key,
        requires_explicit_production_opt_in=posture.requires_explicit_production_opt_in,
        production_validation_error=posture.production_validation_error,
        startup_warning=None,
    )


def _iter_plugin_security_policies() -> tuple[_PluginSecurityPolicy, ...]:
    """Return the shared plugin-managed JWT/TOTP security policy descriptions."""
    return (
        _JWT_REVOCATION_POLICY,
        _TOTP_SECRET_STORAGE_POLICY,
    )
