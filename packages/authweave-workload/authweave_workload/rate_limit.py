"""Stable post-authentication workload rate-limit identities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authweave_core import AuthenticationContext, PrincipalRef


@dataclass(frozen=True, slots=True)
class WorkloadRateLimitIdentity:
    """Rotation-stable and credential-specific rate-limit keys."""

    application_id: str
    principal: PrincipalRef
    credential_id: str | None


def rate_limit_identity(context: AuthenticationContext) -> WorkloadRateLimitIdentity:
    """Build stable workload rate-limit identity from verified evidence.

    Returns:
        Application, principal, and optional credential identities.

    Raises:
        TypeError: If the context is not an authweave-workload result.
    """
    application_id = context.evidence.extensions.get("authweave-workload:application_id")
    if not isinstance(application_id, str):
        msg = "authentication context does not contain a verified workload application"
        raise TypeError(msg)
    return WorkloadRateLimitIdentity(
        application_id=application_id,
        principal=context.subject,
        credential_id=context.evidence.credential_id,
    )


__all__ = ("WorkloadRateLimitIdentity", "rate_limit_identity")
