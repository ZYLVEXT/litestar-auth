"""Shared TOTP controller constants and protocol contracts."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from litestar_auth.config import TOTP_ENROLL_AUDIENCE as _CONFIG_TOTP_ENROLL_AUDIENCE
from litestar_auth.controllers._utils import AccountStateValidatorProvider
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from litestar_auth.ratelimit import TotpSensitiveEndpoint

INVALID_TOTP_TOKEN_DETAIL = "Invalid or expired 2FA pending token."  # noqa: S105
INVALID_TOTP_CODE_DETAIL = "Invalid TOTP code."
INVALID_ENROLL_TOKEN_DETAIL = "Invalid or expired enrollment token."  # noqa: S105
TOTP_ENROLL_AUDIENCE = _CONFIG_TOTP_ENROLL_AUDIENCE
TOTP_SENSITIVE_ENDPOINTS: tuple[TotpSensitiveEndpoint, ...] = (
    "enable",
    "confirm_enable",
    "verify",
    "disable",
    "regenerate_recovery_codes",
)
TOTP_RATE_LIMITED_ENDPOINTS: tuple[TotpSensitiveEndpoint, ...] = ("verify", "confirm_enable")
logger = logging.getLogger("litestar_auth.controllers.totp")


@runtime_checkable
class TotpUserManagerProtocol[UP: UserProtocol[Any], ID](AccountStateValidatorProvider[UP], Protocol):
    """User-manager behavior required by the TOTP controller."""

    async def get(self, user_id: ID) -> UP | None:
        """Return the user for the given identifier."""

    async def on_after_login(self, user: UP) -> None:
        """Run post-login side effects for a fully authenticated user."""

    async def set_totp_secret(self, user: UP, secret: str | None) -> UP:
        """Set or clear the TOTP secret for a user."""

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return a plain-text TOTP secret from storage."""

    async def set_recovery_code_hashes(self, user: UP, hashes: tuple[str, ...]) -> UP:
        """Replace the active TOTP recovery-code hashes for a user."""

    async def read_recovery_code_hashes(self, user: UP) -> tuple[str, ...]:
        """Return active TOTP recovery-code hashes for a user."""

    async def consume_recovery_code_hash(self, user: UP, matched_hash: str) -> bool:
        """Atomically consume a matched recovery-code hash."""

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: LoginIdentifier | None = None,
    ) -> UP | None:
        """Re-authenticate the current user (e.g. password step-up for /enable)."""
