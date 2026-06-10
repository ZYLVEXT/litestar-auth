"""TOTP verification with replay-store integration."""

from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING

from litestar_auth._totp_primitive import (
    TOTP_ALGORITHM,
    USED_TOTP_CODE_TTL_SECONDS,
    TotpAlgorithm,
    _verify_totp_counter,
)
from litestar_auth.exceptions import ConfigurationError, SecurityWarning

if TYPE_CHECKING:
    from litestar_auth._totp_stores import TotpReplayProtection

logger = logging.getLogger("litestar_auth.totp")


async def verify_totp_with_store(
    secret: str,
    code: str,
    *,
    replay: TotpReplayProtection,
    algorithm: TotpAlgorithm = TOTP_ALGORITHM,
) -> bool:
    """Validate a TOTP code and optionally reject same-window replays.

    Returns:
        ``True`` when the code is valid and has not already been used for ``replay.user_id``.

    Raises:
        ConfigurationError: If replay protection is required and no replay store is configured
            outside testing mode.
    """
    counter = _verify_totp_counter(secret, code, algorithm=algorithm)
    if counter is None:
        logger.warning("TOTP verification failed.", extra={"event": "totp_failed", "user_id": str(replay.user_id)})
        return False

    if replay.used_tokens_store is None:
        if replay.require_replay_protection and not replay.unsafe_testing:
            msg = "TOTP replay protection is required in production. Configure a UsedTotpCodeStore."
            raise ConfigurationError(msg)
        warnings.warn(
            "TOTP replay protection is DISABLED because used_tokens_store=None.",
            SecurityWarning,
            stacklevel=2,
        )
        return True

    mark_result = await replay.used_tokens_store.mark_used(replay.user_id, counter, USED_TOTP_CODE_TTL_SECONDS)
    if mark_result.stored:
        return True
    if mark_result.rejected_as_replay:
        logger.warning("TOTP replay detected.", extra={"event": "totp_replay", "user_id": str(replay.user_id)})
    else:
        logger.warning(
            "TOTP used-code store rejected verification under capacity pressure (fail closed).",
            extra={"event": "totp_replay_store_capacity", "user_id": str(replay.user_id)},
        )
    return False
