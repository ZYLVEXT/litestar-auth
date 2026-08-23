"""Signature nonce replay guard (not business idempotency)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from authweave_core import ReplayOutcome, SecurityOperation, SecurityOutcome, observe_security

from authweave_http_signatures.errors import HttpSignatureFailureCode, HttpSignatureVerificationError

if TYPE_CHECKING:
    from authweave_core import ReplayStore, SecurityObserver


class SignatureNonceGuard:
    """Consume one signature nonce exactly once per profile/key namespace."""

    __slots__ = ("_profile_tag", "_store", "_ttl_seconds")

    def __init__(self, store: ReplayStore, *, profile_tag: str, ttl_seconds: float) -> None:
        """Bind the replay store and profile namespace.

        Raises:
            ValueError: If the call cannot complete.
        """
        if ttl_seconds <= 0 or not profile_tag:
            msg = "nonce guard requires positive ttl and profile_tag"
            raise ValueError(msg)
        self._store = store
        self._profile_tag = profile_tag
        self._ttl_seconds = ttl_seconds

    async def consume(self, *, key_id: str, nonce: str, observer: SecurityObserver | None = None) -> None:
        """Record ``nonce`` for ``key_id`` or raise on replay/outage.

        Raises:
            HttpSignatureVerificationError: Mapped from the replay store outcome.
        """
        if not key_id or not nonce:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED)
        key = f"http-sig:{self._profile_tag}:{key_id}:{nonce}"
        with observe_security(observer, SecurityOperation.REPLAY_CHECK, profile=self._profile_tag) as observation:
            outcome = await self._store.check_and_store(key, ttl_seconds=self._ttl_seconds)
            if outcome is ReplayOutcome.STORED:
                observation.set_outcome(SecurityOutcome.STORED)
            elif outcome is ReplayOutcome.REPLAY:
                observation.set_outcome(SecurityOutcome.REPLAY)
            elif outcome is ReplayOutcome.CAPACITY_EXCEEDED:
                observation.set_outcome(SecurityOutcome.CAPACITY_EXCEEDED)
            else:
                observation.set_outcome(SecurityOutcome.UNAVAILABLE)
        if outcome is ReplayOutcome.STORED:
            return
        if outcome is ReplayOutcome.REPLAY:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.NONCE_REPLAY)
        raise HttpSignatureVerificationError(HttpSignatureFailureCode.STORE_UNAVAILABLE)
