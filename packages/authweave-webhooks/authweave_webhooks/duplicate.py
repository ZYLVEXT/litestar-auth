"""Duplicate-delivery helpers built on authweave-core replay outcomes.

These helpers protect against immediate re-delivery. They are not a durable
business inbox: applications own exactly-once semantics across crash windows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from authweave_core import ReplayOutcome, SecurityOperation, SecurityOutcome, observe_security

from authweave_webhooks.errors import WebhookFailureCode, WebhookVerificationError

if TYPE_CHECKING:
    from authweave_core import ReplayStore, SecurityObserver


class DuplicateDeliveryGuard:
    """Claim a webhook-id once per environment/endpoint namespace."""

    __slots__ = ("_endpoint", "_environment", "_observer", "_store", "_ttl_seconds")

    def __init__(
        self,
        store: ReplayStore,
        *,
        environment: str,
        endpoint: str,
        ttl_seconds: float,
        observer: SecurityObserver | None = None,
    ) -> None:
        """Bind the replay store and delivery namespace."""
        if ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        self._store = store
        self._environment = environment
        self._endpoint = endpoint
        self._ttl_seconds = ttl_seconds
        self._observer = observer

    async def claim(self, webhook_id: str) -> None:
        """Record ``webhook_id`` or raise on duplicate/outage/capacity.

        Raises:
            WebhookVerificationError: Mapped from the replay store outcome.
        """
        key = f"webhook:{self._environment}:{self._endpoint}:{webhook_id}"
        with observe_security(
            self._observer,
            SecurityOperation.REPLAY_CHECK,
            profile="standard_webhooks",
        ) as observation:
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
            raise WebhookVerificationError(WebhookFailureCode.DUPLICATE_DELIVERY)
        if outcome is ReplayOutcome.CAPACITY_EXCEEDED:
            raise WebhookVerificationError(WebhookFailureCode.STORE_UNAVAILABLE)
        raise WebhookVerificationError(WebhookFailureCode.STORE_UNAVAILABLE)
