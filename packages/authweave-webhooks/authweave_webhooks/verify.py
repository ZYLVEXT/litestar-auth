"""Standard Webhooks Ed25519 verifier."""

from __future__ import annotations

from typing import TYPE_CHECKING

from authweave_core import SecurityOperation, SecurityOutcome, observe_security
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from authweave_webhooks.errors import WebhookFailureCode, WebhookVerificationError
from authweave_webhooks.headers import build_signing_input, parse_headers
from authweave_webhooks.models import (
    DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    MAX_BODY_BYTES,
    VerifiedWebhook,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from authweave_core import SecurityObserver, TraceCorrelation

    from authweave_webhooks.keys import PublicKeyResolver
    from authweave_webhooks.models import PublicKeyDocument


class StandardWebhooksVerifier:
    """Verify asymmetric Standard Webhooks deliveries before JSON parsing."""

    __slots__ = (
        "_expected_endpoint",
        "_expected_environment",
        "_expected_owner",
        "_max_body_bytes",
        "_observer",
        "_resolver",
        "_time_source",
        "_tolerance",
    )

    def __init__(
        self,
        resolver: PublicKeyResolver,
        *,
        expected_environment: str,
        expected_owner: str,
        expected_endpoint: str,
        timestamp_tolerance_seconds: int = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
        max_body_bytes: int = MAX_BODY_BYTES,
        time_source: Callable[[], int],
        observer: SecurityObserver | None = None,
    ) -> None:
        """Bind onboarding identity, clock, and key resolver."""
        if timestamp_tolerance_seconds <= 0:
            msg = "timestamp_tolerance_seconds must be positive"
            raise ValueError(msg)
        self._resolver = resolver
        self._expected_environment = expected_environment
        self._expected_owner = expected_owner
        self._expected_endpoint = expected_endpoint
        self._tolerance = timestamp_tolerance_seconds
        self._max_body_bytes = max_body_bytes
        self._time_source = time_source
        self._observer = observer

    async def verify(
        self,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]],
        body: bytes,
        links: Sequence[TraceCorrelation] = (),
    ) -> VerifiedWebhook:
        """Verify headers and body, refreshing keys at most once on miss.

        Returns:
            An immutable verified webhook envelope.

        Raises:
            WebhookVerificationError: On any fail-closed verification failure.
        """
        with observe_security(
            self._observer,
            SecurityOperation.VERIFY_WEBHOOK,
            profile="standard_webhooks",
            credential_kind="ed25519",
            links=links,
        ) as observation:
            try:
                result = await self._verify(headers=headers, body=body)
            except WebhookVerificationError as exc:
                outcome = (
                    SecurityOutcome.UNAVAILABLE
                    if exc.code in {WebhookFailureCode.KEY_UNAVAILABLE, WebhookFailureCode.STORE_UNAVAILABLE}
                    else SecurityOutcome.INVALID
                )
                observation.set_outcome(outcome, reason_code=exc.code.value)
                raise
            observation.set_outcome(SecurityOutcome.VERIFIED)
            return result

    async def _verify(
        self,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]],
        body: bytes,
    ) -> VerifiedWebhook:
        parsed = parse_headers(
            headers if isinstance(headers, list) else dict(headers),
            body=body,
            max_body_bytes=self._max_body_bytes,
        )
        self._check_timestamp(parsed.timestamp)
        message = build_signing_input(
            webhook_id=parsed.webhook_id,
            timestamp=parsed.timestamp,
            body=body,
        )
        document = await self._resolver.resolve()
        self._check_ownership(document)
        if self._signatures_match(document, message, parsed.signatures):
            return self._result(parsed.webhook_id, parsed.timestamp, body, document)

        with observe_security(
            self._observer,
            SecurityOperation.KEY_REFRESH,
            profile="standard_webhooks",
        ) as observation:
            refreshed = await self._resolver.refresh()
            candidate = await self._resolver.resolve() if refreshed is None else refreshed
            self._check_ownership(candidate)
            matched = self._signatures_match(candidate, message, parsed.signatures)
            if matched:
                observation.set_outcome(SecurityOutcome.HIT if refreshed is None else SecurityOutcome.SUCCESS)
            else:
                observation.set_outcome(SecurityOutcome.MISS)
        if matched:
            return self._result(parsed.webhook_id, parsed.timestamp, body, candidate)
        raise WebhookVerificationError(WebhookFailureCode.SIGNATURE_INVALID)

    def _check_timestamp(self, timestamp: int) -> None:
        now = self._time_source()
        if abs(now - timestamp) > self._tolerance:
            raise WebhookVerificationError(WebhookFailureCode.TIMESTAMP_OUT_OF_TOLERANCE)

    def _check_ownership(self, document: PublicKeyDocument) -> None:
        if document.environment != self._expected_environment:
            raise WebhookVerificationError(WebhookFailureCode.ENVIRONMENT_MISMATCH)
        if document.owner != self._expected_owner:
            raise WebhookVerificationError(WebhookFailureCode.OWNER_MISMATCH)
        if document.endpoint != self._expected_endpoint:
            raise WebhookVerificationError(WebhookFailureCode.ENDPOINT_MISMATCH)
        now = self._time_source()
        if now < document.not_before:
            raise WebhookVerificationError(WebhookFailureCode.KEY_UNAVAILABLE)
        if document.retire_after is not None and now > document.retire_after:
            raise WebhookVerificationError(WebhookFailureCode.KEY_UNAVAILABLE)

    def _signatures_match(
        self,
        document: PublicKeyDocument,
        message: bytes,
        signatures: tuple[bytes, ...],
    ) -> bool:
        for key in document.keys:
            public_key = Ed25519PublicKey.from_public_bytes(key.public_key)
            for signature in signatures:
                try:
                    public_key.verify(signature, message)
                except InvalidSignature:
                    continue
                else:
                    return True
        return False

    def _result(
        self,
        webhook_id: str,
        timestamp: int,
        body: bytes,
        document: PublicKeyDocument,
    ) -> VerifiedWebhook:
        return VerifiedWebhook(
            webhook_id=webhook_id,
            timestamp=timestamp,
            body=body,
            environment=document.environment,
            owner=document.owner,
            endpoint=document.endpoint,
            key_document_version=document.version,
        )
