"""Optional bounded HTTPS webhook sender (one attempt, no auto-retry)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from urllib.parse import urlparse

from authweave_core import SecurityOperation, SecurityOutcome, observe_security

from authweave_webhooks.models import HEADER_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, WebhookDelivery

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Collection, Mapping, Sequence
    from contextlib import AbstractAsyncContextManager

    from authweave_core import SecurityObserver, TraceCorrelation

_MAX_RESPONSE_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class SenderResult:
    """Outcome of a single webhook POST attempt."""

    status_code: int
    retry_after_seconds: int | None
    body: bytes

    def __repr__(self) -> str:
        """Omit response body contents from representations.

        Returns:
            A secret-free summary.
        """
        return (
            f"SenderResult(status_code={self.status_code}, "
            f"retry_after_seconds={self.retry_after_seconds}, body_len={len(self.body)})"
        )


def validate_https_endpoint(url: str) -> str:
    """Accept only explicit HTTPS endpoints without userinfo or fragment.

    Returns:
        The validated URL.

    Raises:
        ValueError: If the URL is not an allowed HTTPS endpoint.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        msg = "webhook endpoint must be HTTPS without userinfo or fragment"
        raise ValueError(msg)
    return url


@runtime_checkable
class AsyncStreamingResponse(Protocol):
    """The streaming response surface this sender reads."""

    @property
    def headers(self) -> Mapping[str, str]:
        """Response headers."""
        ...

    @property
    def status_code(self) -> int:
        """HTTP status code."""
        ...

    def aiter_bytes(self) -> AsyncIterator[bytes]:
        """Iterate the response body in bounded chunks."""
        ...


@runtime_checkable
class AsyncStreamingClient(Protocol):
    """The httpx-shaped client surface this sender borrows.

    Declared structurally so the sender types its client without depending on
    ``httpx`` itself.
    """

    def stream(  # ruff: ignore[too-many-arguments] - mirrors the httpx call this sender makes
        self,
        method: str,
        url: str,
        /,
        *,
        content: bytes = ...,
        headers: Mapping[str, str] = ...,
        timeout: float = ...,
        follow_redirects: bool = ...,
    ) -> AbstractAsyncContextManager[AsyncStreamingResponse]:
        """Open one streaming request."""
        ...


class HttpxWebhookSender:
    """Send one bounded HTTPS delivery attempt.

    Does not retry automatically. ``Retry-After`` is returned as a typed
    recommendation only. Every destination must match the constructor's exact
    onboarding allowlist. A controlled egress proxy/subnet is still required to
    contain DNS rebinding and compromised allowlisted destinations.
    """

    __slots__ = ("_allowed_endpoints", "_client", "_observer", "_timeout_seconds")

    def __init__(
        self,
        client: AsyncStreamingClient,
        *,
        allowed_endpoints: Collection[str],
        timeout_seconds: float = 5.0,
        observer: SecurityObserver | None = None,
    ) -> None:
        """Bind an httpx-like async client and exact onboarding endpoints."""
        if timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        if not allowed_endpoints:
            msg = "allowed_endpoints must contain at least one endpoint"
            raise ValueError(msg)
        self._client = client
        self._allowed_endpoints = frozenset(validate_https_endpoint(endpoint) for endpoint in allowed_endpoints)
        self._timeout_seconds = timeout_seconds
        self._observer = observer

    async def send(
        self,
        *,
        endpoint: str,
        delivery: WebhookDelivery,
        links: Sequence[TraceCorrelation] = (),
    ) -> SenderResult:
        """POST one delivery attempt to ``endpoint``.

        Returns:
            Status, optional Retry-After recommendation, and a bounded body.

        Raises:
            ValueError: If the endpoint fails the HTTPS policy or exact
                onboarding allowlist.
        """
        with observe_security(
            self._observer,
            SecurityOperation.WEBHOOK_DELIVER,
            profile="standard_webhooks",
            links=links,
        ) as observation:
            validated_endpoint = validate_https_endpoint(endpoint)
            if validated_endpoint not in self._allowed_endpoints:
                msg = "webhook endpoint is not in the configured exact allowlist"
                raise ValueError(msg)
            async with self._client.stream(
                "POST",
                validated_endpoint,
                content=delivery.body,
                headers={
                    HEADER_ID: delivery.webhook_id,
                    HEADER_TIMESTAMP: str(delivery.timestamp),
                    HEADER_SIGNATURE: delivery.signature_header,
                    "content-type": "application/json",
                },
                timeout=self._timeout_seconds,
                follow_redirects=False,
            ) as response:
                body = await _read_bounded_body(response)
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                status_code = int(response.status_code)
            result = SenderResult(status_code=status_code, retry_after_seconds=retry_after, body=body)
            observation.set_outcome(
                SecurityOutcome.SUCCESS if 200 <= result.status_code < 300 else SecurityOutcome.ERROR,
            )
            return result


async def _read_bounded_body(response: AsyncStreamingResponse) -> bytes:
    body = bytearray()
    async for raw_chunk in response.aiter_bytes():
        chunk = bytes(raw_chunk)
        remaining = _MAX_RESPONSE_BYTES - len(body)
        body.extend(chunk[:remaining])
        if len(body) == _MAX_RESPONSE_BYTES:
            break
    return bytes(body)


def _parse_retry_after(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value >= 0 else None
