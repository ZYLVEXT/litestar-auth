"""Optional Litestar raw-body adapter for webhook verification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from authweave_webhooks.models import VerifiedWebhook
    from authweave_webhooks.verify import StandardWebhooksVerifier


class _LitestarRequest(Protocol):
    headers: Mapping[str, str]

    async def body(self) -> bytes: ...


async def verify_litestar_request(
    verifier: StandardWebhooksVerifier,
    request: _LitestarRequest,
) -> VerifiedWebhook:
    """Verify a Litestar request using exact raw body bytes before deserialization.

    Returns:
        The verified webhook envelope.
    """
    body = await request.body()
    headers = list(request.headers.items())
    return await verifier.verify(headers=headers, body=bytes(body))
