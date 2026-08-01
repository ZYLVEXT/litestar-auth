# authweave-webhooks

Asymmetric Standard Webhooks toolkit for AuthWeave integrations
(`authweave-standard-webhooks-v1a` Ed25519 profile).

This package does **not** depend on `litestar-auth` and is not authentication
middleware. It verifies or produces webhook deliveries before JSON parsing.

```bash
uv add 'authweave-webhooks[redis]'
```

```python
from authweave_webhooks import (
    Ed25519PublicKey,
    PublicKeyDocument,
    StandardWebhooksVerifier,
    StaticPublicKeyResolver,
)
from authweave_webhooks.redis_store import RedisReplayStore

resolver = StaticPublicKeyResolver(
    PublicKeyDocument(
        version="1",
        environment="sandbox",
        owner="merchant-1",
        endpoint="https://merchant.example/hooks/payments",
        not_before=0,
        retire_after=None,
        keys=(Ed25519PublicKey(public_key),),
    )
)
verifier = StandardWebhooksVerifier(
    resolver,
    replay_store=RedisReplayStore(redis),
    expected_environment="sandbox",
    expected_owner="merchant-1",
    expected_endpoint="https://merchant.example/hooks/payments",
    time_source=lambda: 1_700_000_000,
)
verified = await verifier.verify(headers=headers, body=raw_body)
```

The replay store is mandatory. After a signature succeeds, `verify()` atomically
claims the `webhook-id` in a namespace derived from environment, owner, endpoint,
and id. The library derives a TTL that covers the complete inclusive timestamp
acceptance window; replay-store outage or capacity pressure fails verification
closed. A repeated valid delivery is returned with `verified.replay_detected=True`;
the flag is telemetry, not business idempotency.

After **every** successful verification, atomically insert the complete raw body
and verified metadata into a durable inbox with a unique key over environment,
owner, endpoint, and `webhook_id`. Never overwrite an existing row, and acknowledge
the HTTP delivery only after that transaction commits. A retry can then restore an
inbox row missing after a crash, while a committed row absorbs concurrent or later
retries. Use a shared replay store such as Redis in multi-worker deployments.

Pass an optional core `SecurityObserver` to the verifier or HTTP sender to emit
bounded verification/replay/delivery telemetry. Retry and queue consumers may
pass `TraceCorrelation` values through `links=`; trace context is correlation
only and is never accepted as identity.

`HttpxWebhookSender` requires a non-empty exact endpoint allowlist, disables
redirects, and streams at most 65,536 response bytes. The application must also
place its HTTP client behind the controlled egress proxy/subnet described in the
merchant sender threat model; DNS safety is not inferred from HTTPS syntax.

```python
from authweave_webhooks.sender import HttpxWebhookSender

sender = HttpxWebhookSender(
    httpx_client,
    allowed_endpoints={"https://merchant.example/hooks/payments"},
)
result = await sender.send(endpoint=merchant_endpoint, delivery=delivery)
```

## Extras

- `[redis]` — shared `RedisReplayStore` for fail-closed verification
- `[httpx]` — one-shot HTTPS sender without auto-retry
- `[litestar]` — raw-body verification helper

Private keys stay inside `AsyncMessageSigner` implementations. The library never
accepts private key bytes on verifier APIs and keeps secrets out of `repr` /
error messages.

See `docs/roadmap.md`, `docs/merchant/webhooks.md`, the sender threat model, and
ADR 0002 for key-tenancy and egress rules. Language-neutral vectors plus Python
and dependency-free Node.js verifiers live in `docs/vectors/webhooks/v1a/`.
