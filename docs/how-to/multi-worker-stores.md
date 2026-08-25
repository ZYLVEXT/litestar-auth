# Multi-worker stores

Single-process development may use in-memory rate limits, lockouts, and replay stores. As soon as
more than one worker serves authentication traffic, those stores must be shared or the guarantees
become per-process only.

## What must be shared

| Concern | Shared store |
| --- | --- |
| Opaque sessions | Database or Redis session strategy |
| Refresh rotation / replay | Refresh tables or Redis digests |
| Email verify / password reset consume-once | JWT denylist / replay store |
| TOTP pending JTI and step-up used codes | Redis (or equivalent) TOTP stores |
| Account lockout | Shared lockout store |
| Auth endpoint rate limits | Shared rate-limit backend |
| Workload / webhook / HTTP-signature nonces | Shared replay/nonce store |

See the full matrix in [secrets and stores](../secrets.md).

## Rate limiting and lockout

Default rate limiting counts failures after a separate admission check; concurrent failures can
overshoot `max_attempts`. Opt into `reserve_attempts=True` on sensitive endpoints for atomic
admission (counts attempts since last success). Account lockout registers the attempt before
password verification so concurrent bad passwords cannot slip the threshold.

## Related

- [Quickstart](../quickstart.md)
- [Redis sessions](redis-sessions.md)
- [TOTP](totp.md)
- [Deployment](../deployment.md)
