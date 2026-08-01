"""Fetch and validate an X.509-SVID from a real SPIRE Workload API."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from authweave_workload.spiffe_snapshot import (
    PySpiffeWorkloadSnapshotSource,
    SpiffeSnapshotPolicy,
    SpiffeWorkloadSnapshotManager,
)

_DOMAIN = "example.org"
_SPIFFE_ID = f"spiffe://{_DOMAIN}/workload/authweave"


async def main() -> None:
    """Fetch two coherent contexts and validate the SPIRE-issued identity."""
    async with PySpiffeWorkloadSnapshotSource(timeout_seconds=10) as source:
        manager = SpiffeWorkloadSnapshotManager(
            source=source,
            policy=SpiffeSnapshotPolicy(
                local_trust_domain=_DOMAIN,
                refresh_interval=timedelta(seconds=1),
                maximum_staleness=timedelta(minutes=5),
            ),
        )
        first = await manager.snapshot()
        second = await manager.snapshot(force_refresh=True)
    assert str(first.svid.spiffe_id) == _SPIFFE_ID
    assert second.source.generation == first.source.generation + 1


if __name__ == "__main__":
    asyncio.run(main())
