"""Optional authweave-workload contribution through Litestar Extension SDK v2."""

from datetime import UTC, datetime
from pathlib import Path

from authweave_workload.events import SecurityEvent
from authweave_workload.integrations.litestar import (
    UNIX_SOCKET_PROXY,
    DirectMTLSProviderConfig,
    EnvoyTLSHeaderEvidence,
    WorkloadAuthExtension,
)
from authweave_workload.provider import DirectMTLSPolicy

policy = DirectMTLSPolicy(
    trust_anchors=frozenset({"production-ca"}),
    termination_boundaries=frozenset({"envoy"}),
)


def deliver_authentication_event(event: SecurityEvent) -> None:
    """Collect a demo event; production callbacks must persist events durably."""
    # Replace this stub with a transactional write to your own audit store.
    audit_inbox.append(event)


audit_inbox: list[SecurityEvent] = []


workload_extension = WorkloadAuthExtension(
    EnvoyTLSHeaderEvidence(
        proxy_addresses=frozenset({UNIX_SOCKET_PROXY}),
        trust_anchors=policy.trust_anchors,
        revocation_checked_at=lambda: datetime.fromtimestamp(
            Path("/run/pki/client-ca.crl").stat().st_mtime,
            tz=UTC,
        ),
    ),
    direct_mtls=(
        DirectMTLSProviderConfig(
            name="direct-machine",
            policy=policy,
            event_callback=deliver_authentication_event,
        ),
    ),
)

# Add ``workload_extension`` to LitestarAuthConfig.extensions. The extension contributes a
# provider to the existing middleware; it never installs a second authentication middleware.
