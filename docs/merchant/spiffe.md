# Merchant SPIFFE notes

AuthWeave authenticates **projected SPIFFE X.509-SVID identities**
([ADR 0006](../adr/0006-spiffe-validation-boundary.md)). It does not run SPIRE
and does not register short-lived SVIDs by certificate thumbprint.

## Validation boundary (pick one)

1. **Mesh termination** — proxy validates the chain; an allowlisted local
   factory (`MeshSPIFFEHeaderEvidence`) projects `SpiffePeerEvidence` onto
   `RequestView` via `WorkloadAuthExtension.spiffe_peer_evidence_factory`.
2. **Headless** — call `SpiffeX509SvidValidator` with leaf+intermediates and a
   bundle snapshot, then `project_spiffe_peer(...)`.

Never do both partially.

## Litestar wiring

```python
from authweave_workload.integrations.litestar import (
    MeshSPIFFEHeaderEvidence,
    SPIFFEProviderConfig,
    WorkloadAuthExtension,
)
from authweave_workload.spiffe import SpiffePolicy

WorkloadAuthExtension(
    tls_peer_evidence_factory=lambda _scope: None,
    spiffe_peer_evidence_factory=MeshSPIFFEHeaderEvidence(
        proxy_addresses=frozenset({"127.0.0.1"}),
        termination_boundary="mesh-local",
    ),
    spiffe=(
        SPIFFEProviderConfig(
            name="spiffe",
            policy=SpiffePolicy(
                allowed_trust_domains=frozenset({"example.org"}),
                termination_boundaries=frozenset({"mesh-local"}),
            ),
            resolver=my_resolver,
            event_callback=deliver_security_event,
        ),
    ),
)
```

`deliver_security_event` is the application-owned durable audit callback required by
[ADR 0001](../adr/0001-authentication-event-callback.md). For explicitly non-audited local
fixtures only, pass `event_callback=None` and set `allow_unaudited=True` on the extension.

Allowlisted mesh headers: `x-auth-spiffe-id`, `x-auth-spiffe-not-before`,
`x-auth-spiffe-not-after`.

## Provider

`SPIFFEProvider` matches when `request.spiffe_peer` is present, checks trust
domain and termination-boundary allowlists, and resolves
`spiffe://trust-domain/path` through an explicit principal mapping.

## Vectors and smoke

See the [X.509-SVID vector manifest](../vectors/spiffe/x509-svid/manifest.json) and
`sh docker/reference/spiffe/verify.sh`.
