# SPIRE Workload API reference

Runs SPIRE Server and Agent, registers a Unix workload, then verifies that the
`spiffe` SDK adapter fetches and validates a coherent X.509-SVID context.

```bash
sh docker/reference/spiffe/verify.sh
```

The join-token and insecure bootstrap settings are test-only. Production node
attestation and trust bootstrap belong to the deployment platform.
