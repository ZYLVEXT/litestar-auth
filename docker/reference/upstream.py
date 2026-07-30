"""Litestar application exercising the complete Envoy workload-auth boundary."""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import uvicorn
from authweave_core import AuthenticationContext, PrincipalRef, RouteProviderPolicy
from authweave_workload.integrations.litestar import UNIX_SOCKET_PROXY, EnvoyTLSHeaderEvidence
from authweave_workload.models import (
    CredentialStatus,
    EntityStatus,
    MachineCredential,
    MachinePrincipal,
    ResolvedMachineIdentity,
    ServiceApplication,
)
from authweave_workload.provider import DirectMTLSPolicy, DirectMTLSProvider
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from litestar import Litestar, Request, get
from litestar.middleware import DefineMiddleware

from litestar_auth.authentication import (
    LitestarAuthMiddleware,
    LitestarAuthMiddlewareConfig,
    LitestarProviderBinding,
)

PKI = Path("/pki")
SOCKET = Path("/shared/upstream.sock")
PROVIDER_NAME = "direct-machine"


def _revocation_checked_at() -> datetime:
    return datetime.fromtimestamp((PKI / "ca.crl").stat().st_mtime, tz=UTC)


certificate = x509.load_pem_x509_certificate((PKI / "client.crt").read_bytes())
thumbprint = base64.urlsafe_b64encode(hashlib.sha256(certificate.public_bytes(Encoding.DER)).digest())
thumbprint_text = thumbprint.rstrip(b"=").decode("ascii")
application = ServiceApplication("reference", EntityStatus.ACTIVE, "sandbox", "verification")
principal = MachinePrincipal(
    "reference-client",
    application.id,
    PrincipalRef("urn:reference", "reference-client", "workload"),
    EntityStatus.ACTIVE,
)
credential = MachineCredential(
    "reference-client-certificate",
    principal.id,
    CredentialStatus.ACTIVE,
    thumbprint_text,
    "local-ca",
    ("reference:read",),
    ("reference",),
    "sandbox",
    certificate.not_valid_before_utc,
    certificate.not_valid_after_utc,
    certificate.subject.rfc4514_string(),
    certificate.issuer.rfc4514_string(),
    format(certificate.serial_number, "x"),
)


class ReferenceStore:
    """Read-only registration used by the boundary verification request."""

    async def resolve_by_thumbprint(self, presented: str) -> ResolvedMachineIdentity | None:
        return ResolvedMachineIdentity(application, principal, credential) if presented == thumbprint_text else None

    async def record_last_used(self, credential_id: str, *, used_at_epoch: int, minimum_interval: int) -> None:
        return None


policy = DirectMTLSPolicy(
    trust_anchors=frozenset({"local-ca"}),
    termination_boundaries=frozenset({"envoy"}),
)
provider = DirectMTLSProvider(name=PROVIDER_NAME, store=ReferenceStore(), policy=policy)
binding = LitestarProviderBinding(provider=provider, load_principal=lambda context: context.subject)
evidence = EnvoyTLSHeaderEvidence(
    proxy_addresses=frozenset({UNIX_SOCKET_PROXY}),
    trust_anchors=policy.trust_anchors,
    revocation_checked_at=_revocation_checked_at,
)


@get("/reference", sync_to_thread=False)
def reference(request: Request[Any, Any, Any]) -> dict[str, str]:
    context = request.auth
    assert isinstance(context, AuthenticationContext)
    return {
        "audience": context.evidence.audiences[0],
        "profile": context.evidence.profile,
        "subject": context.subject.subject,
        "thumbprint": context.evidence.confirmation_thumbprint or "",
    }


app = Litestar(
    route_handlers=[reference],
    middleware=[
        DefineMiddleware(
            LitestarAuthMiddleware,
            config=LitestarAuthMiddlewareConfig(
                get_request_session=lambda _state, _scope: None,
                provider_bindings_factory=lambda _session: (binding,),
                default_policy=RouteProviderPolicy((PROVIDER_NAME,)),
                tls_peer_evidence_factory=evidence,
            ),
        ),
    ],
)

SOCKET.unlink(missing_ok=True)
os.umask(0)
uvicorn.run(app, uds=str(SOCKET), proxy_headers=False, log_level="warning")
