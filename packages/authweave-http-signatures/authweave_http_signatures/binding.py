"""Bind HTTP signature ``keyid`` to an authenticated machine principal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from authweave_http_signatures.errors import HttpSignatureFailureCode, HttpSignatureVerificationError

if TYPE_CHECKING:
    from authweave_core import AuthenticationContext


@dataclass(frozen=True, slots=True)
class SignatureKeyBinding:
    """Exact ownership of one signing key for one authenticated context."""

    key_id: str
    application_id: str
    principal_subject: str
    environment: str

    def __post_init__(self) -> None:
        """Reject empty binding components.

        Raises:
            ValueError: If the call cannot complete.
        """
        if not self.key_id or not self.application_id or not self.principal_subject or not self.environment:
            msg = "signature key binding fields are required"
            raise ValueError(msg)

    def assert_matches(self, context: AuthenticationContext) -> None:
        """Fail closed unless ``context`` matches this binding.

        Raises:
            HttpSignatureVerificationError: On identity mismatch.
        """
        evidence = context.evidence
        application_id = evidence.extensions.get("authweave-workload:application_id")
        if (
            context.subject.subject != self.principal_subject
            or evidence.environment != self.environment
            or application_id != self.application_id
        ):
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.KEY_BINDING_MISMATCH)
