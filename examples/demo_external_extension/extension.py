"""Minimal external-style extension built only on the public extension facade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from litestar import get

from litestar_auth.extensions import (
    EXTENSION_API_VERSION,
    AuthExtension,
    AuthExtensionRegistrationContext,
    AuthExtensionValidationContext,
)


@get("/demo/external-extension/status", sync_to_thread=False)
def demo_external_extension_status() -> dict[str, str]:
    """Return the extension contribution status.

    Returns:
        Extension status payload.
    """
    return {"extension": "demo_external_extension", "status": "registered"}


@dataclass(frozen=True, slots=True)
class DemoExternalExtension:
    """Auth extension that contributes one small controller."""

    name: str = "demo_external_extension"
    enabled: bool = True
    requires_api: ClassVar[tuple[int, int]] = EXTENSION_API_VERSION

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Reject configs that have no startup authentication backend.

        Raises:
            ValueError: If the host app has no configured authentication backend.
        """
        if not context.backend_names:
            msg = f"{self.name} requires at least one authentication backend."
            raise ValueError(msg)

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Register the demo controller through the public context helper."""
        context.set_local_state(self.name, "controller", "demo_external_extension_status")
        context.add_controller(demo_external_extension_status)


extension: AuthExtension = DemoExternalExtension()
