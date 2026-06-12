"""Private AuthExtension implementations used only by tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar import get
from litestar.di import NamedDependency
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.middleware import DefineMiddleware
from litestar.openapi.spec import SecurityScheme
from litestar.response import Response

from litestar_auth.extensions import EXTENSION_API_VERSION

if TYPE_CHECKING:
    from litestar.types import Message, Receive, Scope, Send

    from litestar_auth import AuthExtensionRegistrationContext, AuthExtensionValidationContext
    from litestar_auth.extensions import ExtensionManagerHookEvent, ExtensionManagerHookSubscriber

EXTENSION_HTTP_BAD_REQUEST = 400
EXTENSION_HTTP_TEAPOT = 418
EXTERNAL_DISCOVERED_EVENTS: list[str] = []
EXTERNAL_DISCOVERED_MANAGER_EVENTS: list[ExtensionManagerHookEvent] = []


_ExtensionValueDep = NamedDependency[str]


class ExtensionFailureError(RuntimeError):
    """Exception raised by the private test extension route."""


class ExtensionHeaderMiddleware:
    """Middleware contributed by the private test extension."""

    def __init__(self, app: object) -> None:
        """Store the next ASGI application."""
        self.app = cast("Any", app)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Proxy to the next app while adding an extension-owned response header."""

        async def send_with_extension_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                start_message = cast("Any", message)
                headers = list(start_message.get("headers", []))
                headers.append((b"x-extension-middleware", b"enabled"))
                start_message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_extension_header)


class WiringProbeExtension:
    """Private test-only extension that consumes every registration context helper."""

    name = "wiring-probe"

    def __init__(self, events: list[str], *, enabled: bool = True) -> None:
        """Store the event recorder used by the integration test."""
        self.events = events
        self.enabled = enabled

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Record validation after checking canonical backend state."""
        assert context.backend_names == ("primary",)
        self.events.append("validate")

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Contribute route, DI, middleware, OpenAPI, lifecycle, and exception hooks."""
        self.events.append("register")

        def provide_extension_value() -> str:
            self.events.append("dependency")
            return "extension-value"

        @get("/extension/value", sync_to_thread=False)
        def extension_value(extension_value: _ExtensionValueDep) -> dict[str, str]:
            return {"value": extension_value}

        @get("/extension/failure", sync_to_thread=False)
        def extension_failure() -> None:
            msg = "extension handler"
            raise ExtensionFailureError(msg)

        @get("/extension/client-exception", sync_to_thread=False)
        def extension_client_exception() -> None:
            raise ClientException(
                detail="extension client exception",
                status_code=EXTENSION_HTTP_BAD_REQUEST,
                extra={"code": "EXTENSION_CLIENT_EXCEPTION"},
            )

        def handle_extension_failure(_request: object, exc: ExtensionFailureError) -> Response[dict[str, str]]:
            return Response(
                {"detail": str(exc), "code": "EXTENSION_FAILURE"},
                status_code=EXTENSION_HTTP_TEAPOT,
                media_type=MediaType.JSON,
            )

        context.add_dependency(self.name, "extension_value", provide_extension_value)
        context.add_middleware(DefineMiddleware(ExtensionHeaderMiddleware))
        context.add_openapi_security_scheme(
            self.name,
            "extensionAuth",
            SecurityScheme(type="http", scheme="Bearer", description="Extension bearer authentication."),
        )
        context.add_startup_hook(lambda: self.events.append("startup"))
        context.add_shutdown_hook(lambda: self.events.append("shutdown"))
        context.add_exception_handler(self.name, ExtensionFailureError, handle_extension_failure)
        context.add_controller(context.mark_auth_route_handler(extension_value))
        context.add_controller(context.mark_auth_route_handler(extension_failure))
        context.add_controller(context.mark_auth_route_handler(extension_client_exception))


class EventSubscriberProbeExtension:
    """Private test-only extension that records redacted manager lifecycle events."""

    name = "event-subscriber-probe"

    def __init__(self, events: list[ExtensionManagerHookEvent], *, enabled: bool = True) -> None:
        """Store the event recorder used by extension subscriber tests."""
        self.events = events
        self.enabled = enabled

    def validate(self, _context: AuthExtensionValidationContext) -> None:
        """No-op validation for the event-subscriber probe."""

    def register(self, _context: AuthExtensionRegistrationContext) -> None:
        """No-op registration for the event-subscriber probe."""

    def manager_hook_subscribers(self) -> tuple[ExtensionManagerHookSubscriber, ...]:
        """Return the probe subscriber wired into per-request managers."""
        return (self._record,)

    async def _record(self, event: ExtensionManagerHookEvent) -> None:
        self.events.append(event)


class ExternalGoldenPathExtension:
    """External-style extension target loaded through importlib.metadata entry points."""

    def __init__(
        self,
        *,
        name: str = "external-golden-path",
        requires_api: tuple[int, int] = EXTENSION_API_VERSION,
    ) -> None:
        """Store entry-point-visible extension metadata."""
        self.name = name
        self.requires_api = requires_api

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Record that validation ran with the resolved backend inventory."""
        assert context.backend_names == ("primary",)
        EXTERNAL_DISCOVERED_EVENTS.append("validate")

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Contribute app-visible behavior for the external-discovery integration test."""
        EXTERNAL_DISCOVERED_EVENTS.append("register")

        def provide_external_extension_value() -> str:
            EXTERNAL_DISCOVERED_EVENTS.append("dependency")
            return "external-extension-value"

        @get("/external-extension/value", sync_to_thread=False)
        def external_extension_value(external_extension_value: _ExtensionValueDep) -> dict[str, str]:
            return {"value": external_extension_value}

        context.add_dependency(self.name, "external_extension_value", provide_external_extension_value)
        context.add_controller(context.mark_auth_route_handler(external_extension_value))

    def manager_hook_subscribers(self) -> tuple[ExtensionManagerHookSubscriber, ...]:
        """Return a subscriber proving discovered extensions reach request-scoped managers."""
        return (self._record_manager_event,)

    async def _record_manager_event(self, event: ExtensionManagerHookEvent) -> None:
        EXTERNAL_DISCOVERED_MANAGER_EVENTS.append(event)


def create_external_golden_path_extension() -> ExternalGoldenPathExtension:
    """Entry-point factory used to mimic a separately distributed extension.

    Returns:
        Compatible external-style extension instance.
    """
    return ExternalGoldenPathExtension()


def create_incompatible_external_extension() -> ExternalGoldenPathExtension:
    """Entry-point factory for a discovered extension that must fail the API-version gate.

    Returns:
        External-style extension with an unsupported extension API requirement.
    """
    return ExternalGoldenPathExtension(name="external-incompatible", requires_api=(999, 0))


def reset_external_extension_records() -> None:
    """Clear process-local extension records between integration tests."""
    EXTERNAL_DISCOVERED_EVENTS.clear()
    EXTERNAL_DISCOVERED_MANAGER_EVENTS.clear()
